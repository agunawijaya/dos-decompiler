#!/usr/bin/env python3
"""
placements.py -- Extract "draw sprite S at column C, row R" from 8086 code.

Why
---
A screen in a game of this vintage is not a map file. It is a *sequence of
calls*, each of which writes a column, a row and a sprite selector into fixed
variables and then calls a blitter. Reading one such routine by hand takes ten
minutes; there are dozens.

This walks the call tree from a build routine and recovers the placements.

Do not hand it the variable addresses
-------------------------------------
The first version took `--col-var`, `--row-var` and `--sel-var` and applied
that one triple to every routine it was told was a drawer. That was wrong in
two ways at once, and both were invisible until the coverage number was
computed:

* **A drawer can place more than one sprite per call.** Two of Hard Hat Mack's
  three take a second (column, row, selector) triple and draw both. Every call
  site that set only the second triple looked like a failure to find a sprite
  selector -- there was one, in a variable the extractor had never been told
  about.
* **Routines that are handed coordinates in registers are not placement sites
  at all.** Three of the six addresses being passed as "drawers" were the
  low-level blitters that `0x217` dispatches to. Counting calls to them made
  the denominator wrong, so the coverage figure was pessimistic for a reason
  that had nothing to do with the extraction.

So the conventions are now *read out of the drawing routines themselves*. A
placement triple is the shape

    mul byte [COL]   (or mov cl, byte [COL])   -- the column
    mov dl, byte [ROW]                         -- the row
    mov si, word [SEL]                         -- the sprite pointer

and a routine that closes no such triple is not a placement routine. `mul` by 7
means the column is a character cell; a plain `mov cl` means it is a byte
column, which is a different horizontal scale and would have placed sprites in
the wrong place had it gone unnoticed.

`--drawers` remains, for the case where discovery finds the wrong set. It
should not normally be needed.

What it will not do
-------------------
It is deliberately not an emulator. It recognises a handful of idioms and
refuses the rest -- which keeps the output something you can check by reading,
and keeps "the program was never run" true. Anything it cannot parse is
reported rather than skipped, because a screen that is silently missing a
girder looks fine and is wrong.

The number to read is `coverage()`: the fraction of placement calls reached in
the build routine's call tree that became an actual placement. A rendered
screen on its own is rung 5 -- "looks right" proves nothing. The fraction
explained is a falsifiable claim about the same picture: it says how much of
what the program would have drawn is accounted for. The framing is borrowed
from the CONTRAP reconstruction (knowledge/09-lessons-from-contrap.md), where
the equivalent number was 197/197 blits explained.

**But know what it does not measure.** It counts calls that produced *a*
placement, not calls that produced the *right* one. This extractor reached
100% on all three of Hard Hat Mack's levels while one routine was placing a
fourteen-girder floor as a diagonal staircase across the score line, because
it resolved two different index registers as if they were one. The number was
identical before and after the fix. The picture was not.

So the two oracles are complementary and neither replaces the other: the
fraction catches what is *missing*, and drawing it catches what is *wrong*.
CONTRAP's version does measure correctness -- it compares against blits
captured from the running program, which is an oracle this has no equivalent
of, because nothing here is ever run.

Usage:
    python placements.py GAME.COM --builder 0x14D8
    python placements.py GAME.COM --builder 0x14D8 --drawers 0x217,0x268
    python placements.py GAME.COM --list-drawers
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comrec

# A column multiplied by this many pixels is a character cell. Everything of
# this era that draws on a character grid uses 7 or 8; the value only affects
# the reported scale, never whether a placement is found.
CELL_WIDTHS = (7, 8)


class Triple:
    """One (column, row, selector) convention a drawing routine reads."""

    def __init__(self, col, row, sel, scale, masks_low=False):
        self.col, self.row, self.sel, self.scale = col, row, sel, scale
        # Whether the routine does `and si, 0xff00` before the lookup. If it
        # does, only the high byte selects; if it does not, both bytes do and
        # the low one usually carries a per-iteration delta.
        self.masks_low = masks_low

    def __repr__(self):
        return (f"col=[{self.col:#06x}] row=[{self.row:#06x}] "
                f"sel=[{self.sel:#06x}] x{self.scale}")


def depends_on(v, reg):
    """Whether a tracked value still needs `reg` before it is a number."""
    if not isinstance(v, tuple):
        return False
    if v[0] == "tab" and (v[2] if len(v) > 2 else "bx") == reg:
        return True
    return any(depends_on(p, reg) for p in v[1:])


def routine(rec, start, limit=200):
    """The instructions belonging to the routine at `start`.

    A linear scan that stops only at `ret` runs straight through any routine
    that ends in a tail jump -- and a routine that ends `jmp somewhere_else`
    has no `ret` at all. Hard Hat Mack's `draw_digit` is thirteen instructions
    ending in `jmp draw_text`; the scan read sixty-three, fifty of them
    belonging to the high-score screen, and dutifully extracted its trophy and
    its sign into every level.

    So stop at an unconditional jump as well, unless something already seen
    branches to or past the instruction after it. That is the ordinary
    end-of-basic-block rule, and it is the difference between reading a routine
    and reading everything that happens to follow it.
    """
    ins = sorted(rec.decoded.items())
    idx = {o: i for i, (o, _) in enumerate(ins)}
    out, j = [], idx.get(start)
    if j is None:
        return out
    pending = set()                 # forward targets something has branched to
    while j < len(ins) and len(out) < limit:
        o, (sz, t, g) = ins[j]
        out.append((o, t, g))
        mnemonic = t.split(None, 1)[0]
        if (mnemonic.startswith("j") or mnemonic.startswith("loop")) \
                and g is not None and g > o:
            pending.add(g)
        if t in ("ret", "retf", "iret"):
            break
        if mnemonic == "jmp":
            nxt = ins[j + 1][0] if j + 1 < len(ins) else None
            if nxt is None or not any(p >= nxt for p in pending):
                break
        j += 1
    return out


def analyse_drawer(rec, addr):
    """The placement triples a routine reads, in the order it reads them.

    A triple is closed by the load of the sprite pointer, because that is the
    one part with no other plausible reading: a word read into SI immediately
    before a blit is the sprite.
    """
    col = row = None
    scale = 1
    out, closed_at = [], []
    body = routine(rec, addr)
    for n, (o, t, g) in enumerate(body):
        m = re.match(r"^mul byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            col = int(m.group(1), 16)
            continue
        m = re.match(r"^mov [ac]l, byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            col = int(m.group(1), 16)
            continue
        m = re.match(r"^mov dl, byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            row = int(m.group(1), 16)
            continue
        m = re.match(r"^mov si, word \[(0x[0-9a-f]+)\]$", t)
        if m and col is not None and row is not None:
            out.append(Triple(col, row, int(m.group(1), 16), scale))
            closed_at.append(n)
            col = row = None
            continue
        m = re.match(r"^mov al, (\d+)$", t)
        if m and int(m.group(1)) in CELL_WIDTHS:
            scale = int(m.group(1))       # about to multiply the column by it

    # `and si, 0xff00` comes *after* the load that closes a triple, so the mask
    # belongs to the triple before it, not the one after. Attaching it as it is
    # seen gave place_pair's first triple the wrong answer and its second the
    # right one, and the coverage metric could not see the difference.
    for k, tr in enumerate(out):
        stop = closed_at[k + 1] if k + 1 < len(closed_at) else len(body)
        tr.masks_low = any(re.match(r"^and si, 0xff00$", body[j][1])
                           for j in range(closed_at[k] + 1, stop))
    return out


def find_drawers(rec):
    """Every routine that closes at least one placement triple.

    Call targets only. A routine nothing calls is not a drawer, and scanning
    every offset would match the middle of instructions.
    """
    targets = {g for _, (_, t, g) in rec.decoded.items()
               if g is not None and t.startswith("call")}
    out = {}
    for a in sorted(targets):
        tr = analyse_drawer(rec, a)
        if tr:
            out[a] = tr
    return out


class Run:
    """A rectangle of pixels, from a routine that draws without a sprite.

    Sprite placement is not the only primitive a game has. Hard Hat Mack's
    floor is three horizontal lines, its lift shaft a vertical one, and its
    hoist cables four more -- all drawn by one routine that walks a column
    range against a row range and plots. Nothing identifies such a routine
    from the inside: there is no sprite pointer to close a triple on, which is
    why `find_drawers` cannot see it and why the caller has to name it.
    """

    def __init__(self, col0, col1, row0, row1, step=1, site=None):
        self.col0, self.col1 = col0, col1
        self.row0, self.row1 = row0, row1
        self.step = 2 if step else 1
        self.site = site

    @property
    def vertical(self):
        """Which way the routine walks is decided by the parameters, not by a
        flag: equal column bounds mean it steps the row instead."""
        return self.col0 == self.col1

    def points(self):
        if self.vertical:
            lo, hi = sorted((self.row0, self.row1))
            return [(self.col0, r) for r in range(lo, hi + 1)]
        lo, hi = sorted((self.col0, self.col1))
        return [(c, self.row0) for c in range(lo, hi + 1, self.step)]

    def __repr__(self):
        return (f"Run({'v' if self.vertical else 'h'} "
                f"cols {self.col0:#04x}..{self.col1:#04x}, "
                f"rows {self.row0:#04x}..{self.row1:#04x}, step {self.step})")


class Extractor:
    def __init__(self, rec, drawers=None, load_base=0x100, fillers=None):
        self.r = rec
        self.ins = sorted(rec.decoded.items())
        self.idx = {o: i for i, (o, _) in enumerate(self.ins)}
        self.drawers = drawers if drawers is not None else find_drawers(rec)
        # {routine address: (col_from, col_to, row_from, row_to)} -- the four
        # byte variables a filler reads. Declared, not detected; see Run.
        self.fillers = dict(fillers or {})
        self.runs = []
        self.base = load_base
        self.image = rec.image
        self.unparsed = []
        self.last_sel = None    # the selector a routine that writes none inherits
        self._last = {"bytes": {}, "words": {}}   # a callee's state on return
        # The drawer parameter block: scratch, written fresh before every call,
        # and the one thing a callee must not hand back to its caller.
        self.params = set()
        for v in self.drawers.values():
            for tr in (v if isinstance(v, list) else [v]):
                self.params |= {tr.col, tr.row, tr.sel, tr.sel + 1}
        for spec in (self.fillers or {}).values():
            self.params |= set(spec)
        self.out_guard = []
        self.sites = 0          # placement calls reached
        self.explained = 0      # ...of which produced at least one placement

    # -- reading the image ---------------------------------------------------

    def byte(self, addr):
        off = addr - self.base
        return self.image[off] if 0 <= off < len(self.image) else None

    def table(self, addr, n):
        off = addr - self.base
        return list(self.image[off:off + n])

    # -- walking -------------------------------------------------------------

    def routine(self, start, limit=300):
        return routine(self.r, start, limit)

    @staticmethod
    def var_loop(body):
        """A loop whose counter and whose cursor are both *variables*.

        The loops this tool grew up on keep the counter in BL. draw_conveyor
        keeps two bytes in memory instead -- one counting down, one walking
        across -- and never puts either in a register except to index a table:

            mov al, 0x0e            ; the column, stepping by two
            mov byte [W], al
            mov al, 3               ; the counter, 3 down to 0
            mov byte [V], al
          again:
            mov bl, byte [V]
            mov al, byte [W]
            mov byte [place_col], al
            ... place a pair indexed by BL ...
            inc byte [W]
            inc byte [W]
            dec byte [V]
            js  out
            jmp again

        With no `mov bl, imm` there is no loop as far as the tracker is
        concerned, so it evaluated one iteration and drew one of the four
        conveyor segments. Nothing failed: the segment it drew was correct.

        Returns (V, first, {W: (start, step)}), so an iteration at counter `i`
        reads W as `start + step * (first - i)`.
        """
        text = [t for _, t, _ in body]
        v = None
        for n, t in enumerate(text):
            m = re.match(r"^dec byte \[(0x[0-9a-f]+)\]$", t)
            if m and any(x.startswith("js ") for x in text[n + 1:n + 3]):
                v = m.group(1)
                break
        if v is None or f"mov bl, byte [{v}]" not in text:
            return None

        def initial(var):
            """The immediate a variable is loaded with before the loop opens."""
            for n, t in enumerate(text):
                if re.match(rf"^mov byte \[{var}\], (al|bl)$", t) and n:
                    m = re.match(r"^mov (?:al|bl), (0x[0-9a-f]+|\d+)$",
                                 text[n - 1])
                    if m:
                        return int(m.group(1), 0)
            return None

        first = initial(v)
        if first is None or first < 1:
            return None
        steps = {}
        for w in {m.group(1) for m in
                  (re.match(r"^inc byte \[(0x[0-9a-f]+)\]$", t) for t in text)
                  if m}:
            if w == v:
                continue
            start = initial(w)
            if start is not None:
                steps[int(w, 16)] = (start,
                                     text.count(f"inc byte [{w}]"))
        return int(v, 16), first, steps

    @staticmethod
    def up_loop(body):
        """A counted loop that runs *up* to a `cmp`, rather than down to zero.

        `mov bl, N` with the counter stored to a variable was read as N, N-1,
        ... 0, because that is the shape of the girder loops. Four of Hard Hat
        Mack's routines count the other way:

            mov bl, 1
            mov byte [loop_index], bl
          again:
            ... place a sprite indexed by BL ...
            inc byte [loop_index]
            mov bl, byte [loop_index]
            cmp bl, 5
            je  out
            jmp again

        Read as a down-loop that is indices 1 and 0; the program means 1, 2, 3
        and 4. Every one of the four still produced *a* placement, so nothing
        failed -- draw_rivets drew two rivets at the wrong rows instead of
        four at the right ones, and the coverage number stayed where it was.

        Returns (first, limit) so the caller can walk `range(first, limit)`.
        """
        text = [t for _, t, _ in body]
        for n, t in enumerate(text[:-1]):
            m = re.match(r"^mov bl, (0x[0-9a-f]+|\d+)$", t)
            if not m:
                continue
            v = re.match(r"^mov byte \[(0x[0-9a-f]+)\], bl$", text[n + 1])
            if not v:
                continue
            first, var = int(m.group(1), 0), v.group(1)
            if f"inc byte [{var}]" not in text[n:]:
                continue
            j = text.index(f"inc byte [{var}]", n)
            for t2 in text[j:j + 4]:
                c = re.match(r"^cmp bl, (0x[0-9a-f]+|\d+)$", t2)
                if c and int(c.group(1), 0) > first:
                    return first, int(c.group(1), 0)
        return None

    def walk(self, start, depth=0, seen=None, inherited=None):
        """Collect placements from a routine and everything it calls.

        State is inherited by callees. It has to be: a nested loop sets the row
        in the outer routine and the column in the inner one, so a callee that
        starts from a blank slate loses half of every placement.
        """
        # `seen` is the current call *path*, not every routine ever visited.
        # Blocking a routine because it was called once before loses every
        # repeat -- and a screen is built almost entirely out of repeats.
        if seen is None:
            seen = []
        if start in seen or depth > 5 or len(self.out_guard) > 4000:
            return []
        seen = seen + [start]

        out = []
        state = dict(inherited) if inherited else {}
        # `dict()` is shallow, so the callee shared the caller's `bytes` and
        # `words` dictionaries and every write and pop it made leaked back out.
        # Two calls to the same routine from one parent then saw each other's
        # state: Hard Hat Mack draws a crate at column 9 and again at 0x19, and
        # the second call read the first one's leftovers. Inheriting *in* is
        # deliberate -- a nested loop sets the row outside and the column
        # inside -- but nothing should come back.
        state["bytes"] = dict(state.get("bytes") or {})
        state["words"] = dict(state.get("words") or {})
        state.setdefault("count", None)    # loop trip count from `mov bl, imm`
        state.setdefault("count", None)    # loop trip count from `mov bl, imm`
        state.setdefault("bx", None)       # the loop counter / index register
        state.setdefault("cx", None)       # a second index, not the loop's
        state.setdefault("si", None)       # ...usually reached through CX
        state.setdefault("si_ptr", None)   # or SI holds a table address
        state.setdefault("si_kind", None)  # "index" or "ptr"
        state.setdefault("al", None)
        # AL is *not* cleared on entry. Several of these routines take their
        # column or row as a register argument -- the first thing they do is
        # `mov byte [COL], al` -- so clearing it threw away the parameter and
        # the call looked like a placement with no column.

        body = self.routine(start)
        up = self.up_loop(body)
        if up:
            state["up"] = up
        vl = self.var_loop(body)
        state["vloop"] = vl if vl else None
        sel_addrs = {tr.sel for v in self.drawers.values()
                     for tr in (v if isinstance(v, list) else [v])}
        # Following a branch it can decide. Without this the walk runs both
        # arms of every conditional and draws from both: draw_pits and
        # draw_rivet_row test a per-slot state byte, the program skips the
        # slots whose byte is zero, and the reading put six sprites on the
        # screen that the game never draws. The flag comes from the 6502
        # translation's own idiom -- `mov al, X / inc al / dec al` sets Z from
        # AL, which is what LDA did -- and from `cmp reg, imm`.
        #
        # Only forward jumps are followed. A back edge is a loop, and loops
        # are handled by unrolling the call site rather than by walking round,
        # so following one would count every placement twice.
        pos = {o: i for i, (o, _, _) in enumerate(body)}
        n, budget = 0, 4 * len(body) + 16
        while n < len(body) and budget > 0:
            budget -= 1
            o, t, g = body[n]
            nxt = body[n + 1][1] if n + 1 < len(body) else ""
            mn = t.split(None, 1)[0]
            if mn in ("je", "jne", "jz", "jnz", "jmp") and g in pos \
                    and pos[g] > n:
                z = state.get("zf")
                take = (True if mn == "jmp" else
                        None if z is None else
                        (z if mn in ("je", "jz") else not z))
                if take is True:
                    n = pos[g]
                    continue
                if take is False:
                    n += 1
                    continue
            if t == "dec al" and n and body[n - 1][1] == "inc al":
                v = self.resolve(state, state.get("al"))
                state["zf"] = None if v is None else v == 0
                n += 1
                continue
            m = re.match(r"^cmp (al|bl|cl), (0x[0-9a-f]+|\d+)$", t)
            if m:
                v = (self.resolve(state, state.get("al"))
                     if m.group(1) == "al"
                     else state.get("bx" if m.group(1) == "bl" else "cx"))
                state["zf"] = (None if not isinstance(v, int)
                               else v == int(m.group(2), 0))
                n += 1
                continue
            n += 1
            if self.step(state, t, nxt):
                # The selector is a real global and it outlives the routine
                # that set it. Callee state is deliberately not merged back --
                # that once let two calls to draw_crate read each other's
                # columns -- so remember the last value written to it here,
                # in walk order, which is the order the program writes it in.
                for a in sel_addrs:
                    if a in state["words"]:
                        self.last_sel = state["words"][a]
                    elif a in state["bytes"] or a + 1 in state["bytes"]:
                        lo = self.resolve(state, state["bytes"].get(a))
                        hi = self.resolve(state, state["bytes"].get(a + 1))
                        # An undecided write makes the *carried* selector
                        # undecided too, or draw_rivets -- which writes none of
                        # its own -- would inherit the last shape anyone
                        # managed to resolve rather than the one actually left
                        # there.
                        self.last_sel = (None if lo is None or hi is None
                                         else (hi << 8) | lo)
                continue
            if t.startswith("call") and g is not None:
                if g in self.fillers:
                    self.sites += 1
                    spec = self.fillers[g]
                    vals = [state["bytes"].get(a) for a in spec[:4]]
                    step = state["bytes"].get(spec[4]) if len(spec) > 4 else 0
                    if all(isinstance(v, int) for v in vals):
                        self.explained += 1
                        self.runs.append(
                            Run(*vals, step=step if isinstance(step, int) else 0,
                                site=o))
                    # A filler consumes its parameters the way a drawer does,
                    # except the step, which the caller sets once for a group.
                    for a in spec[:4]:
                        state["bytes"].pop(a, None)
                elif g in self.drawers:
                    self.sites += 1
                    got = self.emit(state, o, self.drawers[g])
                    if got:
                        self.explained += 1
                    self.out_guard += got
                    out += got
                    # A drawer consumes its coordinates; the next call sets its
                    # own. Selectors are deliberately *not* cleared -- runs of
                    # calls reuse one sprite and only move.
                    for tr in self.drawers[g]:
                        state["bytes"].pop(tr.col, None)
                        state["bytes"].pop(tr.row, None)
                else:
                    out += self.walk(g, depth + 1, seen, state)
                    # What the callee left in AL is not modelled, so it is not
                    # known. spawn_lunchbox calls `random` and masks the result
                    # to choose one of four shapes; keeping the AL from before
                    # the call turned "cannot be decided" into a definite wrong
                    # shape, and a wrong shape is emitted where nothing should
                    # be.
                    state["al"] = None
                    state["zf"] = None
                    # What a callee writes to *game state* is still written
                    # when it returns. Isolating everything was too blunt: it
                    # was added because two calls to draw_crate read each
                    # other's columns, and a column is scratch -- the drawer
                    # parameter block, re-set before every call. hoist_y is
                    # not. `reset_screen_state` sets it to 180 and
                    # draw_hoist_car reads it three calls later, and with the
                    # write dropped the car was drawn at row 0.
                    #
                    # So the rule is by address, not by direction: the drawer
                    # parameters stay isolated, everything else comes back.
                    for k, v in self._last["bytes"].items():
                        if k not in self.params:
                            state["bytes"][k] = v
                    for k, v in self._last["words"].items():
                        if k not in self.params:
                            state["words"][k] = v
        self._last = state
        return out

    def step(self, state, t, nxt=""):
        """One instruction's effect on the tracked state. True if recognised."""
        m = re.match(r"^mov al, (0x[0-9a-f]+|\d+)$", t)
        if m:
            state["al"] = int(m.group(1), 0)
            return True
        m = re.match(r"^mov cl, (0x[0-9a-f]+|\d+)$", t)
        if m:
            # CL opens the *outer* loop of a nested pair the same way BL opens
            # the inner one, and by the same tell: the counter is stored to a
            # variable so the body can decrement it. Missing this collapsed
            # four floors of girders onto one row -- every column right, every
            # floor but one absent, and the coverage metric none the wiser.
            state["cx"] = int(m.group(1), 0)
            state["ccount"] = (state["cx"] + 1
                               if re.match(r"^mov byte \[0x[0-9a-f]+\], cl$", nxt)
                               else None)
            return True
        m = re.match(r"^mov bl, (0x[0-9a-f]+|\d+)$", t)
        if m:
            # `mov bl, N` opens a counted loop that runs N, N-1, ... 0, with
            # BL as both the counter and the index into whatever tables the
            # body reads. Recording only the count was not enough: the sprite
            # selector is often indexed by the same counter, so a placement
            # inside such a loop failed for want of an index it plainly had.
            state["bx"] = int(m.group(1), 0)
            # ...but BL is also just a register, and `mov bl, 0x88` passing a
            # row to a subroutine would otherwise be read as a 137-iteration
            # loop. What distinguishes a loop is that the counter is stored to
            # a variable so the body can decrement it.
            state["count"] = (state["bx"] + 1
                              if re.match(r"^mov byte \[0x[0-9a-f]+\], bl$", nxt)
                              else None)
            return True
        m = re.match(r"^mov al, byte \[bx \+ si\]$", t)
        if m:
            if state.get("si_kind") == "ptr" and state.get("si_ptr") is not None:
                state["al"] = ("tab", state["si_ptr"], "bx")
            else:
                state["al"] = None
            return True
        m = re.match(r"^mov al, byte \[(bx|si) \+ (0x[0-9a-f]+)\]$", t)
        if m:
            # Which register indexes the table matters, and getting it wrong is
            # not a near miss. One routine reads its column from a table indexed
            # by the loop counter in BX and its row from a table indexed by a
            # fixed value in SI: treating both as the loop index turns a
            # horizontal run of fourteen girders into a diagonal staircase.
            state["al"] = ("tab", int(m.group(2), 16), m.group(1))
            return True
        m = re.match(r"^mov al, byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            state["al"] = ("var", int(m.group(1), 16))
            return True
        def freeze(reg):
            """Collapse every stored value that still depends on `reg`.

            A store keeps the expression, not the number, so that one call site
            inside a loop can be evaluated once per iteration. But between two
            stores a routine may *change* the register:

                mov bl, al                  ; screen x 2
                mov al, byte [bx + SPOTS]
                mov byte [lunchbox_x], al   ; ("tab", SPOTS, "bx")
                inc bl
                mov al, byte [bx + SPOTS]
                mov byte [lunchbox_y], al   ; ("tab", SPOTS, "bx")

            Both are the same expression, so both resolved with the *later* BL
            and the lunchbox came out at (39, 39) -- its row twice, on every
            screen. Freezing at the point the register moves is safe for the
            loop case: the drawer is called inside the body, so its site has
            already been emitted before the counter steps at the bottom.
            """
            for table in ("bytes", "words"):
                for k, v in list(state[table].items()):
                    if depends_on(v, reg):
                        state[table][k] = self.resolve(state, v)

        # AL to an index register, and the arithmetic on the way. A routine
        # that takes a screen number, doubles it and indexes a table of pairs
        # does all three, and none of them was recognised -- so BL kept
        # whatever the caller had left and spawn_lunchbox read its position
        # out of the wrong pair on every screen.
        if t == "shl al, 1":
            state["al"] = ("shl", state.get("al"), 1)
            return True
        m = re.match(r"^mov (bl|cl), al$", t)
        if m:
            r = "bx" if m.group(1) == "bl" else "cx"
            freeze(r)
            state[r] = self.resolve(state, state.get("al"))
            return True
        m = re.match(r"^(inc|dec) (bl|cl)$", t)
        if m:
            r = "bx" if m.group(2) == "bl" else "cx"
            freeze(r)
            v = state.get(r)
            state[r] = None if not isinstance(v, int) else \
                (v + (1 if m.group(1) == "inc" else -1)) & 0xFF
            return True
        m = re.match(r"^mov bl, byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            # The index comes from a variable, not an immediate. Leaving BL
            # alone here was the worst of the three options: draw_pits took
            # whatever index the *caller* had left in it and read its column
            # table past the end, producing a sprite at column 238. Resolve it
            # if the value is known, and clear it if not -- an index nobody
            # has decided must not be inherited from a stranger.
            # ...and only from what something has actually written. For a
            # value a table is indexed by, the file's initial byte is almost
            # never the run-time one, and guessing it reads the table
            # somewhere it was never read: draw_pits produced a sprite at
            # column 238 that way.
            a = int(m.group(1), 16)
            state["bx"] = (self.resolve(state, state["bytes"][a])
                           if a in state["bytes"] else None)
            return True
        m = re.match(r"^add al, byte \[(bx|si) \+ (0x[0-9a-f]+)\]$", t)
        if m:
            # A selector is often a base plus a per-iteration delta:
            #   mov word [SEL], 0x1B00
            #   mov al, byte [SEL]  /  add al, byte [bx + DELTAS]  /  mov [SEL], al
            # Losing the delta leaves every sprite in a run at the base shape,
            # which is why Hard Hat Mack's girders all came out as the same
            # cell -- right position, wrong picture, and the coverage metric
            # could not tell because a placement was still produced.
            base = self.resolve(state, state.get("al"))
            # Collapse the base now. Deferring it lets the expression name the
            # very byte it is about to be stored into -- `mov al, [SEL]` then
            # `add al, ...` then `mov [SEL], al` -- and resolving that recurses
            # until the depth guard returns None.
            state["al"] = ("add", base if base is not None else state.get("al"),
                           ("tab", int(m.group(2), 16), m.group(1)))
            return True
        m = re.match(r"^add al, byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            base = self.resolve(state, state.get("al"))
            state["al"] = ("add", base if base is not None else state.get("al"),
                           ("var", int(m.group(1), 16)))
            return True
        m = re.match(r"^mov (bl|cl), byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            state[m.group(1)[0] + "x"] = self.resolve(
                state, ("var", int(m.group(2), 16)))
            return True
        m = re.match(r"^mov (bl|cl), al$", t)
        if m:
            state[m.group(1)[0] + "x"] = self.resolve(state, state.get("al"))
            return True
        m = re.match(r"^mov si, word \[(0x[0-9a-f]+)\]$", t)
        if m:
            # SI is either a loop index (from CX or BX) or the address of a
            # table (from a word variable). Which one decides how `[bx + si]`
            # reads, so remember where it came from. Hard Hat Mack keeps its
            # per-screen tables this way: the screen sets the pointer, the
            # drawing loop indexes through it.
            a = int(m.group(1), 16)
            v = state["words"].get(a)
            state["si_ptr"] = v if isinstance(v, int) else None
            state["si_kind"] = "ptr"
            return True
        if t == "mov si, cx":
            state["si"] = state.get("cx")
            state["si_kind"] = "index"
            return True
        if t == "mov si, bx":
            state["si"] = state.get("bx")
            state["si_kind"] = "index"
            return True
        m = re.match(r"^(shl|sal) al, 1$", t)
        if m:
            # A table of (column, row) pairs is indexed by twice the selector,
            # then read twice with the index stepped. Without the shift and the
            # step, every such table reads its first entry for every level.
            v = self.resolve(state, state.get("al"))
            state["al"] = None if v is None else (v * 2) & 0xFF
            return True
        m = re.match(r"^(inc|dec) bl$", t)
        if m and state.get("bx") is not None:
            state["bx"] += 1 if m.group(1) == "inc" else -1
            return True
        m = re.match(r"^add ax, (0x[0-9a-f]+)$", t)
        if m:
            # The selector is often computed rather than written whole:
            #     mov bl, [level] / mov al, [bx + table] / add ax, 0x2800
            # picks a variant per level and adds the sprite base.
            # Kept symbolic. Resolving here uses whatever the loop counter
            # happens to be at this instruction, which is its value on the
            # first pass -- so every sprite in a run got the first one's
            # variant. The whole point of a per-iteration delta is that it
            # varies, and emit_one is the only place that knows the index.
            state["al"] = ("hi", int(m.group(1), 16) >> 8, state.get("al"))
            return True
        m = re.match(r"^mov word \[(0x[0-9a-f]+)\], ax$", t)
        if m:
            a = int(m.group(1), 16)
            v = state.get("al")
            if isinstance(v, int):
                state["words"][a] = v
                state["bytes"][a] = v & 0xFF
                state["bytes"][a + 1] = v >> 8
            else:
                # Symbolic: the high byte carries the selector, the low is 0.
                state["words"].pop(a, None)
                state["bytes"][a] = 0
                state["bytes"][a + 1] = ("hibyte", v)
            return True
        m = re.match(r"^mov byte \[(0x[0-9a-f]+)\], al$", t)
        if m:
            state["bytes"][int(m.group(1), 16)] = state["al"]
            return True
        m = re.match(r"^mov byte \[(0x[0-9a-f]+)\], bl$", t)
        if m:
            # The loop counter is kept in a variable and read back into BL each
            # iteration, so it has to survive the round trip.
            state["bytes"][int(m.group(1), 16)] = state.get("bx")
            return True
        m = re.match(r"^mov byte \[(0x[0-9a-f]+)\], cl$", t)
        if m:
            state["bytes"][int(m.group(1), 16)] = state.get("cx")
            return True
        m = re.match(r"^mov byte \[(0x[0-9a-f]+)\], (dl|ch|dh|bh)$", t)
        if m:
            # A register we are not tracking. Record the write as unknown
            # rather than leaving a stale earlier value in place.
            state["bytes"][int(m.group(1), 16)] = None
            return True
        # `0` and not `0x0000`: NASM prints a zero immediate in decimal, and
        # requiring the 0x form silently dropped every write of it.
        # draw_beams sets `mov word [shape_select], 0` and nothing else, so its
        # four beams came out with whatever shape the previous routine left.
        m = re.match(r"^mov word \[(0x[0-9a-f]+)\], (0x[0-9a-f]+|\d+)$", t)
        if m:
            a, v = int(m.group(1), 16), int(m.group(2), 0)
            state["words"][a] = v
            # A word write sets both bytes, and code reads them back:
            # `mov word [SEL], 0x1B00` then `mov al, byte [SEL]` is how a
            # selector's base is fetched before a per-iteration delta is added
            # to it. Recording only the word left that read to fall through to
            # the file's initial byte, which is a different number.
            state["bytes"][a] = v & 0xFF
            state["bytes"][a + 1] = v >> 8
            return True
        m = re.match(r"^mov word \[(0x[0-9a-f]+)\], ax$", t)
        if m:
            v = state.get("al")
            if isinstance(v, int):
                state["words"][int(m.group(1), 16)] = v
            else:
                state["words"].pop(int(m.group(1), 16), None)
            return True
        return False

    def resolve(self, state, v, regs=None, depth=0):
        """A tracked value as a number, or None if it is not decided.

        `regs` overrides the index registers for one evaluation, which is how a
        loop is enumerated: the same expression is resolved once per iteration
        with a different counter, without disturbing the tracked state.
        """
        if v is None or isinstance(v, int):
            return v
        if depth > 8:
            # A 16-bit add done as two 8-bit steps writes a variable back to
            # itself, which is a cycle rather than a value.
            return None
        kind, addr = v[0], v[1]
        if kind == "var":
            # A variable the loop steps: the cursor in a two-variable loop is
            # read the same way a constant is, and only the override says
            # otherwise.
            if regs and addr in regs:
                return regs[addr]
            # A builder configures the routines it is about to call by writing
            # constants into variables. Reading a variable's *initial* value
            # from the file gives the wrong answer for every screen but the one
            # the file happened to be saved in, so what the builder wrote wins.
            if addr in state["bytes"]:
                return self.resolve(state, state["bytes"][addr], regs, depth + 1)
            return self.byte(addr)
        if kind == "shl":
            b = self.resolve(state, v[1], regs, depth + 1)
            return None if b is None else (b << v[2]) & 0xFF
        if kind == "hibyte":
            w = self.resolve(state, v[1], regs, depth + 1)
            return None if w is None else (w >> 8) & 0xFF
        if kind == "hi":
            # `add ax, 0xNN00` after a byte load: the result is a word whose
            # high byte is the base plus the byte, and whose low byte is zero.
            b = self.resolve(state, v[2], regs, depth + 1)
            return None if b is None else (((v[1] + b) & 0xFF) << 8)
        if kind == "add":
            a = self.resolve(state, v[1], regs, depth + 1)
            b = self.resolve(state, v[2], regs, depth + 1)
            return None if a is None or b is None else (a + b) & 0xFF
        if kind == "tab":
            # Which register indexes the table decides which loop varies it.
            reg = v[2] if len(v) > 2 else "bx"
            i = (regs or {}).get(reg, state.get(reg))
            if i is None:
                i = state.get(reg)
            if i is None:
                return None
            return self.byte(addr + i)
        return None

    # -- emitting ------------------------------------------------------------

    def emit(self, s, site, triples):
        out = []
        for tr in triples:
            out += self.emit_one(s, site, tr)
        return out

    def emit_one(self, s, site, tr):
        raws = (s["bytes"].get(tr.col), s["bytes"].get(tr.row),
                self.raw_selector(s, tr))

        # Inside a counted loop the same call site places a different sprite on
        # every iteration, so the site has to be evaluated once per index --
        # but only when something it reads is actually indexed. Repeating a
        # call whose operands are all constants would emit the same sprite N
        # times and inflate the count with copies of one placement.
        # Inside a counted loop the same call site places a different sprite on
        # every iteration, so it is evaluated once per index -- but only for
        # registers something it reads is actually indexed by. Repeating a call
        # whose operands are all constants would emit one sprite N times.
        def indexed_by(v, into):
            """Which registers a value depends on, however deeply nested.

            A selector can be ("add", base, ("tab", T, "bx")). Looking only at
            the outermost tuple misses the table underneath it, the loop is not
            unrolled, and a run of fourteen girders collapses to one.
            """
            if not isinstance(v, tuple):
                return
            if v[0] == "tab":
                into.add(v[2] if len(v) > 2 else "bx")
            for part in v[1:]:
                indexed_by(part, into)

        uses = set()
        for v in raws:
            indexed_by(v, uses)

        def span(reg, count):
            top = s.get(reg)
            if reg not in uses or top is None:
                return [top]
            up = s.get("up") if reg == "bx" else None
            if up and up[0] == top:
                return range(up[0], up[1])
            if s.get(count):
                return range(top, -1, -1)      # counted loop, walked down
            # No immediate count. If every table this placement indexes ends in
            # 0xFF, the trip count is however many entries come before it --
            # which is a fact in the file, not a guess. Without this the loop
            # ran once and drew the first chain of a row of them.
            n = self.terminated(raws, reg, top)
            return range(top, top + n) if n > 1 else [top]

        inner = span("bx", "count")     # the column counter
        outer = span("si", "ccount")    # the floor counter, one level out

        # A loop kept entirely in memory: the counter is not in BL until the
        # instruction that indexes a table with it, so nothing above sees a
        # loop at all. Take the trip count from the variable instead.
        vloop = s.get("vloop")
        if vloop:
            # ...and the placement need not touch BL at all to be in that loop.
            # A `place_pair` erases the previous cell before drawing the new
            # one, and the erase reads only the stepped column and two
            # constants -- no table, no index register. Deciding on `"bx" in
            # uses` alone unrolled the draw four times and the erase once, so
            # three of the four conveyor segments were never rubbed out.
            def steps_var(v):
                if not isinstance(v, tuple):
                    return False
                if v[0] == "var" and v[1] in vloop[2]:
                    return True
                return any(steps_var(p) for p in v[1:])

            if "bx" in uses or any(steps_var(v) for v in raws):
                inner = range(vloop[1], -1, -1)

        out, why = [], None
        for j in outer:
            for i in inner:
                over = {"bx": i, "si": j}
                if vloop:
                    v, first, steps = vloop
                    over[v] = i
                    for w, (start, k) in steps.items():
                        over[w] = (start + k * (first - i)) & 0xFF
                sel = self.resolve(s, raws[2], regs=over)
                if sel is None:
                    why = why or f"no sprite selector in [{tr.sel:#06x}]"
                    continue
                col = self.resolve(s, raws[0], regs=over)
                row = self.resolve(s, raws[1], regs=over)
                if col is None or row is None:
                    why = why or ("column not decided" if col is None
                                  else "row not decided")
                    continue
                if col == 0xFF or row == 0xFF:
                    continue                  # the table's end marker
                p = (sel, col, row, tr.scale)
                if p not in out:
                    out.append(p)
        if not out:
            self.unparsed.append((site, why or "nothing resolved"))
        return out

    def terminated(self, raws, reg, top, cap=128):
        """How many entries a 0xFF-terminated table has, from `top`.

        Returns 0 when there is no terminator within `cap`, which is the signal
        to fall back to a single iteration -- over-unrolling a loop that has no
        terminator would invent placements, and precision is dearer than the
        last chain.
        """
        bases = set()

        def collect(v):
            if not isinstance(v, tuple):
                return
            if v[0] == "tab" and (v[2] if len(v) > 2 else "bx") == reg:
                bases.add(v[1])
            for part in v[1:]:
                collect(part)

        for v in raws:
            collect(v)
        if not bases:
            return 0
        n = 0
        while n < cap:
            vals = [self.byte(b + top + n) for b in bases]
            if any(v is None or v == 0xFF for v in vals):
                return n
            n += 1
        return 0

    def raw_selector(self, s, tr):
        """The selector as tracked, before resolving.

        Some drawers mask the pointer with 0xFF00, and for those only the high
        byte of the selector word carries the sprite number. The rest add the
        two bytes together, and then the low byte matters: it is where a
        per-iteration delta lands. Hard Hat Mack has one drawer of each kind
        and the difference is not cosmetic -- reading the high byte alone put
        every girder in a run at the same shape, and produced a placement every
        time, so the coverage metric stayed at 100%.
        """
        hi, written = None, True
        if tr.sel in s["words"]:
            w = s["words"][tr.sel]
            hi = None if w is None else w >> 8
        elif tr.sel + 1 in s["bytes"]:
            hi = s["bytes"][tr.sel + 1]
        else:
            written = False
        if written and hi is None:
            # Written, and with something nobody could decide. That is not the
            # same as not written at all, and treating the two alike was how a
            # random shape came out as a definite wrong one: spawn_lunchbox
            # stores `lunchbox_shapes[random() & 3]` here, so the address holds
            # a value -- it is just not one the file contains.
            return None
        if not written:
            # The selector is a real global and it persists. Two of Hard Hat
            # Mack's routines never write it -- draw_rivets and draw_beams set
            # the blit mode and nothing else, and draw whatever shape the last
            # routine left behind. Callee state is deliberately not merged back
            # into the caller, because that once let two calls to draw_crate
            # read each other's columns, so the value cannot reach here that
            # way. Carrying the last selector *emitted* does reach it, and
            # emission order is execution order: the walk is depth-first and
            # in order, which is how the program runs.
            return self.last_sel
        if tr.masks_low:
            return hi
        lo = s["bytes"].get(tr.sel)
        if lo is None:
            if tr.sel in s["words"]:
                lo = s["words"][tr.sel] & 0xFF
            else:
                return hi
        return ("add", hi, lo)

    def coverage(self):
        """(explained, reached, fraction) over the placement calls in the tree.

        Reached, not total: a placement call inside a routine the walker never
        enters is not counted, so this is an upper bound on how complete the
        screen is, never a lower one. Say which you are quoting.
        """
        return (self.explained, self.sites,
                self.explained / self.sites if self.sites else 0.0)


def load(binary, nasm):
    image = Path(binary).read_bytes()
    rec = comrec.Reconstructor(binary, comrec.parse_segments([], len(image)), [0])
    rec.run(nasm)
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--builder", help="address of a screen-building routine")
    ap.add_argument("--drawers", help="override the discovered drawer list")
    ap.add_argument("--list-drawers", action="store_true",
                    help="show the placement conventions found, and stop")
    ap.add_argument("--nasm", default=None)
    args = ap.parse_args()

    nasm = args.nasm
    if not nasm:
        from shutil import which
        import os
        nasm = os.environ.get("NASM") or which("nasm")

    rec = load(args.binary, nasm)
    found = find_drawers(rec)
    if args.drawers:
        keep = {int(x, 16) for x in args.drawers.split(",")}
        found = {a: t for a, t in found.items() if a in keep}
        for a in sorted(keep - set(found)):
            print(f"note: 0x{a:05X} reads no placement triple; not a drawer",
                  file=sys.stderr)

    print(f"{len(found)} placement routines found:")
    for a, trs in sorted(found.items()):
        print(f"  0x{a:05X}  {len(trs)} sprite(s) per call")
        for tr in trs:
            print(f"      {tr}")
    if args.list_drawers:
        return 0
    if not args.builder:
        ap.error("--builder is required unless --list-drawers is given")

    ex = Extractor(rec, found)
    places = ex.walk(int(args.builder, 16))
    got, reached, frac = ex.coverage()
    print(f"\n{len(places)} placements from builder {args.builder}")
    print(f"placement calls explained: {got}/{reached} ({frac * 100:.1f}%) "
          f"of those reached")
    for sel, c, r, scale in places[:40]:
        print(f"  sprite {sel:>3}  col {c:>3}  row {r:>3}  (x{scale})")
    if len(places) > 40:
        print(f"  ... {len(places) - 40} more")
    if ex.unparsed:
        # More than one per call is normal: a drawer that places two sprites
        # can fail on both, and each is a separate missing sprite.
        print(f"\n{len(ex.unparsed)} sprites not placed:")
        seen = set()
        for site, why in ex.unparsed:
            if (site, why) in seen:
                continue
            seen.add((site, why))
            print(f"  0x{site:05X}  {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
