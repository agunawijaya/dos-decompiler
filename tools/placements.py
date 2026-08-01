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

    def __init__(self, col, row, sel, scale):
        self.col, self.row, self.sel, self.scale = col, row, sel, scale

    def __repr__(self):
        return (f"col=[{self.col:#06x}] row=[{self.row:#06x}] "
                f"sel=[{self.sel:#06x}] x{self.scale}")


def routine(rec, start, limit=200):
    ins = sorted(rec.decoded.items())
    idx = {o: i for i, (o, _) in enumerate(ins)}
    out, j = [], idx.get(start)
    if j is None:
        return out
    while j < len(ins) and len(out) < limit:
        o, (sz, t, g) = ins[j]
        out.append((o, t, g))
        if t in ("ret", "retf"):
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
    out = []
    for o, t, g in routine(rec, addr):
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
            col = row = None
            continue
        m = re.match(r"^mov al, (\d+)$", t)
        if m and int(m.group(1)) in CELL_WIDTHS:
            scale = int(m.group(1))       # about to multiply the column by it
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


class Extractor:
    def __init__(self, rec, drawers=None, load_base=0x100):
        self.r = rec
        self.ins = sorted(rec.decoded.items())
        self.idx = {o: i for i, (o, _) in enumerate(self.ins)}
        self.drawers = drawers if drawers is not None else find_drawers(rec)
        self.base = load_base
        self.image = rec.image
        self.unparsed = []
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
        state.setdefault("bytes", {})      # address -> value or a deferred read
        state.setdefault("words", {})      # address -> immediate
        state.setdefault("count", None)    # loop trip count from `mov bl, imm`
        state.setdefault("bx", None)       # the loop counter / index register
        state.setdefault("cx", None)       # a second index, not the loop's
        state.setdefault("si", None)       # ...usually reached through CX
        state.setdefault("al", None)
        # AL is *not* cleared on entry. Several of these routines take their
        # column or row as a register argument -- the first thing they do is
        # `mov byte [COL], al` -- so clearing it threw away the parameter and
        # the call looked like a placement with no column.

        body = self.routine(start)
        for n, (o, t, g) in enumerate(body):
            nxt = body[n + 1][1] if n + 1 < len(body) else ""
            if self.step(state, t, nxt):
                continue
            if t.startswith("call") and g is not None:
                if g in self.drawers:
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
        m = re.match(r"^mov (bl|cl), byte \[(0x[0-9a-f]+)\]$", t)
        if m:
            state[m.group(1)[0] + "x"] = self.resolve(
                state, ("var", int(m.group(2), 16)))
            return True
        m = re.match(r"^mov (bl|cl), al$", t)
        if m:
            state[m.group(1)[0] + "x"] = self.resolve(state, state.get("al"))
            return True
        if t == "mov si, cx":
            state["si"] = state.get("cx")
            return True
        if t == "mov si, bx":
            state["si"] = state.get("bx")
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
            v = self.resolve(state, state.get("al"))
            if v is not None:
                state["al"] = (int(m.group(1), 16) >> 8) * 256 + v * 256
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
        m = re.match(r"^mov word \[(0x[0-9a-f]+)\], (0x[0-9a-f]+)$", t)
        if m:
            state["words"][int(m.group(1), 16)] = int(m.group(2), 16)
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
            # A builder configures the routines it is about to call by writing
            # constants into variables. Reading a variable's *initial* value
            # from the file gives the wrong answer for every screen but the one
            # the file happened to be saved in, so what the builder wrote wins.
            if addr in state["bytes"]:
                return self.resolve(state, state["bytes"][addr], regs, depth + 1)
            return self.byte(addr)
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
        uses = {v[2] if len(v) > 2 else "bx"
                for v in raws if isinstance(v, tuple) and v[0] == "tab"}

        def span(reg, count):
            top = s.get(reg)
            if reg not in uses or not s.get(count) or top is None:
                return [top]
            return range(top, -1, -1)

        inner = span("bx", "count")     # the column counter
        outer = span("si", "ccount")    # the floor counter, one level out

        out, why = [], None
        for j in outer:
            for i in inner:
                over = {"bx": i, "si": j}
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

    def raw_selector(self, s, tr):
        """The selector as tracked, before resolving.

        The drawers mask the sprite pointer with 0xFF00, so only the high byte
        of the selector word carries the sprite number -- and code that sets it
        often writes that byte directly rather than writing the word.
        """
        if tr.sel in s["words"]:
            return s["words"][tr.sel] >> 8
        if tr.sel + 1 in s["bytes"]:
            return s["bytes"][tr.sel + 1]
        return None

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
