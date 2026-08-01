#!/usr/bin/env python3
"""
comrec.py -- Reconstruct assembly source for a DOS .COM that reassembles
byte-for-byte into the original.

Why a separate tool from the MZ pipeline
-----------------------------------------
A .COM has no header, no relocations and one segment: it loads at offset 0x100
and starts there. That makes it the wrong shape for Ghidra's MZ loader and the
right shape for direct reconstruction, because there is nothing between the
file and the code. Programs of this vintage are also usually hand-written
assembly, so "decompile to C" was never the goal -- the provable deliverable is
assembly source whose output hashes to the original.

The always-green loop
---------------------
Correctness is not asserted, it is measured, on every pass:

    disassemble -> emit source -> assemble -> compare bytes
                        ^                          |
                        +--- demote what differs ---+

An instruction that NASM re-encodes differently from the original -- a short
jump where the original used a near one, a different ModR/M form for the same
operation -- is demoted to raw `db` and the loop runs again. Demotion always
fixes a mismatch, so the loop converges, and the output is byte-identical from
the first successful build rather than at the end of a long cleanup.

Which means byte-identity is the *floor*, not the achievement. Emitting all
16 KB as `db` would also hash correctly and tell you nothing. The number that
matters is how much of the file came back as real instructions, and that is
what this reports.

Segments
--------
Some .COM programs relocate themselves to a fresh segment boundary and jump
there, so the same file holds regions whose addresses are relative to different
bases. Pass `--segment FILE_OFFSET:BASE` for each; anything before the first is
assumed to be the usual .COM layout at 0x100.

Usage:
    python comrec.py GAME.COM --out src/game.asm
    python comrec.py GAME.COM --out src/game.asm --segment 0x2B40:0 --entry 0x2B40
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
except ImportError:  # pragma: no cover
    print("comrec: capstone is required (pip install capstone)", file=sys.stderr)
    raise

# Branches whose operand is a code address we should turn into a label.
BRANCH = {
    "jmp", "call", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg",
    "jge", "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jpe", "jpo",
    "jcxz", "loop", "loope", "loopne", "loopz", "loopnz",
}

# String instructions: capstone spells out the implicit operands, NASM does not
# accept them in that form.
STRING_OPS = {
    "movsb", "movsw", "stosb", "stosw", "lodsb", "lodsw", "scasb", "scasw",
    "cmpsb", "cmpsw", "insb", "insw", "outsb", "outsw",
}


class Segment:
    """A region of the file whose addresses are relative to its own base."""

    def __init__(self, file_start, file_end, base):
        self.file_start = file_start
        self.file_end = file_end
        self.base = base

    def addr(self, file_off):
        return self.base + (file_off - self.file_start)

    def file_off(self, addr):
        return self.file_start + (addr - self.base)

    def contains_addr(self, addr):
        return self.base <= addr < self.base + (self.file_end - self.file_start)


REP_PREFIXES = {"rep", "repe", "repne", "repz", "repnz"}

# Capstone hands back the 32-bit name for these even in 16-bit mode: a bare
# 0x98 is reported as `cwde` when in real mode it is `cbw`. Both the reading
# and the rebuild suffer. NASM assembles `cwde` as `66 98`, two bytes, so the
# instruction fails verification and gets pinned to raw bytes -- correct, but
# it loses eight instructions in ParaTrooper and leaves a comment stating the
# wrong mnemonic, which is worse than losing them.
#
# The prefix is what distinguishes the two, so the fix is to trust the bytes
# rather than the name.
WIDTH_ALIASES = {
    "cwde": "cbw", "cdq": "cwd", "jecxz": "jcxz", "iretd": "iret",
    "pushfd": "pushf", "popfd": "popf", "pushad": "pushaw", "popad": "popaw",
}


def to_nasm(insn):
    """Translate capstone's Intel syntax into something NASM accepts.

    Capstone and NASM agree on most of it. The differences that matter:
    `word ptr` versus `word`, segment overrides written outside the brackets
    rather than inside, and string instructions printed with their implicit
    operands spelled out.

    The repeat prefixes need care: capstone folds them into the mnemonic, so
    the text arrives as `rep stosw` with operands attached — `rep stosw word
    [es:di], ax` — and NASM rejects every one of them. Nineteen instructions in
    a 16 KB program, all failing for this single reason.
    """
    mn, ops = insn.mnemonic, insn.op_str

    # No 0x66 prefix means the operand size is the mode default -- 16 bits.
    if mn in WIDTH_ALIASES and insn.bytes and insn.bytes[0] != 0x66:
        mn = WIDTH_ALIASES[mn]

    parts = mn.split()
    if len(parts) == 2 and parts[0] in REP_PREFIXES and parts[1] in STRING_OPS:
        return mn                       # "rep stosw", operands implicit
    if mn in STRING_OPS:
        return mn                       # implicit operands, no text form

    ops = ops.replace("ptr ", "")
    # es:[0x10] -> [es:0x10]
    ops = re.sub(r"\b(cs|ds|es|ss|fs|gs):\[", r"[\1:", ops)
    # NASM wants no space inside the size specifier it already understands
    ops = re.sub(r"\s+", " ", ops).strip()
    return f"{mn} {ops}".strip() if ops else mn


# Real-mode instructions a 1980s game has no reason to contain. Meeting one
# while sweeping unreferenced bytes means the sweep has wandered into data.
IMPLAUSIBLE = {
    "insb", "insw", "outsb", "outsw", "arpl", "bound",
    "into", "salc", "aam", "aad", "xlatb", "lock",
}


def variants(text, has_label):
    """Alternate NASM spellings of the same instruction, in order of preference.

    An x86 instruction usually has more than one legal encoding, and NASM picks
    the shortest. A 1982 assembler often did not: `add ax, 0x11` sits in the
    file as `05 11 00` (the accumulator form) where NASM emits `83 C0 11`. Both
    are correct; only one matches the file.

    Left alone this costs real ground -- 147 of 223 rejected instructions in
    ParaTrooper differ by encoding choice alone, not by meaning. `strict`
    suppresses NASM's optimiser and recovers them as readable code instead of
    anonymous bytes.
    """
    out = []
    if has_label:
        mn, _, rest = text.partition(" ")
        out.append(f"{mn} strict near {rest}")
        # There is no short form of CALL on x86 -- only jumps have one. Offering
        # it wastes a round and then reports "mismatch in operand sizes", which
        # reads like an encoding problem rather than an impossible instruction.
        if mn != "call":
            out.append(f"{mn} strict short {rest}")
        return out

    m = re.match(r"^(\w+)\s+([^,]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$", text)
    if m:
        mn, dst, imm = m.groups()
        out.append(f"{mn} {dst}, strict word {imm}")
        out.append(f"{mn} {dst}, strict byte {imm}")
    return out


class Reconstructor:
    def __init__(self, path, segments, entries, image=None):
        self.path = Path(path)
        # `image` overrides what is on disk. An MZ's load image is the file
        # minus its header, and reconstructing the header as though it were
        # code is both wrong and, because the result still rebuilds exactly,
        # silently wrong.
        self.image = self.path.read_bytes() if image is None else bytes(image)
        self.segments = segments
        self.entries = entries
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True
        self.decoded = {}          # file_off -> (size, text, target_file_off)
        self.demoted = set()       # file offsets forced back to db
        self.labels = set()        # file offsets that need a label
        self.form = {}             # file_off -> which variant spelling to use
        self.extra = set()         # entry points found by the gap sweep
        self.swept = {}            # sweep start -> end, what each one claimed
        self.blocked = set()       # addresses the sweep must not swallow
        self.reclaimed = False     # a swept run was taken back this round
        self.ds_bias = None        # file_off - DS-relative address, if known

    def segment_of_file(self, off):
        for s in self.segments:
            if s.file_start <= off < s.file_end:
                return s
        return None

    def detect_ds_bias(self):
        """Work out where DS points, so data addresses can be resolved.

        A .COM starts with DS = the PSP segment, and programs that keep their
        data below the code adjust it once, early: `add ax, 0x11 / mov ds, ax`.
        Knowing that delta is what turns `mov si, 0x19F6` from a bare number
        into a pointer at a specific row of the dump.

        Sets self.ds_bias to (file offset - DS-relative address), or leaves it
        None when the pattern does not appear.
        """
        for start in sorted(set(self.entries) | self.extra):
            seg = self.segment_of_file(start)
            if seg is None:
                continue
            off, delta = start, None
            for _ in range(12):
                e = self.decoded.get(off)
                if e is None:
                    break
                text = e[1]
                m = re.match(r"^add ax, (0x[0-9a-f]+|\d+)$", text)
                if m:
                    delta = int(m.group(1), 0)
                elif text == "mov ds, ax" and delta is not None:
                    # DS:0 is at PSP*16 + delta*16; the file's first byte is at
                    # PSP*16 + 0x100.
                    self.ds_bias = delta * 16 - 0x100
                    return
                elif text.startswith("mov ds") or text.startswith("call"):
                    break
                off += e[0]
        return

    def detect_interrupt_handlers(self):
        """Find code the program installs in the interrupt vector table.

        An interrupt handler is an entry point that nothing branches to. The
        hardware calls it. Recursive descent therefore cannot reach it, and a
        game that takes over the keyboard or the timer hides a whole routine
        from the disassembler that way.

        The install is recognisable. The vector table lives at absolute address
        0, so the program points a segment register at zero and writes a
        far pointer into slot `vector * 4`:

            xor ax, ax
            mov es, ax                  ; ES -> the vector table
            lea ax, [0x171]             ; handler offset
            mov bx, cs                  ; handler segment
            xchg word [es:0x24], ax     ; 0x24 / 4 = vector 9, the keyboard
            xchg word [es:0x26], bx

        `xchg` rather than `mov` because the program wants the old vector back
        to chain to, or to restore on exit.

        The slot need not be written as an absolute address. Zaxxon (1984)
        installs its timer tick by pointing DS at zero and walking a base
        register to the slot instead:

            mov ax, cs
            lea dx, [0x191]             ; handler offset
            xor cx, cx
            mov ds, cx                  ; DS -> the vector table
            mov bx, 0x70                ; 0x70 / 4 = vector 0x1C, the timer
            mov word [bx], dx
            mov word [bx + 2], ax

        Same install, no `es:` anywhere in it. Reading only the absolute form
        left the whole 47-byte handler sitting in the file as data, and with it
        every conclusion about how the game keeps time.

        Hard Hat Mack's keyboard handler *was* recovered before this existed --
        but by the gap sweep, which accepted it because its bytes happened to
        decode cleanly and land on the boundary. That is luck, not method: a
        handler containing one implausible-looking opcode, or sitting in a gap
        that does not end where it does, is silently lost. Reading the install
        makes it deliberate.

        Returns [(vector, file_offset)], and adds each to the entry points.
        """
        HALVES = {"al": "ax", "ah": "ax", "bl": "bx", "bh": "bx",
                  "cl": "cx", "ch": "cx", "dl": "dx", "dh": "dx"}
        found = []
        imm = {}                  # register -> the constant it last held
        zeroed = set()            # segment registers known to hold zero

        for off, (sz, text, _) in sorted(self.decoded.items()):
            m = re.match(r"^(?:lea (\w+), \[(0x[0-9a-f]+)\]"
                         r"|mov (\w+), (0x[0-9a-f]+))$", text)
            if m:
                imm[m.group(1) or m.group(3)] = int(m.group(2) or m.group(4), 16)
                continue

            z = re.match(r"^xor (\w+), (\w+)$", text)
            if z and z.group(1) == z.group(2):
                imm[z.group(1)] = 0
                continue

            s = re.match(r"^mov (ds|es|ss), (\w+)$", text)
            if s:
                if imm.get(s.group(2)) == 0:
                    zeroed.add(s.group(1))
                else:
                    zeroed.discard(s.group(1))
                continue

            p = re.match(r"^pop (ds|es|ss)$", text)
            if p:
                zeroed.discard(p.group(1))
                continue

            w = re.match(r"^(?:mov|xchg) word \[(es:)?(0x[0-9a-f]+|bx|si|di)"
                         r"(?: \+ (\d+))?\], (\w+)$", text)
            if w:
                sreg = "es" if w.group(1) else "ds"
                base, disp, src = w.group(2), int(w.group(3) or 0), w.group(4)
                if base.startswith("0x"):
                    # An explicit [es:0x24] carries its own evidence: a low,
                    # four-byte-aligned absolute offset is not something a
                    # program writes to for any other reason.
                    slot = int(base, 16) + disp if sreg == "es" else None
                else:
                    slot = (imm[base] + disp
                            if base in imm and sreg in zeroed else None)
                # Offsets live in the low word of a slot; the high word is the
                # segment, which is always CS here and tells us nothing.
                if (slot is not None and slot < 0x400 and slot % 4 == 0
                        and src in imm):
                    seg = self.segment_of_file(off)
                    if seg is not None and seg.contains_addr(imm[src]):
                        target = seg.file_off(imm[src])
                        found.append((slot // 4, target))
                        if target not in self.extra:
                            self.extra.add(target)
                            self.labels.add(target)
                continue

            # Anything else: forget whatever it wrote, so a stale constant
            # cannot be read as the handler address three instructions later.
            mn = text.split(" ", 1)[0]
            if mn in ("cmp", "test", "push", "call", "int", "out", "ret",
                      "retf", "iret", "nop") or mn.startswith("j"):
                continue
            d = re.match(r"^\w+ (?:word |byte )?(\w+)(?:,|$)", text)
            if d:
                imm.pop(HALVES.get(d.group(1), d.group(1)), None)
        return found

    def walks_to_return(self, off, seg, limit=400):
        """Does a straight-line read from here look like a routine?

        This is the test that separates a table of code addresses from a table
        of data pointers, and it is the only evidence available: both are words
        that land inside the file. Disassemble forwards and see whether the
        bytes behave like a routine -- no opcode a game never executes, and an
        end reached rather than run past.

        Measured on Zaxxon: all 21 addresses in its three jump tables reach a
        return; 21 of the 22 sprite-graphics pointers next to them do not, and
        the one that does is not the first word of its table, so the scan has
        already stopped. Artwork decodes into valid instructions -- that is why
        the sweep needs the same guards -- but it does not decode into
        something shaped like a routine.
        """
        seen = 0
        while seen < limit and off < seg.file_end:
            insn = next(self.md.disasm(
                bytes(self.image[off:min(off + 16, seg.file_end)]),
                seg.addr(off)), None)
            if insn is None or insn.mnemonic in IMPLAUSIBLE:
                return False
            if insn.mnemonic in ("ret", "retf", "iret", "jmp"):
                return True
            off += insn.size
            seen += 1
        return False

    def detect_jump_tables(self):
        """Follow `jmp word [cs:reg]` when the table it reads is a gap in the file.

        The pass below resolves an indirect jump through a *variable*, because
        the program writes a constant into it. This one resolves the other
        shape, where the pointer is read out of a table:

            mov bp, word [bx]           ; an index the game keeps
            add bp, 0x75e               ; ... into a table at cs:0x75e
            jmp word [cs:bp]

        Zaxxon's whole level script is that table, and eleven routines
        totalling about 2,400 bytes are reachable only through it. Left alone
        they sit in the file as data: 57.9% of the code region came back as
        instructions without this, 71.3% with it.

        A table has no length field, so the question is where to stop, and
        guessing is how a disassembler ends up walking through artwork. Two
        facts in the file answer it without guessing:

        * **The table is a gap.** It was not reached by the walk, so it lies in
          a run of unclaimed bytes. It cannot extend past the end of that run,
          because the next byte after it is already known to be an instruction.
        * **A table does not run into the code it points at.** Both of
          Zaxxon's inner tables end exactly where their first forward target
          begins, and carry no terminator at all.
        * **Every entry has to look like a routine.** `walks_to_return` above
          is the test, and it is the one that does the real work: it separates
          a table of code addresses from a table of *data* pointers, which is
          what Zaxxon's sprite dispatch is. Its first word points at artwork,
          the test refuses it, and the scan stops with one target and reports
          nothing.

        Stopping dead there is the right answer: the drawing routines that
        table selects are reached another way, and a table of data pointers
        read as code addresses would be exactly the confident wrong answer
        this toolkit exists to avoid.

        Returns [(table address, [target file offsets])].
        """
        gaps = self.gaps(min_len=4)
        order = sorted(self.decoded.items())
        found = []
        reclaimed = False
        # Nothing past the last instruction already found is accepted as a
        # target. It is the bound that kills the one false positive Zaxxon
        # produces: a table whose slot zero holds 0x2022, which is not a
        # routine but a word in the middle of the tile pointer table, 69 bytes
        # past the end of the program's code. It passes every other test --
        # `and dh, [bx+di]` and its neighbours decode, and the run reaches a
        # return. The price is that code living entirely beyond the known body
        # is not found this way, which no file here does.
        code_hi = max((off + sz for off, (sz, _, _) in self.decoded.items()),
                      default=0)

        for i, (off, (_, text, _)) in enumerate(order):
            m = re.fullmatch(r"(?:jmp|call) word \[cs:(\w+)(?: \+ (\d+))?\]",
                             text)
            if not m:
                continue
            reg, disp = m.group(1), int(m.group(2) or 0)

            # The base is loaded a few instructions earlier, usually as the
            # last thing before the jump. Look back a short way and no further:
            # a constant found twenty instructions up is not evidence.
            base = None
            for j in range(i - 1, max(-1, i - 12), -1):
                pm = re.fullmatch(rf"(?:mov|add) {reg}, (0x[0-9a-f]+|\d+)",
                                  order[j][1][1])
                if pm:
                    base = int(pm.group(1), 0) + disp
                    break
            seg = self.segment_of_file(off)
            if base is None or seg is None or not seg.contains_addr(base):
                continue

            table = seg.file_off(base)
            span = next(((a, b) for a, b in gaps if a <= table < b), None)
            if span is None:
                # The gap sweep got here first and read the table as code. It
                # had no way not to: a run of code addresses disassembles
                # cleanly and lands exactly on its far end, which is the whole
                # of the sweep's test. An instruction naming this address as a
                # jump table is better evidence, so take the run back and let
                # the next round read it properly. Zaxxon has two tables the
                # sweep had claimed, hiding about 700 bytes of routines behind
                # twelve bytes of pointers apiece.
                claim = next((s for s, e in self.swept.items()
                              if s <= table < e), None)
                if claim is not None and table not in self.blocked:
                    self.blocked.add(table)
                    self.extra.discard(claim)
                    self.swept.pop(claim, None)
                    reclaimed = True
                continue
            hi = span[1]

            targets, at = [], table
            while at + 2 <= hi:
                # A table cannot run into the code it points at. Both of
                # Zaxxon's inner tables end exactly where their first forward
                # target begins, and carry no terminator at all.
                ahead = [t for t in targets if t >= table]
                if ahead and at >= min(ahead):
                    break
                word = self.image[at] | (self.image[at + 1] << 8)
                if not seg.contains_addr(word):
                    break
                dest = seg.file_off(word)
                if table <= dest <= at:
                    break
                if dest >= code_hi or not self.walks_to_return(dest, seg):
                    # Slot zero is allowed to be junk and nothing else is. One
                    # of Zaxxon's four tables opens with a word that points
                    # into the tile pointer table, behind a caller that only
                    # reaches slot zero for values it appears never to produce.
                    # Every later entry has to be a routine, or this is not a
                    # jump table -- which is what stops the sprite dispatch,
                    # whose second word is artwork.
                    if at != table:
                        break
                    at += 2
                    continue
                targets.append(dest)
                at += 2

            # One target is a jump, not a table. Two consecutive code
            # addresses in a gap is a shape data does not fall into by chance.
            if len(targets) < 2:
                continue
            found.append((base, sorted(set(targets))))
            for t in targets:
                if t not in self.extra:
                    self.extra.add(t)
                    self.labels.add(t)
        # Taking a run back changes nothing this round but everything in the
        # next one, so it has to count as progress or the loop stops early.
        self.reclaimed = reclaimed
        return found

    def detect_dispatch_targets(self):
        """Find where `jmp word [var]` goes, by finding who writes the pointer.

        An indirect jump ends a recursive-descent walk. Everything the program
        does after it is invisible, and the effect is not marginal: Hard Hat
        Mack reaches **236 of its 9,086 instructions** from the entry point
        before this runs, because the whole game is entered through one
        `jmp word [0xbd9]`.

        This is the "functions reached only through pointers" problem, which
        this toolkit records as unsolved for Sopwith and which the CONTRAP
        reconstruction independently reported having no technique for. It is
        not solved in general -- but a large part of it dissolves once you
        notice that a state machine of this era rarely *computes* the pointer.
        It stores a constant into it:

            mov word [0xbd9], 0xcb6     ; the game loop
            ...
            jmp word [0xbd9]

        So: find every jump or call through a memory word, then find every
        instruction that writes an immediate to that word, and treat those
        immediates as entry points. Iterate, because the code newly reached
        contains more of both.

        On Hard Hat Mack one pass over one variable takes reachability from
        2.6% to 94.9% of the decoded instructions, and the count of sprite
        placement calls reachable from 37 to 85 of 89.

        What it will not do is follow a pointer that is loaded from a table or
        arrived at by arithmetic. When that happens there is nothing to report
        and it reports nothing, which is the correct failure: a guessed entry
        point sends the disassembler into the middle of a routine.

        Returns [(variable, [file offsets])], and adds each target as an entry.
        """
        # The `(?:0x)?` is not decoration. Capstone drops the prefix on a
        # single-digit address, so a program that keeps its dispatch pointer at
        # `[9]` -- Zaxxon does, and calls nine different routines through it --
        # produces `call word [9]`, which an 0x-only pattern silently ignores.
        # The branch-target walk in disassemble() already had this fix; this
        # pass did not, and the cost was nine routines left in the file as data.
        ADDR = r"((?:0x)?[0-9a-f]+)"
        wanted = set()
        for off, (sz, text, _) in self.decoded.items():
            m = re.match(rf"^(?:jmp|call) word \[{ADDR}\]$", text)
            if m:
                wanted.add(int(m.group(1), 16))
        if not wanted:
            return []

        found = []
        for var in sorted(wanted):
            targets = []
            for off, (sz, text, _) in sorted(self.decoded.items()):
                m = re.match(rf"^mov word \[{ADDR}\], {ADDR}$", text)
                if not m or int(m.group(1), 16) != var:
                    continue
                seg = self.segment_of_file(off)
                addr = int(m.group(2), 16)
                if seg is None or not seg.contains_addr(addr):
                    continue
                target = seg.file_off(addr)
                targets.append(target)
                if target not in self.extra:
                    self.extra.add(target)
                    self.labels.add(target)
            if targets:
                found.append((var, sorted(set(targets))))
        return found

    def detect_provenance(self):
        """Look for signs the code was machine-translated from another CPU.

        On the 6502, `CMP` and `SBC` set carry to mean *no borrow*: C = 1 when
        A >= operand. On x86, `CMP` and `SUB` set CF to mean *borrow*: CF = 1
        when dest < src. The two conventions are exact opposites, so 6502 code
        moved to x86 mechanically has to flip the carry after every compare and
        subtract to keep its own branches correct.

        One instruction does that: `cmc`. Finding it after almost every `cmp`
        is not a style; it is an adapter, emitted unconditionally by a
        translator that never checked whether the carry was going to be read.
        A human porting by hand flips the carry only where it matters.

        Hard Hat Mack (1983) shows it plainly: 391 `cmc`, 99% of them directly
        after a `cmp` or `sub`, covering 93% of every compare in the program --
        and only 37% anywhere near an instruction that consumes carry. The
        other 63% are dead, which is the tell.

        Knowing this changes how the disassembly should be read: the structure
        is the 6502 original's, not an x86 programmer's, and the dead flag
        operations are noise rather than meaning.

        Returns a list of (finding, evidence) pairs.
        """
        out = []
        ins = sorted(self.decoded.items())
        idx = {o: i for i, (o, _) in enumerate(ins)}
        cmc = [o for o, (_, t, _) in ins if t == "cmc"]
        cmps = [o for o, (_, t, _) in ins if t.split()[0] in ("cmp", "sub")]
        if len(cmc) >= 20 and cmps:
            after_cmp = sum(1 for o in cmc
                            if idx[o] > 0
                            and ins[idx[o] - 1][1][1].split()[0] in ("cmp", "sub"))
            share = after_cmp / len(cmc)
            covered = after_cmp / len(cmps)
            if share > 0.85 and covered > 0.5:
                out.append((
                    "mechanically translated from 6502",
                    f"{len(cmc)} cmc, {share:.0%} of them straight after a "
                    f"cmp/sub, covering {covered:.0%} of all compares -- a "
                    f"carry-convention adapter, not hand-written x86"))
        return out

    def coverage(self):
        """Bytes claimed by instructions that survived verification."""
        cov = bytearray(len(self.image))
        for off, (size, _, _) in self.decoded.items():
            if off not in self.demoted:
                for i in range(off, min(off + size, len(self.image))):
                    cov[i] = 1
        return cov

    def gaps(self, min_len=6):
        cov = self.coverage()
        out, i, n = [], 0, len(self.image)
        while i < n:
            if cov[i]:
                i += 1
                continue
            j = i
            while j < n and not cov[j]:
                j += 1
            if j - i >= min_len:
                out.append((i, j))
            i = j
        return out

    def sweep_gaps(self):
        """Claim gaps that are unmistakably code, and only those.

        Recursive descent only reaches what something jumps to, so code entered
        through a jump table or a computed call is left behind as data --
        ParaTrooper hides about a kilobyte that way, including a 779-byte block
        that opens with a plain `jmp`.

        The test for whether a gap is code is that linear disassembly lands
        *exactly* on its far end. Real code abuts the next known instruction;
        arbitrary data almost never decodes into a whole number of instructions
        that finishes precisely on the boundary. That single condition is
        strict enough to leave the 11 KB screen-offset table alone, which any
        density heuristic happily shreds into nonsense.

        Returns the number of new entry points found.
        """
        found = 0
        for start, end in self.gaps(min_len=12):
            seg = self.segment_of_file(start)
            if seg is None or end > seg.file_end:
                continue
            # Something else has since proved this run holds a table. The
            # landing test cannot tell a table of code addresses from code --
            # both decode, both finish on the boundary -- so once there is
            # better evidence, it wins.
            if any(start <= b < end for b in self.blocked):
                continue

            # Text decodes into perfectly valid instructions -- "Hello from a
            # plain COM file$" becomes insb/outsw/popaw and lands neatly on the
            # boundary, passing the test below while being obvious data. Judge
            # the bytes before trusting the decode.
            body = self.image[start:end]
            if sum(1 for b in body if 0x20 <= b < 0x7F) >= 0.6 * len(body):
                continue

            # Zero fill is the other kind of data that passes the landing test
            # for free. Two zero bytes decode as `add [bx + si], al`, so any
            # even-length run of them finishes exactly on the far end however
            # long it is. Zaxxon has 112 bytes of padding between its entry
            # stub and the code the stub jumps to; before this guard they came
            # back as fifty-six identical instructions, which inflated the
            # recovered-code figure with bytes the program never executes.
            if sum(1 for b in body if b == 0) >= 0.9 * len(body):
                continue

            off, ok = start, True
            while off < end:
                insn = next(self.md.disasm(
                    bytes(self.image[off:min(off + 16, end)]), seg.addr(off)), None)
                if insn is None or off + insn.size > end:
                    ok = False
                    break
                # Instructions a game never executes. Their presence means the
                # bytes are being read as code by accident.
                if insn.mnemonic in IMPLAUSIBLE:
                    ok = False
                    break
                off += insn.size
            if ok and off == end and start not in self.extra:
                self.extra.add(start)
                self.swept[start] = end
                found += 1
        return found

    def disassemble(self):
        """Recursive descent from every entry point."""
        self.decoded.clear()
        starts = list(self.entries) + sorted(self.extra)
        self.labels = set(starts)
        queue = list(starts)
        seen = set()

        while queue:
            off = queue.pop()
            seg = self.segment_of_file(off)
            if off in seen or seg is None or not (seg.file_start <= off < seg.file_end):
                continue

            last_ax = None
            while off < seg.file_end and off not in seen:
                # A demoted instruction is still an instruction -- it is only
                # emitted as raw bytes because NASM re-encodes it differently.
                # Stopping the walk there abandons everything after it, which
                # collapsed a 1,600-instruction disassembly to six.
                seen.add(off)
                chunk = self.image[off:min(off + 16, seg.file_end)]
                insn = next(self.md.disasm(bytes(chunk), seg.addr(off)), None)
                if insn is None:
                    break

                target = None
                # Capstone drops the 0x on single-digit addresses, so a branch
                # to 8 arrives as "8". Insisting on the prefix silently turned
                # those into unlabelled numbers that no longer point anywhere
                # once the file was re-emitted.
                if insn.mnemonic in BRANCH and \
                        re.fullmatch(r"(?:0x)?[0-9a-f]+", insn.op_str):
                    try:
                        addr = int(insn.op_str, 16)
                    except ValueError:
                        addr = None
                    if addr is not None and seg.contains_addr(addr):
                        target = seg.file_off(addr)
                        self.labels.add(target)
                        queue.append(target)

                text = to_nasm(insn)
                self.decoded[off] = (insn.size, text, target)
                off += insn.size

                # Control does not fall through these.
                if insn.mnemonic in ("jmp", "ret", "retf", "iret", "hlt"):
                    break

                # Nor past a call to DOS that never returns. `mov ax, 0x4C00`
                # followed by `int 0x21` is how every DOS program exits, and
                # what usually sits after it is the message it just printed.
                # Walking on through turns that text into invented code.
                m = re.match(r"^mov ax, (0x[0-9a-f]+|\d+)$", text)
                if m:
                    last_ax = int(m.group(1), 0)
                elif text == "int 0x20":
                    break
                elif text == "int 0x21" and last_ax is not None \
                        and last_ax >> 8 == 0x4C:
                    break
                elif text.startswith("mov ax") or text.startswith("xor ax"):
                    last_ax = None

    def emit(self, with_map=False):
        """Produce NASM source covering every byte of the file.

        Optionally also returns {line_index: file_offset}. Recording that while
        generating is the only reliable way to map a NASM error back to the
        instruction that caused it -- reconstructing the mapping afterwards by
        counting lines is fragile, and getting it wrong makes the demotion loop
        blame innocent instructions and never converge.
        """
        line_map = {}
        lines = [
            "; Reconstructed from " + self.path.name,
            "; Generated by comrec.py -- do not edit by hand.",
            "; Verified: this source assembles to a byte-identical copy.",
            "",
            "BITS 16",
            "",
        ]
        seg_starts = {s.file_start: s for s in self.segments}

        off = 0
        pending_data = []           # list of (byte, note-or-None)
        data_at = [0]               # file offset of pending_data[0]
        ds_bias = self.ds_bias      # file_off - DS-relative address, or None

        def annotate(text, row_off):
            """File offset, and the DS-relative address the code would use.

            ParaTrooper reaches its text through DS = PSP + 0x11, so the
            `mov si, 0x19F6` in the code and the bytes at file offset 0x1A06
            are the same string. Without both numbers on the line there is
            nothing connecting them.
            """
            tag = f"0x{row_off:05X}"
            if ds_bias is not None and row_off >= ds_bias:
                tag += f"  ds:0x{row_off - ds_bias:04X}"
            return f"{text:<74}; {tag}"

        def flush_data():
            while pending_data:
                base = data_at[0]

                # A printable run is almost always a message. Spelling it out
                # turns a wall of hex into the game's own words, and NASM
                # assembles the quoted form to exactly the same bytes.
                #
                # Find where the next run begins before emitting anything, and
                # stop the hex short of it. Emitting a fixed 16 bytes first
                # would slice the front off every string -- "Greg Kuperberg"
                # arrives as "uperberg" with the rest buried in hex above it.
                def run_len(at):
                    n = 0
                    while (at + n < len(pending_data)
                           and 0x20 <= pending_data[at + n][0] < 0x7F
                           and pending_data[at + n][1] is None):
                        n += 1
                    return n

                run = run_len(0)
                if run < 8:
                    ahead = 0
                    limit = min(len(pending_data), 4096)
                    while ahead < limit and run_len(ahead) < 8:
                        ahead += 1
                    if ahead < limit and 0 < ahead < 16:
                        row = pending_data[:ahead]
                        del pending_data[:ahead]
                        data_at[0] += len(row)
                        lines.append(annotate(
                            "    db " + ", ".join(f"0x{b:02X}" for b, _ in row),
                            base))
                        continue

                if run >= 8:
                    chunk = bytes(b for b, _ in pending_data[:run])
                    del pending_data[:run]
                    data_at[0] += run
                    for i in range(0, len(chunk), 56):
                        piece = chunk[i:i + 56]
                        quote = "'" if b'"' in piece or b"'" not in piece else '"'
                        if bytes(quote, "ascii") in piece:
                            lines.append(annotate(
                                "    db " + ", ".join(f"0x{b:02X}" for b in piece),
                                base + i))
                        else:
                            lines.append(annotate(
                                f"    db {quote}{piece.decode('ascii')}{quote}",
                                base + i))
                    continue

                row = pending_data[:16]
                del pending_data[:16]
                data_at[0] += len(row)
                text = "    db " + ", ".join(f"0x{b:02X}" for b, _ in row)
                # A demoted instruction is still an instruction. Carrying its
                # disassembly as a comment keeps the source readable where
                # byte-identity forced raw bytes.
                notes = [n for _, n in row if n]
                if notes:
                    lines.append(f"{text:<74}; {' | '.join(notes)}")
                else:
                    lines.append(annotate(text, base))

        while off < len(self.image):
            if off in seg_starts:
                flush_data()
                s = seg_starts[off]
                lines.append("")
                lines.append(f"; ---- file 0x{s.file_start:04X}, "
                             f"addresses relative to 0x{s.base:04X} ----")
                lines.append(f"    ORG 0x{s.base:04X}" if s.file_start == 0
                             else f"; (segment base 0x{s.base:04X})")
                lines.append("")

            if off in self.labels:
                flush_data()
                lines.append(f"L_{off:05X}:")

            entry = self.decoded.get(off)
            if entry and off not in self.demoted:
                # Buffered data must go out before this instruction, or the
                # bytes of a demoted instruction end up emitted *after* the
                # code that follows them and the whole file shifts.
                flush_data()
                size, text, target = entry
                if target is not None:
                    mn = text.split()[0]
                    text = f"{mn} L_{target:05X}"
                v = self.form.get(off)
                if v is not None:
                    alts = variants(text, target is not None)
                    if v < len(alts):
                        text = alts[v]
                line_map[len(lines)] = off
                lines.append(f"    {text}")
                off += size
            elif entry:
                # Demoted: emit its own bytes and step over the whole thing, so
                # the bytes inside it are never mistaken for instruction starts.
                size = entry[0]
                note = entry[1]
                if not pending_data:
                    data_at[0] = off
                for i, b in enumerate(self.image[off:off + size]):
                    pending_data.append((b, note if i == 0 else None))
                off += size
            else:
                if not pending_data:
                    data_at[0] = off
                pending_data.append((self.image[off], None))
                off += 1

        flush_data()
        lines.append("")
        source = "\n".join(lines)
        return (source, line_map) if with_map else source

    def assemble(self, source, nasm, want_listing=False):
        """Assemble, optionally returning NASM's own account of what it emitted.

        The listing is what makes this reliable. Comparing the finished binary
        only reveals the *first* byte that differs, and re-encodings shift
        everything after them, so a whole-file diff cannot say which
        instructions are actually at fault. The listing gives per-line bytes,
        which turns "something is wrong somewhere" into an exact list.
        """
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "out.asm"
            binf = Path(td) / "out.bin"
            lst = Path(td) / "out.lst"
            src.write_text(source, encoding="ascii", errors="replace")
            cmd = [nasm, "-f", "bin", "-o", str(binf), str(src)]
            if want_listing:
                cmd += ["-l", str(lst)]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                return None, r.stderr, {}
            listing = self.parse_listing(lst) if want_listing and lst.exists() else {}
            return binf.read_bytes(), "", listing

    @staticmethod
    def parse_listing(path):
        """{source line index (0-based): emitted bytes} from a NASM listing.

        A line that emits more than nine bytes is printed across several
        listing rows carrying the same source line number, the earlier ones
        ending in `-`:

            50 00000060 BC1809FBE46124FEE6-   db 0xBC, 0x18, ...
            50 00000069 61B80400CD10EB

        Assigning rather than appending keeps only the tail, so a sixteen-byte
        row reads back as seven bytes. No instruction is long enough to hit
        this, which is why it went unnoticed -- but any check extended to data
        rows would have been quietly comparing the wrong bytes.
        """
        out = {}
        for raw in path.read_text(encoding="latin-1",
                                  errors="replace").splitlines():
            m = re.match(r"\s*(\d+)\s+([0-9A-F]{8})\s+([0-9A-F]+)", raw)
            if not m:
                continue
            hexpart = m.group(3)
            if len(hexpart) % 2:
                hexpart = hexpart[:-1]
            try:
                chunk = bytes.fromhex(hexpart)
            except ValueError:
                continue
            li = int(m.group(1)) - 1
            out[li] = out.get(li, b"") + chunk
        return out

    def first_mismatch(self, built):
        n = min(len(built), len(self.image))
        for i in range(n):
            if built[i] != self.image[i]:
                return i
        if len(built) != len(self.image):
            return n
        return None

    def owning_instruction(self, file_off):
        """Which decoded instruction covers this byte."""
        for start, (size, _, _) in self.decoded.items():
            if start <= file_off < start + size:
                return start
        return None

    # A note on an idea that does not work, so nobody spends a day on it twice.
    #
    def release_pins(self, nasm, good, max_rounds=8):
        """Hand the pins back once the file is right, and see which stick.

        Each pin is decided in one round against a program that later rounds
        change: the sweep turns data into code, labels appear where a `db` run
        used to be, and an instruction demoted in round 3 may have been
        perfectly spellable by round 20. Zaxxon pinned 41 plain `call`
        instructions that assemble to the original bytes on the first try.

        **This note used to say the idea does not work, and that was wrong.**
        What was measured then was releasing every pin and reading the
        mismatch count off the very next assembly. That number is meaningless,
        for the reason recorded at the time: `and ax, 0x2324` sits in Hard Hat
        Mack as the 4-byte ModR/M form where NASM emits the 3-byte accumulator
        form, and one shrunk instruction moves every displacement after it, so
        337 `call` instructions report a mismatch they had nothing to do with.
        The conclusion drawn -- that pins cannot be evaluated in bulk -- did
        not follow. Only a *length* change shifts anything. Put the
        length-changers back, and the round after that compares clean:

        | | pins before | pins after |
        |---|---|---|
        | ParaTrooper | 236 | 178 |
        | Zaxxon | 138 | 90 |
        | Hard Hat Mack | 649 | 320 |

        All three still rebuild byte-identically, which is the only thing that
        was ever at stake -- byte-identity is re-proved here, not assumed, and
        if the release does not settle the pinned version is put back.
        """
        saved = (set(self.demoted), dict(self.form))

        # A label that lands strictly inside another instruction is never
        # emitted -- emit() steps over instructions whole -- so releasing a
        # branch to one only makes NASM reject the file.
        interior = set()
        for off, (sz, _, _) in self.decoded.items():
            interior.update(range(off + 1, off + sz))
        for off in list(self.demoted):
            target = self.decoded[off][2]
            if target is None or target not in interior:
                self.demoted.discard(off)
                self.form.pop(off, None)

        for _ in range(max_rounds):
            source, line_map = self.emit(with_map=True)
            built, err, listing = self.assemble(source, nasm, want_listing=True)

            if built is None:
                bad = {line_map[int(m.group(1)) - 1]
                       for m in re.finditer(r":(\d+): error:", err)
                       if (int(m.group(1)) - 1) in line_map}
                bad -= self.demoted
                if not bad:
                    break
                self.demoted |= bad
                continue

            wrong_len, wrong_bytes = set(), set()
            for line_idx, off in line_map.items():
                produced = listing.get(line_idx)
                entry = self.decoded.get(off)
                if produced is None or entry is None:
                    continue
                want = self.image[off:off + entry[0]]
                if len(produced) != len(want):
                    wrong_len.add(off)
                elif produced != want:
                    wrong_bytes.add(off)

            # Length first, on its own. Judging the byte comparisons in the
            # same round is what produced the wrong answer last time.
            bad = wrong_len or wrong_bytes
            if bad:
                for off in bad:
                    entry = self.decoded[off]
                    alts = variants(entry[1], entry[2] is not None)
                    nxt = self.form.get(off, -1) + 1
                    if nxt < len(alts):
                        self.form[off] = nxt
                    else:
                        self.demoted.add(off)
                continue

            if self.first_mismatch(built) is None:
                return source
            break

        # It did not settle. The pinned version was already proved correct, so
        # that is what ships; a readability gain is not worth a maybe.
        self.demoted, self.form = saved
        return good

    def run(self, nasm, max_rounds=40):
        rounds = 0
        while rounds < max_rounds:
            rounds += 1
            self.disassemble()
            self.detect_ds_bias()
            # Handlers are entry points nothing branches to, so they have to be
            # discovered before the walk can be considered complete.
            if self.detect_interrupt_handlers() and rounds == 1:
                self.disassemble()
            # Indirect jumps have to be resolved after the walk, because the
            # instruction that writes the pointer is often only reached by the
            # walk itself. Re-running the disassembly then reaches the target.
            while True:
                changed = self.detect_dispatch_targets()
                tables = self.detect_jump_tables()
                if not (changed or tables or self.reclaimed):
                    break
                before = len(self.decoded)
                self.disassemble()
                if len(self.decoded) == before and not self.reclaimed:
                    break
            source, line_map = self.emit(with_map=True)
            built, err, listing = self.assemble(source, nasm, want_listing=True)

            if built is None:
                # Demote every line NASM refused, not just the first. Taking
                # them one per round turns nineteen bad instructions into
                # nineteen full disassembly passes.
                bad = set()
                for m in re.finditer(r":(\d+): error:", err):
                    off = line_map.get(int(m.group(1)) - 1)
                    if off is not None and off not in self.demoted:
                        bad.add(off)
                if not bad:
                    return None, source, rounds, f"nasm error: {err.strip()[:400]}"
                # A rejected line means this spelling is wrong, so drop straight
                # to raw bytes: a `strict` variant of an unparsable instruction
                # is just as unparsable.
                self.demoted |= bad
                continue

            # Compare what NASM emitted for each instruction against the bytes
            # that were actually in the file, and demote every one that differs.
            # Done per instruction rather than per file byte, so a re-encoding
            # that shifts everything after it does not hide the rest.
            bad = set()
            for line_idx, off in line_map.items():
                produced = listing.get(line_idx)
                entry = self.decoded.get(off)
                if produced is None or entry is None:
                    continue
                if produced != self.image[off:off + entry[0]]:
                    bad.add(off)
            if bad:
                # Try the next spelling before giving up on an instruction.
                # Only when every variant has failed does it become raw bytes.
                for off in bad:
                    entry = self.decoded[off]
                    alts = variants(entry[1], entry[2] is not None)
                    nxt = self.form.get(off, -1) + 1
                    if nxt < len(alts):
                        self.form[off] = nxt
                    else:
                        self.demoted.add(off)
                continue

            if self.first_mismatch(built) is None:
                # Byte-identical, so the source is already correct. Spend the
                # remaining rounds turning leftover data back into code; every
                # pass is re-verified, so a wrong guess costs a round, not
                # correctness.
                if rounds < max_rounds and self.sweep_gaps():
                    continue
                source = self.release_pins(nasm, source)
                return source, source, rounds, None

            # Listing agreed instruction by instruction yet the file differs:
            # the gap is in data emission, not encoding.
            bad_at = self.first_mismatch(built)
            return None, source, rounds, (
                f"byte 0x{bad_at:X} differs though every instruction matched "
                f"its original encoding")

        return None, None, rounds, "did not converge"

    def blame_error(self, err):
        """Map a NASM error back to the instruction that produced it."""
        m = re.search(r":(\d+):", err)
        if not m:
            return None
        # Re-emit and count lines to find which offset that line belongs to.
        line_no = int(m.group(1))
        source = self.emit().splitlines()
        if line_no - 1 >= len(source):
            return None
        # Walk back to the nearest label, then map forward.
        for i in range(line_no - 1, -1, -1):
            lm = re.match(r"L_([0-9A-F]{5}):", source[i])
            if lm:
                base = int(lm.group(1), 16)
                off = base
                for j in range(i + 1, line_no):
                    e = self.decoded.get(off)
                    if e and off not in self.demoted:
                        off += e[0]
                    else:
                        off += 1
                return self.owning_instruction(off) or off
        return None


def mz_load_image(data):
    """Split an MZ into (header, load image, entry offset), if it is worth it.

    An MZ is normally the other pipeline's business: Ghidra loads it, applies
    the relocations and hands back segments. But some MZ programs are a `.COM`
    wearing a header -- one segment, a handful of relocations, hand-written
    assembly -- and for those the MZ route is strictly weaker. It reaches
    "readable, probably right". This route reaches a rebuild that is
    byte-identical and says so.

    Karateka (1984) is the case that prompted this: 87,990 bytes, four
    relocations, an entry stub that sets DS once and never thinks about
    segments again. Peeling the header off and treating the image as a .COM
    with base 0 reconstructed 85.0% of its code region, and the header put back
    reproduced the shipped .EXE exactly -- SHA-256 checked outside the tool.

    The test is deliberately narrow, because the failure mode of being wrong
    here is silent. Many relocations mean many segments, and a program that
    really uses them will not survive being addressed from a single base.
    """
    if len(data) < 0x40 or data[:2] not in (b"MZ", b"ZM"):
        return None
    hdr_paras = struct.unpack_from("<H", data, 8)[0]
    nreloc = struct.unpack_from("<H", data, 6)[0]
    pages = struct.unpack_from("<H", data, 4)[0]
    last = struct.unpack_from("<H", data, 2)[0]
    ip = struct.unpack_from("<H", data, 20)[0]
    cs = struct.unpack_from("<H", data, 22)[0]
    hdr = hdr_paras * 16
    end = (pages - 1) * 512 + (last or 512)
    if not (0 < hdr < len(data)) or end > len(data):
        return None
    # More than a few relocations means the program moves between segments,
    # and a single base is then a wrong answer that still assembles.
    if nreloc > 8:
        return None
    return data[:hdr], data[hdr:end], (cs << 4) + ip


def detect_layout(image, md):
    """Find a far transfer in the entry stub and the segment split it implies.

    A .COM is nominally one segment, but a program larger than a few kilobytes
    often opens with a stub that reloads CS and continues at a fresh base.
    ParaTrooper does exactly this:

        mov ax, cs / add ax, 0x2C4 / push ax / xor ax, ax / push ax / retf

    which lands at (CS+0x2C4):0 -- file offset 0x2B40, addressed from base 0.
    Miss that and everything after 0x2B40 disassembles against the wrong base,
    so every branch target is wrong and the recursive descent walks off into
    data. It is also the one fact a newcomer to the file is least likely to
    guess, which is reason enough for the tool to work it out rather than ask.

    The stub is not always the first thing in the file. Zaxxon (1984) opens
    with `jmp 0x180` over a twenty-line text banner and puts the same far
    return on the other side of it, which is enough to make this walk give up
    at the first instruction: evaluating from offset 0 and refusing to follow a
    jump found nine instructions in a 20,736-byte file. So a direct jump is
    followed rather than treated as the end of the stub. Nothing in the
    evaluation cares whether two instructions were adjacent in the file, only
    that control reached the second from the first.

    Returns (file_start, base) or None. Only the far-return idiom is handled;
    anything stranger is left to an explicit --segment.
    """
    CSREL, CONST = "csrel", "const"
    regs = {}
    stack = []
    off = 0
    hops = set()

    for _ in range(32):
        insn = next(md.disasm(bytes(image[off:off + 16]), 0x100 + off), None)
        if insn is None:
            return None
        mn, ops = insn.mnemonic, insn.op_str
        off += insn.size

        if mn == "retf":
            if len(stack) < 2:
                return None
            ip, cs = stack[-1], stack[-2]
            if cs[0] != CSREL or ip[0] != CONST:
                return None
            start = cs[1] * 16 + ip[1] - 0x100
            if not (0 < start < len(image)):
                return None
            return start, ip[1]

        m = re.match(r"^(\w+), (\w+)$", ops)
        if mn == "mov" and m and m.group(2) == "cs":
            regs[m.group(1)] = (CSREL, 0)
        elif mn == "mov" and m and m.group(2) in regs:
            regs[m.group(1)] = regs[m.group(2)]
        elif mn == "xor" and m and m.group(1) == m.group(2):
            regs[m.group(1)] = (CONST, 0)
        elif mn == "add" and re.match(r"^(\w+), (0x[0-9a-f]+|\d+)$", ops):
            dst, imm = ops.split(", ")
            cur = regs.get(dst)
            if cur is None:
                return None
            regs[dst] = (cur[0], cur[1] + int(imm, 0))
        elif mn == "mov" and re.match(r"^(\w+), (0x[0-9a-f]+|\d+)$", ops):
            dst, imm = ops.split(", ")
            regs[dst] = (CONST, int(imm, 0))
        elif mn == "push":
            if ops in regs:
                stack.append(regs[ops])
            elif ops == "cs":
                stack.append((CSREL, 0))
            elif re.match(r"^(0x[0-9a-f]+|\d+)$", ops):
                stack.append((CONST, int(ops, 0)))
            else:
                return None
        elif mn == "jmp":
            # A jump over a block of data -- a banner, a copyright line, a
            # table -- is the commonest reason the stub is not at offset 0.
            # Follow it, but only when the target is a plain address inside
            # the file, and only to somewhere this walk has not already been:
            # a computed jump is unresolvable and a jump backwards is a loop,
            # and in both cases the honest answer is to stop.
            if not re.fullmatch(r"0x[0-9a-f]+|\d+", ops):
                return None
            dest = int(ops, 0) - 0x100
            if not (0 <= dest < len(image)) or dest in hops:
                return None
            hops.add(dest)
            off = dest
        elif mn in ("ret", "iret", "hlt"):
            return None
        # Anything else is assumed not to disturb the values being tracked;
        # a wrong guess shows up immediately as a failed reconstruction.

    return None


def parse_segments(specs, size):
    if not specs:
        return [Segment(0, size, 0x100)]
    points = []
    for spec in specs:
        off_s, base_s = spec.split(":")
        points.append((int(off_s, 0), int(base_s, 0)))
    points.sort()
    segs = []
    if points[0][0] > 0:
        segs.append(Segment(0, points[0][0], 0x100))
    for i, (off, base) in enumerate(points):
        end = points[i + 1][0] if i + 1 < len(points) else size
        segs.append(Segment(off, end, base))
    return segs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("com")
    ap.add_argument("--out", required=True, help="where to write the .asm")
    ap.add_argument("--segment", action="append", default=[],
                    metavar="OFF:BASE",
                    help="a region with its own address base, e.g. 0x2B40:0")
    ap.add_argument("--entry", action="append", default=[],
                    help="extra entry point, as a file offset")
    ap.add_argument("--nasm", default=None,
                    help="path to nasm; defaults to $NASM, then PATH")
    ap.add_argument("--map", dest="mapfile", default=None, metavar="PATH",
                    help="write a code/data region map, for deciding what to "
                         "render with gfxdump.py")
    args = ap.parse_args()

    # No path from this machine belongs in the repository. Look where the user
    # said, then where they told the environment, then on PATH -- and say all
    # three if none of them answer.
    nasm = args.nasm or os.environ.get("NASM")
    if not nasm:
        from shutil import which
        nasm = which("nasm")
    if not nasm or not Path(nasm).exists():
        raise SystemExit(
            "nasm not found. Pass --nasm PATH, set the NASM environment "
            "variable, or put nasm on PATH. It is a single executable: "
            "https://www.nasm.us/")

    image = Path(args.com).read_bytes()
    mz = mz_load_image(image)
    if mz is not None:
        header, image, mz_entry = mz
        print(f"format      : MZ, {len(header)}-byte header stripped; "
              f"entry CS:IP -> image offset 0x{mz_entry:X}")
        print("              a single-segment MZ takes the .COM route, which "
              "reaches a\n              byte-identical rebuild; the header is "
              "put back on the way out")
        if not args.segment:
            # An MZ image is addressed from 0, not from a PSP at 0x100.
            args.segment = ["0x0:0x0"]
        args.entry = list(args.entry) + [str(mz_entry)]

    entries = [0] + [int(e, 0) for e in args.entry]

    detected = None
    if not args.segment:
        probe = Cs(CS_ARCH_X86, CS_MODE_16)
        detected = detect_layout(image, probe)
        if detected:
            start, base = detected
            args.segment = [f"0x{start:X}:0x{base:X}"]
            entries.append(start)
    segments = parse_segments(args.segment, len(image))

    r = Reconstructor(args.com, segments, entries,
                      image=image if mz is not None else None)
    source, last, rounds, err = r.run(nasm)

    total = len(image)
    code_bytes = sum(sz for off, (sz, _, _) in r.decoded.items()
                     if off not in r.demoted)
    disasm_bytes = sum(sz for sz, _, _ in r.decoded.values())

    print(f"file        : {args.com}  ({total:,} bytes)")
    print(f"segments    : " + ", ".join(
        f"0x{s.file_start:04X}+ @ base 0x{s.base:04X}" for s in segments)
        + ("   (detected from the entry stub)" if detected else ""))
    handlers = r.detect_interrupt_handlers()
    if handlers:
        print("interrupts  : " + ", ".join(
            f"INT {v:02X}h -> file 0x{o:05X}" for v, o in sorted(set(handlers))))
    dispatch = r.detect_dispatch_targets()
    if dispatch:
        print("dispatch    : " + "; ".join(
            f"jmp [{v:#06x}] -> "
            + ", ".join(f"0x{t:05X}" for t in ts) for v, ts in dispatch))
        print("              indirect jumps resolved from the constants "
              "written to the pointer")
    tables = r.detect_jump_tables()
    if tables:
        print("jump tables : " + "; ".join(
            f"cs:{base:#06x} -> {len(ts)} targets, 0x{min(ts):05X}..0x{max(ts):05X}"
            for base, ts in tables))
        print("              every entry disassembles as a routine and lies "
              "inside the code\n              already found; the first that "
              "does not ends the table")
    for finding, evidence in r.detect_provenance():
        print(f"provenance  : {finding}")
        print(f"              {evidence}")
    print(f"rounds      : {rounds}")
    print(f"instructions: {len(r.decoded):,} disassembled "
          f"({len(r.demoted):,} pinned to fixed bytes to preserve encoding)")
    print(f"bytes as code: {code_bytes:,} / {total:,}  "
          f"({code_bytes / total:.1%} of file)")

    # A whole-file percentage says more about how much of the program is
    # artwork and lookup tables than about how well it was recovered. The
    # figure that matters is how much of the region that actually holds code
    # came back as instructions.
    #
    # A big block of data counts as being outside that region only if it sits
    # against one end of the file. ParaTrooper keeps its tables at the front
    # and its code behind them; Zaxxon does the opposite, code first and 12,323
    # bytes of artwork after it. Both shapes are one contiguous block bounded
    # by an edge, so trim from each end -- allowing for the few bytes of entry
    # stub that precede a leading block, as in ParaTrooper's twelve-byte jump.
    body_lo, body_hi = 0, total
    for st, en in r.gaps(min_len=256):
        if en - st <= total * 0.15:
            continue
        if st < max(64, total * 0.02):
            body_lo = max(body_lo, en)
        elif en >= total - 16:
            body_hi = min(body_hi, st)
    # A body of zero bytes is not a degenerate case to divide by, it is a
    # finding: the walk from the entry point reached nothing, so whatever this
    # file is, it does not start where a .COM normally starts.
    if (body_lo or body_hi < total) and body_hi > body_lo:
        body = body_hi - body_lo
        in_body = sum(r.coverage()[body_lo:body_hi])
        print(f"code region : 0x{body_lo:04X}..0x{body_hi:04X}  ({body:,} bytes)")
        print(f"  recovered : {in_body:,} bytes as instructions "
              f"({in_body / body:.1%} of the code region)")
        if body_lo:
            print(f"  data head : 0x0000..0x{body_lo:04X} left as data "
                  f"({body_lo:,} bytes)")
        if body_hi < total:
            print(f"  data tail : 0x{body_hi:04X}..0x{total:04X} left as data "
                  f"({total - body_hi:,} bytes)")
    print(f"disassembled: {disasm_bytes:,} bytes carry a decoded instruction "
          f"({disasm_bytes / total:.1%}), counting the pinned ones")

    if args.mapfile:
        # Which bytes are data is the question the next step asks, and it is
        # not answerable from the .asm without reading all of it. The two
        # columns beside each run are the cheap test for what kind of data:
        # mostly printable is text, mostly zero is padding or a sparse table,
        # and neither is what artwork looks like -- see gfxdump.py.
        # 'pin' has to be its own kind or the map is unreadable: a pinned
        # instruction is emitted as `db`, so counting it as data chops the
        # routines into three-byte fragments and buries the real tables among
        # two hundred spurious ones.
        kinds = bytearray(total)
        for off, (size, _, _) in r.decoded.items():
            for i in range(off, min(off + size, total)):
                kinds[i] = 1 if off in r.demoted else 2
        names = {0: "data", 1: "pin", 2: "code"}

        Path(args.mapfile).parent.mkdir(parents=True, exist_ok=True)
        with open(args.mapfile, "w", encoding="ascii") as fh:
            fh.write(f"# region map of {os.path.basename(args.com)} "
                     f"({total:,} bytes)\n")
            fh.write("# code = covered by an instruction that survived "
                     "verification\n")
            fh.write("# pin  = an instruction NASM could not be made to "
                     "re-encode, emitted as db\n")
            fh.write("# data = not reached, or reached and rejected\n")
            fh.write(f"# {'kind':<5} {'start':>7} {'end':>7} {'length':>7} "
                     f"{'zero':>5} {'ascii':>6}\n")
            i = 0
            while i < total:
                j = i
                while j < total and kinds[j] == kinds[i]:
                    j += 1
                run = image[i:j]
                zero = sum(1 for b in run if b == 0) / len(run)
                text = sum(1 for b in run if 0x20 <= b < 0x7F) / len(run)
                fh.write(f"  {names[kinds[i]]:<5} "
                         f"0x{i:05X} 0x{j:05X} {j - i:7,} "
                         f"{zero:5.0%} {text:6.0%}\n")
                i = j
        print(f"map         : wrote {args.mapfile}")

    if disasm_bytes < total * 0.02:
        # Say it plainly rather than leaving a 0.1% to be read as a bad day.
        # The rebuild can still be byte-identical -- emitting the whole file as
        # `db` would be -- and that would prove nothing about understanding it.
        print("\nNOTE: almost nothing was reached from the entry point. The "
              "rebuild below may\n      still be byte-identical, which in this "
              "state means only that the bytes were\n      copied. Likely "
              "causes, in the order worth checking:")
        print("        - the file is packed or self-decrypting, and the real "
              "code appears only\n          after the loader has run")
        print("        - execution leaves the entry stub through a jump the "
              "walker does not\n          follow (a table, a computed target, "
              "an interrupt vector)")
        print("        - it is not a .COM at all, whatever the extension says")
        print("      Look at the first 64 bytes before going further.")

    if err:
        print(f"\nFAILED: {err}")
        if last:
            Path(args.out).write_text(last, encoding="ascii", errors="replace")
            print(f"wrote the last attempt to {args.out} for inspection")
        return 1

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(source, encoding="ascii", errors="replace")
    print(f"\nBYTE-IDENTICAL. wrote {args.out}")
    if mz is not None:
        # The claim has to be about the file the user handed over, not about
        # the image inside it. So write the header out beside the source, with
        # the one line that reassembles the whole executable.
        hdr_path = Path(args.out).with_suffix(".mzheader")
        hdr_path.write_bytes(header)
        print(f"              wrote {hdr_path.name} ({len(header)} bytes)")
        print(f"              nasm -f bin -o image.bin {Path(args.out).name}")
        print(f"              cat {hdr_path.name} image.bin > rebuilt.exe   "
              f"# and that is the original")
    return 0


if __name__ == "__main__":
    sys.exit(main())
