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
        out.append(f"{mn} strict short {rest}")
        return out

    m = re.match(r"^(\w+)\s+([^,]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$", text)
    if m:
        mn, dst, imm = m.groups()
        out.append(f"{mn} {dst}, strict word {imm}")
        out.append(f"{mn} {dst}, strict byte {imm}")
    return out


class Reconstructor:
    def __init__(self, path, segments, entries):
        self.path = Path(path)
        self.image = self.path.read_bytes()
        self.segments = segments
        self.entries = entries
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True
        self.decoded = {}          # file_off -> (size, text, target_file_off)
        self.demoted = set()       # file offsets forced back to db
        self.labels = set()        # file offsets that need a label
        self.form = {}             # file_off -> which variant spelling to use
        self.extra = set()         # entry points found by the gap sweep
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

            # Text decodes into perfectly valid instructions -- "Hello from a
            # plain COM file$" becomes insb/outsw/popaw and lands neatly on the
            # boundary, passing the test below while being obvious data. Judge
            # the bytes before trusting the decode.
            body = self.image[start:end]
            if sum(1 for b in body if 0x20 <= b < 0x7F) >= 0.6 * len(body):
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
        """{source line index (0-based): emitted bytes} from a NASM listing."""
        out = {}
        for raw in path.read_text(encoding="latin-1",
                                  errors="replace").splitlines():
            m = re.match(r"\s*(\d+)\s+([0-9A-F]{8})\s+([0-9A-F]+)", raw)
            if not m:
                continue
            hexpart = m.group(3)
            if len(hexpart) % 2:            # NASM marks continuations with '-'
                hexpart = hexpart[:-1]
            try:
                out[int(m.group(1)) - 1] = bytes.fromhex(hexpart)
            except ValueError:
                continue
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

    def run(self, nasm, max_rounds=40):
        rounds = 0
        while rounds < max_rounds:
            rounds += 1
            self.disassemble()
            self.detect_ds_bias()
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

    Returns (file_start, base) or None. Only the far-return idiom is handled;
    anything stranger is left to an explicit --segment.
    """
    CSREL, CONST = "csrel", "const"
    regs = {}
    stack = []
    off = 0

    for _ in range(24):
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
        elif mn in ("jmp", "ret", "iret", "hlt"):
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

    r = Reconstructor(args.com, segments, entries)
    source, last, rounds, err = r.run(nasm)

    total = len(image)
    code_bytes = sum(sz for off, (sz, _, _) in r.decoded.items()
                     if off not in r.demoted)
    disasm_bytes = sum(sz for sz, _, _ in r.decoded.values())

    print(f"file        : {args.com}  ({total:,} bytes)")
    print(f"segments    : " + ", ".join(
        f"0x{s.file_start:04X}+ @ base 0x{s.base:04X}" for s in segments)
        + ("   (detected from the entry stub)" if detected else ""))
    print(f"rounds      : {rounds}")
    print(f"instructions: {len(r.decoded):,} disassembled "
          f"({len(r.demoted):,} pinned to fixed bytes to preserve encoding)")
    print(f"bytes as code: {code_bytes:,} / {total:,}  "
          f"({code_bytes / total:.1%} of file)")

    # A whole-file percentage says more about how much of the program is
    # artwork and lookup tables than about how well it was recovered. The
    # figure that matters is how much of the region that actually holds code
    # came back as instructions.
    # A leading data block counts as "head" only if it sits at the very front
    # of the file -- allowing for the few bytes of entry stub that usually
    # precede it, as in ParaTrooper's twelve-byte jump into the real code.
    body_lo = 0
    for st, en in r.gaps(min_len=256):
        if en - st > total * 0.15 and st < max(64, total * 0.02):
            body_lo = max(body_lo, en)
    if body_lo:
        body = total - body_lo
        in_body = sum(r.coverage()[body_lo:])
        print(f"code region : 0x{body_lo:04X}..0x{total:04X}  ({body:,} bytes)")
        print(f"  recovered : {in_body:,} bytes as instructions "
              f"({in_body / body:.1%} of the code region)")
        print(f"  data head : 0x0000..0x{body_lo:04X} left as data "
              f"({body_lo:,} bytes)")
    print(f"disassembled: {disasm_bytes:,} bytes carry a decoded instruction "
          f"({disasm_bytes / total:.1%}), counting the pinned ones")

    if err:
        print(f"\nFAILED: {err}")
        if last:
            Path(args.out).write_text(last, encoding="ascii", errors="replace")
            print(f"wrote the last attempt to {args.out} for inspection")
        return 1

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(source, encoding="ascii", errors="replace")
    print(f"\nBYTE-IDENTICAL. wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
