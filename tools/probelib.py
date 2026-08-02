#!/usr/bin/env python3
"""probelib.py -- Identify C library routines by calling them.

Reading a routine's shape answers "what does this look like". Calling it
answers "what does this do", and only the second can be wrong in a way you
notice. `emuverify.py` already decides *equivalence* by execution; this decides
*identity* the same way, against a specification instead of against another
binary.

Push what `strlen` would take, call, and check that 5 comes back for "hello",
3 for "abc" and 0 for "". Four cases agreeing is a function; one is a
coincidence.

    python probelib.py GAME.EXE --warmup 3000000 --ds 0x6CA0
    python probelib.py GAME.COM --at 0x5b2e --at 0x66b9

Without `--at` it probes every `push bp` prologue it can find.

Three things this got wrong before it got them right, all worth knowing:

* **The call must respect SS.** `comrun.call` writes its sentinel at
  `BASE + SP`, which is segment zero. Karateka's SS after start-up is 0x16DA,
  so every routine returned into nothing and reported a fault that belonged to
  the harness. Fifty-nine routines "faulted" and none of them had.

* **A probe with an unbounded family passes too easily.** "Two calls, two
  different non-zero results" matched six routines as `malloc`; every counter
  passes it. Demanding non-overlapping blocks and a refusal for a large enough
  request cut it to one.

* **Arguments you do not push are still read.** Testing `stricmp` with two
  arguments left the third as stack garbage, and a `strncmp` compared zero
  bytes, returned equal, and looked case-insensitive. If the family has a
  three-argument member, push three.
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import comrun
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_DX, UC_X86_REG_SP,
                               UC_X86_REG_SS, UC_X86_REG_CS)

BIAS = comrun.BASE + comrun.LOAD
A, B, FMT = 0x9000, 0x9100, 0x9200      # scratch, well clear of anything


class Probe:
    """A warmed-up machine that can be rewound between calls."""

    def __init__(self, path, warmup, ds, files=None):
        self.ds = ds
        self.m = comrun.Machine(Path(path).read_bytes(), files=files)
        self.m.run(budget=warmup)
        self.snap = bytes(self.m.uc.mem_read(0, comrun.MEMSZ))
        self.regs = [self.m.uc.reg_read(r) for r in
                     (UC_X86_REG_AX, UC_X86_REG_DX, UC_X86_REG_SP,
                      UC_X86_REG_SS, UC_X86_REG_CS)]

    def rewind(self):
        """Put the whole megabyte back.

        Rebuilding the machine per probe means the start-up cost again for
        every one of hundreds of calls, and not rewinding at all means one
        probe's writes become the next one's inputs -- library routines keep
        statics.
        """
        self.m.uc.mem_write(0, self.snap)
        for r, v in zip((UC_X86_REG_AX, UC_X86_REG_DX, UC_X86_REG_SP,
                         UC_X86_REG_SS, UC_X86_REG_CS), self.regs):
            self.m.uc.reg_write(r, v)
        self.m.stopped = None

    def call(self, off, args, buf=None, budget=300_000):
        """cdecl: arguments pushed right to left, result in AX (DX:AX long)."""
        uc = self.m.uc
        ss, cs = uc.reg_read(UC_X86_REG_SS), uc.reg_read(UC_X86_REG_CS)
        for at, data in (buf or {}).items():
            uc.mem_write(BIAS + self.ds + at, data)
        sp0 = sp = uc.reg_read(UC_X86_REG_SP)
        for a in reversed(args):
            sp -= 2
            uc.mem_write((ss << 4) + sp, struct.pack("<H", a & 0xFFFF))
        sp -= 2
        RET = 0xFFF0
        uc.mem_write((ss << 4) + sp, struct.pack("<H", RET))
        uc.reg_write(UC_X86_REG_SP, sp)
        self.m.stopped, bad = None, False
        try:
            uc.emu_start(BIAS + off, (cs << 4) + RET, count=budget)
        except Exception:
            bad = True
        uc.reg_write(UC_X86_REG_SP, sp0)
        if bad or self.m.stopped:
            return None
        return uc.reg_read(UC_X86_REG_AX), uc.reg_read(UC_X86_REG_DX)

    def read(self, at, n):
        return bytes(self.m.uc.mem_read(BIAS + self.ds + at, n))


def sgn(v):
    v = v - 0x10000 if v > 0x7FFF else v
    return (v > 0) - (v < 0)


def tests(p):
    """The battery. Each returns True only if every case agrees."""

    def strlen(f):
        return all((r := p.call(f, [A], {A: s + b"\x00"})) and r[0] == n
                   for s, n in [(b"hello", 5), (b"abc", 3), (b"", 0),
                                (b"0123456789", 10)])

    def strcpy(f):
        # B starts non-empty on purpose: with a zeroed destination, strcat
        # produces the same bytes as strcpy and both tests pass.
        for s in (b"hello", b"a", b"0123456789ab"):
            if not p.call(f, [B, A, 0xFFFF],
                          {A: s + b"\x00", B: b"ZZZ\x00" + bytes(20)}):
                return False
            if p.read(B, len(s) + 1) != s + b"\x00":
                return False
        return True

    def strncpy(f):
        if not p.call(f, [B, A, 2], {A: b"abcdef\x00", B: b"\xEE" * 12}):
            return False
        return p.read(B, 2) == b"ab" and p.read(B, 3)[2] == 0xEE

    def strcat(f):
        if not p.call(f, [B, A], {A: b"def\x00", B: b"abc\x00" + bytes(12)}):
            return False
        return p.read(B, 7) == b"abcdef\x00"

    def strcmp(f):
        for x, y, s in [(b"abc", b"abc", 0), (b"abc", b"abd", -1),
                        (b"abd", b"abc", 1), (b"a", b"ab", -1)]:
            r = p.call(f, [A, B, 0xFFFF], {A: x + b"\x00", B: y + b"\x00"})
            if not r or sgn(r[0]) != s:
                return False
        return True

    def strncmp(f):
        r2 = p.call(f, [A, B, 2], {A: b"abX\x00", B: b"abY\x00"})
        r9 = p.call(f, [A, B, 9], {A: b"abX\x00", B: b"abY\x00"})
        return bool(r2) and bool(r9) and sgn(r2[0]) == 0 and sgn(r9[0]) == -1

    def memcmp(f):
        """Unlike strncmp, a NUL inside the range does not stop it.

        Three cases, not one. A single case here matched three copy routines,
        which is the same mistake as the malloc probe made and for the same
        reason: one agreement is not evidence.
        """
        for x, y, s in [(b"ab\x00X", b"ab\x00Y", -1),
                        (b"ab\x00Y", b"ab\x00X", 1),
                        (b"ab\x00X", b"ab\x00X", 0)]:
            r = p.call(f, [A, B, 4], {A: x, B: y})
            if not r or sgn(r[0]) != s:
                return False
        return True

    def memset(f):
        if not p.call(f, [A, 0x41, 6], {A: bytes(12)}):
            return False
        return p.read(A, 6) == b"A" * 6

    def toupper(f):
        return all((r := p.call(f, [c])) and r[0] & 0xFF == u
                   for c, u in [(97, 65), (122, 90), (65, 65), (53, 53)])

    def tolower(f):
        return all((r := p.call(f, [c])) and r[0] & 0xFF == u
                   for c, u in [(65, 97), (90, 122), (97, 97), (53, 53)])

    def atoi(f):
        return all((r := p.call(f, [A], {A: s + b"\x00"})) and r[0] == n
                   for s, n in [(b"1234", 1234), (b"7", 7), (b"0", 0),
                                (b"32000", 32000)])

    def malloc(f):
        r1, r2 = p.call(f, [64]), p.call(f, [64])
        if not (r1 and r2) or r1[0] in (0, 0xFFFF) or r2[0] in (0, 0xFFFF):
            return False
        if abs(r2[0] - r1[0]) < 64:
            return False
        huge = p.call(f, [0xF000])
        return bool(huge) and huge[0] in (0, 0xFFFF)

    def sprintf(f):
        for n, want in ((42, b"42"), (0, b"0"), (12345, b"12345")):
            if not p.call(f, [n, FMT, A], {A: bytes(16), FMT: b"%d\x00"}):
                return False
            if p.read(A, len(want) + 1) != want + b"\x00":
                return False
        return True

    def arith(f):
        # every pair must not have x > y, or "returns its first argument"
        # passes as max -- which is how six routines were first called max.
        pairs = [(7, 3), (3, 7), (100, 7), (5, 100), (255, 16), (9, 9)]
        got = []
        for x, y in pairs:
            r = p.call(f, [x, y])
            if not r:
                return None
            got.append(r[0])
        for n, fn in (("add", lambda x, y: x + y), ("sub", lambda x, y: x - y),
                      ("mul", lambda x, y: x * y), ("div", lambda x, y: x // y),
                      ("mod", lambda x, y: x % y), ("max", max), ("min", min)):
            if all(g == fn(x, y) & 0xFFFF for g, (x, y) in zip(got, pairs)):
                return n
        return None

    return ([("strlen", strlen), ("strcpy", strcpy), ("strncpy", strncpy),
             ("strcat", strcat), ("strcmp", strcmp), ("strncmp", strncmp),
             ("memcmp", memcmp), ("memset", memset), ("toupper", toupper),
             ("tolower", tolower), ("atoi", atoi), ("malloc", malloc),
             ("sprintf", sprintf)], arith)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--warmup", type=int, default=3_000_000,
                    help="instructions of start-up before probing, so DS and "
                         "the runtime are set up")
    ap.add_argument("--ds", type=lambda s: int(s, 0), default=0,
                    help="the data segment, as an image offset")
    ap.add_argument("--files", help="a folder the program may open")
    ap.add_argument("--at", action="append", type=lambda s: int(s, 0),
                    default=[], help="probe only these; repeatable")
    args = ap.parse_args()

    p = Probe(args.binary, args.warmup, args.ds, args.files)
    img = p.m.image
    todo = args.at or [k for k in range(len(img) - 2)
                       if img[k] == 0x55 and img[k + 1] in (0x8B, 0x83, 0x2B)]
    battery, arith = tests(p)
    print(f"probing {len(todo)} routines against {len(battery)} "
          f"specifications\n")
    found = 0
    for a in todo:
        hits = []
        for name, fn in battery:
            p.rewind()
            try:
                if fn(a):
                    hits.append(name)
            except Exception:
                pass
        p.rewind()
        try:
            w = arith(a)
        except Exception:
            w = None
        if w:
            hits.append(w)
        if hits:
            found += 1
            print(f"  0x{a:05X}  {', '.join(hits)}")
    print(f"\n{found} of {len(todo)} matched a specification.")
    print("More than one hit means the family overlaps -- push the third "
          "argument\nand see which one still agrees.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
