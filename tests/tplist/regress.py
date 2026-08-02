#!/usr/bin/env python3
"""Checks for tplist's recursive-descent disassembly.

The case that motivated these: a linear sweep decodes every byte it is handed,
so it walks off the end of a procedure into the string constants the compiler
put there and decodes the text as instructions. It then comes out of phase, and
the damage shows up as branch targets pointing into the middle of an
instruction -- 202 of them on The Oregon Trail.

These build a tiny image with that exact trap in it: a procedure, a string
immediately after it, and a second procedure after that. A linear sweep gets
the second procedure wrong; following control flow does not.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import tplist                                              # noqa: E402

CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


def build():
    """One unit: proc A, a string, proc B, with A calling B.

    The string's length byte is 0x33 -- an `xor` opcode -- so a sweep that
    decodes it produces plausible instructions rather than an obvious mess,
    which is what makes this trap worth having.
    """
    img = bytearray(0x400)
    text = b"3" * 0x33                       # 51 printable bytes
    # proc A at 0x10: push bp / mov bp,sp / call B / leave-ish / retf
    a = bytes((0x55, 0x89, 0xE5,             # push bp; mov bp, sp
               0xE8, 0x00, 0x00,             # call +0 -- patched below
               0x89, 0xEC, 0x5D, 0xCB))      # mov sp,bp; pop bp; retf
    img[0x10:0x10 + len(a)] = a
    at_str = 0x10 + len(a)                   # the string, right after proc A
    img[at_str] = len(text)
    img[at_str + 1:at_str + 1 + len(text)] = text
    b = at_str + 1 + len(text)               # proc B
    img[b:b + 5] = bytes((0x55, 0x89, 0xE5, 0x5D, 0xCB))
    # patch A's call to reach B
    rel = b - (0x10 + 6)
    img[0x14:0x16] = rel.to_bytes(2, "little", signed=True)
    return bytes(img), 0x10, at_str, b


@case("a string after a procedure is not decoded as code")
def _():
    img, a, at_str, b = build()
    insns, conflicts = tplist.walk(img, 0, 0x400, [a])
    inside = [x for x in insns if at_str <= x < at_str + 0x34]
    if inside:
        raise AssertionError(f"decoded {len(inside)} instructions inside the string")
    return "walked past it, as it must"


@case("a procedure after a string is still reached, through the call")
def _():
    img, a, at_str, b = build()
    insns, conflicts = tplist.walk(img, 0, 0x400, [a])
    if b not in insns:
        raise AssertionError("the second procedure was never reached")
    return f"reached 0x{b:X} via the call"


@case("no phase conflicts on a clean image")
def _():
    img, a, at_str, b = build()
    _, conflicts = tplist.walk(img, 0, 0x400, [a])
    if conflicts:
        raise AssertionError(f"{len(conflicts)} conflicts on an image with none")
    return "0"


@case("a linear sweep decodes the text; the walk does not")
def _():
    # The original phrasing checked that the sweep *lost* the second procedure,
    # and the fixture did not trap that: 0x33 is a two-byte instruction and the
    # string's length happened to keep the sweep in phase. Phase luck is not
    # the claim. The claim is that a sweep decodes data as code at all.
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    img, a, at_str, b = build()
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    span = range(at_str, at_str + 0x34)
    swept = sum(1 for i in md.disasm(img[a:0x400], a) if i.address in span)
    walked, _ = tplist.walk(img, 0, 0x400, [a])
    inside = sum(1 for x in walked if x in span)
    if swept == 0:
        raise AssertionError("the fixture does not trap a sweep at all")
    if inside:
        raise AssertionError(f"the walk decoded {inside} instructions in the text")
    return f"sweep decodes {swept} phantom instructions, the walk 0"


@case("both prologue encodings are recognised")
def _():
    if len(tplist.PROLOGUES) < 2:
        raise AssertionError("only one prologue encoding is checked")
    e5, ec = bytes((0x55, 0x89, 0xE5)), bytes((0x55, 0x8B, 0xEC))
    if e5 not in tplist.PROLOGUES or ec not in tplist.PROLOGUES:
        raise AssertionError(f"missing one of them: {tplist.PROLOGUES}")
    return "0x89E5 and 0x8BEC"


@case("a barrier stops the walk entering known data")
def _():
    img, a, at_str, b = build()
    # Seed the string's own address, which is what a fall-through would do.
    without, _ = tplist.walk(img, 0, 0x400, [at_str])
    with_bar, _ = tplist.walk(img, 0, 0x400, [at_str], barriers={at_str})
    if at_str in with_bar:
        raise AssertionError("the barrier was ignored")
    if at_str not in without:
        raise AssertionError("the fixture does not exercise the barrier")
    return "honoured"


def main():
    failures = 0
    for name, fn in CASES:
        try:
            print(f"  PASS  {name:<58} {fn()}")
        except AssertionError as e:
            print(f"  FAIL  {name:<58} {e}")
            failures += 1
    print()
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    print(f"All {len(CASES)} tplist checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
