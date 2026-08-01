#!/usr/bin/env python3
"""
regress.py -- Check that the packer-header readers in unpack.py still read.

Why this suite is different from the others
-------------------------------------------
`tests/com/` builds its fixtures with NASM and `tests/sopwith/` builds a whole
program. Neither is possible here: the input to an unpacker is a *packed
executable*, and producing one means running LZEXE or Microsoft LINK, which are
someone else's software and not redistributable. The packed files this was
developed against are commercial games and cannot be committed either.

So this tests the part that can be tested without them -- the header readers --
against byte blocks assembled here from the documented layouts, plus the field
values actually observed in a real file. That is narrower than the other
suites and it is worth being plain about which half it covers:

    covered      the layout, the arithmetic, and the refusal cases
    not covered  that a real packed file decompresses correctly

The second half is covered by measurement rather than by test, and the numbers
are in knowledge/00-scope.md: an EXEPACK image at 99.7% of a known-good build,
a PKLITE dump gaining 181 strings of the game's own text, and an LZEXE entry
point that the heuristic missed by one instruction.

The refusal cases are the point of the exercise. A header reader that accepts
anything is worse than none, because a wrong entry point sends a disassembler
into the middle of a routine and everything after it inherits the error.

Usage:
    python tests/unpack/regress.py
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import unpack                                             # noqa: E402


def mz(cs, ip, hdr_paras=2, sig_at_1c=b"\0\0\0\0", tail=b""):
    """The smallest MZ header that the readers look at, plus a body."""
    h = bytearray(hdr_paras * 16)
    h[0:2] = b"MZ"
    struct.pack_into("<HHHHHHHHHHHH", h, 2,
                     0, 0, 0, hdr_paras, 0, 0xFFFF, 0, 0, 0, ip, cs, 0x1C)
    h[0x1C:0x20] = sig_at_1c
    return bytes(h) + tail


# --- LZEXE ------------------------------------------------------------------
# The values are the ones measured in The Oregon Trail (MECC, 1990): the stub
# sits at segment 0x130F, the compressed-size word agrees with it, and the
# original entry is 0000:010A.
def lzexe_file(packed_paras=0x130F, cs0=0x0000, ip0=0x010A,
               ss=0x274A, sp=0x9C40, sig=b"LZ91"):
    hdr_paras = 2
    stub_at = hdr_paras * 16 + (packed_paras << 4)
    body = bytearray(stub_at - hdr_paras * 16 + 32)
    struct.pack_into("<8H", body, stub_at - hdr_paras * 16,
                     ip0, cs0, sp, ss, packed_paras, 0x11A4, 0x0ED8, 0x0E06)
    return mz(packed_paras, 0x0E, hdr_paras, sig, bytes(body))


CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


@case("LZEXE 0.91: entry, stack and version are read")
def _():
    d = lzexe_file()
    got = unpack.lzexe_header(d, 32, 0x130F)
    assert got is not None, "returned nothing"
    assert (got["cs"] << 4) + got["ip"] == 0x10A, f"entry {got}"
    assert (got["ss"], got["sp"]) == (0x274A, 0x9C40), f"stack {got}"
    assert got["version"] == "LZ91", got["version"]
    return "entry 0x10A, SS:SP 274A:9C40"


@case("LZEXE 0.90 is accepted as well")
def _():
    got = unpack.lzexe_header(lzexe_file(sig=b"LZ90"), 32, 0x130F)
    assert got is not None and got["version"] == "LZ90"
    return "accepted"


@case("refused: the signature is absent")
def _():
    d = lzexe_file(sig=b"\0\0\0\0")
    assert unpack.lzexe_header(d, 32, 0x130F) is None
    return "refused, as it must"


@case("refused: the compressed-size word disagrees with the stub segment")
def _():
    # This is the cross-check that makes the read evidence rather than
    # assumption. A file merely *containing* the bytes LZ91 must not be able to
    # hand a disassembler an entry point.
    d = lzexe_file(packed_paras=0x130F)
    body = bytearray(d)
    struct.pack_into("<H", body, 32 + (0x130F << 4) + 8, 0x1234)
    assert unpack.lzexe_header(bytes(body), 32, 0x130F) is None
    return "refused, as it must"


@case("refused: the stub would be past the end of the file")
def _():
    d = lzexe_file()[:100]
    assert unpack.lzexe_header(d, 32, 0x130F) is None
    return "refused, as it must"


# --- EXEPACK ----------------------------------------------------------------
@case("EXEPACK: the 16 bytes before the stub are read")
def _():
    blob = bytearray(0x400)
    at = 0x200
    struct.pack_into("<HHHHHHH", blob, at - 16,
                     0x06B2, 0x0000, 0x1000, 0x0120, 0x0800, 0x0700, 0x0900)
    blob[at - 2:at] = b"RB"
    got = unpack.exepack_header(bytes(blob), at)
    assert got is not None, "returned nothing"
    assert (got["cs"] << 4) + got["ip"] == 0x6B2, got
    assert got["dest_paragraphs"] == 0x900, got
    return "entry 0x6B2 -- the value the heuristic missed"


@case("EXEPACK refused: no RB marker")
def _():
    blob = bytearray(0x400)
    assert unpack.exepack_header(bytes(blob), 0x200) is None
    return "refused, as it must"


def main():
    failures = 0
    for name, fn in CASES:
        try:
            detail = fn()
            print(f"  PASS  {name:<58} {detail}")
        except AssertionError as e:
            print(f"  FAIL  {name:<58} {e}")
            failures += 1
    print()
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    print(f"All {len(CASES)} packer-header checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
