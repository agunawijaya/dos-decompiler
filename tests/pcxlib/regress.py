#!/usr/bin/env python3
"""
regress.py -- Check that pcxlib.py still reads PCX images and pcxLib containers.

The fixtures are built here rather than taken from a game, for the usual
reason: the containers this was developed against are commercial artwork. What
is testable without them is everything that matters -- the RLE, the bit depths,
the container walk, and the refusals -- because the format is open and an
encoder is fifteen lines.

The one property worth stating explicitly: an image is encoded, decoded, and
compared **pixel for pixel** against what went in. A decoder that is subtly
wrong about bit order or scanline padding passes a "does it look like a
picture" check and fails this one.

Usage:
    python tests/pcxlib/regress.py
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import pcxlib                                             # noqa: E402


def encode_rle(raw):
    """The encoder ZSoft's format expects: runs of 1..63, top two bits set."""
    out = bytearray()
    i = 0
    while i < len(raw):
        v = raw[i]
        n = 1
        while i + n < len(raw) and raw[i + n] == v and n < 63:
            n += 1
        if n > 1 or v >= 0xC0:
            out += bytes([0xC0 | n, v])
        else:
            out.append(v)
        i += n
    return bytes(out)


def make_pcx(rows, bpp, palette16=None, trailing=None):
    """A single-plane PCX carrying `rows` of colour indices."""
    h, w = len(rows), len(rows[0])
    per = 8 // bpp
    bpl = (w + per - 1) // per
    packed = bytearray()
    for row in rows:
        line = bytearray(bpl)
        for x, v in enumerate(row):
            line[x // per] |= (v & ((1 << bpp) - 1)) << (8 - bpp * (x % per + 1))
        packed += line
    hdr = bytearray(128)
    hdr[0:4] = bytes([0x0A, 5, 1, bpp])
    struct.pack_into("<HHHH", hdr, 4, 0, 0, w - 1, h - 1)
    hdr[65] = 1
    struct.pack_into("<H", hdr, 66, bpl)
    for i, c in enumerate(palette16 or []):
        hdr[16 + i * 3:19 + i * 3] = bytes(c)
    body = encode_rle(bytes(packed))
    tail = b""
    if trailing:
        tail = b"\x0c" + b"".join(bytes(c) for c in trailing)
    return bytes(hdr) + body + tail


def make_container(entries):
    """A pcxLib container: 122-byte header, then 84-byte entries + images."""
    out = bytearray(pcxlib.FIRST_ENTRY)
    out[0:7] = pcxlib.MAGIC
    out[10:60] = b"Copyright (c) nobody, for a test".ljust(50, b"\0")
    for name, blob in entries:
        e = bytearray(pcxlib.ENTRY_SIZE)
        e[0] = 0x01
        e[1:14] = name.encode("ascii").ljust(13, b"\0")[:13]
        struct.pack_into("<I", e, pcxlib.SIZE_AT, len(blob))
        out += e + blob
    return bytes(out)


CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


CHECKER = [[(x ^ y) & 0xFF for x in range(37)] for y in range(11)]


@case("8-bit: round-trips pixel for pixel")
def _():
    rows = CHECKER
    p = pcxlib.Pcx(make_pcx(rows, 8))
    got = p.rows()
    assert (p.width, p.height) == (37, 11), (p.width, p.height)
    assert [r[:37] for r in got] == rows, "pixels differ"
    return "37x11, exact"


@case("2-bit: round-trips, including the padding at the line end")
def _():
    rows = [[(x + y) & 3 for x in range(13)] for y in range(5)]
    p = pcxlib.Pcx(make_pcx(rows, 2))
    got = [r[:13] for r in p.rows()]
    assert got == rows, f"pixels differ: {got[0]} vs {rows[0]}"
    return "13x5 at 2bpp, exact"


@case("1-bit: round-trips")
def _():
    rows = [[(x * y) & 1 for x in range(17)] for y in range(4)]
    p = pcxlib.Pcx(make_pcx(rows, 1))
    assert [r[:17] for r in p.rows()] == rows
    return "17x4 at 1bpp, exact"


@case("a run crossing a scanline boundary still decodes")
def _():
    # Encoders differ on whether a run may span two lines. One that does is
    # legal and was what broke the first version of this reader.
    rows = [[7] * 40 for _ in range(6)]
    raw = bytes([7] * 240)
    hdr = bytearray(128)
    hdr[0:4] = bytes([0x0A, 5, 1, 8])
    struct.pack_into("<HHHH", hdr, 4, 0, 0, 39, 5)
    hdr[65] = 1
    struct.pack_into("<H", hdr, 66, 40)
    p = pcxlib.Pcx(bytes(hdr) + encode_rle(raw))
    assert p.rows() == rows
    return "6 lines from runs that ignore the line ends"


@case("the trailing 256-colour palette is found")
def _():
    pal = [(i, 255 - i, (i * 3) & 0xFF) for i in range(256)]
    p = pcxlib.Pcx(make_pcx(CHECKER, 8, trailing=pal))
    assert p.trailing_palette() == pal
    return "256 entries"


@case("the 16-colour header palette is read")
def _():
    pal = [(i * 16, 0, 255 - i * 16) for i in range(16)]
    p = pcxlib.Pcx(make_pcx([[1, 2, 3]], 4, palette16=pal))
    assert p.header_palette == pal
    return "16 entries"


@case("container: members are found, named, and land where the size says")
def _():
    blobs = [("ANIMALS .PCC", make_pcx(CHECKER, 8)),
             ("MAP     .PCX", make_pcx([[x & 1 for x in range(64)]] * 3, 1)),
             ("TERRAIN .PCC", make_pcx([[x & 3 for x in range(20)]] * 7, 2))]
    data = make_container(blobs)
    got = list(pcxlib.members(data))
    assert len(got) == 3, f"{len(got)} members"
    assert [g[0] for g in got] == ["ANIMALS .PCC", "MAP     .PCX",
                                   "TERRAIN .PCC"], got
    # The size field and an independent decode must agree, which is the check
    # that validated the layout against the real containers in the first place.
    for (name, at, size), (_, blob) in zip(got, blobs):
        p = pcxlib.Pcx(data, at)
        p.rows()
        assert abs((p.end - at) - size) <= 1, f"{name}: {p.end - at} vs {size}"
    return "3 members, sizes agree with an independent decode"


@case("refused: not a container")
def _():
    try:
        list(pcxlib.members(b"MZ" + b"\0" * 400))
    except ValueError:
        return "refused, as it must"
    raise AssertionError("accepted a non-container")


@case("refused: not a PCX")
def _():
    try:
        pcxlib.Pcx(b"\x00" * 200)
    except ValueError:
        return "refused, as it must"
    raise AssertionError("accepted a non-PCX")


@case("truncated data is reported, not padded over")
def _():
    good = make_pcx(CHECKER, 8)
    try:
        pcxlib.Pcx(good[:150]).rows()
    except ValueError:
        return "reported, as it must"
    raise AssertionError("a truncated image decoded silently")


@case("2bpp CGA: the colour map is mode flags, not a palette")
def _():
    # A CGA header whose sixteen-colour map reads black, dark red, black,
    # black -- which is what The Oregon Trail's LOGO.004 actually contains.
    # Read literally, three of the four indices render identically and the
    # picture loses its foreground. The mode flags say palette 1, and the four
    # colours must come from there instead.
    rows = [[(x + y) & 3 for x in range(16)] for y in range(4)]
    head = [(0, 0, 0), (0x60, 0, 0)] + [(0, 0, 0)] * 14
    pcx = pcxlib.Pcx(make_pcx(rows, 2, palette16=head))
    pal = pcxlib.palette_for(pcx, None)
    if len(set(pal[:4])) != 4:
        raise AssertionError(f"only {len(set(pal[:4]))} distinct colours: {pal[:4]}")
    if pal[0] != (0, 0, 0):
        raise AssertionError(f"background not taken from the file: {pal[0]}")
    return f"four distinct colours, background honoured"


@case("2bpp CGA: bit 6 of the flags selects the palette")
def _():
    rows = [[1, 2, 3, 0]]
    zero = pcxlib.palette_for(
        pcxlib.Pcx(make_pcx(rows, 2, palette16=[(0, 0, 0), (0x00, 0, 0)] + [(0, 0, 0)] * 14)), None)
    one = pcxlib.palette_for(
        pcxlib.Pcx(make_pcx(rows, 2, palette16=[(0, 0, 0), (0x40, 0, 0)] + [(0, 0, 0)] * 14)), None)
    if zero[1:4] == one[1:4]:
        raise AssertionError("the flag byte changed nothing")
    if one[1] != (85, 255, 255):
        raise AssertionError(f"palette 1 should start cyan, got {one[1]}")
    return "green/red and cyan/magenta told apart"


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
    print(f"All {len(CASES)} PCX checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
