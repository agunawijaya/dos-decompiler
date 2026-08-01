#!/usr/bin/env python3
"""
pcxlib.py -- Read ZSoft PCX images, and the pcxLib containers that hold them.

Why this is in the toolkit and not in a game's folder
-----------------------------------------------------
`gfxdump.py` renders a *region of an executable* as CGA, because that is where
the artwork lives in a 1982 game: there are no data files, so the sprite format
has to be guessed from a pointer table's stride and confirmed by rendering it.

By 1990 that had stopped being true. The Oregon Trail (MECC) keeps 511 KB of
artwork in two files beside an 82 KB executable, in a documented, open format
that predates the game by five years -- so there is nothing to reverse engineer
about the images at all, only about the container holding them. That is a
different problem and a much easier one, and it will recur: PCX was the DOS
artwork format, and Genus Microprogramming sold the library that packs it into
`.PCL` files to whoever wanted it.

The container, worked out from the file
---------------------------------------
Nothing here is from a specification; it is what the bytes say, and each claim
below is checked against the next member's position:

    0x0000  file header, 122 bytes, opening "pcxLib\\0" and a copyright line
    0x007A  first entry
            +0   0x01, a marker
            +1   name, 13 bytes: eight of stem, a dot, three of extension, NUL
            +14  size of the image data, 4 bytes
            +18  66 bytes of metadata, including a partial copy of the header
            +84  the PCX image, exactly `size` bytes
                 ... and the next entry begins immediately after it

The size field is the check that makes this evidence rather than a guess.
Decoding a member's RLE independently -- reading exactly
`bytesPerLine x planes x height` pixels and seeing where that lands -- lands on
the byte the size field predicts, for all 58 members of the game's two
containers. Two ways of finding the same boundary is the standard this package
uses for believing one.

Palettes
--------
An 8-bit PCX normally carries its 256-colour palette as a `0x0C` byte and 768
bytes at the end. **The members of these containers do not**: the size field
stops at the last pixel. The palette ships separately, as a tiny PCX whose
image is 9x6 and irrelevant -- `PAL.256` in this game -- carrying the palette
the whole container is drawn in. Pass it with `--palette`.

Without one, an 8-bit image is written as greyscale, which is honest and
useless. Anything 4 bits or fewer uses the 16-colour palette in the PCX
header, which is where it belongs and is always present.

Usage:
    python pcxlib.py OTMCGA.PCL --list
    python pcxlib.py OTMCGA.PCL --extract out/ --palette PAL.256
    python pcxlib.py LOGO.256 --extract out/          # a bare PCX works too
"""

import argparse
import struct
import sys
from pathlib import Path

ENTRY_SIZE = 84          # marker + name + size + metadata, then the image
NAME_AT = 1
SIZE_AT = 14
FIRST_ENTRY = 0x7A
MAGIC = b"pcxLib\0"


class Pcx:
    """One ZSoft PCX image."""

    def __init__(self, data, at=0):
        h = data[at:at + 128]
        if len(h) < 128 or h[0] != 0x0A:
            raise ValueError("not a PCX header")
        self.version, self.encoding, self.bpp = h[1], h[2], h[3]
        xmin, ymin, xmax, ymax = struct.unpack_from("<HHHH", h, 4)
        self.width, self.height = xmax - xmin + 1, ymax - ymin + 1
        self.planes = h[65]
        self.bytes_per_line = struct.unpack_from("<H", h, 66)[0]
        self.header_palette = [tuple(h[16 + i * 3:19 + i * 3]) for i in range(16)]
        self.data = data
        self.start = at
        self.end = None

    def rows(self):
        """Decode to one list of colour indices per row.

        PCX run-length encoding: a byte with the top two bits set is a count
        of 1..63 and the next byte is the value; anything else is one literal
        byte. Runs are allowed to cross the end of a scanline -- some encoders
        do it and some readers get it wrong -- so this decodes the whole image
        as one stream and cuts it into lines afterwards.
        """
        stride = self.bytes_per_line * self.planes
        need = stride * self.height
        out = bytearray()
        p = self.start + 128
        d = self.data
        while len(out) < need and p < len(d):
            b = d[p]; p += 1
            if (b & 0xC0) == 0xC0:
                if p >= len(d):
                    break
                out += bytes([d[p]]) * (b & 0x3F)
                p += 1
            else:
                out.append(b)
        self.end = p
        if len(out) < need:
            raise ValueError(f"ran out of data: {len(out)} of {need} bytes")

        rows = []
        for y in range(self.height):
            line = out[y * stride:(y + 1) * stride]
            if self.planes == 1:
                rows.append(self._unpack(line))
            else:
                # Planar: each plane contributes one bit, plane 0 least
                # significant. EGA's arrangement, and rarer than it used to be.
                px = [0] * (self.bytes_per_line * 8 // max(1, self.bpp))
                for pl in range(self.planes):
                    seg = line[pl * self.bytes_per_line:(pl + 1) * self.bytes_per_line]
                    for i, v in enumerate(self._unpack(seg, bits=1)):
                        if i < len(px):
                            px[i] |= v << pl
                rows.append(px)
        return rows

    def _unpack(self, line, bits=None):
        """Split packed bytes into pixels at this image's bit depth."""
        bits = bits or self.bpp
        if bits == 8:
            return list(line)
        out, per = [], 8 // bits
        mask = (1 << bits) - 1
        for b in line:
            for k in range(per):
                out.append((b >> (8 - bits * (k + 1))) & mask)
        return out

    def trailing_palette(self):
        """The 256-colour palette some PCX files carry at the end."""
        d = self.data
        if len(d) >= 769 and d[-769] == 0x0C:
            p = d[-768:]
            return [tuple(p[i * 3:i * 3 + 3]) for i in range(256)]
        return None


def members(data):
    """Walk a pcxLib container, yielding (name, offset of the image, size)."""
    if not data.startswith(MAGIC):
        raise ValueError("not a pcxLib container")
    at = FIRST_ENTRY
    while at + ENTRY_SIZE < len(data):
        if data[at] != 0x01:
            break
        raw = data[at + NAME_AT:at + NAME_AT + 13]
        name = raw.split(b"\0")[0].decode("latin-1").strip()
        size = struct.unpack_from("<I", data, at + SIZE_AT)[0]
        img = at + ENTRY_SIZE
        if size == 0 or img + size > len(data):
            break
        yield name, img, size
        at = img + size


def load_palette(path):
    d = Path(path).read_bytes()
    pal = Pcx(d).trailing_palette()
    if pal is None:
        raise SystemExit(f"{path} carries no 256-colour palette")
    return pal


def write_png(rows, palette, path, scale=1):
    from PIL import Image
    h, w = len(rows), max(len(r) for r in rows)
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y, row in enumerate(rows):
        for x, v in enumerate(row):
            px[x, y] = palette[v] if v < len(palette) else (255, 0, 255)
    if scale > 1:
        img = img.resize((w * scale, h * scale), Image.NEAREST)
    img.save(path)
    return w, h


def palette_for(pcx, external):
    if pcx.bpp * pcx.planes > 4:
        return (external or pcx.trailing_palette()
                or [(v, v, v) for v in range(256)])
    return pcx.header_palette


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", metavar="DIR")
    ap.add_argument("--palette", help="a PCX carrying a 256-colour palette")
    ap.add_argument("--scale", type=int, default=1)
    args = ap.parse_args()

    data = Path(args.file).read_bytes()
    external = load_palette(args.palette) if args.palette else None
    container = data.startswith(MAGIC)

    if container:
        items = list(members(data))
        print(f"{args.file}: pcxLib container, {len(data):,} bytes, "
              f"{len(items)} members")
    else:
        items = [(Path(args.file).stem, 0, len(data))]
        print(f"{args.file}: a bare PCX, {len(data):,} bytes")

    out = Path(args.extract) if args.extract else None
    if out:
        out.mkdir(parents=True, exist_ok=True)

    print(f"\n{'name':<14} {'offset':>9} {'bytes':>8} {'size':>11} "
          f"{'depth':>7}  ")
    ok = bad = 0
    for name, at, size in items:
        try:
            pcx = Pcx(data, at)
            rows = pcx.rows()
        except ValueError as e:
            print(f"  {name:<12} {at:#9x} {size:8,}  FAILED: {e}")
            bad += 1
            continue
        # The size field and an independent decode must agree, or one of them
        # is wrong and it matters which.
        actual = pcx.end - at
        note = "" if abs(actual - size) <= 1 else f"  <- size field says {size}"
        print(f"  {name:<12} {at:#9x} {size:8,} {pcx.width:5}x{pcx.height:<5} "
              f"{pcx.bpp * pcx.planes:5}bpp{note}")
        ok += 1
        if out:
            stem = name.replace(".", "_").replace(" ", "")
            write_png(rows, palette_for(pcx, external),
                      out / f"{stem}.png", args.scale)
    print(f"\n{ok} decoded, {bad} failed")
    if out:
        print(f"wrote {ok} PNGs to {out}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
