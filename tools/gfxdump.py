#!/usr/bin/env python3
"""
gfxdump.py -- Render a region of a DOS binary as CGA graphics, to a PNG.

Why this exists
---------------
A reconstruction can be byte-perfect and still be misunderstood. `comrec.py`
proves the *source* is right; it says nothing about whether the region you have
labelled "sprites" is sprites.

This is the cheapest check there is. Decode the bytes as pixels and look. If
recognisable shapes appear, the region is graphics and the format is right. If
noise appears, one of those two is wrong -- and you find out in a minute rather
than after a fortnight of building a port around a wrong assumption.

The format
----------
CGA mode 4 packs four pixels into a byte, two bits each, most significant pair
leftmost:

    byte 0xAA = 10 10 10 10 = four pixels of colour 2
    byte 0x55 = 01 01 01 01 = four pixels of colour 1
    byte 0xF0 = 11 11 00 00 = two of colour 3, two of colour 0

A high count of 0xAA, 0x55, 0xFF and 0xF0 in a region is itself a good sign
that it is artwork: solid runs of a single colour are what sprites are made of.

Widths are guesses, so `--sheet` renders the same bytes at several and lets you
pick the one where the picture lines up. Getting the width wrong shears the
image diagonally, which is unmistakable once you have seen it once.

Usage:
    python gfxdump.py GAME.COM --at 0x6D10 --len 4096 --width 6 --out sprites.png
    python gfxdump.py GAME.COM --at 0x6D10 --len 2112 --sheet --out widths.png
    python gfxdump.py GAME.COM --at 0x6D10 --stride 66 --count 24 --out grid.png
"""

import argparse
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover
    print("gfxdump: Pillow is required (pip install pillow)", file=sys.stderr)
    raise

# CGA mode 4 had two fixed palettes and one intensity bit. Palette 1 is the
# cyan/magenta/white most games chose; palette 0 is green/red/brown.
PALETTES = {
    "1": [(0, 0, 0), (85, 255, 255), (255, 85, 255), (255, 255, 255)],
    "0": [(0, 0, 0), (85, 255, 85), (255, 85, 85), (255, 255, 85)],
    "mono": [(0, 0, 0), (85, 85, 85), (170, 170, 170), (255, 255, 255)],
}


def unpack(data, width_bytes):
    """CGA 2bpp bytes -> rows of palette indices."""
    rows = []
    for i in range(0, len(data) - width_bytes + 1, width_bytes):
        row = []
        for b in data[i:i + width_bytes]:
            row += [(b >> 6) & 3, (b >> 4) & 3, (b >> 2) & 3, b & 3]
        rows.append(row)
    return rows


def render(rows, palette, scale, mirror=False):
    """Draw the rows. `mirror` flips horizontally.

    Some games store sprites as a mirror image of what appears on screen,
    because the routine that draws them walks the data backwards. Hard Hat
    Mack does: its Electronic Arts logo is unreadable until flipped, and then
    it is unmistakable. If a sprite sheet looks like plausible shapes rendered
    by someone holding the paper up to a mirror, this is why.
    """
    if not rows:
        return Image.new("RGB", (1, 1))
    if mirror:
        rows = [row[::-1] for row in rows]
    h, w = len(rows), len(rows[0])
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y, row in enumerate(rows):
        for x, v in enumerate(row):
            px[x, y] = palette[v]
    return img.resize((w * scale, h * scale), Image.NEAREST)


def label(img, text, pad=18):
    """Put a caption strip above an image."""
    out = Image.new("RGB", (img.width, img.height + pad), (18, 18, 24))
    out.paste(img, (0, pad))
    ImageDraw.Draw(out).text((3, 4), text, fill=(210, 210, 225))
    return out


def sheet(data, palette, scale, widths, mirror=False):
    """The same bytes at several widths, side by side.

    Only one width makes the picture stand up straight. The rest shear it, and
    the difference is obvious at a glance -- which is the whole point.
    """
    panels = [label(render(unpack(data, w), palette, scale, mirror), f"{w} bytes = {w*4}px")
              for w in widths]
    gap = 10
    W = sum(p.width for p in panels) + gap * (len(panels) + 1)
    H = max(p.height for p in panels) + gap * 2
    out = Image.new("RGB", (W, H), (12, 12, 16))
    x = gap
    for p in panels:
        out.paste(p, (x, gap))
        x += p.width + gap
    return out


def grid(data, base, stride, count, width_bytes, palette, scale, cols=8, mirror=False):
    """One cell per fixed-size record, laid out as a contact sheet."""
    cells = []
    for i in range(count):
        chunk = data[i * stride:(i + 1) * stride]
        if len(chunk) < stride:
            break
        cells.append(label(render(unpack(chunk, width_bytes), palette, scale, mirror),
                           f"#{i}  0x{base + i * stride:05X}"))
    if not cells:
        return Image.new("RGB", (1, 1))
    cw, ch = max(c.width for c in cells), max(c.height for c in cells)
    rows = (len(cells) + cols - 1) // cols
    gap = 8
    out = Image.new("RGB", (cols * (cw + gap) + gap, rows * (ch + gap) + gap),
                    (12, 12, 16))
    for i, c in enumerate(cells):
        out.paste(c, (gap + (i % cols) * (cw + gap), gap + (i // cols) * (ch + gap)))
    return out


def selfsized(data, base, count, palette, scale, cols=10, mirror=False):
    """Sprites that carry their own size: two header bytes, then the pixels.

    Hard Hat Mack stores them as [width_in_bytes, height_in_rows, pixels...].
    A 4x16 sprite is 2 + 64 = 66 bytes, which is exactly the stride seen in its
    pointer table -- so the header is not a guess, it is what makes the table's
    arithmetic come out right.

    Reading the size from the data rather than being told it means one pass
    renders every sprite correctly regardless of shape, which is the difference
    between a contact sheet you can read and a wall of sheared noise.
    """
    cells, off, i = [], 0, 0
    while off + 2 < len(data) and i < count:
        w, h = data[off], data[off + 1]
        if not (1 <= w <= 40 and 1 <= h <= 64):
            off += 1                     # not a header here; step and retry
            continue
        n = w * h
        if off + 2 + n > len(data):
            break
        rows = unpack(data[off + 2:off + 2 + n], w)
        cells.append(label(render(rows, palette, scale, mirror),
                           f"0x{base + off:05X}  {w*4}x{h}"))
        off += 2 + n
        i += 1
    if not cells:
        return Image.new("RGB", (1, 1))
    cw, ch = max(c.width for c in cells), max(c.height for c in cells)
    gap = 8
    rows_n = (len(cells) + cols - 1) // cols
    out = Image.new("RGB", (cols * (cw + gap) + gap, rows_n * (ch + gap) + gap),
                    (12, 12, 16))
    for k, c in enumerate(cells):
        out.paste(c, (gap + (k % cols) * (cw + gap), gap + (k // cols) * (ch + gap)))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--at", required=True, help="file offset to start at")
    ap.add_argument("--len", dest="length", default=None, help="how many bytes")
    ap.add_argument("--width", type=int, default=8, help="row width in BYTES (x4 = pixels)")
    ap.add_argument("--scale", type=int, default=3)
    ap.add_argument("--palette", choices=list(PALETTES), default="1")
    ap.add_argument("--sheet", action="store_true",
                    help="render at several widths for comparison")
    ap.add_argument("--widths", default="2,4,6,8,10,16,20,40,80")
    ap.add_argument("--stride", type=int, default=None,
                    help="record size, for a contact sheet of sprites")
    ap.add_argument("--self-sized", action="store_true",
                    help="each sprite begins with [width_bytes, height_rows]")
    ap.add_argument("--count", type=int, default=32)
    ap.add_argument("--mirror", action="store_true",
                    help="flip horizontally; some games store sprites mirrored")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    image = Path(args.binary).read_bytes()
    at = int(args.at, 0)
    n = int(args.length, 0) if args.length else len(image) - at
    data = image[at:at + n]
    pal = PALETTES[args.palette]

    if args.self_sized:
        img = selfsized(data, at, args.count, pal, args.scale, mirror=args.mirror)
    elif args.sheet:
        img = sheet(data, pal, args.scale, [int(w) for w in args.widths.split(",")], args.mirror)
    elif args.stride:
        img = grid(data, at, args.stride, args.count, args.width, pal, args.scale, mirror=args.mirror)
    else:
        img = render(unpack(data, args.width), pal, args.scale, args.mirror)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    img.save(args.out)
    print(f"{args.binary}  0x{at:05X} + {len(data):,} bytes")
    print(f"  -> {args.out}  ({img.width}x{img.height})")


if __name__ == "__main__":
    sys.exit(main())
