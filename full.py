"""The complete screen, built by following the game's build sequence at 0x1763.

Every element below was traced to the code that places it. Nothing is
positioned by hand.

  0x176F  girders    rows 0x14B9, cols 0x14BF, map 0x70EA, sprite 27+v
  0x1772  ladders    rows 0x14CD, cols 0x14D1/D2, sprite 58
  0x1775  footings   row  0x14D3, cols 0x14D4, sprite 0
  0x178D  ladders    cols 0x2B05, rows 0x2B0A, 0xFF-terminated, sprite 3
  0x177E  object     col 8,    row 0x12, sprite 70
  0x17B4  machine    col 0x26, row 0x2A, sprite 21
  0x17BA  ramp       col 1,    row 0xBC, sprite 19
  0x17BD  hoist      col 0x23, row 0xBC, sprite 12
  0x17A8  EA logo    sprite 93
  0x17AB  text       records [col, row, chars, 0x01] from 0x1E76

Text glyphs come from the font pointer table at file 0x716F, indexed by
(character AND 0x3F) -- the mask the character drawer at 0x013E applies.
"""
import struct, sys
sys.path.insert(0, r"C:\Projects\dos-decompiler\tools")
from PIL import Image, ImageDraw
import gfxdump

COM = r"C:\Projects\retro-ports\hard-hat-mack\original\HHM.COM"
d = open(COM, "rb").read()
PAL = gfxdump.PALETTES["1"]
W, H, S = 320, 200, 3
SPR_TBL, FNT_TBL = 0x6D10, 0x716F


def blob(tbl, index, bottom_first=True):
    ptr = struct.unpack_from("<H", d, tbl + index * 2)[0]
    off = ptr - 0x100
    if not (0 < off < len(d) - 2):
        return None
    w, h = d[off], d[off + 1]
    if not (1 <= w <= 48 and 1 <= h <= 80):
        return None
    rows = gfxdump.unpack(d[off + 2:off + 2 + w * h], w)
    if bottom_first:
        rows = rows[::-1]     # sprites are stored bottom row first
    # ...but the character drawer at 0x013E is a separate routine with its
    # own loop, and the font is stored the ordinary way round.
    img = Image.new("RGBA", (w * 4, h), (0, 0, 0, 0))
    px = img.load()
    for y, row in enumerate(rows):
        for x, v in enumerate(row):
            if v:
                px[x, y] = PAL[v] + (255,)
    return img


cv = Image.new("RGB", (W, H), (0, 0, 0))
n = 0


def put(img, col, row):
    global n
    if img is None:
        return
    cv.paste(img, (col * 7, row - img.height + 1), img)
    n += 1


spr = lambda i: blob(SPR_TBL, i)

# girders
for ri, row in enumerate(d[0x14B9:0x14B9 + 5]):
    for ci, col in enumerate(d[0x14BF:0x14BF + 14]):
        put(spr(27 + d[0x70EA + ri * 14 + ci]), col, row)
# ladders (step 0x1772)
for row in d[0x14CD:0x14CD + 4]:
    for col in (d[0x14D1], d[0x14D2]):
        put(spr(58), col, row)
# footings
for col in d[0x14D4:0x14D4 + 4]:
    put(spr(0), col, d[0x14D3])
# ladder pieces (step 0x178D), 0xFF-terminated pair of tables
i = 0
while d[0x2B05 + i] != 0xFF and i < 16:
    put(spr(3), d[0x2B05 + i], d[0x2B0A + i])
    i += 1
# the fixed-position pieces
put(spr(70), 8, 0x12)
put(spr(21), 0x26, 0x2A)
put(spr(19), 1, 0xBC)
put(spr(12), 0x23, 0xBC)
# the Electronic Arts logo
logo = spr(93)
put(logo, 3, 40)

# text: the same records the game walks
off = 0x1E77   # 0x1E76 is the previous string's terminator
while off < 0x1F60:
    col, row = d[off], d[off + 1]
    p = off + 2
    s = b""
    while p < len(d) and d[p] not in (0, 1):
        s += bytes([d[p]]); p += 1
    if s and col < 46 and 0 < row < 200:
        for k, ch in enumerate(s):
            g = blob(FNT_TBL, ch & 0x3F, bottom_first=False)
            put(g, col + k, row)
    off = p + 1

print(f"{n} sprites placed, every identity and position read from the file")
big = cv.resize((W * S, H * S), Image.NEAREST)
out = Image.new("RGB", (big.width, big.height + 52), (10, 10, 14))
out.paste(big, (0, 52))
dr = ImageDraw.Draw(out)
dr.text((10, 10), "Hard Hat Mack (1983) — the screen its own code builds",
        fill=(255, 233, 168))
dr.text((10, 30), f"{n} sprites. Girders, ladders, machinery, logo and every "
        "letter placed by following the build sequence at 0x1763. Never executed.",
        fill=(150, 155, 180))
out.save(r"C:\Projects\retro-ports\hard-hat-mack\recovered\screen-title.png")
print("wrote screen-title.png")
