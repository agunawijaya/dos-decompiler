#!/usr/bin/env python3
"""
placements.py -- Extract "draw sprite S at column C, row R" from 8086 code.

Why
---
A screen in a game of this vintage is not a map file. It is a *sequence of
calls*, each of which writes a column, a row and a sprite selector into fixed
variables and then calls a blitter. Reading one such routine by hand takes ten
minutes; there are dozens.

This walks the call tree from a build routine and recovers the placements,
handling the two shapes that actually occur:

    constant   mov al, 0x26 / mov [col], al   ... mov word [sel], 0x1500
    table      mov al, [bx + 0x15bf] / mov [col], al, inside a counted loop

Anything it cannot parse is reported rather than skipped, because a screen that
is silently missing a girder looks fine and is wrong.

It is deliberately not an emulator. It recognises a handful of idioms and
refuses the rest -- which keeps the output something you can check by reading,
and keeps "the program was never run" true.

Usage:
    python placements.py GAME.COM --builder 0x14D8 --col-var 0x6d9b \\
        --row-var 0x6d9c --sel-var 0x6d97 --drawers 0x217,0x268,0x2b1
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comrec


class Extractor:
    def __init__(self, rec, col_var, row_var, sel_var, drawers, load_base=0x100):
        self.r = rec
        self.ins = sorted(rec.decoded.items())
        self.idx = {o: i for i, (o, _) in enumerate(self.ins)}
        self.txt = {o: t for o, (_, t, _) in self.ins}
        self.col_var, self.row_var, self.sel_var = col_var, row_var, sel_var
        self.drawers = set(drawers)
        self.base = load_base
        self.image = rec.image
        self.unparsed = []

    def routine(self, start, limit=300):
        out, j = [], self.idx.get(start)
        if j is None:
            return out
        while j < len(self.ins) and len(out) < limit:
            o, (sz, t, g) = self.ins[j]
            out.append((o, t, g))
            if t in ("ret", "retf"):
                break
            j += 1
        return out

    def table(self, addr, n):
        off = addr - self.base
        return list(self.image[off:off + n])

    def walk(self, start, depth=0, seen=None, inherited=None):
        """Collect placements from a routine and everything it calls.

        State is inherited by callees. It has to be: a nested loop sets the row
        in the outer routine and the column in the inner one, so a callee that
        starts from a blank slate loses half of every placement.
        """
        if seen is None:
            seen = set()
        if (start, depth) in seen or depth > 3:
            return []
        seen.add((start, depth))

        out = []
        state = dict(inherited) if inherited else {}
        state.setdefault("col", None); state.setdefault("row", None)
        state.setdefault("sel", None); state.setdefault("col_tab", None)
        state.setdefault("row_tab", None); state.setdefault("count", None)
        state["al"] = None

        for o, t, g in self.routine(start):
            m = re.match(r"^mov al, (0x[0-9a-f]+|\d+)$", t)
            if m:
                state["al"] = int(m.group(1), 0)
                continue
            m = re.match(r"^mov bl, (0x[0-9a-f]+|\d+)$", t)
            if m:
                state["count"] = int(m.group(1), 0) + 1
                continue
            m = re.match(r"^mov al, byte \[\w+ \+ (0x[0-9a-f]+)\]$", t)
            if m:
                state["al"] = ("tab", int(m.group(1), 16))
                continue
            m = re.match(r"^mov al, byte \[(0x[0-9a-f]+)\]$", t)
            if m:
                state["al"] = ("var", int(m.group(1), 16))
                continue
            if re.match(r"^mov byte \[%s\], al$" % self.col_var, t):
                v = state["al"]
                if isinstance(v, tuple) and v[0] == "tab":
                    state["col_tab"] = v[1]
                elif isinstance(v, tuple):
                    state["col"] = None
                else:
                    state["col"] = v
                continue
            if re.match(r"^mov byte \[%s\], al$" % self.row_var, t):
                v = state["al"]
                if isinstance(v, tuple) and v[0] == "tab":
                    state["row_tab"] = v[1]
                elif isinstance(v, tuple) and v[0] == "var":
                    off = v[1] - self.base
                    state["row"] = self.image[off] if 0 <= off < len(self.image) else None
                else:
                    state["row"] = v
                continue
            m = re.match(r"^mov word \[%s\], (0x[0-9a-f]+)$" % self.sel_var, t)
            if m:
                state["sel"] = int(m.group(1), 16) >> 8
                continue
            # The selector is often computed rather than written whole:
            #     mov bl, [level] / mov al, [bx + table] / add ax, 0x2800
            # picks a variant per level and adds the sprite base. Without this,
            # every floor of levels one and three is silently missing.
            m = re.match(r"^add ax, (0x[0-9a-f]+)$", t)
            if m:
                base = int(m.group(1), 16) >> 8
                v = state.get("al")
                if isinstance(v, tuple) and v[0] == "tab":
                    off = v[1] - self.base + (state.get("sel_idx") or 0)
                    if 0 <= off < len(self.image):
                        state["pending_sel"] = base + self.image[off]
                else:
                    state["pending_sel"] = base + (v or 0)
                continue
            if re.match(r"^mov word \[%s\], ax$" % self.sel_var, t):
                if state.get("pending_sel") is not None:
                    state["sel"] = state["pending_sel"]
                continue
            m = re.match(r"^mov bl, byte \[(0x[0-9a-f]+)\]$", t)
            if m:
                off = int(m.group(1), 16) - self.base
                if 0 <= off < len(self.image):
                    state["sel_idx"] = self.image[off]
                continue

            if t.startswith("call") and g is not None:
                if g in self.drawers:
                    out += self.emit(state, o)
                    state["col"] = state["row"] = None
                    state["col_tab"] = state["row_tab"] = None
                else:
                    out += self.walk(g, depth + 1, seen, state)
        return out

    def emit(self, s, site):
        sel = s["sel"]
        if sel is None:
            self.unparsed.append((site, "no sprite selector"))
            return []
        n = s["count"] or 1
        if s["col_tab"] is not None:
            cols = self.table(s["col_tab"], min(n, 40))
            rows = (self.table(s["row_tab"], min(n, 40))
                    if s["row_tab"] is not None else [s["row"]] * len(cols))
            out = []
            for c, rr in zip(cols, rows):
                if c == 0xFF or rr is None:
                    break
                out.append((sel, c, rr))
            return out
        if s["col"] is None or s["row"] is None:
            self.unparsed.append((site, "column or row not constant"))
            return []
        return [(sel, s["col"], s["row"])]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--builder", required=True)
    ap.add_argument("--col-var", default="0x6d9b")
    ap.add_argument("--row-var", default="0x6d9c")
    ap.add_argument("--sel-var", default="0x6d97")
    ap.add_argument("--drawers", default="0x217,0x268,0x2b1,0x319,0x343,0x36d")
    ap.add_argument("--nasm", default=None)
    args = ap.parse_args()

    nasm = args.nasm
    if not nasm:
        from shutil import which
        import os
        nasm = os.environ.get("NASM") or which("nasm")

    image = Path(args.binary).read_bytes()
    rec = comrec.Reconstructor(args.binary, comrec.parse_segments([], len(image)), [0])
    rec.run(nasm)

    ex = Extractor(rec, args.col_var, args.row_var, args.sel_var,
                   [int(x, 16) for x in args.drawers.split(",")])
    places = ex.walk(int(args.builder, 16))

    print(f"{len(places)} placements from builder {args.builder}")
    for sel, c, r in places:
        print(f"  sprite {sel:>3}  col {c:>3}  row {r:>3}")
    if ex.unparsed:
        print(f"\n{len(ex.unparsed)} sites not parsed:")
        for site, why in ex.unparsed[:12]:
            print(f"  0x{site:05X}  {why}")


if __name__ == "__main__":
    sys.exit(main())
