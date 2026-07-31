#!/usr/bin/env python3
"""
mapparse.py -- Turn a linker MAP file into a ground-truth symbol map.

A MAP file is the only artefact that states, without inference, exactly which
address each function was placed at. When you can rebuild a program from
source you get one for free, and it becomes the answer key that measures how
well the decompilation pipeline actually performs.

Handles both formats that matter for this era:
  * Open Watcom wlink   "Address  Symbol" sections, grouped by Module:
  * Microsoft LINK      "Address  Publics by Name" / "Publics by Value"

Symbol names are undecorated back to source names: a leading underscore is the
C convention of the period and is removed, so `_swmove` becomes `swmove`. A
name that starts with two underscores keeps one (`__intsetup` -> `_intsetup`),
because that leading underscore is part of the source-level name.

The segment bias matters. A MAP file numbers segments from zero, but a
disassembler places the image at some base -- Ghidra's MZ loader uses 0x1000.
Pass --seg-bias to line the two up.

Usage:
    python mapparse.py sopwith.map --seg-bias 0x1000 --json truth.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

SYMBOL_LINE = re.compile(
    r"^\s*(?P<seg>[0-9A-Fa-f]{4}):(?P<off>[0-9A-Fa-f]{4,8})\s+"
    r"(?P<name>[A-Za-z_@$?][\w@$?.]*)\s*$")
MODULE_LINE = re.compile(r"^\s*Module:\s*(?P<mod>\S+)")
SEGMENT_LINE = re.compile(
    r"^\s*(?P<name>[A-Z_][\w]*)\s+(?P<cls>[A-Z]+)\s+(?P<grp>\S*)\s+"
    r"(?P<seg>[0-9A-Fa-f]{4}):(?P<off>[0-9A-Fa-f]{4,8})\s+(?P<size>[0-9A-Fa-f]+)",
    re.IGNORECASE)


def undecorate(name):
    """Recover the source-level name from a linker symbol.

    Leading underscore is the Microsoft/Borland C convention; trailing
    underscore is Open Watcom's register convention. A binary can contain
    both: even when Watcom is told to use __cdecl, its startup still reaches
    `main` by the register-convention name `main_`, so handling only the
    leading form silently loses symbols -- `main` among them.
    """
    if name.startswith("__"):
        return name[1:]        # __intsetup -> _intsetup
    if name.startswith("_"):
        return name[1:]        # _swmove    -> swmove
    if name.endswith("_") and not name.endswith("__"):
        return name[:-1]       # main_      -> main
    return name


def parse(path, seg_bias=0):
    text = Path(path).read_text(encoding="latin-1", errors="replace")
    module = None
    symbols = []
    segments = []
    seen = set()

    for line in text.splitlines():
        m = MODULE_LINE.match(line)
        if m:
            module = m.group("mod")
            continue

        m = SEGMENT_LINE.match(line)
        if m and m.group("cls").upper() in ("CODE", "DATA", "BSS", "STACK", "CONST"):
            segments.append({
                "name": m.group("name"),
                "class": m.group("cls"),
                "group": m.group("grp"),
                "address": f"{int(m.group('seg'), 16) + seg_bias:04x}:{m.group('off').lower()}",
                "size": int(m.group("size"), 16),
            })
            continue

        m = SYMBOL_LINE.match(line)
        if m:
            seg = int(m.group("seg"), 16) + seg_bias
            off = m.group("off").lower().zfill(4)
            addr = f"{seg:04x}:{off}"
            raw = m.group("name")
            key = (raw, addr)
            if key in seen:
                continue
            seen.add(key)
            symbols.append({
                "symbol": raw,
                "name": undecorate(raw),
                "address": addr,
                "module": module,
            })

    return {"map_file": str(path), "seg_bias": seg_bias,
            "segments": segments, "symbols": symbols}


def to_truth(result, modules=None):
    """Reduce to {source_name: address} for the scoring harness.

    Where two symbols share a name the first wins and a note is emitted --
    silently picking one would corrupt the accuracy figures that depend on it.
    """
    truth, dupes = {}, []
    for s in result["symbols"]:
        if modules and s["module"] not in modules:
            continue
        if s["name"] in truth:
            if truth[s["name"]] != s["address"]:
                dupes.append((s["name"], truth[s["name"]], s["address"]))
            continue
        truth[s["name"]] = s["address"]
    return truth, dupes


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mapfile")
    ap.add_argument("--seg-bias", default="0",
                    help="added to every segment number (Ghidra MZ loader: 0x1000)")
    ap.add_argument("--json", help="write the full parse here")
    ap.add_argument("--truth", help="write {name: address} pairs here")
    ap.add_argument("--module", action="append",
                    help="restrict to these modules (repeatable)")
    args = ap.parse_args()

    bias = int(args.seg_bias, 0)
    r = parse(args.mapfile, bias)
    truth, dupes = to_truth(r, set(args.module) if args.module else None)

    print(f"map file : {args.mapfile}")
    print(f"seg bias : 0x{bias:x}")
    print(f"segments : {len(r['segments'])}")
    print(f"symbols  : {len(r['symbols'])}")
    print(f"truth    : {len(truth)} unique names")
    if dupes:
        print(f"\n{len(dupes)} name collision(s) -- first occurrence kept:")
        for name, kept, other in dupes[:10]:
            print(f"  {name}: kept {kept}, also at {other}")
    if r["segments"]:
        print("\nsegments:")
        for s in r["segments"]:
            print(f"  {s['address']}  {s['name']:<12} {s['class']:<6} {s['size']:>7} bytes")

    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    if args.truth:
        Path(args.truth).write_text(json.dumps(truth, indent=2), encoding="utf-8")
        print(f"wrote {args.truth}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
