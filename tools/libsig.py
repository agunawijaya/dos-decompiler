#!/usr/bin/env python3
"""
libsig.py -- Recognise C runtime library functions inside a stripped binary.

The problem this solves
-----------------------
A linked 1980s C program is part game, part C library, and nothing in the
binary says which is which. Every library function shows up in the decompiled
output as another FUN_1000_xxxx competing for attention and, worse, competing
for matches: measured on Sopwith, the library inflates the function count by
roughly a fifth and drags identification precision down, because a source
function can be "matched" to a library routine that merely resembles it.

Telling the two apart is therefore worth more than it sounds. Once library
functions are labelled they can be excluded from matching, and the ones that
remain are the program.

How the signatures work
-----------------------
The same approach IDA's FLIRT uses, built from parts available here.

A library function's bytes are almost identical wherever it is linked, with
two exceptions: relative call/jump displacements change when the callee sits
at a different distance, and absolute data references change when the
variable lands at a different offset. So the signature stores the bytes and a
mask marking which of them are allowed to differ. The mask comes from
disassembling with capstone and blanking every displacement and immediate
field the encoding declares.

Building a database needs a program you compiled yourself with the same
toolchain, plus its linker map -- see signatures/, which uses a
reference program written purely to pull in as much of the library as
possible. That makes matching against a *different* binary a genuine
held-out test.

Usage:
    python libsig.py build  libref.exe libref.map --json sigs.json
    python libsig.py apply  target.exe functions.json --db sigs.json
    python libsig.py apply  target.exe functions.json --db sigs.json \\
                            --map target.map        # scores itself
"""

import argparse
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
except ImportError:  # pragma: no cover
    print("libsig: capstone is required (pip install capstone)", file=sys.stderr)
    raise

SIG_BYTES = 32          # how much of each function to fingerprint
MIN_SIG_BYTES = 8       # below this a signature matches half the binary


def header_size(path):
    data = Path(path).read_bytes()
    if data[:2] not in (b"MZ", b"ZM"):
        raise SystemExit(f"{path}: not an MZ executable")
    return struct.unpack_from("<H", data, 8)[0] * 16, data


def parse_map(path):
    """Return [(offset, symbol, module)] sorted by offset, for the code segment.

    Only segment 0000 is taken: in a small-model program that is _TEXT, and
    mixing in data symbols would produce signatures made of sprite bitmaps.
    """
    import re
    sym_re = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+"
                        r"([A-Za-z_@$?][\w@$?.]*)\s*$")
    mod_re = re.compile(r"^\s*Module:\s*(\S+)")

    out, module = [], None
    for line in Path(path).read_text(encoding="latin-1",
                                     errors="replace").splitlines():
        m = mod_re.match(line)
        if m:
            module = m.group(1)
            continue
        m = sym_re.match(line)
        if m and int(m.group(1), 16) == 0:
            out.append((int(m.group(2), 16), m.group(3), module))
    out.sort()
    return out


def is_library(module):
    return bool(module) and ".lib" in module.lower()


def mask_for(code, base=0):
    """Bytes that must match exactly (True) versus bytes free to vary (False).

    Displacements and immediates are blanked because they encode addresses,
    and addresses move when a function is linked into a different program.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    mask = [True] * len(code)
    consumed = 0
    for insn in md.disasm(bytes(code), base):
        start = insn.address - base
        enc = insn.encoding
        for off, size in ((enc.disp_offset, enc.disp_size),
                          (enc.imm_offset, enc.imm_size)):
            if size:
                for k in range(off, min(off + size, insn.size)):
                    if 0 <= start + k < len(mask):
                        mask[start + k] = False
        consumed = start + insn.size
    # Anything capstone could not decode is data; do not demand it matches.
    for i in range(consumed, len(mask)):
        mask[i] = False
    return mask


def build(exe, mapfile, only_library=True, exclude=()):
    hdr, data = header_size(exe)
    symbols = parse_map(mapfile)
    if not symbols:
        raise SystemExit(f"{mapfile}: no code symbols found")

    # Microsoft LINK's map has no "Module:" lines, so there is no way to tell
    # library code from the reference program's own. Everything is taken, and
    # the handful of symbols belonging to the reference program are excluded by
    # name instead. Open Watcom's wlink does record modules, so there the
    # distinction is exact.
    have_modules = any(m for _, _, m in symbols)
    if only_library and not have_modules:
        only_library = False
        print(f"note: {Path(mapfile).name} carries no module information "
              f"(Microsoft LINK format); taking every symbol and relying on "
              f"--exclude-symbol", file=sys.stderr)

    excluded = {e.lstrip("_").lower() for e in exclude}

    sigs = {}
    for i, (off, name, module) in enumerate(symbols):
        if only_library and not is_library(module):
            continue
        if name.lstrip("_").lower() in excluded:
            continue
        end = symbols[i + 1][0] if i + 1 < len(symbols) else off + SIG_BYTES
        length = max(0, end - off)
        take = min(SIG_BYTES, length)
        if take < MIN_SIG_BYTES:
            continue
        start = hdr + off
        code = data[start:start + take]
        if len(code) < MIN_SIG_BYTES:
            continue
        mask = mask_for(code)
        if sum(mask) < MIN_SIG_BYTES:
            continue        # too little fixed content to identify anything
        sigs.setdefault(name, {
            "name": name,
            # Only the library file and member, never the path it was built
            # from. A database is meant to be shared; baking in someone's
            # directory layout makes it machine-specific for no benefit.
            "module": short_module(module),
            "length": length,
            "bytes": code.hex(),
            "mask": "".join("1" if m else "0" for m in mask),
        })
    return {"source": Path(exe).name, "count": len(sigs),
            "signatures": list(sigs.values())}


def short_module(module):
    """Reduce a linker's module reference to library(member)."""
    if not module:
        return module
    tail = module.replace("/", "\\").split("\\")[-1]
    return tail


def compile_db(db):
    """Group signatures by their first fixed byte, for a cheap prefilter."""
    table = defaultdict(list)
    for s in db["signatures"]:
        raw = bytes.fromhex(s["bytes"])
        mask = [c == "1" for c in s["mask"]]
        table[raw[0] if mask[0] else None].append((raw, mask, s))
    return table


def match_at(code, table):
    """Best signature matching these bytes, or None."""
    best = None
    candidates = table.get(code[0], []) + table.get(None, [])
    for raw, mask, s in candidates:
        n = min(len(raw), len(code))
        fixed = 0
        for i in range(n):
            if not mask[i]:
                continue
            if code[i] != raw[i]:
                break
            fixed += 1
        else:
            if fixed >= MIN_SIG_BYTES and (best is None or fixed > best[1]):
                best = (s, fixed)
    return best


def apply(exe, functions_json, db):
    hdr, data = header_size(exe)
    funcs = json.loads(Path(functions_json).read_text(encoding="utf-8"))["functions"]
    table = compile_db(db)

    hits = []
    for f in funcs:
        seg, off = f["entry"].split(":")
        offset = int(off, 16)
        start = hdr + offset
        code = data[start:start + SIG_BYTES]
        if len(code) < MIN_SIG_BYTES:
            continue
        m = match_at(code, table)
        if m:
            hits.append({"entry": f["entry"], "name": m[0]["name"],
                         "module": m[0]["module"], "fixed_bytes": m[1]})
    return hits


def score(hits, mapfile, functions_json, seg_bias=0x1000):
    """Compare detections against a map that says which functions are library."""
    symbols = parse_map(mapfile)
    truth = {}
    for off, name, module in symbols:
        truth[f"{seg_bias:04x}:{off:04x}"] = is_library(module)

    funcs = json.loads(Path(functions_json).read_text(encoding="utf-8"))["functions"]
    known = [f["entry"] for f in funcs if f["entry"] in truth]
    lib_true = {e for e in known if truth[e]}
    detected = {h["entry"] for h in hits}

    tp = len(detected & lib_true)
    fp = len({e for e in detected if e in truth} - lib_true)
    fn = len(lib_true - detected)
    return {
        "functions_with_known_status": len(known),
        "library_functions": len(lib_true),
        "detected": len(detected),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(tp / max(1, tp + fp), 3),
        "recall": round(tp / max(1, len(lib_true)), 3),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build a signature database")
    b.add_parser = None
    b.add_argument("exe")
    b.add_argument("mapfile")
    b.add_argument("--json", required=True)
    b.add_argument("--all", action="store_true",
                   help="include non-library modules too")
    b.add_argument("--exclude-symbol", action="append", default=[],
                   help="symbol belonging to the reference program itself, not "
                        "the library (repeatable; leading underscore optional)")

    a = sub.add_parser("apply", help="identify library functions in a binary")
    a.add_argument("exe")
    a.add_argument("functions_json")
    a.add_argument("--db", required=True)
    a.add_argument("--map", help="linker map for the target, to score accuracy")
    a.add_argument("--seg-bias", default="0x1000")
    a.add_argument("--json", help="write detections here")
    a.add_argument("--exclude", help="write a match.py --exclude list here")

    args = ap.parse_args()

    if args.cmd == "build":
        db = build(args.exe, args.mapfile, only_library=not args.all,
                   exclude=args.exclude_symbol)
        Path(args.json).write_text(json.dumps(db, indent=2), encoding="utf-8")
        print(f"built {db['count']} signatures -> {args.json}")
        return 0

    db = json.loads(Path(args.db).read_text(encoding="utf-8"))
    hits = apply(args.exe, args.functions_json, db)
    print(f"signatures in database : {db['count']}")
    print(f"library functions found: {len(hits)}")
    for h in hits[:20]:
        print(f"  {h['entry']}  {h['name']:<20} ({h['fixed_bytes']} fixed bytes)")
    if len(hits) > 20:
        print(f"  ... {len(hits) - 20} more")

    if args.map:
        ev = score(hits, args.map, args.functions_json, int(args.seg_bias, 0))
        print("\naccuracy against the target's linker map:")
        for k, v in ev.items():
            print(f"  {k:<28} {v}")

    if args.json:
        Path(args.json).write_text(json.dumps(hits, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
