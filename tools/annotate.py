#!/usr/bin/env python3
"""annotate.py -- Turn a recovered listing into source somebody can read.

`comrec.py` produces assembly that reassembles to the original byte for byte.
It is *correct* and it is not *source*: thousands of instructions under labels
named after their own addresses, and every global written as a bare number.

This applies a symbol file to it. `L_02605` becomes `guard_choose_move`,
`word [0x116]` becomes `word [player_health]`, and each name arrives with the
comment that says why it is called that. The result still assembles to the same
bytes -- NASM sees `%define player_health 0x116` and emits what it emitted
before -- and that is the design rule: **naming a thing must not change it.**
With `--nasm` and `--original` the script proves that rather than claiming it,
and reports failure on anything short of an exact match.

    python annotate.py --asm recovered/game.asm --symbols symbols.json
                       --out recovered/game-named.asm
                       --nasm <path>/nasm.exe --original original/GAME.COM

`--header` is needed only for an MZ that took the `.COM` route, where comrec
writes the stripped header out beside the source and the rebuild is the two
concatenated.

The symbol file belongs to the game, not to this toolkit --
`retro-ports/karateka/symbols.json` is the worked example, including the `why`
against every name. A name with no evidence behind it is a guess that the next
reader will believe.

**Do not commit what this produces.** A byte-identical reconstruction is the
program, named or not. The names are the part worth keeping; this re-derives
the rest from a copy the reader already owns.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def load_symbols(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    routines = {int(k, 16): tuple(v) for k, v in raw["routines"].items()}
    globals_ = {int(k, 16): tuple(v) for k, v in raw["globals"].items()}
    return routines, globals_


def rename(text, routines, globals_):
    """Apply the names, and count what actually landed.

    Two substitutions, deliberately narrow. `L_xxxxx` is unambiguous -- comrec
    generates no other label of that shape. Globals are replaced only inside
    square brackets, because the same number appearing as an immediate is an
    immediate: `mov ax, 0x116` is the constant 278, not the health variable, and
    rewriting it would be a lie that still assembles.
    """
    hits = {"routines": 0, "globals": 0}

    def label(m):
        addr = int(m.group(1), 16)
        if addr in routines:
            hits["routines"] += 1
            return routines[addr][0]
        return m.group(0)

    text = re.sub(r"\bL_([0-9A-Fa-f]{5})\b", label, text)

    def mem(m):
        addr = int(m.group(1), 16)
        if addr in globals_:
            hits["globals"] += 1
            return f"[{globals_[addr][0]}{m.group(2) or ''}]"
        return m.group(0)

    text = re.sub(r"\[(0x[0-9a-f]+)((?:\s*[-+]\s*\w+)?)\]", mem, text)
    return text, hits


def preamble(routines, globals_):
    """`%define`s for every global, so the numbers are unchanged underneath."""
    out = ["; ---------------------------------------------------------------",
           "; Names applied by tools/annotate.py from symbols.json.",
           ";",
           "; Every one is a %define, so NASM emits exactly the bytes it emitted",
           "; before the names existed. If this file stops rebuilding, the names",
           "; are not the reason -- check the listing it was made from.",
           "; ---------------------------------------------------------------",
           ""]
    for addr, (name, why) in sorted(globals_.items()):
        pad = " " * max(1, 22 - len(name))
        out.append(f"%define {name}{pad}0x{addr:04x}"
                   + (f"    ; {why}" if why else ""))
    out.append("")
    return "\n".join(out)


def routine_comments(text, routines):
    """Put each routine's evidence directly above its label."""
    lines = text.split("\n")
    byname = {name: (addr, why) for addr, (name, why) in routines.items()}
    out = []
    for line in lines:
        m = re.match(r"^([A-Za-z_]\w*):", line)
        if m and m.group(1) in byname:
            addr, why = byname[m.group(1)]
            out.append("")
            out.append(f"; ---- image 0x{addr:05X} " + "-" * 40)
            if why:
                out.append(f"; {why}")
        out.append(line)
    return "\n".join(out)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def verify(named, nasm, header, original):
    """Assemble the named source and compare with the shipped file."""
    work = Path(tempfile.mkdtemp(prefix="annotate-verify-"))
    try:
        img = work / "image.bin"
        r = subprocess.run([nasm, "-f", "bin", "-o", str(img), str(named)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False, r.stderr.strip()[:400]
        rebuilt = work / "rebuilt.bin"
        head = Path(header).read_bytes() if header else b""
        rebuilt.write_bytes(head + img.read_bytes())
        a, b = sha(rebuilt), sha(original)
        if a != b:
            return False, (f"assembled, but the bytes differ\n"
                           f"  rebuilt  {a}\n  original {b}")
        return True, a
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--asm", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--symbols", default="symbols.json")
    ap.add_argument("--nasm", help="verify by rebuilding")
    ap.add_argument("--header", help="an MZ header comrec wrote out beside the source")
    ap.add_argument("--original", help="the shipped file, to compare against")
    args = ap.parse_args()

    src = Path(args.asm)
    if not src.exists():
        ap.error(f"{src} is not there. Generate it first:\n"
                 f"    python <toolkit>/tools/comrec.py {args.original} "
                 f"--out {src}")

    routines, globals_ = load_symbols(args.symbols)
    text = src.read_text(encoding="latin-1")
    text, hits = rename(text, routines, globals_)
    text = routine_comments(text, routines)
    out = Path(args.out)
    out.write_text(preamble(routines, globals_) + text, encoding="latin-1")

    print(f"{len(routines)} routine names, {len(globals_)} globals")
    print(f"  applied: {hits['routines']} label references, "
          f"{hits['globals']} memory references")
    print(f"  wrote {out}")

    if not (args.nasm and args.original):
        print("\n  (pass --nasm to rebuild and check it still matches)")
        return 0

    ok, detail = verify(out, args.nasm, args.header, args.original)
    if not ok:
        print(f"\nFAILED: {detail}")
        return 1
    print(f"\nBYTE-IDENTICAL after naming. SHA-256 {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
