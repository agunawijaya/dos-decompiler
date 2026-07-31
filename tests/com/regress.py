#!/usr/bin/env python3
"""
regress.py -- Check that comrec.py still rebuilds .COM files exactly.

The claim comrec makes is narrow and absolute: the .asm it writes assembles
back to a file identical to the one it read. That is rung 1 of the
verification ladder in knowledge/05-verification.md -- not "looks right", not
"behaves the same", but the same bytes. A test either confirms it or the tool
is broken, so this suite reassembles every fixture with NASM and compares
SHA-256.

Byte-identity alone is a low bar, though: emitting the whole file as `db`
lines would pass. So each fixture also carries a floor for how much of it must
come back as instructions, and a list of things the output has to contain.
Those are what catch a regression that is still technically correct but has
stopped being a decompilation.

The fixtures are written here rather than taken from a real game because games
from the period are still under copyright. They reproduce the patterns that
made a real reconstruction hard -- ParaTrooper's measured figures are recorded
in CASE-STUDY.md.

Usage:
    python tests/com/regress.py [--nasm PATH]
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COMREC = ROOT / "tools" / "comrec.py"
FIXTURES = HERE / "fixtures"

# name -> (floor for the share of the file that must come back as
#          instructions, substrings that must appear in the source or in
#          comrec's own report)
#
# The floors sit a little under what the tools currently achieve, so a real
# regression trips them while ordinary variation does not. They are low in
# absolute terms because these fixtures are mostly data -- farstub is 543
# bytes of which 480 are padding between the stub and the code it jumps to.
# A percentage of the whole file measures the fixture, not the tool, which is
# exactly why comrec reports the code region separately.
EXPECTATIONS = {
    "plain": (
        30.0,
        ["db 'A plain COM file, one segment, nothing clever.",
         "db 'Press Q to quit.'",
         # The message must not be disassembled as code: the walk has to stop
         # at the DOS exit that precedes it.
         "mov ax, 0x4c00"],
    ),
    "farstub": (
        7.0,
        ["detected from the entry stub",       # the split was found
         "% of the code region",               # and reported separately
         "db 'Reached the second segment.'",
         "ds:0x0002",                          # DS bias resolved
         "; ---- file 0x0200, addresses relative to 0x0000 ----"],
    ),
    "encodings": (
        30.0,
        ["strict word",                        # long immediate form recovered
         "; mov dx, ax"],                      # direction-bit alternate pinned
    ),
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def nasm_build(nasm, src, out):
    r = subprocess.run([nasm, "-f", "bin", "-o", str(out), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"nasm failed on {src}:\n{r.stderr}")


def run_case(nasm, name, workdir):
    src = FIXTURES / f"{name}.asm"
    original = workdir / f"{name}.com"
    nasm_build(nasm, src, original)

    asm = workdir / f"{name}.rec.asm"
    r = subprocess.run([sys.executable, str(COMREC), str(original),
                        "--out", str(asm), "--nasm", nasm],
                       capture_output=True, text=True)
    stdout = r.stdout

    if r.returncode != 0 or "BYTE-IDENTICAL" not in stdout:
        return False, f"comrec did not report byte-identity\n{stdout}{r.stderr}"

    # Rebuild independently rather than trusting comrec's own account of it.
    rebuilt = workdir / f"{name}.rebuilt.com"
    nasm_build(nasm, asm, rebuilt)
    if sha(rebuilt) != sha(original):
        return False, "rebuilt file differs from the original"

    floor, needles = EXPECTATIONS[name]
    m = re.search(r"bytes as code: [\d,]+ / [\d,]+\s+\(([\d.]+)% of file\)",
                  stdout)
    if not m:
        return False, "could not read the code fraction from comrec's output"
    pct = float(m.group(1))
    if pct < floor:
        return False, (f"only {pct:.1f}% of the file came back as instructions, "
                       f"floor is {floor:.1f}%")

    body = asm.read_text(encoding="latin-1") + stdout
    missing = [n for n in needles if n not in body]
    if missing:
        return False, "output is missing: " + "; ".join(repr(x) for x in missing)

    return True, f"byte-identical, {pct:.1f}% as instructions"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nasm", default=None)
    args = ap.parse_args()

    nasm = args.nasm or os.environ.get("NASM")
    if not nasm:
        from shutil import which
        nasm = which("nasm")
    if not nasm or not Path(nasm).exists():
        raise SystemExit("nasm not found. Pass --nasm PATH, set NASM, or put "
                         "nasm on PATH.")

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        for name in sorted(EXPECTATIONS):
            try:
                ok, detail = run_case(nasm, name, work)
            except SystemExit as e:
                ok, detail = False, str(e)
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<12} {detail}")
            if not ok:
                failures += 1

    print()
    if failures:
        print(f"{failures} of {len(EXPECTATIONS)} fixtures failed.")
        return 1
    print(f"All {len(EXPECTATIONS)} .COM fixtures rebuild byte-identically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
