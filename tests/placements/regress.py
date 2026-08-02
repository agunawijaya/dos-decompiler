#!/usr/bin/env python3
"""
regress.py -- Check that placements.py still reads each loop shape correctly.

`placements.py` reconstructs what a program draws without running it: which
sprite, at which column and row, from the tables and loops in the file alone.
It is the most valuable thing in this toolkit and the most fragile, and until
this suite existed the only thing checking it was a referee that runs Hard Hat
Mack -- which found ten bugs in one session and cannot ship, because it needs a
copyrighted game.

So `fixtures/loops.asm` is that program in miniature: a drawer, and one builder
per shape that was once read wrongly. Each is checked two ways.

**Against a written-down expectation.** The fixture's tables are in the source
and the answer can be worked out by hand, which is the point of a fixture.

**Against the program itself.** If Unicorn is installed the same file is run
under `comrun.py` with the drawer hooked, and the two lists must agree exactly.
That is the same referee Hard Hat Mack has, on a program this repository owns.

The failure this guards against is specific and quiet: every one of the ten
bugs still produced *a* placement. Nothing raised, nothing crashed, the
coverage number stayed where it was, and the picture was wrong. A test that
only asks "did something come out" would have passed throughout, so this one
compares by value.

Usage:
    python tests/placements/regress.py [--nasm PATH]
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

FIXTURE = HERE / "fixtures" / "loops.asm"

def entry(sel):
    """The shape slot: the selector's two bytes added together.

    `placements.py` reports this rather than the sixteen-bit word, because
    that is what the games index their shape tables with. Both sides of this
    test are put through it so they are the same quantity -- the extractor
    returned a raw word down one branch and a combined byte down another for
    as long as it existed, and no game noticed, because applying this twice
    gives the same answer as applying it once.
    """
    return (sel & 0xFF) + (sel >> 8)


# (column, row, shape) for every placement the fixture makes, in the order its
# builders run. Worked out from the tables in the fixture source:
#
#   cols_a 10 11 12 13 14      rows_a 20 21 22 23 24
#   cols_b 30 31 32            rows_b 40 41 42        slots 1 0 1 0
EXPECTED = [
    # 1. counts down, BL 3..0
    (13, 23, 5), (12, 22, 5), (11, 21, 5), (10, 20, 5),
    # 2. counts up, BL 1..4
    (11, 21, 6), (12, 22, 6), (13, 23, 6), (14, 24, 6),
    # 3. counter 3..0 in one variable, cursor 14,16,18,20 in another
    (14, 23, 7), (16, 22, 7), (18, 21, 7), (20, 20, 7),
    # 4. slots[3] and slots[1] are zero, so only 2 and 0 are drawn
    (12, 22, 8), (10, 20, 8),
    # 5. writes no selector: inherits 0x0800 from the builder before it
    (31, 41, 8), (32, 42, 8),
    # 6. `mov word [sel], 0` -- NASM prints the zero in decimal
    (9, 40, 0),
]


def find_nasm(given):
    for c in (given, os.environ.get("NASM")):
        if c and Path(c).exists():
            return c
    from shutil import which
    return which("nasm")


def assemble(nasm, out):
    r = subprocess.run([nasm, "-f", "bin", "-o", str(out), str(FIXTURE)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("nasm could not build the fixture:\n" + r.stderr)
    return out


def builders(rec, entry=0x0000):
    """The routines `start` calls, in order -- the fixture's own table of
    contents, so the test does not carry hard-coded offsets that move whenever
    the fixture is edited."""
    import placements
    out = []
    for _, t, g in placements.routine(rec, entry):
        if t.startswith("call") and g is not None and g not in out:
            out.append(g)
    return out


def observed(com, drawer):
    """What the program does, run under comrun with the drawer hooked."""
    try:
        from unicorn import UC_HOOK_CODE
        import comrun
    except Exception as e:                       # noqa: BLE001
        return None, f"not run ({e.__class__.__name__})"
    image = Path(com).read_bytes()
    m = comrun.Machine(image)
    seen = []

    def rd(addr, n=1):
        b = m.uc.mem_read(comrun.BASE + comrun.LOAD + addr - 0x100, n)
        return b[0] if n == 1 else b[0] | (b[1] << 8)

    at = comrun.BASE + comrun.LOAD + drawer

    def hook(uc, addr, size, _):
        if addr == at:
            seen.append((rd(COL), rd(ROW), entry(rd(SEL, 2))))

    m.uc.hook_add(UC_HOOK_CODE, hook)
    m.run()
    return seen, None


COL = ROW = SEL = None                 # filled in from the drawer's own triple


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--nasm")
    a = ap.parse_args()
    nasm = find_nasm(a.nasm)
    if not nasm:
        print("placements regress: nasm not found (set NASM or pass --nasm)")
        return 77

    import placements
    work = Path(tempfile.mkdtemp(prefix="placements-regress-"))
    com = assemble(nasm, work / "loops.com")
    rec = placements.load(str(com), nasm)
    drawers = placements.find_drawers(rec)
    if len(drawers) != 1:
        print(f"FAIL  expected one drawer, found {len(drawers)}: "
              + ", ".join(f"0x{a:05X}" for a in drawers))
        return 1
    addr, triples = next(iter(drawers.items()))
    if len(triples) != 1:
        print(f"FAIL  the drawer should close one triple, not {len(triples)}")
        return 1

    global COL, ROW, SEL
    tr = triples[0]
    COL, ROW, SEL = tr.col, tr.row, tr.sel
    print(f"drawer at 0x{addr:05X}: column [{tr.col:#06x}], "
          f"row [{tr.row:#06x}], selector [{tr.sel:#06x}]")

    ex = placements.Extractor(rec, drawers)
    got = [(col, row, sel) for sel, col, row, _ in ex.walk(0x0000)]

    fails = 0
    if got != EXPECTED:
        fails += 1
        print(f"FAIL  the reading does not match what the fixture says.")
        show(EXPECTED, got)
    else:
        print(f"PASS  {len(got)} placements, all as written down")

    obs, why = observed(com, addr)
    if obs is None:
        print(f"      the program itself was {why}; static side only")
    elif obs != EXPECTED:
        fails += 1
        print("FAIL  the expectation does not match the program itself -- "
              "the fixture or the table above is wrong, not the tool")
        show(EXPECTED, obs)
    else:
        print(f"PASS  the program makes the same {len(obs)}, run under comrun")

    if not fails:
        print("\nEvery loop shape reads correctly.")
    return 1 if fails else 0


def show(want, got):
    for i in range(max(len(want), len(got))):
        w = want[i] if i < len(want) else None
        g = got[i] if i < len(got) else None
        if w != g:
            print(f"        {i:>3}  expected {w}   got {g}")


if __name__ == "__main__":
    sys.exit(main())
