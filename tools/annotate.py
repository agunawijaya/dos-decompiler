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


SEG = re.compile(r"^(cs|ds|es|ss):", re.I)


def _key(k):
    """A global's key, optionally carrying the segment it is read through.

    Most games keep one data segment and a bare `0x0116` is unambiguous.
    Zaxxon does not: it reads its tables as `[cs:0x04E8]` out of the image and
    its variables as `[0x0055]` out of a segment that starts past the end of
    the file. Those are different addresses that happen to share a number, so
    the key may be written `cs:0x04E8` to bind only to that prefix.
    """
    m = SEG.match(k)
    if m:
        return (m.group(1).lower(), int(k[m.end():], 16))
    return (None, int(k, 16))


def load_symbols(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    routines = {int(k, 16): tuple(v) for k, v in raw["routines"].items()}
    globals_ = {_key(k): tuple(v) for k, v in raw["globals"].items()}

    # A name used for both a routine and a global is silently fatal: the global
    # becomes a `%define`, the routine's label is rewritten to the same word,
    # and NASM is handed `0x4230:` where a label should be. The error it gives
    # points at the label and says nothing about the collision, so catch it
    # here where the cause is obvious.
    clash = ({n for n, _ in routines.values()} & {n for n, _ in globals_.values()})
    if clash:
        raise SystemExit(
            "a name is used for both a routine and a global: "
            + ", ".join(sorted(clash))
            + "\n  rename one of them in the symbol file; a %define would "
              "rewrite the label.")
    for kind, table in (("routine", routines), ("global", globals_)):
        seen = {}
        for addr, (name, _) in sorted(table.items(), key=lambda kv: repr(kv[0])):
            # Two keys may share a name when they are the same address reached
            # through different prefixes. Hard Hat Mack sets DS = CS, so the
            # interrupt handler writes `[cs:0x0781]` and everything else writes
            # `[0x0781]`, and those are one variable. Zaxxon's `cs:` and bare
            # addresses are not, which is why the check is on the number and
            # not on the prefix.
            here = addr[1] if isinstance(addr, tuple) else addr
            there = seen.get(name)
            if there is not None and there != here:
                raise SystemExit(
                    f"two {kind}s share the name {name!r} at different "
                    f"addresses: 0x{there:05X} and 0x{here:05X}")
            seen[name] = here
    return routines, globals_


def rename(text, routines, globals_):
    """Apply the names, and count what actually landed.

    Two substitutions, deliberately narrow. `L_xxxxx` is unambiguous -- comrec
    generates no other label of that shape. Globals are replaced only inside
    square brackets, because the same number appearing as an immediate is an
    immediate: `mov ax, 0x116` is the constant 278, not the health variable, and
    rewriting it would be a lie that still assembles.

    A bracketed reference carrying a segment prefix matches only a key written
    with the same prefix. `[cs:0x04E8]` and `[0x04E8]` are two addresses in
    Zaxxon, which loads its data segment past the end of its own image, so
    letting one name cover both would be that same lie in a different place.
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
        seg = (m.group(1) or "").rstrip(":").lower() or None
        key = (seg, int(m.group(2), 16))
        if key in globals_:
            hits["globals"] += 1
            return (f"[{m.group(1) or ''}{globals_[key][0]}"
                    f"{m.group(3) or ''}]")
        return m.group(0)

    text = re.sub(r"\[([a-z]{2}:)?(0x[0-9a-f]+)((?:\s*[-+]\s*\w+)?)\]",
                  mem, text)

    def indexed(m):
        seg = (m.group(1) or "").rstrip(":").lower() or None
        key = (seg, int(m.group(3), 16))
        if key in globals_:
            hits["globals"] += 1
            return (f"[{m.group(1) or ''}{m.group(2)} + "
                    f"{globals_[key][0]}]")
        return m.group(0)

    # `[bx + 0x052d]` is a table read, and in hand-written assembly it is the
    # commonest form there is -- Hard Hat Mack indexes almost every table this
    # way. BP and SP are excluded because a displacement off those is a stack
    # frame, and `[bp + 0x08]` is an argument, not whatever global happens to
    # live at 8.
    text = re.sub(r"\[([a-z]{2}:)?(?!bp|sp)([a-z]{2}(?:\s*\+\s*[a-z]{2})?)"
                  r"\s*\+\s*(0x[0-9a-f]+)\]", indexed, text)
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
    for (seg, addr), (name, why) in sorted(globals_.items(),
                                           key=lambda kv: (kv[0][0] or "",
                                                           kv[0][1])):
        pad = " " * max(1, 22 - len(name))
        note = f" ({seg}-relative)" if seg else ""
        out.append(f"%define {name}{pad}0x{addr:04x}"
                   + (f"    ; {why}{note}" if why or note else ""))
    out.append("")
    return "\n".join(out)


def routine_comments(text, routines):
    """Put each routine's evidence directly above its label.

    A name whose address has no label still belongs in the listing. comrec
    labels what something branches to, so an address nothing reaches comes out
    as `db` bytes -- Karateka's five-byte `push bp / mov bp, sp / pop bp / ret`
    at 0x02A0A is real, and is documented precisely because nothing calls it.
    Renaming had nowhere to put that, so the name existed only in the symbol
    file. It goes above the `db` line instead, found by the offset comment
    comrec writes on every one.
    """
    lines = text.split("\n")
    byname = {name: (addr, why) for addr, (name, why) in routines.items()}
    labelled = {int(m.group(1), 16)
                for m in re.finditer(r"^L_([0-9A-Fa-f]{5}):", text, re.M)}
    byname.update({name: (addr, why) for addr, (name, why) in routines.items()})
    orphans = {addr: (name, why) for addr, (name, why) in routines.items()
               if addr not in labelled}
    out = []
    for line in lines:
        m = re.match(r"^([A-Za-z_]\w*):", line)
        if m and m.group(1) in byname:
            addr, why = byname[m.group(1)]
            out.append("")
            out.append(f"; ---- image 0x{addr:05X} " + "-" * 40)
            if why:
                out.append(f"; {why}")
        else:
            m = re.search(r";\s*0x([0-9A-Fa-f]{5})\s*$", line)
            if m and int(m.group(1), 16) in orphans:
                name, why = orphans.pop(int(m.group(1), 16))
                out.append("")
                out.append(f"; ---- image 0x{int(m.group(1), 16):05X} "
                           + "-" * 40)
                out.append(f"; {name} -- no label: nothing branches here, so "
                           f"comrec emits the bytes rather than a routine")
                if why:
                    out.append(f"; {why}")
        out.append(line)
    return "\n".join(out), orphans


def audit(text, routines, globals_, unplaced=None):
    """What the symbol file misses, and what it names that is not there.

    A name that never substitutes cannot fail loudly. Hard Hat Mack carried a
    `scanline_table` for a whole session recorded in file offsets while every
    other key was an address, and nothing noticed, because the only symptom of
    a key in the wrong coordinate is silence. So say both numbers out loud.
    """
    labels = {int(m.group(1), 16)
              for m in re.finditer(r"^L_([0-9A-Fa-f]{5}):", text, re.M)}
    ghost = sorted(a for a in routines if a not in labels)

    refs = set()
    for m in re.finditer(r"\[([a-z]{2}:)?(?:[a-z]{2}\s*\+\s*)?(0x[0-9a-f]+)\]",
                         text):
        seg = (m.group(1) or "").rstrip(":").lower() or None
        refs.add((seg, int(m.group(2), 16)))
    unnamed = sorted(refs - set(globals_),
                     key=lambda k: ((k[0] or ""), k[1]))

    named = len(refs) - len(unnamed)
    print(f"  covers {named} of {len(refs)} bracketed constants")
    print("    (some of those are displacements into a struct rather than "
          "addresses; the listing cannot tell you which)")
    if ghost:
        placed = [a for a in ghost if a not in (unplaced or {})]
        if placed:
            print(f"  {len(placed)} routine names have no label and were "
                  "written in as comments: "
                  + ", ".join(f"0x{a:05X}" for a in placed[:8])
                  + ("..." if len(placed) > 8 else ""))
        left = [a for a in ghost if a in (unplaced or {})]
        if left:
            print(f"  {len(left)} routine names landed nowhere at all: "
                  + ", ".join(f"0x{a:05X}" for a in left[:8]))
            print("    (no label and no line carrying that offset -- most "
                  "likely a key in the wrong coordinate system)")
    if unnamed:
        show = ", ".join((f"{s}:" if s else "") + f"0x{a:04X}"
                         for s, a in unnamed[:10])
        print(f"  {len(unnamed)} unnamed: {show}"
              + ("..." if len(unnamed) > 10 else ""))


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
    text, orphans = routine_comments(text, routines)
    out = Path(args.out)
    out.write_text(preamble(routines, globals_) + text, encoding="latin-1")

    print(f"{len(routines)} routine names, {len(globals_)} globals")
    print(f"  applied: {hits['routines']} label references, "
          f"{hits['globals']} memory references")
    print(f"  wrote {out}")
    audit(src.read_text(encoding="latin-1"), routines, globals_,
          unplaced=orphans)

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
