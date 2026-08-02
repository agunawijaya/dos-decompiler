#!/usr/bin/env python3
"""docaudit.py -- read the numbers in the documents back against the symbol file.

Prose drifts. A count written into a paragraph is right on the day and wrong a
week later, and nothing complains. In this project that produced, in order:

    "120 of 120 routines"          -- true of prologues, 56 call targets short
    "99.5% of the data segment"    -- from a script, not from the spans, which
                                      covered 86.7%
    "38% / 83% / 58% of the blits" -- never checked against anything
    "252 routines and 604 globals" -- 273 and 605 by the end of the same session

Every one of those was written honestly and went stale quietly, and every one
was found by somebody asking "is it finished?" rather than by a tool. This is
the tool.

It does not know what a number *should* be. It finds the shapes a count takes,
prints each next to the line it came from, and prints what the symbol file says
now, so the comparison is one glance instead of a search.

    python docaudit.py ../retro-ports/karateka
    python docaudit.py ../retro-ports --symbols karateka/symbols.json
"""

import argparse
import json
import re
from pathlib import Path

PATTERNS = [
    (r"\b(\d{2,5})\s+routines?\b", "routines"),
    (r"\b(\d{2,5})\s+globals?\b", "globals"),
    (r"\b(\d{2,5})\s+variables?\b", "variables"),
    (r"\b(\d{2,5})\s+call targets?\b", "call targets"),
    (r"\b(\d{2,5})\s+(?:named\s+)?addresses\b", "addresses"),
    (r"\ball (\d{2,5})\b", "all-N claim"),
    (r"(\d{1,3}(?:\.\d)?)\s*%", "percentage"),
]

SKIP_DIRS = {".git", "node_modules", "recovered", "original", "reference"}


def truth(path):
    """What the symbol files under `path` say right now."""
    out = {}
    for s in sorted(Path(path).rglob("symbols.json")):
        if any(p in SKIP_DIRS for p in s.parts):
            continue
        d = json.loads(s.read_text(encoding="utf-8"))
        spans = {k: v for k, v in d.get("_data_spans", {}).items()
                 if k.startswith("0x")}
        total = 0
        for v in spans.values():
            total += next((x for x in v if isinstance(x, int)), 0)
        out[str(s.parent.name)] = {
            "routines": len(d.get("routines", {})),
            "globals": len(d.get("globals", {})),
            "spans": len(spans),
            "span bytes": total,
        }
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="a game folder, or a folder of them")
    ap.add_argument("--kind", action="append",
                    help="only report this kind (routines, globals, "
                         "percentage, ...); repeatable")
    args = ap.parse_args()
    root = Path(args.path)
    if not root.exists():
        raise SystemExit(f"{root} is not there")

    facts = truth(root)
    if facts:
        print("what the symbol files say now:")
        for name, v in facts.items():
            print(f"  {name:<16} " + "  ".join(f"{k} {n:,}"
                                               for k, n in v.items()))
        print()

    wanted = set(args.kind) if args.kind else None
    hits = 0
    for md in sorted(root.rglob("*.md")):
        if any(p in SKIP_DIRS for p in md.parts):
            continue
        rows, seen = [], set()
        for n, line in enumerate(md.read_text(encoding="utf-8",
                                              errors="replace").splitlines(), 1):
            s = line.strip()
            if s.startswith(("|---", "```", "    ")):
                continue
            for pat, kind in PATTERNS:
                if wanted and kind not in wanted:
                    continue
                for m in re.finditer(pat, line):
                    if (n, m.group(0)) in seen:
                        continue
                    seen.add((n, m.group(0)))
                    rows.append((n, kind, m.group(0).strip(), s[:92]))
        if rows:
            hits += len(rows)
            print(f"--- {md.relative_to(root)}")
            for n, kind, got, line in rows:
                print(f"  {n:>4}  {kind:<13} {got:<10} {line}")
            print()
    print(f"{hits} numbers to check by eye. This tool cannot tell you which "
          f"are stale -- only where they are.")


if __name__ == "__main__":
    main()
