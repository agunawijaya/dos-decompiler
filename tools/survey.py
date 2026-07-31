#!/usr/bin/env python3
"""
survey.py -- Take stock of a whole game directory before touching any of it.

`triage.py` answers "is this executable in scope". That is the wrong first
question when what you were handed is a folder. A DOS release is rarely one
file: there is a game, usually a setup or install program, sometimes drivers,
often overlays loaded at run time, and data spread across subdirectories. Which
of those is the game is not always obvious, and picking the wrong one wastes a
day.

So: walk the tree, classify everything, triage every executable, and say which
one looks like the game and why.

What it looks for
-----------------
  * every MZ executable and .COM file, each with its own triage verdict
  * overlay files -- .OVL, .OVR, and MZ files whose header says they are
    overlay modules rather than programs
  * batch files, which frequently name the real entry point
  * data files, grouped, with the ones large enough to matter called out
  * the interpreted-engine pattern, judged across the whole tree rather than
    one directory

Usage:
    python survey.py path/to/game/folder
    python survey.py path/to/game/folder --json survey.json
"""

import argparse
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage  # noqa: E402  -- same directory, deliberate

OVERLAY_SUFFIXES = {".ovl", ".ovr", ".ov1", ".ov2", ".dat"}
DOC_SUFFIXES = {".txt", ".doc", ".me", ".1st", ".nfo", ".diz", ".hlp"}
ARCHIVE_SUFFIXES = {".zip", ".arj", ".lzh", ".arc", ".rar", ".7z", ".gz"}
BATCH_SUFFIXES = {".bat", ".cmd"}

# Data files this size or larger are worth naming individually: below it they
# are usually configuration or saved games rather than game content.
NOTABLE_DATA_BYTES = 16 * 1024


def is_mz(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) in (b"MZ", b"ZM")
    except OSError:
        return False


def overlay_number(path):
    try:
        with open(path, "rb") as f:
            head = f.read(32)
        if len(head) < 28 or head[:2] not in (b"MZ", b"ZM"):
            return None
        return struct.unpack_from("<H", head, 26)[0]
    except OSError:
        return None


def classify(path, root):
    suffix = path.suffix.lower()
    rel = str(path.relative_to(root))
    size = path.stat().st_size
    entry = {"path": rel, "size": size, "suffix": suffix}

    if is_mz(path):
        ov = overlay_number(path)
        entry["kind"] = "overlay-module" if ov else "executable"
        entry["overlay_number"] = ov
    elif suffix == ".com":
        entry["kind"] = "com"
    elif suffix in BATCH_SUFFIXES:
        entry["kind"] = "batch"
    elif suffix in OVERLAY_SUFFIXES:
        entry["kind"] = "overlay-or-data"
    elif suffix in DOC_SUFFIXES:
        entry["kind"] = "doc"
    elif suffix in ARCHIVE_SUFFIXES:
        entry["kind"] = "archive"
    else:
        entry["kind"] = "data"
    return entry


# A bare word on a line in a batch file is usually a program to run, but the
# shell's own commands look identical. Without this filter a startup script
# reports CLS and REM as candidate entry points.
DOS_BUILTINS = {
    "CLS", "REM", "ECHO", "PAUSE", "EXIT", "CD", "CHDIR", "MD", "MKDIR", "RD",
    "RMDIR", "DEL", "ERASE", "COPY", "XCOPY", "MOVE", "REN", "RENAME", "DIR",
    "TYPE", "SET", "PATH", "PROMPT", "GOTO", "IF", "FOR", "CALL", "SHIFT",
    "VER", "VOL", "DATE", "TIME", "CHOICE", "MODE", "MEM", "TREE", "ATTRIB",
    "FIND", "SORT", "MORE", "FC", "COMP", "LABEL", "SUBST", "ASSIGN", "BREAK",
    "VERIFY", "CTTY", "LOADHIGH", "LH", "DOSKEY", "KEYB", "GRAPHICS", "PRINT",
    "START", "@ECHO", "NOT", "ERRORLEVEL", "EXIST",
}


def batch_targets(path):
    """Executable names a batch file invokes -- often the real entry point."""
    try:
        text = path.read_text(encoding="latin-1", errors="replace")
    except OSError:
        return []
    names = set()
    for m in re.finditer(r"(?im)^\s*(?:@?call\s+)?([A-Za-z0-9_~\-]{1,8})"
                         r"(?:\.(exe|com))?\s*$", text):
        names.add(m.group(1).upper())
    for m in re.finditer(r"(?i)\b([A-Za-z0-9_~\-]{1,8})\.(exe|com)\b", text):
        names.add(m.group(1).upper())
    return sorted(names - DOS_BUILTINS)


def pick_main(executables, batch_named, root_name):
    """Which executable is the game?

    Three signals, in order of trust: a batch file naming it, a name matching
    the directory, and size. Size alone is a weak signal -- an installer can be
    larger than the game -- so it decides only when nothing else does.
    """
    if not executables:
        return None, "no executables found"
    named = [e for e in executables
             if Path(e["path"]).stem.upper() in batch_named]
    if len(named) == 1:
        return named[0], "named by a batch file"
    matching = [e for e in executables
                if Path(e["path"]).stem.upper() == root_name.upper()]
    if len(matching) == 1:
        return matching[0], "name matches the directory"
    if named:
        biggest = max(named, key=lambda e: e["size"])
        return biggest, "largest of those a batch file names"
    biggest = max(executables, key=lambda e: e["size"])
    return biggest, "largest executable, no stronger signal available"


def survey(root):
    given = str(root)
    root = Path(root)
    if root.is_file():
        root = root.parent
    if not root.is_dir():
        raise SystemExit(f"{root}: not a directory")

    files, dirs = [], set()
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            dirs.add(str(p.relative_to(root)))
            continue
        try:
            files.append(classify(p, root))
        except OSError:
            continue

    by_kind = defaultdict(list)
    for f in files:
        by_kind[f["kind"]].append(f)

    batch_named = set()
    for b in by_kind["batch"]:
        batch_named.update(batch_targets(root / b["path"]))

    # Triage every executable, not just the one you were pointed at.
    for e in by_kind["executable"] + by_kind["com"]:
        try:
            r = triage.analyse(str(root / e["path"]))
            e["verdict"] = ("in scope" if r["verdict"]["in_scope"]
                            else "out of scope")
            e["confidence"] = r["verdict"]["confidence"]
            e["blockers"] = [t for lvl, t, _ in r["findings"] if lvl == "blocker"]
            e["model"] = r.get("memory_model_guess")
            e["prologue_density"] = r.get("prologue_density")
        except SystemExit:
            e["verdict"] = "unreadable"
            e["blockers"] = []

    main, why = pick_main(by_kind["executable"], batch_named, root.name)

    notable = sorted(
        (f for f in by_kind["data"] + by_kind["overlay-or-data"]
         if f["size"] >= NOTABLE_DATA_BYTES),
        key=lambda f: -f["size"])

    # The interpreter pattern, judged across the whole tree: a modest executable
    # sitting beside data that dwarfs it.
    #
    # Deliberately hedged. A single large graphics or sound file produces this
    # ratio in a perfectly ordinary game -- Creative Contraptions trips a 6:1
    # ratio on one art file and is not an interpreter. What distinguishes a real
    # engine is *many* large resources, so the count matters as much as the
    # total, and even then this is a prompt to check rather than a verdict.
    engine_hint = None
    if main and len(notable) >= 2:
        data_total = sum(f["size"] for f in notable)
        ratio = data_total / max(1, main["size"])
        if ratio > 4:
            engine_hint = (f"{len(notable)} data files totalling "
                           f"{data_total:,} bytes against a "
                           f"{main['size']:,} byte executable "
                           f"({ratio:.0f}x)")

    return {
        "root": str(root),
        "given": given,
        "subdirectories": sorted(dirs),
        "counts": {k: len(v) for k, v in sorted(by_kind.items())},
        "executables": by_kind["executable"],
        "com_files": by_kind["com"],
        "overlay_modules": by_kind["overlay-module"],
        "batch_files": by_kind["batch"],
        "batch_named": sorted(batch_named),
        "notable_data": notable[:20],
        "main": main,
        "main_reason": why,
        "engine_hint": engine_hint,
        "total_files": len(files),
    }


def report(s):
    out = []
    A = out.append
    A(f"Directory : {s['root']}")
    A(f"Files     : {s['total_files']} in "
      f"{len(s['subdirectories']) + 1} director{'y' if not s['subdirectories'] else 'ies'}")
    if s["subdirectories"]:
        A(f"Subfolders: {', '.join(s['subdirectories'][:10])}"
          + ("..." if len(s['subdirectories']) > 10 else ""))
    A("")

    A("-- Executables ----------------------------------------------------")
    every = s["executables"] + s["com_files"]
    if not every:
        A("  none found")
    for e in sorted(every, key=lambda x: -x["size"]):
        star = " <== likely the game" if s["main"] and e["path"] == s["main"]["path"] else ""
        A(f"  {e['path']:<28} {e['size']:>9,}  {e.get('verdict', '?')}{star}")
        if e.get("blockers"):
            for b in e["blockers"]:
                A(f"      blocker: {b}")
        elif e.get("model"):
            A(f"      {e['model']} model, {e.get('prologue_density', 0)} prologues/KB")
    if s["main"]:
        A("")
        A(f"  Chosen: {s['main']['path']} — {s['main_reason']}")
    A("")

    if s["overlay_modules"]:
        A("-- Overlay modules ------------------------------------------------")
        for e in s["overlay_modules"]:
            A(f"  {e['path']:<28} {e['size']:>9,}  overlay #{e['overlay_number']}")
        A("  These are loaded on demand into a shared region. Nothing in this")
        A("  toolkit handles overlaid programs; see knowledge/00-scope.md.")
        A("")

    if s["batch_files"]:
        A("-- Batch files ----------------------------------------------------")
        for b in s["batch_files"]:
            A(f"  {b['path']}")
        if s["batch_named"]:
            A(f"  They invoke: {', '.join(s['batch_named'][:12])}")
        A("")

    if s["notable_data"]:
        A("-- Data files worth knowing about ---------------------------------")
        for f in s["notable_data"][:12]:
            A(f"  {f['path']:<28} {f['size']:>9,}")
        A("")

    A("-- Read this before starting --------------------------------------")
    if s["engine_hint"]:
        A("  Worth checking: could this executable be an interpreter?")
        for line in triage._wrap(
                s["engine_hint"] + ". That ratio is what an engine looks like -- "
                "the executable is a virtual machine and the game lives in the "
                "resources -- but plain graphics or sound data produces it too. "
                "The discriminator is cheap: look for the game's own text. If "
                "menu and dialogue strings are in the executable it is a normal "
                "program; if they are only in the data files, decompiling the "
                "executable will succeed and tell you nothing you wanted.", 66):
            A(f"    {line}")
    elif s["main"] and s["main"].get("verdict") == "out of scope":
        A("  The main executable is out of scope. See its blockers above.")
    elif s["main"]:
        # Quote the path the way the caller would type it, not relative to the
        # surveyed folder -- otherwise the suggested command does not run.
        usable = str(Path(s["given"]) / s["main"]["path"])
        A(f"  Start with: python tools/triage.py \"{usable}\"")
        A("  then tools/pipeline.ps1 on the same file.")
    if len(s["executables"]) > 1:
        A("")
        A("  More than one executable is present. Setup and install programs")
        A("  decompile just as willingly as the game and are not the game.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--json", help="write the full survey here")
    args = ap.parse_args()

    s = survey(args.folder)
    print(report(s))
    if args.json:
        Path(args.json).write_text(json.dumps(s, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
