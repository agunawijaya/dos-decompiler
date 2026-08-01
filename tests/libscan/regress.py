#!/usr/bin/env python3
"""
regress.py -- Check that libscan.py recovers an entry point it was never told.

The claim libscan makes is falsifiable in one line: scanning a binary against
the library it was linked with recovers the same entry point the MZ header
records -- without ever reading the header. So the test builds a program with a
known toolchain, hides nothing and asserts nothing about the contents, and only
asks whether the recovered offset equals the header's.

It also checks the failure modes, which matter more than the success:

* Scanning against a *different* compiler's library must find nothing. A tool
  that guesses when it does not know is worse than one that says nothing.
* When the startup code ships **outside** the archive, the scan must say so
  rather than report "no entry point" as if that were a fact about the binary.
  Microsoft C 1.04 is the real case -- its startup is a loose `C.OBJ` named on
  the link line ahead of `MC.LIB`, and none of the archive's 75 modules
  declares a start address. That layout is reproduced here with Open Watcom by
  extracting `cstart` from `clibs.lib`, so the case is tested rather than
  merely described.

Needs Open Watcom (free): set WATCOM, or pass --watcom. Microsoft C is used
for a second toolchain if MSC_HOME points at it, and skipped if not.

    python regress.py
    python regress.py --watcom C:\\Applications\\watcom-snap
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import libscan                                          # noqa: E402

PROGRAM = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buf[64];
    long n = strtol(argc > 1 ? argv[1] : "17", (char **)0, 10);
    sprintf(buf, "%ld", n * 3);
    puts(buf);
    return (int)strlen(buf);
}
"""


def header_entry(path):
    """(cs:ip as a load-image offset) straight out of the MZ header."""
    d = Path(path).read_bytes()
    hdr = struct.unpack_from("<H", d, 8)[0] * 16
    ip = struct.unpack_from("<H", d, 20)[0]
    cs = struct.unpack_from("<H", d, 22)[0]
    return (cs << 4) + ip, hdr


def build_watcom(watcom, work):
    # Windows resolves the executable from the parent process's PATH, not from
    # the env passed to subprocess, so every tool is invoked by full path.
    bins = [Path(watcom) / "binnt64", Path(watcom) / "binnt"]

    def tool(name):
        for b in bins:
            p = b / f"{name}.exe"
            if p.exists():
                return str(p)
        raise RuntimeError(f"{name}.exe not found under {watcom}")

    env = dict(os.environ, WATCOM=str(watcom),
               PATH=os.pathsep.join([str(b) for b in bins if b.exists()]
                                    + [os.environ["PATH"]]),
               INCLUDE=str(Path(watcom) / "h"))
    (work / "probe.c").write_text(PROGRAM, encoding="ascii")
    r = subprocess.run([tool("wcc"), "-ms", "-0", "-zq", "-q", "probe.c"],
                       cwd=work, env=env, capture_output=True, text=True)
    if r.returncode or not (work / "probe.obj").exists():
        raise RuntimeError(f"wcc failed: {r.stdout}{r.stderr}")
    r = subprocess.run([tool("wlink"), "system", "dos", "option", "quiet",
                        "name", "probe.exe", "file", "probe.obj"],
                       cwd=work, env=env, capture_output=True, text=True)
    if r.returncode or not (work / "probe.exe").exists():
        raise RuntimeError(f"wlink failed: {r.stdout}{r.stderr}")
    return work / "probe.exe", Path(watcom) / "lib286" / "dos" / "clibs.lib"


def split_startup(watcom, work):
    """A library with its startup module removed, plus that module loose.

    This is Microsoft C 1.04's layout, built out of Open Watcom so that anyone
    can run the test: the archive alone must not silently answer "no entry
    point", and the archive plus the loose object must answer correctly.
    """
    wlib = None
    for b in ("binnt64", "binnt"):
        p = Path(watcom) / b / "wlib.exe"
        if p.exists():
            wlib = str(p)
            break
    if wlib is None:
        return None, None
    split = work / "split"
    split.mkdir(exist_ok=True)
    lib = split / "clibs.lib"
    shutil.copyfile(Path(watcom) / "lib286" / "dos" / "clibs.lib", lib)
    for op in ("*cstart", "-cstart"):        # extract, then delete
        r = subprocess.run([wlib, "-q", "clibs.lib", op],
                           cwd=split, capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(f"wlib {op} failed: {r.stdout}{r.stderr}")
    obj = split / "cstart.obj"
    if not obj.exists():
        raise RuntimeError("wlib did not produce cstart.obj")
    return lib, obj


def run_case(name, exe, libs, expect, expect_startup=None):
    """expect: 'entry' | 'nothing' | 'no-startup'."""
    data = Path(exe).read_bytes()
    hdr = libscan.mz_header_size(data) or 0
    image = data[hdr:]
    mods = []
    for lib in libs:
        mods += libscan.read_source(lib)
    hits, ambiguous, entry, collisions = libscan.scan(image, mods)
    truth, _ = header_entry(exe)
    declared = [m.name for m in mods if m.start is not None]

    if expect == "nothing":
        ok = not hits and entry is None
        detail = (f"{len(hits)} modules, "
                  f"entry {'none' if entry is None else hex(entry['file_offset'])}")
    elif expect == "no-startup":
        # The point is the diagnosis, not just the absence: the runtime was
        # found, and nothing loaded declares a start address. Reporting that as
        # "no entry point" would be a claim about the binary rather than about
        # what the caller passed in.
        ok = bool(hits) and entry is None and not declared
        detail = (f"{len(hits)} modules, {len(declared)} declaring a start "
                  f"address, entry {'none' if entry is None else 'RECOVERED'}")
    else:
        ok = entry is not None and entry["file_offset"] == truth
        got = "not recovered" if entry is None else f"0x{entry['file_offset']:05X}"
        detail = f"{len(hits)} modules, entry {got} vs header 0x{truth:05X}"

    if expect_startup is not None:
        ok = ok and declared == expect_startup
    print(f"  {name:<52} {detail}   {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watcom", default=os.environ.get("WATCOM"))
    ap.add_argument("--msc", default=os.environ.get("MSC_HOME"))
    args = ap.parse_args()

    if not args.watcom or not Path(args.watcom).exists():
        print("libscan regress: Open Watcom not found "
              "(set WATCOM or pass --watcom); nothing to test")
        return 77

    work = Path(tempfile.mkdtemp(prefix="libscan-"))
    try:
        exe, clibs = build_watcom(args.watcom, work)
        print(f"built {exe.name} with Open Watcom, small model")
        results = [run_case("archive holding its own startup module",
                            exe, [clibs], "entry", ["cstart"])]

        stripped, loose = split_startup(args.watcom, work)
        if stripped:
            results.append(run_case("archive with the startup module removed",
                                    exe, [stripped], "no-startup", []))
            results.append(run_case("...plus the startup object, loose",
                                    exe, [stripped, loose], "entry", ["cstart"]))
            results.append(run_case("...or just the directory holding both",
                                    exe, [stripped.parent], "entry", ["cstart"]))
        else:
            print("  (wlib not found; the loose-startup checks were skipped)")

        msc_lib = None
        if args.msc:
            for cand in ("SLIBC.LIB", "SLIBCR.LIB"):
                p = Path(args.msc) / "LIB" / cand
                if p.exists():
                    msc_lib = p
                    break
        if msc_lib:
            results.append(run_case("the wrong compiler's library entirely",
                                    exe, [msc_lib], "nothing"))
        else:
            print("  (Microsoft C not configured; wrong-library check skipped)")

        print("\n" + ("PASS" if all(results) else "FAIL")
              + f"  {sum(results)}/{len(results)} checks")
        return 0 if all(results) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
