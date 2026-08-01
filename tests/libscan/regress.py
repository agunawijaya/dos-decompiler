#!/usr/bin/env python3
"""
regress.py -- Check that libscan.py recovers an entry point it was never told.

The claim libscan makes is falsifiable in one line: scanning a binary against
the library it was linked with recovers the same entry point the MZ header
records -- without ever reading the header. So the test builds a program with a
known toolchain, hides nothing and asserts nothing about the contents, and only
asks whether the recovered offset equals the header's.

It also checks the failure mode, which matters more than the success: scanning
the same binary against a *different* compiler's library must find nothing.
A tool that guesses when it does not know is worse than one that says nothing.

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


def run_case(name, exe, libs, expect_match):
    data = Path(exe).read_bytes()
    hdr = libscan.mz_header_size(data) or 0
    image = data[hdr:]
    mods = []
    for lib in libs:
        mods += libscan.read_library(lib)
    hits, ambiguous, entry, collisions = libscan.scan(image, mods)
    truth, _ = header_entry(exe)

    if not expect_match:
        ok = not hits and entry is None
        print(f"  {name:<46} {len(hits)} modules, "
              f"entry {'none' if entry is None else hex(entry['file_offset'])}"
              f"   {'PASS' if ok else 'FAIL'}")
        return ok

    ok = entry is not None and entry["file_offset"] == truth
    got = "not recovered" if entry is None else f"0x{entry['file_offset']:05X}"
    print(f"  {name:<46} {len(hits)} modules, entry {got} "
          f"vs header 0x{truth:05X}   {'PASS' if ok else 'FAIL'}")
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
        results = [run_case("Watcom binary vs the Watcom library",
                            exe, [clibs], True)]

        msc_lib = None
        if args.msc:
            for cand in ("SLIBC.LIB", "SLIBCR.LIB"):
                p = Path(args.msc) / "LIB" / cand
                if p.exists():
                    msc_lib = p
                    break
        if msc_lib:
            results.append(run_case("Watcom binary vs the Microsoft library",
                                    exe, [msc_lib], False))
        else:
            print("  (Microsoft C not configured; wrong-library check skipped)")

        print("\n" + ("PASS" if all(results) else "FAIL")
              + f"  {sum(results)}/{len(results)} checks")
        return 0 if all(results) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
