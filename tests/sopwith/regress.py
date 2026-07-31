#!/usr/bin/env python3
"""
regress.py -- Score the pipeline against Sopwith's known-correct answer.

Sopwith is the regression fixture for this skill because its original source
survives, so a rebuilt binary comes with a linker map that states exactly
where every function is. Any change to the tools can therefore be measured
rather than argued about.

What it checks, and the figures measured when the method was built:

    function entry points recovered   120 of 148 known   (81%)
    library detection                 precision 1.000, recall 0.905
    identification, inferred order    precision 0.875, recall 0.583
    identification, known order       precision 0.897, recall 0.583
    emulation matching (optional)     110 matches, precision 1.000

Identification figures are with C runtime functions excluded via libsig.py.
Without that exclusion they fall to 0.696 and 0.800 respectively -- see
knowledge/03-what-works.md.

A change that pushes precision below the floors below made things worse.

Prerequisites: run build/build.ps1 first to produce sopwith.exe and
sopwith.map, then tools/pipeline.ps1 over that binary.

Usage:
    python regress.py --build-dir WORK/build --decompiled WORK/decompiled/out \
                      --source SRCDIR
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent.parent / "tools"

# Floors, not targets. Set a little under the measured figures so that normal
# variation between Ghidra versions does not cause spurious failures, but a
# real regression does.
FLOOR_ENTRY_RECALL = 0.75
FLOOR_PRECISION_KNOWN_ORDER = 0.85
FLOOR_PRECISION_INFERRED = 0.83
FLOOR_RECALL_KNOWN_ORDER = 0.52
FLOOR_LIBRARY_PRECISION = 0.95    # a false positive discards real game code
FLOOR_LIBRARY_RECALL = 0.80
# Emulation decides equivalence rather than scoring resemblance, so anything
# below a perfect score means the harness is wrong, not merely weak.
FLOOR_EMU_PRECISION = 1.0
FLOOR_EMU_MATCHES = 100


def run(cmd):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(str(c) for c in cmd)}")
    return r.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", required=True,
                    help="directory containing sopwith.exe and sopwith.map")
    ap.add_argument("--decompiled", required=True,
                    help="pipeline output directory (functions.json)")
    ap.add_argument("--source", required=True, help="Sopwith source directory")
    ap.add_argument("--work", default=None, help="scratch directory")
    ap.add_argument("--variant-dir",
                    help="a second build of the same source with different code "
                         "generation (build.ps1 -Variant). Enables scoring "
                         "tools/emuverify.py, which needs two binaries.")
    args = ap.parse_args()

    build = Path(args.build_dir)
    work = Path(args.work) if args.work else build.parent / "regress"
    work.mkdir(parents=True, exist_ok=True)

    src_json = work / "source-inventory.json"
    truth_json = work / "truth.json"
    funcs = Path(args.decompiled) / "functions.json"

    if not funcs.exists():
        raise SystemExit(f"missing {funcs}; run tools/pipeline.ps1 first")

    print("building inventories")
    run([sys.executable, TOOLS / "srcinv.py", args.source, "--json", src_json])
    run([sys.executable, TOOLS / "mapparse.py", build / "sopwith.map",
         "--seg-bias", "0x1000", "--truth", truth_json])

    truth = json.loads(truth_json.read_text(encoding="utf-8"))
    src = json.loads(src_json.read_text(encoding="utf-8"))
    binr = json.loads(funcs.read_text(encoding="utf-8"))

    # swnetio.c is present in the release but absent from SW.MAK, so it is not
    # part of the binary and must not count against recall.
    src_names = {f["name"] for f in src["functions"]
                 if f.get("file", "").lower() != "swnetio.c"}
    entries = {f["entry"] for f in binr["functions"]}

    code_truth = {k: v for k, v in truth.items() if k in src_names}
    located = {k: v for k, v in code_truth.items() if v in entries}
    entry_recall = len(located) / max(1, len(code_truth))

    print(f"\nfunction entry points: {len(located)} of {len(code_truth)} "
          f"known  ({entry_recall:.0%})")

    # Library detection. Excluding C runtime functions is the single largest
    # win available, so it is scored in its own right and then used.
    sigdb = HERE.parent.parent / "signatures" / "watcom-16bit-small.json"
    lib_hits = work / "library-hits.json"
    lib_ev = None
    if sigdb.exists():
        out = run([sys.executable, TOOLS / "libsig.py", "apply",
                   build / "sopwith.exe", funcs, "--db", sigdb,
                   "--map", build / "sopwith.map", "--json", lib_hits])
        lib_ev = {}
        for line in out.splitlines():
            for key in ("precision", "recall"):
                if line.strip().startswith(key):
                    lib_ev[key] = float(line.split()[-1])
        print(f"\nlibrary detection: precision {lib_ev.get('precision')}  "
              f"recall {lib_ev.get('recall')}")
    else:
        print(f"\nlibrary signature database missing ({sigdb}); "
              "skipping library exclusion")

    lib_arg = ["--exclude-library", str(lib_hits)] if lib_hits.exists() else []

    results = {}
    for label, extra in (("inferred order", []),
                         ("known order", ["--module-order", HERE / "module-order.json"])):
        out = work / f"match-{label.split()[0]}.json"
        run([sys.executable, TOOLS / "match.py", src_json, funcs,
             "--exclude-file", "swnetio.c", "--align",
             "--truth", truth_json, "--json", out,
             "--report", work / f"report-{label.split()[0]}.md"] + lib_arg + extra)
        ev = json.loads(out.read_text(encoding="utf-8"))["evaluation"]
        results[label] = ev
        print(f"identification, {label:<15} precision {ev['precision']:.3f}  "
              f"recall {ev['recall']:.3f}  ({ev['correct']} correct, "
              f"{ev['wrong']} wrong of {ev['truth_size']})")

    # Emulation-based equivalence, when a second build is available.
    emu = None
    if args.variant_dir:
        vdir = Path(args.variant_dir)
        out = run([sys.executable, TOOLS / "emuverify.py",
                   build / "sopwith.exe", build / "sopwith.map",
                   vdir / "sopwith.exe", vdir / "sopwith.map", "--quiet"])
        emu = {}
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("unique matches"):
                # "unique matches : 110 (9 from non-returning functions)"
                emu["matches"] = int(s.split(":")[1].split("(")[0])
            elif s.startswith("precision"):
                emu["precision"] = float(s.split(":")[1])
        print(f"\nemulation matching: {emu.get('matches')} matches, "
              f"precision {emu.get('precision')}")

    failures = []
    if emu:
        if emu.get("precision", 0) < FLOOR_EMU_PRECISION:
            failures.append(f"emulation precision {emu.get('precision')} below "
                            f"{FLOOR_EMU_PRECISION}; behavioural equivalence "
                            f"should never produce a wrong match")
        if emu.get("matches", 0) < FLOOR_EMU_MATCHES:
            failures.append(f"emulation found only {emu.get('matches')} matches, "
                            f"below floor {FLOOR_EMU_MATCHES}")
    if entry_recall < FLOOR_ENTRY_RECALL:
        failures.append(f"entry-point recall {entry_recall:.2f} below floor "
                        f"{FLOOR_ENTRY_RECALL}")
    if results["known order"]["precision"] < FLOOR_PRECISION_KNOWN_ORDER:
        failures.append(f"precision with known order "
                        f"{results['known order']['precision']} below floor "
                        f"{FLOOR_PRECISION_KNOWN_ORDER}")
    if results["known order"]["recall"] < FLOOR_RECALL_KNOWN_ORDER:
        failures.append(f"recall with known order "
                        f"{results['known order']['recall']} below floor "
                        f"{FLOOR_RECALL_KNOWN_ORDER}")
    if results["inferred order"]["precision"] < FLOOR_PRECISION_INFERRED:
        failures.append(f"precision with inferred order "
                        f"{results['inferred order']['precision']} below floor "
                        f"{FLOOR_PRECISION_INFERRED}")
    if lib_ev:
        if lib_ev.get("precision", 0) < FLOOR_LIBRARY_PRECISION:
            failures.append(f"library detection precision "
                            f"{lib_ev.get('precision')} below floor "
                            f"{FLOOR_LIBRARY_PRECISION} -- a false positive "
                            f"deletes real game code from consideration")
        if lib_ev.get("recall", 0) < FLOOR_LIBRARY_RECALL:
            failures.append(f"library detection recall {lib_ev.get('recall')} "
                            f"below floor {FLOOR_LIBRARY_RECALL}")

    print()
    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1
    print("PASS  all metrics at or above their floors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
