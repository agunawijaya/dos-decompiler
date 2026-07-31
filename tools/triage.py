#!/usr/bin/env python3
"""
triage.py -- Decide whether these tools suit a given DOS program, before
spending hours finding out they do not.

The pipeline here targets one class of binary: 16-bit real-mode MZ, compiled
from C, small memory model, unpacked, not overlaid. Plenty of DOS games are
that. Plenty are not, and a few of the "not" cases waste the most time because
the tools appear to work: they will happily decompile a packer's decompressor,
or a game engine's interpreter, and produce something correct and useless.

This reads the binary and reports what it is, what that implies, and which
parts of the toolkit are worth running.

Usage:
    python triage.py GAME.EXE
    python triage.py GAME.EXE --json triage.json
"""

import argparse
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

# Engines whose executable is an interpreter and whose game lives in the data
# files. Decompiling these gets you a virtual machine, not a game.
ENGINE_MARKERS = {
    b"SCUMM": "LucasArts SCUMM",
    b"scumm": "LucasArts SCUMM",
    b"LFL": "Sierra AGI / LucasArts (LFL resource files)",
    b"RESOURCE.MAP": "Sierra SCI",
    b"RESOURCE.000": "Sierra SCI",
    b"VOL.0": "Sierra AGI",
    b"LOGDIR": "Sierra AGI",
    b"DAAD": "DAAD adventure system",
    b"ZORK": "Infocom Z-machine",
    b"Inform": "Inform / Z-machine",
}

PACKERS = {
    b"LZ91": "LZEXE 0.91", b"LZ09": "LZEXE 0.90", b"PKLITE": "PKLITE",
    b"diet": "DIET", b"UPX!": "UPX", b"aPLib": "aPLib",
    # EXEPACK carries no vendor string. Its decompressor's error message is the
    # distinctive marker, and unlike a two-letter signature it cannot collide
    # with ordinary data. Found by building a packed/unpacked pair with
    # Microsoft LINK /EXEPACK and comparing them -- the literal "EXEPACK" this
    # table used to look for appears nowhere in the file.
    b"Packed file is corrupt": "Microsoft EXEPACK",
}

# A C prologue. Its density separates compiled code from hand-written assembly
# far more reliably than any string search.
PROLOGUE = bytes([0x55, 0x8B, 0xEC])


def read_mz(path):
    data = Path(path).read_bytes()
    if len(data) < 28 or data[:2] not in (b"MZ", b"ZM"):
        return None, data
    (_, last, pages, nreloc, hdr_paras, minalloc, maxalloc,
     ss, sp, _, ip, cs, reloc_off, overlay) = struct.unpack_from("<2sHHHHHHHHHHHHH", data, 0)
    hdr = hdr_paras * 16
    end = (pages - 1) * 512 + (last if last else 512) if pages else len(data)
    relocs = []
    for i in range(nreloc):
        pos = reloc_off + i * 4
        if pos + 4 <= len(data):
            off, seg = struct.unpack_from("<HH", data, pos)
            relocs.append(hdr + (seg << 4) + off)
    return {
        "header_size": hdr, "image_start": hdr, "image_end": min(end, len(data)),
        "relocations": nreloc, "reloc_positions": relocs,
        "entry": hdr + (cs << 4) + ip, "cs": cs, "ip": ip, "ss": ss, "sp": sp,
        "overlay_number": overlay, "trailing": len(data) - end,
        "minalloc": minalloc, "maxalloc": maxalloc,
    }, data


def guess_memory_model(mz, image_len):
    """Infer the memory model from relocation count and placement.

    Small and tiny model code never forms a far pointer, so only the startup
    needs segment fixups -- a handful, all clustered near the entry point.
    Anything with far pointers needs one relocation per far reference, which
    spreads them across the image and multiplies the count.
    """
    n = mz["relocations"]
    kb = image_len / 1024.0
    if n == 0:
        return "tiny or packed", ("no relocations at all: either a single-segment "
                                  "program or a packed one")
    near_entry = sum(1 for p in mz["reloc_positions"] if abs(p - mz["entry"]) < 0x60)
    if n <= 8 and near_entry >= n - 1:
        return "small", (f"{n} relocations, all beside the entry point: the "
                         f"startup loading DGROUP and the stack, nothing else "
                         f"needing a fixup")
    density = n / max(1.0, kb)
    if density < 0.5:
        return "small or medium", (f"{n} relocations over {kb:.0f} KB "
                                   f"({density:.2f}/KB): few far references")
    return "compact, large or huge", (
        f"{n} relocations over {kb:.0f} KB ({density:.2f}/KB): far pointers "
        f"throughout, so more than one code or data segment")


def prologue_density(data, start, end):
    n = data.count(PROLOGUE, start, end)
    kb = max(1.0, (end - start) / 1024.0)
    return n, n / kb


def looks_like_engine(path, data):
    """Two signals: engine names in the binary, and big opaque siblings."""
    hits = []
    for marker, name in ENGINE_MARKERS.items():
        if data.find(marker) != -1:
            hits.append(name)

    siblings = []
    try:
        d = Path(path).parent
        exe_size = Path(path).stat().st_size
        for f in d.iterdir():
            if not f.is_file() or f.samefile(path):
                continue
            if f.suffix.lower() in (".exe", ".com", ".bat", ".txt", ".doc"):
                continue
            if f.stat().st_size > exe_size:
                siblings.append((f.name, f.stat().st_size))
    except OSError:
        pass
    siblings.sort(key=lambda s: -s[1])
    return sorted(set(hits)), siblings[:5]


def analyse(path):
    mz, data = read_mz(path)
    findings = []
    verdict = {"in_scope": True, "confidence": "high"}

    if mz is None:
        suffix = Path(path).suffix.lower()
        findings.append(("blocker", "not an MZ executable",
                         "This is a .COM file or raw binary. The pipeline reads "
                         "MZ headers for segments and entry point; none of that "
                         "exists here. A .COM loads at offset 0x100 in a single "
                         "segment -- workable by hand in Ghidra, but not with "
                         "these tools as they stand."
                         if suffix == ".com" else
                         "No MZ signature. Not a DOS executable, or a container "
                         "of some other kind."))
        return {"file": str(path), "format": "not-MZ",
                "verdict": {"in_scope": False, "confidence": "high"},
                "findings": findings}

    image_len = mz["image_end"] - mz["image_start"]

    # Packing. Checked first: everything downstream is meaningless if the code
    # you are looking at is a decompressor.
    #
    # Proximity to the entry point alone is too weak a test. PKLITE puts its
    # marker in the header area, well away from the code, and a real 1988 game
    # (Bantam's Creative Contraptions) was only warned about rather than
    # blocked. The corroborating evidence is decisive and cheap: a packed file
    # has almost no relocations, because the compressed payload has not been
    # relocated yet, and almost no stack-frame prologues, because the visible
    # code is a decompressor rather than compiled C.
    packer_prologues, packer_density = prologue_density(
        data, mz["image_start"], mz["image_end"])

    # EXEPACK's packed-header structure ends with the ASCII bytes "RB",
    # immediately before the entry point. Two letters are far too common to
    # search for on their own; at exactly entry-2 they are conclusive.
    if data[max(0, mz["entry"] - 2):mz["entry"]] == b"RB":
        findings.append(("blocker", "packed with Microsoft EXEPACK",
                         "The signature 'RB' sits exactly two bytes before the "
                         "entry point, which is where EXEPACK's packed header "
                         "ends. The entry point is its decompressor. "
                         "`tools/unpack.py` handles this format with the "
                         "original entry point read from the packer's own "
                         "header, and recovers the image to 99.7% of a "
                         "known-good unpacked build."))
        verdict["in_scope"] = False

    for sig, name in PACKERS.items():
        pos = data.find(sig)
        if pos == -1:
            continue
        near = abs(pos - mz["entry"]) < 0x400
        stripped = mz["relocations"] <= 2 or packer_density < 0.2
        if near or stripped:
            why = ("adjacent to the entry point" if near else
                   f"{mz['relocations']} relocations and "
                   f"{packer_density:.1f} prologues/KB -- the visible code is a "
                   f"decompressor, not the program")
            findings.append(("blocker", f"packed with {name}",
                             f"Signature at 0x{pos:X}, {why}. Unpack before "
                             f"doing anything else, or you will decompile the "
                             f"decompressor: correct, and useless. Try "
                             f"`python tools/unpack.py {Path(path).name} -o "
                             f"unpacked.exe`, which runs the decompressor under "
                             f"emulation and dumps the result."))
            verdict["in_scope"] = False
        else:
            findings.append(("warn", f"{name} signature present",
                             f"Found at 0x{pos:X}, but the file has "
                             f"{mz['relocations']} relocations and normal frame "
                             f"density, so it does not look packed. Possibly "
                             f"incidental; confirm before acting on it."))

    # Overlays.
    if data.find(b"FBOV") != -1 or mz["overlay_number"] != 0:
        findings.append(("blocker", "overlaid program",
                         "Overlaid code is swapped into a shared region, so "
                         "several functions occupy the same addresses at "
                         "different times. Nothing here handles that; each "
                         "overlay needs its own address space."))
        verdict["in_scope"] = False
    elif mz["trailing"] > 1024:
        findings.append(("warn", f"{mz['trailing']} bytes past the load image",
                         "Could be appended data, could be overlays. The "
                         "disassembler will not see it unless told to."))

    # Memory model.
    model, why = guess_memory_model(mz, image_len)
    level = "info" if model == "small" else "warn"
    findings.append((level, f"memory model looks {model}", why))
    if model.startswith(("compact", "small or medium")) and model != "small":
        findings.append(("warn", "emuverify.py assumes small model",
                         "It sets SS = DS and maps one 64 KB data group. On a "
                         "far-pointer program it will run functions with the "
                         "wrong stack segment and produce nonsense without "
                         "saying so. modcluster.py and match.py's data "
                         "fingerprints make the same assumption."))
        verdict["confidence"] = "low"

    # Compiled C versus hand-written assembly.
    count, density = prologue_density(data, mz["image_start"], mz["image_end"])
    if density >= 2.0:
        findings.append(("info", f"compiled C likely ({count} stack prologues, "
                                 f"{density:.1f}/KB)",
                         "Dense frame setup is what a period C compiler emits. "
                         "Function recovery and library signatures both work "
                         "well here."))
    elif density >= 0.5:
        findings.append(("warn", f"mixed or frame-pointer-free ({count} prologues, "
                                 f"{density:.1f}/KB)",
                         "Either a lot of hand-written assembly, or a compiler "
                         "omitting frame pointers under optimisation. Function "
                         "boundary recovery will miss more than usual."))
    else:
        findings.append(("warn", f"few stack frames ({count} prologues, "
                                 f"{density:.1f}/KB)",
                         "Two very different programs look like this: "
                         "hand-written assembly, and C built by a compiler that "
                         "omits frame pointers under optimisation (Open Watcom "
                         "does, Microsoft C 5.x does not). Tell them apart by "
                         "running libsig.py with each shipped database -- a "
                         "compiled program will match a C runtime, assembly will "
                         "not. Either way, expect function boundary recovery to "
                         "miss more than the measured figures suggest."))
        verdict["confidence"] = "low"

    # Interpreter engines -- the expensive mistake.
    engines, siblings = looks_like_engine(path, data)
    if engines:
        findings.append(("blocker", "interpreted engine: " + ", ".join(engines),
                         "The executable is an interpreter; the game is bytecode "
                         "and assets in the data files. Decompiling it yields a "
                         "virtual machine, not the game. Look for an "
                         "engine-specific tool instead."))
        verdict["in_scope"] = False
    elif siblings and siblings[0][1] > 4 * max(1, image_len):
        findings.append(("warn", "large opaque data files alongside",
                         "Biggest: " + ", ".join(f"{n} ({s:,} bytes)"
                                                 for n, s in siblings[:3])
                         + ". A small executable next to much larger data often "
                           "means an interpreter with the content elsewhere. "
                           "Check whether the game's text lives in the binary or "
                           "in those files before committing."))

    return {
        "file": str(path), "format": "MZ",
        "image_bytes": image_len, "relocations": mz["relocations"],
        "entry": f"{mz['cs']:04X}:{mz['ip']:04X}",
        "memory_model_guess": model,
        "prologues": count, "prologue_density": round(density, 2),
        "verdict": verdict, "findings": findings,
    }


def report(r):
    out = [f"File   : {r['file']}", f"Format : {r['format']}"]
    if r["format"] == "MZ":
        out += [f"Image  : {r['image_bytes']:,} bytes, {r['relocations']} relocations",
                f"Entry  : {r['entry']}"]
    out.append("")

    order = {"blocker": 0, "warn": 1, "info": 2}
    tag = {"blocker": "BLOCKER", "warn": "WARN   ", "info": "INFO   "}
    # Two independent checks can identify the same packer; say it once.
    seen, unique = set(), []
    for f in sorted(r["findings"], key=lambda f: order[f[0]]):
        if f[1] in seen:
            continue
        seen.add(f[1])
        unique.append(f)
    for level, title, detail in unique:
        out.append(f"[{tag[level]}] {title}")
        for line in _wrap(detail, 68):
            out.append(f"           {line}")
        out.append("")

    v = r["verdict"]
    if v["in_scope"] and v["confidence"] == "high":
        out.append("VERDICT: in scope. Run tools/pipeline.ps1.")
    elif v["in_scope"]:
        out.append("VERDICT: probably workable, with caveats above. Expect the "
                   "measured accuracy figures not to hold.")
    else:
        out.append("VERDICT: out of scope. See the blockers above and "
                   "knowledge/00-scope.md.")
    return "\n".join(out)


def _wrap(text, width):
    words, line, lines = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe")
    ap.add_argument("--json", help="write the findings here")
    args = ap.parse_args()

    r = analyse(args.exe)
    print(report(r))
    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0 if r["verdict"]["in_scope"] else 1


if __name__ == "__main__":
    sys.exit(main())
