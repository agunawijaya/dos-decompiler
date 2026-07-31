#!/usr/bin/env python3
"""
anchors.py -- Find the functions you can identify from evidence alone.

When no matching source exists -- the normal case for a lost 1980s game --
statistical matching has nothing to match against. What still works is
evidence: a function that executes `INT 10h` is doing video, whatever it is
called. This surfaces every such function so that a human, or Claude, starts
from facts instead of from a wall of FUN_1000_xxxx.

Ranked by how much the evidence actually pins down:

  1. entry point and the first thing it calls  -- in a C program that call is
     `main` almost without exception
  2. string references                         -- self-describing
  3. interrupt numbers                         -- says which subsystem
  4. I/O ports                                 -- says which device
  5. distinctive memory constants              -- says which screen mode

Usage:
    python anchors.py functions.json
    python anchors.py functions.json --entry 1000:8b46 --json anchors.json
"""

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path

INTERRUPTS = {
    0x05: "BIOS print screen",
    0x08: "IRQ0 timer (hardware)",
    0x09: "IRQ1 keyboard (hardware)",
    0x10: "BIOS video",
    0x11: "BIOS equipment list",
    0x12: "BIOS memory size",
    0x13: "BIOS disk",
    0x14: "BIOS serial",
    0x15: "BIOS misc / cassette",
    0x16: "BIOS keyboard",
    0x17: "BIOS printer",
    0x1A: "BIOS time of day",
    0x1B: "Ctrl-Break handler",
    0x1C: "timer tick user hook -- the game's heartbeat",
    0x20: "DOS terminate (old)",
    0x21: "DOS services",
    0x25: "DOS absolute disk read",
    0x26: "DOS absolute disk write",
    0x27: "DOS terminate and stay resident",
    0x33: "mouse driver",
}

PORTS = {
    0x20: "PIC command (interrupt acknowledge)",
    0x21: "PIC mask",
    0x40: "PIT channel 0 -- system timer",
    0x41: "PIT channel 1",
    0x42: "PIT channel 2 -- PC speaker tone",
    0x43: "PIT control",
    0x60: "keyboard data",
    0x61: "keyboard control / speaker gate",
    0x201: "joystick",
    0x278: "parallel port",
    0x2F8: "serial COM2",
    0x3B4: "MDA CRTC",
    0x3BC: "parallel port",
    0x3D4: "CGA CRTC index",
    0x3D5: "CGA CRTC data",
    0x3D8: "CGA mode control",
    0x3D9: "CGA colour select",
    0x3DA: "CGA status -- vertical retrace polling",
    0x3F2: "floppy digital output",
    0x3F8: "serial COM1",
    0x388: "AdLib address",
    0x389: "AdLib data",
}

CONSTANTS = {
    0xB800: "CGA / colour text video segment",
    0xB000: "MDA / Hercules video segment",
    0xA000: "EGA / VGA graphics segment",
    0x2000: "CGA odd-scanline bank offset",
    0x0040: "BIOS data area segment",
    320: "screen width, mode 4/13h",
    200: "screen height, mode 4/13h",
    640: "screen width, mode 6/12h",
    80: "CGA bytes per scanline, or text columns",
    25: "text rows",
    18: "ticks per second (approx), timer reprogramming",
}


def load(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return d["functions"], d


def _reach(by_entry, root, limit=4000):
    seen, queue = set(), deque([root])
    while queue and len(seen) < limit:
        node = queue.popleft()
        if node in seen:
            continue
        seen.add(node)
        f = by_entry.get(node)
        if f:
            queue.extend(f.get("calls", []))
    return seen


def reachable_roots(by_entry):
    """Functions nothing calls, ranked by how much they reach."""
    called = set()
    for f in by_entry.values():
        called.update(f.get("calls", []))
    roots = [e for e in by_entry if e not in called]
    return sorted(((len(_reach(by_entry, r)), r) for r in roots), reverse=True)


def descend_to_main(by_entry, entry, max_depth=12):
    """Follow the startup chain down to the point where the program fans out.

    A C runtime startup is a straight line -- each step calls essentially one
    thing that accounts for everything below it -- until it reaches main,
    where the program branches. Verified against Sopwith's ground-truth build,
    where it walks 1000:7771 -> 1000:7ccd -> 1000:1459 and 1000:1459 is
    exactly what the linker map calls main.

    It stops early when the startup reaches main by an indirect call the
    disassembler could not resolve, which does happen; treat the answer as a
    strong lead, not proof.
    """
    chain, current = [entry], entry
    for _ in range(max_depth):
        f = by_entry.get(current)
        if not f:
            break
        callees = f.get("calls", [])
        if not callees or len(callees) > 3:
            break
        here = len(_reach(by_entry, current))
        best = max(callees, key=lambda c: len(_reach(by_entry, c)))
        if len(_reach(by_entry, best)) < here - 3:
            break                      # the fan-out starts here: this is main
        current = best
        chain.append(current)
    return current, chain


def analyze(functions, entry=None):
    by_entry = {f["entry"]: f for f in functions}
    called_by = defaultdict(set)
    for f in functions:
        for c in f.get("calls", []):
            called_by[c].add(f["entry"])

    findings = []

    # 1. The entry point, and main found by descending the startup chain.
    if entry and entry in by_entry:
        findings.append({
            "address": entry, "kind": "entry", "confidence": "certain",
            "claim": "C runtime startup (program entry point)",
            "evidence": "declared entry point in the MZ header",
        })
        guess, chain = descend_to_main(by_entry, entry)
        if guess == entry:
            # The declared entry often sits in a stub whose calls the
            # disassembler could not resolve. The startup proper is then the
            # callerless function reaching the most code, so restart there.
            roots = reachable_roots(by_entry)
            if roots:
                guess, chain = descend_to_main(by_entry, roots[0][1])
        if guess and guess != entry:
            findings.append({
                "address": guess, "kind": "entry", "confidence": "medium",
                "claim": "main",
                "evidence": "reached from the entry point through "
                            + " -> ".join(chain)
                            + "; the runtime startup is a straight chain and "
                              "main is where the program fans out. MEASURED: "
                              "correct on 1 of the 2 Sopwith builds tested -- "
                              "right on the Watcom build, wrong on the shipped "
                              "Microsoft C one, whose startup reaches main by "
                              "a call the disassembler could not resolve. "
                              "Verify by reading: main is normally "
                              "init(argc,argv) followed by an endless loop.",
            })

    # Fallback and cross-check: functions nothing calls, ranked by how much of
    # the program they reach. main normally sits at or near the top. Worth
    # printing even when the chain succeeded, because on binaries where the
    # startup calls main indirectly the chain stops early and this is the only
    # signal left.
    for size, addr in reachable_roots(by_entry)[:3]:
        if size >= 10:
            findings.append({
                "address": addr, "kind": "entry", "confidence": "medium",
                "claim": "top-level driver (main or the game loop)",
                "evidence": f"nothing calls it, yet it reaches {size} functions",
            })

    for f in functions:
        addr = f["entry"]

        for s in f.get("strings", []):
            findings.append({
                "address": addr, "kind": "string", "confidence": "high",
                "claim": f"handles text: {s!r}",
                "evidence": "references this string literal",
            })

        for i in f.get("interrupts", []):
            desc = INTERRUPTS.get(i)
            findings.append({
                "address": addr, "kind": "interrupt",
                "confidence": "high" if desc else "medium",
                "claim": desc or f"uses INT {i:02X}h",
                "evidence": f"executes INT {i:02X}h",
            })

        for p in f.get("io_ports", []):
            desc = PORTS.get(p)
            findings.append({
                "address": addr, "kind": "port",
                "confidence": "high" if desc else "medium",
                "claim": desc or f"talks to port {p:03X}h",
                "evidence": f"IN/OUT on port {p:03X}h",
            })

        for c in f.get("scalars", []):
            if c in CONSTANTS and c >= 0x100:
                findings.append({
                    "address": addr, "kind": "constant", "confidence": "medium",
                    "claim": CONSTANTS[c],
                    "evidence": f"uses constant {c:#x}",
                })

    return findings


def summarize(findings, functions):
    by_addr = defaultdict(list)
    for f in findings:
        by_addr[f["address"]].append(f)

    rank = {"certain": 0, "high": 1, "medium": 2}
    order = sorted(by_addr.items(),
                   key=lambda kv: (min(rank[f["confidence"]] for f in kv[1]),
                                   -len(kv[1])))

    out = []
    A = out.append
    A(f"{len(by_addr)} of {len(functions)} functions carry identifying evidence")
    A("")
    for addr, items in order:
        best = min(rank[i["confidence"]] for i in items)
        label = [k for k, v in rank.items() if v == best][0]
        A(f"{addr}   [{label}]")
        seen = set()
        for i in items:
            key = (i["kind"], i["claim"])
            if key in seen:
                continue
            seen.add(key)
            A(f"    {i['claim']}")
            A(f"        because: {i['evidence']}")
        A("")
    return "\n".join(out)


ROLE_NAMES = {
    "BIOS video": "bios_video",
    "BIOS keyboard": "bios_keyboard",
    "BIOS disk": "bios_disk",
    "BIOS serial": "bios_serial",
    "BIOS printer": "bios_printer",
    "BIOS time of day": "bios_time",
    "BIOS equipment list": "bios_equipment",
    "BIOS memory size": "bios_memsize",
    "BIOS print screen": "bios_printscreen",
    "DOS services": "dos_svc",
    "DOS terminate (old)": "dos_terminate",
    "mouse driver": "mouse",
    "Ctrl-Break handler": "ctrl_break_handler",
    "timer tick user hook -- the game's heartbeat": "timer_tick_handler",
    "IRQ1 keyboard (hardware)": "keyboard_isr",
    "IRQ0 timer (hardware)": "timer_isr",
    "PIC command (interrupt acknowledge)": "pic_ack",
    "PIC mask": "pic_mask",
    "PIT channel 2 -- PC speaker tone": "speaker_tone",
    "PIT control": "pit_control",
    "PIT channel 0 -- system timer": "pit_timer",
    "keyboard data": "keyboard_port",
    "keyboard control / speaker gate": "speaker_gate",
    "joystick": "joystick_read",
    "CGA mode control": "cga_mode",
    "CGA colour select": "cga_colour",
    "CGA status -- vertical retrace polling": "cga_retrace_wait",
    "CGA CRTC index": "cga_crtc",
    "CGA CRTC data": "cga_crtc",
    "AdLib address": "adlib",
    "AdLib data": "adlib",
    "CGA / colour text video segment": "cga_access",
    "EGA / VGA graphics segment": "vga_access",
    "MDA / Hercules video segment": "mda_access",
    "CGA odd-scanline bank offset": "cga_access",
    "floppy digital output": "floppy_port",
    "serial COM1": "serial_com1",
    "serial COM2": "serial_com2",
}

# Only evidence this strong earns a name. A wrong name is worse than none:
# it survives into every later reading of the code as if it were established.
NAMEABLE_KINDS = {"interrupt", "port", "entry", "constant"}


def propose_names(findings):
    """Turn evidence into names that state what was actually established.

    Deliberately conservative. `bios_video_3` claims only that the function
    executes INT 10h, which is a fact. It does not claim to be `drawsprite`,
    which would be a guess dressed as knowledge.

    Corroboration is required for confidence, and that requirement is not a
    matter of taste. A sibling project reconstructing Tapper kept a table of
    every conclusion it later had to retract -- 35 of them -- and stated the
    pattern outright: *a conclusion drawn from one source of evidence almost
    always needs correcting later.* What survived review was what had two
    independent sources.

    So a function whose only evidence is "it executes INT 10h" gets a name
    scored below the certainty line, which makes ApplyNames.java suffix it
    `__maybe` and attach a warning. A function that executes INT 10h *and*
    touches 0xB800 has two independent lines of evidence agreeing, and is
    scored as confirmed.
    """
    # Group by address, tracking how many distinct KINDS of evidence support
    # each claim. Two interrupts in one function are one kind, not two: they
    # come from the same observation and can be wrong together.
    per_address = defaultdict(list)
    for f in findings:
        if f["kind"] in NAMEABLE_KINDS:
            per_address[f["address"]].append(f)

    chosen = {}
    for addr, items in per_address.items():
        kinds = {f["kind"] for f in items}
        best = None
        for f in items:
            if f["kind"] == "entry":
                base = {"C runtime startup (program entry point)": "crt_startup",
                        "main": "main"}.get(f["claim"])
                # The entry point comes from the MZ header, which is a fact and
                # needs no corroboration. `main` comes from a chain heuristic
                # that was right on one of two test binaries, so it never gets
                # promoted regardless of what else agrees.
                score = 0.95 if f["confidence"] == "certain" else 0.6
                fixed = True
            else:
                base = ROLE_NAMES.get(f["claim"])
                score = {"certain": 0.9, "high": 0.68, "medium": 0.5}[f["confidence"]]
                fixed = False
            if not base:
                continue
            if best is None or score > best[1]:
                best = (base, score, fixed)
        if best is None:
            continue

        base, score, fixed = best
        if not fixed:
            # Two independent kinds agreeing is what earns confidence. One kind
            # stays provisional however strong it looked on its own.
            score = min(0.9, score + 0.15) if len(kinds) >= 2 else min(score, 0.65)
        chosen[addr] = (base, score, sorted(kinds))

    # Disambiguate repeats: bios_video, bios_video_2, ...
    counts, mapping = {}, []
    for addr in sorted(chosen):
        base, score, kinds = chosen[addr]
        counts[base] = counts.get(base, 0) + 1
        name = base if counts[base] == 1 else f"{base}_{counts[base]}"
        mapping.append({"source": name, "binary": addr, "score": round(score, 3),
                        "file": "(evidence)", "evidence_kinds": kinds,
                        "corroborated": len(kinds) >= 2,
                        "binary_name": None,
                        "source_lines": None, "binary_instructions": None})
    return {"mapping": mapping, "mapped": len(mapping),
            "corroborated": sum(1 for m in mapping if m["corroborated"])}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("functions_json")
    ap.add_argument("--entry", help="entry point address, e.g. 1000:8b46")
    ap.add_argument("--json", help="write findings here")
    ap.add_argument("--report", help="write the readable report here")
    ap.add_argument("--names", metavar="FILE",
                    help="write evidence-based names in ApplyNames.java format")
    args = ap.parse_args()

    functions, _ = load(args.functions_json)
    findings = analyze(functions, args.entry)
    text = summarize(findings, functions)

    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
        print(f"wrote {args.report}")
    else:
        print(text)
    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    if args.names:
        names = propose_names(findings)
        Path(args.names).write_text(json.dumps(names, indent=2), encoding="utf-8")
        print(f"wrote {args.names} ({names['mapped']} evidence-based names, "
              f"{names['corroborated']} corroborated by two or more independent "
              f"kinds of evidence; the rest stay provisional)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
