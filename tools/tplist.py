#!/usr/bin/env python3
"""tplist.py -- an annotated disassembly of a Turbo Pascal MZ program.

Why this exists
---------------
`comrec.py` reconstructs a `.COM` file to assembly that reassembles to a
byte-identical copy, and that is the strongest evidence a reading can have. For
a *compiled* MZ program there was nothing: the analysis lived in documents and
a segment table, and no file said "here is the program". This writes that file.

It is a disassembly, not a decompilation to Pascal. Nothing here recovers `for`
loops or variable names, because the information is gone. What it does is apply
everything `tpscan.py` established to every byte: the unit each address belongs
to, every exported procedure as a label, every string constant resolved against
its own unit's segment base, and every runtime call named if you supply a table.

It follows control flow rather than sweeping linearly, and that is the whole
difference. A linear sweep decodes every byte it is handed, walks into a string
constant, decodes the text as instructions and comes out of phase. On The Oregon
Trail that left 202 branch targets pointing into the middle of an instruction.
Recursive descent never enters data, because nothing jumps into it.

Three numbers are reported and every one can fail:

  * **phase conflicts** -- two paths decoding the same byte at different
    offsets. Zero, or the reading is wrong somewhere.
  * **branch targets landing in a hole** -- a jump to a byte nothing decoded.
    Zero, or something reachable was not reached.
  * **bytes not reached** -- the honest remainder.

Measured on The Oregon Trail (MECC, 1990), over the 89,008 bytes that are the
program's own rather than its libraries':

    instructions            26,935
    code reached            72,250 bytes
    string data             16,552 bytes
    not reached                259 bytes   (0.3%, about half alignment padding)
    accounted for           88,802 (99.8%)
    phase conflicts              0
    branch targets           1,740
    landing in a hole            0

Three things were needed to get there from 69%, and each was found by watching
those counters rather than by guessing. They are worth knowing before pointing
this at a new program:

  * **A program's own unit is far-called by nobody.** It is entered from the MZ
    header, so `tpscan.py` gives it no entry points and a walk seeded from that
    list never enters it. Pass `--entry`.
  * **Turbo Pascal emits both encodings of `mov bp, sp`** -- 0x89E5 and 0x8BEC.
    Seeding on procedure prologues while looking for one of them found 0 of 78
    procedures on Oregon Trail. Both are checked.
  * **A referenced string address beats any heuristic.** A gap scan starting one
    byte early reads a length out of the wrong byte, emits a plausible short
    string and orphans a real one. The `mov di, off / push cs / push di` idiom
    gives the true boundaries.

Usage:
    python tplist.py IMAGE --units units.json --out prog.asm
    python tplist.py IMAGE --units units.json --out prog.asm \
                     --entry 0x10A --names names.json --runtime rt.json \
                     --skip 0x1db8,0x1de9,0x213d,0x219f

`--names`   {"0x1042": "ui", ...}      segment -> label
`--runtime` {"System": {"0xd8": "Halt"}, ...}   named entry points per unit.
            These are per *program*: Turbo Pascal smart-links, so a routine the
            program never calls is absent and everything after it shifts. A
            table from one binary is wrong for the next one.
"""

import argparse
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

# `push bp / mov bp, sp`. Both encodings of the second instruction appear.
PROLOGUES = (bytes((0x55, 0x89, 0xE5)), bytes((0x55, 0x8B, 0xEC)))

def pascal_string(img, at, hi):
    """The Pascal string at `at`, or None. A length byte then that many
    printable characters -- exact, not heuristic."""
    if not (0 <= at < hi):
        return None
    n = img[at]
    # 255, not 200: `string[255]` is legal Pascal and this program uses it.
    # Capping lower leaves the tail of every long string looking like an
    # unreached hole, which is what 815 stray bytes turned out to be.
    if not (1 <= n <= 255 and at + 1 + n <= hi):
        return None
    body = img[at + 1:at + 1 + n]
    if not all(0x20 <= c < 0x7F for c in body):
        return None
    return body.decode("ascii")


def find_data_runs(img, lo, hi):
    """Where the string constants are, so they are not disassembled.

    A compiler puts string literals in the code segment, after the procedure
    that uses them. Walking length-prefixed strings back to back finds those
    blocks exactly: two or more in a row is a data run, and a lone one is more
    likely a coincidence inside an instruction stream.
    """
    runs, i = [], lo
    while i < hi:
        s = pascal_string(img, i, hi)
        if s is None or len(s) < 4:
            i += 1
            continue
        start, count = i, 0
        while i < hi:
            s = pascal_string(img, i, hi)
            if s is None or len(s) < 4:
                break
            i += 1 + len(s)
            count += 1
        if count >= 2 and i - start >= 24:
            runs.append((start, i))
    return runs


# Instructions after which control does not fall through.
STOPS = {"ret", "retf", "iret", "iretd", "jmp", "ljmp", "hlt"}


def walk(img, lo, hi, seeds, barriers=frozenset()):
    """Recursive descent: decode only what control flow can reach.

    A linear sweep decodes every byte it is handed, so it walks straight into
    a string constant, decodes it as instructions, and comes out the far side
    out of phase -- which is what the 202 misaligned branch targets were. Every
    one of them sat just past a block of text.

    Following the control flow instead means data is never decoded, because
    nothing jumps into it. The seeds are the far-called entry points the
    segment scan already recovered, and each direct call or jump found along
    the way adds another.

    `barriers` are addresses known to be data because something references them
    as a string constant. Without them a procedure whose last instruction the
    walker does not recognise as a terminator runs straight on into the text
    that follows it, decoding the first few bytes as instructions and leaving
    the rest looking unreachable. The reference idiom gives those boundaries
    exactly, so they are worth honouring rather than guessing at.

    Returns (instructions by address, phase conflicts). A conflict is two paths
    decoding the same byte at different offsets, which is the thing that cannot
    happen if the reading is right -- so it is the number worth watching.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    insns, owner, conflicts = {}, {}, []
    work = [s for s in seeds if lo <= s < hi]
    seen_seed = set(work)
    while work:
        at = work.pop()
        while lo <= at < hi:
            if at in barriers:
                break               # this is a string, not the next instruction
            if at in insns:
                break                       # already walked from here
            if at in owner:                 # lands mid-instruction: a conflict
                conflicts.append((at, owner[at]))
                break
            got = next(md.disasm(img[at:min(at + 16, hi)], at), None)
            if got is None:
                break
            insns[at] = got
            for b in range(at, at + got.size):
                owner[b] = at
            mn, op = got.mnemonic, got.op_str
            if (mn.startswith("j") or mn == "call") and op.startswith("0x"):
                try:
                    tgt = int(op, 0)
                    if lo <= tgt < hi and tgt not in seen_seed:
                        seen_seed.add(tgt)
                        work.append(tgt)
                except ValueError:
                    pass
            if mn in STOPS:
                break
            at += got.size
    return insns, conflicts


def string_barriers(img, lo, hi):
    """Addresses this unit's own code names as string constants.

    `bf <off16> 0e 57` -- mov di, offset / push cs / push di. The offset is
    relative to the unit's own segment base, which is why the segment map has
    to be right before any of this means anything.
    """
    out = set()
    for i in range(lo, max(lo, hi - 5)):
        if img[i] != 0xBF or img[i + 3] != 0x0E or img[i + 4] != 0x57:
            continue
        at = lo + int.from_bytes(img[i + 1:i + 3], "little")
        if pascal_string(img, at, hi):
            out.add(at)
    return out


def name_far(seg, off, names, runtime, bias):
    """`lcall 0x319F:0x0CAA` -> `System.RandomReal`, if a table says so."""
    unit = names.get(seg - bias)
    if unit is None:
        return None
    sym = runtime.get(unit, {}).get(off)
    return f"{unit}.{sym}" if sym else f"{unit}:{off:#06x}"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--units", required=True, help="tpscan.py --json output")
    ap.add_argument("--out", required=True)
    ap.add_argument("--entry", default="",
                    help="comma-separated seed addresses for the unit nothing "
                         "far-calls -- typically the MZ entry and the begin "
                         "block it falls into")
    ap.add_argument("--names", help="JSON: segment -> label")
    ap.add_argument("--runtime", help="JSON: unit -> {offset: symbol}")
    ap.add_argument("--skip", default="",
                    help="segments to leave out, e.g. the compiler's own units")
    ap.add_argument("--load-seg", default="0x1000",
                    help="bias applied to segment words (unpack.py uses 0x1000)")
    ap.add_argument("--only", help="just one unit, by label or segment")
    args = ap.parse_args()

    names = {int(k, 0): v for k, v in
             (json.load(open(args.names)) if args.names else {}).items()}
    runtime = {k: {int(o, 0): s for o, s in v.items()} for k, v in
               (json.load(open(args.runtime)) if args.runtime else {}).items()}
    bias = int(args.load_seg, 0)
    skip = {int(s, 0) for s in args.skip.split(",") if s.strip()}
    entries_cli = [int(e, 0) for e in args.entry.split(",") if e.strip()]

    raw = Path(args.image).read_bytes()
    img = raw[32:] if raw[:2] in (b"MZ", b"ZM") else raw
    units = json.load(open(args.units))
    code_end = units["code_end"]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    out = []
    boundaries, branch_targets, decoded_span = set(), set(), set()
    code_reached = data_bytes = insn_count = 0
    unexplained = all_conflicts = prologue_seeded = 0
    total = 0

    out.append(f"; {Path(args.image).name} -- annotated disassembly")
    out.append("; Generated by tplist.py, by following control flow. This is a")
    out.append("; disassembly, not a reconstruction to Pascal: the information")
    out.append("; a decompiler would need is not in the file.")
    out.append(";")

    for u in units["units"]:
        seg, lo, size = u["segment"], u["start"], u["size"]
        hi = lo + size
        label = names.get(seg, f"seg_{seg:04x}")
        if args.only and label != args.only:
            continue
        if label in ("Dos", "Graph", "Crt", "System", "genusfont", "genuspcx"):
            out.append(f"\n; ==== {label}: {size:,} bytes, not ours -- skipped")
            continue

        total += size
        out.append(f"\n; ======================================================")
        out.append(f"; unit {label}  segment {seg:#06x}  "
                   f"image {lo:#08x}..{hi:#08x}  {size:,} bytes")
        out.append(f"; ======================================================")

        entries = set(u.get("procs", []))
        # The program's own unit is far-called by nobody -- it is entered from
        # the MZ header -- so the segment scan gives it no entry points at all
        # and a walk seeded only from that list never enters it. Seed the entry
        # point and the begin block it falls into.
        entries |= {e for e in entries_cli if lo <= e < hi}
        # A unit with an initialization section is entered at offset 0 -- but
        # only then. Several units start with a string constant instead, and
        # seeding those decodes text as instructions: 164 phase conflicts, all
        # of them mine. Seed offset 0 only when it opens like a procedure.
        if img[lo:lo + 3] in PROLOGUES:
            entries.add(lo)
        entries = sorted(entries)
        runs = find_data_runs(img, lo, hi)

        barriers = string_barriers(img, lo, hi)
        insns, conflicts = walk(img, lo, hi, entries, barriers)

        # The program's own unit is far-called by nobody, so the segment scan
        # gives it no entry points and the walk above reaches only what the
        # begin block calls directly. Most of a 31 KB unit hangs off menu
        # dispatches the walker cannot follow.
        #
        # A Turbo Pascal procedure that has parameters or locals always opens
        # `push bp / mov bp, sp`. Looking for that signature in the bytes
        # nothing reached, seeding it, and walking again recovers the rest --
        # and it is safe to try precisely because a wrong guess shows up
        # immediately as a phase conflict, which is counted and printed.
        found = 0
        inferred_procs = set()
        while True:
            extra = []
            a = lo
            while a < hi - 3:
                if a not in insns and img[a:a + 3] in PROLOGUES:
                    extra.append(a)
                    a += 3
                else:
                    a += 1
            if not extra:
                break
            inferred_procs.update(extra)
            more, c2 = walk(img, lo, hi, extra, barriers)
            conflicts += c2
            new_bytes = {k: v for k, v in more.items() if k not in insns}
            if not new_bytes:
                break
            insns.update(more)
            found += len(extra)
        prologue_seeded += found

        all_conflicts += len(conflicts)
        reached = sum(i.size for i in insns.values())
        code_reached += reached
        insn_count += len(insns)
        for a, ins in insns.items():
            boundaries.add(a)
            if (ins.mnemonic.startswith("j") or ins.mnemonic == "call")                     and ins.op_str.startswith("0x"):
                try:
                    tgt = int(ins.op_str, 0)
                    if lo <= tgt < hi:
                        branch_targets.add(tgt)
                except ValueError:
                    pass

        at = lo
        while at < hi:
            if at in insns:
                ins = insns[at]
                if at in entries:
                    out.append("")
                    out.append(f"proc_{at:05X}:            ; far-called entry point")
                elif at in inferred_procs:
                    out.append("")
                    out.append(f"proc_{at:05X}:            ; [inferred] from its "
                               f"prologue -- nothing far-calls it")
                note = ""
                if ins.mnemonic == "lcall" and "," in ins.op_str:
                    try:
                        s16, o16 = ins.op_str.split(", ")
                        nm = name_far(int(s16, 0), int(o16, 0),
                                      names, runtime, bias)
                        if nm:
                            note = f"      ; {nm}"
                    except ValueError:
                        pass
                elif ins.mnemonic == "mov" and ins.op_str.startswith("di, 0x"):
                    try:
                        tv = lo + int(ins.op_str[4:], 0)
                        sv = pascal_string(img, tv, hi)
                        if sv and img[at + 3:at + 5] == b"W":
                            note = f"      ; '{sv[:60]}'"
                    except ValueError:
                        pass
                out.append(f"  {at:05X}:  {ins.mnemonic:<7} {ins.op_str}{note}")
                at += ins.size
                continue

            # Not reached by control flow. Either a string constant, or code
            # nothing calls -- and the two are worth telling apart.
            #
            # A referenced address is authoritative and beats the heuristic.
            # Without that, a scan starting one byte early reads a length of 10
            # out of the byte before "Please check your disk...", emits ten
            # plausible characters, and leaves the other thirty looking like a
            # hole. Snapping to the next known start fixes a whole class of it.
            if at not in barriers:
                nb = min((b for b in barriers if at < b < at + 64), default=None)
                if nb is not None:
                    out.append(f"  {at:05X}:  db " +
                               ", ".join(str(b) for b in img[at:nb]))
                    data_bytes += nb - at
                    at = nb
                    continue
            s = pascal_string(img, at, hi)
            if s is not None and (at in barriers or len(s) >= 4):
                shown = s.replace("\\", "\\\\").replace("'", "''")
                out.append(f"L_{at:05X}:  db {len(s)}, '{shown}'")
                data_bytes += 1 + len(s)
                at += 1 + len(s)
                continue
            run = at
            while run < hi and run not in insns and                     not (pascal_string(img, run, hi) and
                         len(pascal_string(img, run, hi)) >= 4):
                run += 1
            unexplained += run - at
            out.append(f"; ---- {run - at} bytes not reached from any entry "
                       f"point, at {at:#07x}")
            at = run

    # Three numbers, and every one of them can fail.
    #
    # Recursive descent does not let a branch target land mid-instruction, so
    # the old "90.17% aligned" figure is gone rather than improved -- it was
    # measuring the linear sweep's phase, and there is no sweep now. What
    # replaces it is stricter: a target that points at a byte nothing reached
    # is a hole in the reading, and a phase conflict is two paths disagreeing
    # about where an instruction starts, which cannot happen if this is right.
    into_hole = sorted(tgt for tgt in branch_targets if tgt not in boundaries)
    accounted = code_reached + data_bytes

    summary = [
        "",
        "; " + "=" * 58,
        f"; instructions            {insn_count:,}",
        f"; procedures seeded by prologue  {prologue_seeded:,}",
        f"; code reached            {code_reached:,} bytes",
        f"; string data             {data_bytes:,} bytes",
        f"; not reached             {unexplained:,} bytes",
        f"; accounted for           {accounted:,} of {total:,} "
        f"({100 * accounted / total:.1f}%)",
        "; " + "-" * 58,
        f"; phase conflicts         {all_conflicts}   "
        f"(two paths disagreeing -- must be 0)",
        f"; branch targets          {len(branch_targets):,}",
        f"; landing in a hole       {len(into_hole)}   "
        f"({100 * len(into_hole) / max(len(branch_targets), 1):.2f}%)",
        "; " + "=" * 58,
    ]
    for h in into_hole[:40]:
        summary.append(f";   unreached target {h:#07x}")
    out.extend(summary)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(out) + "\n", encoding="ascii",
                              errors="replace")
    print("\n".join(s[2:] for s in summary[1:-1]))
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
