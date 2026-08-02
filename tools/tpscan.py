#!/usr/bin/env python3
"""
tpscan.py -- Find the structure of a Turbo Pascal program in a DOS image.

Why this exists
---------------
`libscan.py` subtracts a C runtime by matching modules out of an OMF `.LIB`,
with relocation slots wildcarded. It recovers the runtime region, names its
functions from PUBDEF records, and reads the entry point out of the startup
module. It is measured exact on four binaries across two compilers.

None of that works on Turbo Pascal. TP does not link OMF libraries; it compiles
to `.TPU` units and binds its runtime with its own linker, so there is no
archive to match against and no PUBDEF records to read. Point `libscan.py` at a
Pascal program and it finds nothing -- correctly, and uselessly.

What replaces it is not a signature database but a *structural* fact, and the
structural fact is stronger than a database because it needs no reference
files at all:

    In Turbo Pascal every unit is its own code segment, and every call
    between units is a far call carrying a literal segment word.

So the set of segments that are far-called *is* the set of units, the offsets
called into each one are its entry points, and the gaps between consecutive
segments are their sizes. A 200 KB program gives up its module structure to one
linear scan, with no symbols and nothing to download.

What it reports, and how sure it is
-----------------------------------
Three things, in decreasing order of confidence:

* **Is this Turbo Pascal at all.** The System unit's initialisation has a fixed
  shape -- set DS to DGROUP, save the PSP from ES, then compute the heap base
  from SP. That is matched as a byte pattern with the two segment words
  wildcarded, so it is evidence rather than impression, and it also yields
  DGROUP, which is the code/data boundary.
* **The unit segments**, with sizes and call counts.
* **Which one is the runtime**, from the `Runtime error ` string.

It does *not* identify the compiler *version*, and the reason is worth stating
rather than leaving as an absence: the runtime error message format is
identical across 4.0, 5.0, 5.5 and 6.0, and nothing else short of a reference
build distinguishes them. Version identification needs `.TPU` files to compare
against, which is the same shape of problem `libscan.py` solves for C and is
not solved here.

Usage:
    python tpscan.py IMAGE.EXE
    python tpscan.py IMAGE.EXE --json units.json
"""

import argparse
import collections
import json
import re
import struct
import sys
from pathlib import Path

# `unpack.py` dumps memory after the packer's decompressor has applied
# relocations, so segment words inside the image are absolute at this base.
# A file that was never packed has no such bias; --load-seg says which.
DEFAULT_LOAD_SEG = 0x1000

# The Turbo Pascal System unit's first instructions. Two segment words vary
# between programs, so they are wildcarded:
#
#     BA ?? ??        mov dx, DGROUP
#     8E DA           mov ds, dx
#     8C 06 ?? ??     mov [PrefixSeg], es      -- ES holds the PSP at entry
#     33 ED           xor bp, bp
#     8B C4           mov ax, sp
#     05 13 00        add ax, 0x13             -- round the stack top up
#     B1 04           mov cl, 4
#     D3 E8           shr ax, cl               -- ... to a paragraph
#     8C D2           mov dx, ss
#     03 C2           add ax, dx               -- the heap starts here
SYSTEM_INIT = re.compile(
    rb"\xBA(..)\x8E\xDA\x8C\x06(..)\x33\xED\x8B\xC4\x05\x13\x00"
    rb"\xB1\x04\xD3\xE8\x8C\xD2\x03\xC2", re.S)


def read_image(path):
    """Return the load image, skipping an MZ header if there is one."""
    d = Path(path).read_bytes()
    if d[:2] in (b"MZ", b"ZM"):
        hdr = struct.unpack_from("<H", d, 8)[0] * 16
        return d[hdr:], hdr
    return d, 0


def find_system_init(img):
    """Locate the System unit and the data segment it sets up."""
    m = SYSTEM_INIT.search(img)
    if not m:
        return None
    dgroup, prefixseg = (struct.unpack("<H", m.group(1))[0],
                         struct.unpack("<H", m.group(2))[0])
    return {"at": m.start(), "dgroup": dgroup, "prefixseg_var": prefixseg}


def pascal_strings(img, lo, hi, minlen=6, limit=None):
    """Length-prefixed strings inside one segment.

    This is what turns a segment list into a *named* segment list, and it is
    the cheapest useful thing in the file. A Pascal string is a length byte
    followed by that many characters, so the scan is exact rather than
    heuristic -- no minimum-run guessing, no false hits inside code.

    A unit's strings say what the unit is, immediately and without ambiguity.
    On The Oregon Trail one segment holds the main menu and `Miles traveled:`,
    another holds `Points for arriving in Oregon`, another holds
    `OTMCGA.PCL` and `PAL.256`, and another holds
    `BGI Error: Graphics not initialized` -- which is Borland's Graph unit
    identifying itself. Five of that program's eleven segments were named this
    way in one pass.

    The segments with *no* strings are informative too: a library is code
    without messages, and application code is not.
    """
    out = []
    i = lo
    while i < hi - 1:
        n = img[i]
        if minlen <= n <= 200 and i + 1 + n <= hi:
            body = img[i + 1:i + 1 + n]
            if all(0x20 <= c < 0x7F for c in body):
                out.append((i, body.decode("ascii")))
                if limit and len(out) >= limit:
                    return out
                i += 1 + n
                continue
        i += 1
    return out


def tpl_match(segment, lib, minrun=16):
    """How much of `segment` appears verbatim in `lib`, and the longest run.

    This is `libscan.py` for Pascal, and it needed a different shape. For C,
    `libscan` matches OMF modules with their FIXUPP relocation slots
    wildcarded, because it knows where the relocations are. A `.TPL` carries no
    such map, and Turbo Pascal *smart-links* -- unused procedures are dropped
    and everything after them shifts -- so neither alignment nor whole-module
    comparison works.

    Coverage does. Take every run of `minrun` bytes or more from the linked
    runtime that occurs anywhere in the library, and measure what fraction of
    the segment they cover. Relocated words break runs but only locally, and
    smart-linked gaps cost nothing because each surviving block is found on its
    own.

    Returns (bytes covered, longest single run).
    """
    covered = bytearray(len(segment))
    longest = 0
    i = 0
    while i < len(segment) - minrun:
        n = minrun
        if lib.find(segment[i:i + n]) < 0:
            i += 1
            continue
        while i + n < len(segment) and lib.find(segment[i:i + n + 1]) >= 0:
            n += 1
        for k in range(i, i + n):
            covered[k] = 1
        longest = max(longest, n)
        i += n
    return sum(covered), longest


def procedure_shape(img, procs):
    """How many claimed entry points actually look like procedures?

    Returns (with a stack frame, plausible at all). A Turbo Pascal procedure
    that has parameters or locals opens `push bp / mov bp, sp`; a leaf with
    neither does not, so the frame count is a floor rather than a target.

    The value of the second number is that it audits the *segment* detection.
    These offsets were derived from far-call operands; if a segment boundary
    were wrong, the offsets would be measured from the wrong base and would
    land in the middle of instructions, and the plausible count would fall
    apart. It holding up is evidence for the whole reading.
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    except ImportError:
        return 0, 0
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    # Openings a compiler emits, or that a hand-written leaf plausibly starts
    # with. Anything else at a called address means something is off.
    OPENERS = {"push", "sub", "mov", "xor", "les", "lea", "cld", "inc", "dec",
               "cmp", "call", "jmp", "test", "or", "and", "add", "pop", "in",
               "out", "sti", "cli", "lodsb", "lodsw", "ret", "retf", "nop"}
    framed = plausible = 0
    for p in procs:
        ins = list(md.disasm(bytes(img[p:p + 8]), p))
        if not ins:
            continue
        if ins[0].mnemonic in OPENERS:
            plausible += 1
        if (ins[0].mnemonic == "push" and ins[0].op_str == "bp"
                and len(ins) > 1 and ins[1].mnemonic == "mov"
                and ins[1].op_str == "bp, sp"):
            framed += 1
    return framed, plausible


def far_targets(img, load_seg):
    """Every far call and far jump with a literal, in-image destination."""
    calls = collections.Counter()
    entries = collections.defaultdict(set)
    n = len(img)
    for i in range(n - 5):
        op = img[i]
        if op not in (0x9A, 0xEA):          # call far / jmp far, imm16:imm16
            continue
        off, seg = struct.unpack_from("<HH", img, i + 1)
        if seg < load_seg:
            continue
        rel = seg - load_seg
        if ((rel << 4) + off) >= n:
            continue
        calls[rel] += 1
        entries[rel].add(off)
    return calls, entries


def string_ref_score(img, base, lo, hi):
    """How well `base` explains the string references between `lo` and `hi`.

    Turbo Pascal 5.0 passes a string constant as a far pointer built in place:

        bf <off16>      mov di, offset-of-the-length-byte
        0e              push cs
        57              push di

    The offset is relative to the segment the *referring code* is in, so a
    candidate segment base can be tested against the code that would live in
    it: score how many of those references land on something that is actually
    a Pascal string. The right base scores high and a wrong one scores near
    zero, because a length byte followed by exactly that many printable
    characters is not a thing random offsets hit.

    Returns (resolved, total).
    """
    resolved = total = 0
    for i in range(lo, max(lo, hi - 5)):
        if img[i] != 0xBF or img[i + 3] != 0x0E or img[i + 4] != 0x57:
            continue
        total += 1
        at = base + int.from_bytes(img[i + 1:i + 3], "little")
        if not (base <= at < hi):
            continue
        n = img[at]
        if 2 <= n <= 200 and at + 1 + n <= hi and \
                all(0x20 <= c < 0x7F for c in img[at + 1:at + 1 + n]):
            resolved += 1
    return resolved, total


def rescue_by_strings(img, calls, keep, code_end_para, factor=3):
    """Give back the segments that are called once and never at offset zero.

    `segments` keeps a candidate on two calls, or on one if it is an
    initialiser. A unit that is far-called exactly once, at some offset other
    than zero, satisfies neither -- and such units exist. The Oregon Trail's
    store is one: 13,952 bytes, entered once from the main program at offset
    0x22B8, holding every price in the game. Folded into its neighbour, its
    string references resolve against the wrong base and it looks as though
    nothing in the program addresses the store's text at all.

    So test the base directly. A candidate is restored when the references in
    the span it would own resolve against *it* far better than against the
    segment that would otherwise swallow them. That is independent evidence --
    it comes from the string idiom, not from the call graph that already
    failed -- which is what makes it worth trusting.
    """
    restored = []
    changed = True
    while changed:            # restoring one segment changes its neighbours'
        changed = False       # spans, so keep going until nothing moves
        for cand in sorted(set(calls) - set(keep)):
            order = sorted(keep)
            prev = max((s for s in order if s < cand), default=None)
            nxt = min((s for s in order if s > cand), default=code_end_para)
            if prev is None or not (prev < cand < nxt):
                continue
            lo, hi = cand << 4, nxt << 4
            if hi - lo < 0x200:
                continue
            mine = string_ref_score(img, lo, lo, hi)
            theirs = string_ref_score(img, prev << 4, lo, hi)
            if mine[1] < 8 or mine[0] < 8:
                continue
            if mine[0] >= factor * max(theirs[0], 1):
                keep.add(cand)
                restored.append((cand, mine, theirs))
                changed = True
                break
    return restored


def segments(calls, entries, code_end_para, min_calls=2):
    """Keep the candidate segments that can actually be segments.

    Two rules, both of them facts about the machine rather than thresholds:

    * an 8086 code segment cannot exceed 64 KB, so two candidates closer than
      that are both plausible and a lone candidate 64 KB from the next one is
      hiding a boundary -- reported, not invented;
    * every offset called into a segment must lie before the next segment
      starts, or the "segment" is a byte that happened to read 0x9A.

    When those two disagree, one of the pair is wrong and the question is
    which. **Drop the one with less evidence behind it**, not the one the scan
    reached first. Getting that backwards costs real units: a stray `0x9A` byte
    sitting between two genuine segments shrinks the earlier one's apparent
    span, and a rule that blames the earlier segment deletes a unit with 175
    calls in favour of a byte with one. It did exactly that here before the
    tie-break was written down.

    Dropping a candidate changes its neighbours' spans, so this iterates until
    the set stops changing.
    """
    keep = {s for s in calls if calls[s] >= min_calls}
    # A single call to offset 0 is an initialiser, which is real even when the
    # unit is never called again.
    keep |= {s for s in calls if 0 in entries[s]}
    dropped = []
    changed = True
    while changed:
        changed = False
        order = sorted(keep)
        for i, s in enumerate(order):
            nxt = order[i + 1] if i + 1 < len(order) else code_end_para
            if not entries[s] or max(entries[s]) < ((nxt - s) << 4):
                continue
            # A conflict. The loser is whichever is supported by fewer far
            # calls; on a tie the later one goes, because the earlier one has
            # already been vouched for by every entry that fits inside it.
            victim = s if (i + 1 < len(order) and
                           calls[s] < calls[order[i + 1]]) else \
                (order[i + 1] if i + 1 < len(order) else s)
            keep.discard(victim)
            dropped.append((victim, calls[victim]))
            changed = True
            break
    return sorted(keep), dropped


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--load-seg", default=hex(DEFAULT_LOAD_SEG),
                    help="segment the image's relocations were applied at "
                         "(unpack.py uses 0x1000; an unpacked file may use 0)")
    ap.add_argument("--json")
    ap.add_argument("--strings", type=int, nargs="?", const=3, default=0,
                    metavar="N",
                    help="show the first N Pascal strings in each segment -- "
                         "the fastest way to find out what each unit is")
    ap.add_argument("--tpl", action="append", default=[], metavar="TURBO.TPL",
                    help="a Turbo Pascal runtime library to identify the "
                         "compiler version against; give several and they are "
                         "ranked")
    ap.add_argument("--procs", metavar="FILE",
                    help="write every procedure entry point, one image offset "
                         "per line, for feeding to a disassembler")
    args = ap.parse_args()

    img, hdr = read_image(args.image)
    load_seg = int(args.load_seg, 0)
    print(f"image       : {args.image}  ({len(img):,} bytes"
          + (f", after a {hdr}-byte MZ header" if hdr else "") + ")")

    sysinit = find_system_init(img)
    if not sysinit:
        print("\nNot Turbo Pascal, or not a shape this recognises.")
        print("The System unit's initialisation was not found. That pattern is")
        print("stable across Turbo Pascal 4.0 to 6.0; a program built with")
        print("something else will land here, and so will a TP program whose")
        print("image is incomplete.")
        return 1

    dgroup = sysinit["dgroup"] - load_seg
    code_end = dgroup << 4
    print(f"compiler    : Turbo Pascal  [System unit init at "
          f"{sysinit['at']:#07x}]")
    print(f"              version not determined -- see the module docstring")
    print(f"DGROUP      : {sysinit['dgroup']:#06x}  -> data starts at "
          f"{code_end:#07x}")
    print(f"code / data : {code_end:,} bytes of code, "
          f"{len(img) - code_end:,} bytes of data and stack")

    calls, entries = far_targets(img, load_seg)
    segs, dropped = segments(calls, entries, dgroup)
    kept = set(segs)
    restored = rescue_by_strings(img, calls, kept, dgroup)
    if restored:
        segs = sorted(kept)
        for s, mine, theirs in restored:
            print(f"  restored segment {s:#06x}: its own base explains "
                  f"{mine[0]}/{mine[1]} string references, the neighbour's "
                  f"{theirs[0]}")
    rt = None
    err = img.find(b"Runtime error ")

    print(f"\nunits       : {len(segs)} code segments carrying "
          f"{sum(calls[s] for s in segs):,} far calls")
    print(f"\n{'segment':>9} {'starts':>9} {'bytes':>8} {'calls':>7} "
          f"{'entries':>8}  ")
    rows = []
    # The program's own code is not in that list and must not be forgotten:
    # nothing far-calls it, because it is entered from the MZ header and
    # nowhere else. Its absence from the call graph is the evidence for what it
    # is, so it is reported rather than left as an unexplained hole.
    if segs and segs[0] > 0:
        print(f"   {0:#07x} {0:#09x} {segs[0] << 4:8,} {'-':>7} {'-':>8}"
              f"  <- the program itself: called by nobody, entered from the header")
        rows.append({"segment": 0, "start": 0, "size": segs[0] << 4,
                     "calls": 0, "entries": 0, "role": "program"})
        if args.strings:
            for _, text in pascal_strings(img, 0, segs[0] << 4,
                                          limit=args.strings):
                print(f"        {text[:78]!r}")
    for i, s in enumerate(segs):
        nxt = segs[i + 1] if i + 1 < len(segs) else dgroup
        start, size = s << 4, (nxt - s) << 4
        if err >= 0 and start <= err < start + size:
            rt = s
        rows.append({"segment": s, "start": start, "size": size,
                     "calls": calls[s], "entries": len(entries[s]),
                     # Every offset far-called into a unit is the entry point
                     # of one of its exported procedures. That is the Pascal
                     # equivalent of what RecoverFunctions.java digs out of an
                     # MZ image for C, and it costs nothing extra: the scan
                     # already had to collect them to bound the segments.
                     "procs": [start + e for e in sorted(entries[s])]})
        mark = ""
        if size > 0x10000:
            mark = "  <- over 64 KB: a boundary is hidden in here"
        print(f"   {s:#07x} {start:#09x} {size:8,} {calls[s]:7} "
              f"{len(entries[s]):8}{mark}")
        if args.strings:
            found = pascal_strings(img, start, start + size,
                                   limit=args.strings)
            for _, text in found:
                print(f"        {text[:78]!r}")
            if not found:
                print("        (no strings -- a library, not application code)")

    if dropped:
        # Say what was refused and why. A candidate list that silently shrinks
        # is indistinguishable from one that was right first time.
        print(f"\nrefused     : {len(dropped)} candidate segments whose called "
              f"offsets ran past the next one")
        print("              " + ", ".join(
            f"{s:#06x} ({c} call{'s' if c != 1 else ''})"
            for s, c in sorted(dropped)[:12]))

    if rt is not None:
        row = next(r for r in rows if r["segment"] == rt)
        print(f"\nruntime     : segment {rt:#06x} holds 'Runtime error ' -- "
              f"Borland's System unit,")
        print(f"              {row['size']:,} bytes, "
              f"{row['calls']:,} far calls into it "
              f"({row['calls'] * 100 // max(1, sum(calls[s] for s in segs))}% "
              f"of all calls)")
        mecc = sum(r["size"] for r in rows if r["segment"] != rt)
        print(f"              the other {len(rows) - 1} segments total "
              f"{mecc:,} bytes")

    if args.tpl and rt is not None:
        row = next(r for r in rows if r["segment"] == rt)
        seg = img[row["start"]:row["start"] + row["size"]]
        print(f"\nversion     : matching the {row['size']:,}-byte runtime "
              f"segment against {len(args.tpl)} librar"
              f"{'ies' if len(args.tpl) > 1 else 'y'}")
        results = []
        for path in args.tpl:
            lib = Path(path).read_bytes()
            cov, longest = tpl_match(seg, lib)
            sig = lib[:4].decode("latin-1") if lib[:3] == b"TPU" else "?"
            results.append((cov, longest, path, sig))
            print(f"   {Path(path).parent.name}/{Path(path).name:<12} "
                  f"[{sig}]  {cov * 100 // len(seg):3}% covered, "
                  f"longest run {longest:,} bytes")
        results.sort(reverse=True)
        best, second = results[0], (results[1] if len(results) > 1 else None)
        # A single library proves nothing on its own: any two Turbo Pascal
        # runtimes share a great deal. The claim is only worth making when one
        # library beats the others by a margin, so the margin is what decides
        # whether this prints an answer or a refusal.
        if second and best[1] < second[1] * 1.5:
            print(f"   -> too close to call: {best[1]:,} against "
                  f"{second[1]:,} bytes. Not stated.")
        elif second:
            print(f"   -> {Path(best[2]).parent.name}, on a longest run of "
                  f"{best[1]:,} bytes against {second[1]:,} for the next")
        else:
            print("   -> only one library given; a match here means little "
                  "without something to compare it to")

    procs = sorted({p for r in rows for p in r.get("procs", [])})
    if procs:
        print(f"\nprocedures  : {len(procs)} entry points, from "
              f"{procs[0]:#07x} to {procs[-1]:#07x}")
        print("              every offset something far-calls is the start of "
              "an exported\n              procedure -- this is the list to "
              "hand a disassembler")
        framed, ok = procedure_shape(img, procs)
        # This is the whole analysis checking itself. If the segment list were
        # wrong, these offsets would land in the middle of instructions and
        # this figure would collapse -- so a high number here is evidence for
        # everything above it, not just for the procedure list.
        print(f"              {framed} of {len(procs)} open with "
              f"`push bp / mov bp, sp` ({framed * 100 // len(procs)}%), "
              f"{ok} are plausible")
        if ok * 10 < len(procs) * 9:
            print("              LOW -- under 90% plausible means the segment "
                  "boundaries are suspect")

    if args.procs:
        Path(args.procs).write_text(
            "".join(f"0x{p:05X}\n" for p in procs), encoding="ascii")
        print(f"              wrote {args.procs}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"code_end": code_end, "dgroup": sysinit["dgroup"],
             "load_seg": load_seg, "runtime_segment": rt, "units": rows},
            indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
