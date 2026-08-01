#!/usr/bin/env python3
"""
libscan.py -- Find a compiler's runtime library inside a binary, and with it
the original entry point.

Why
---
A linked 1980s C program is part game, part C runtime. `libsig.py` recognises
runtime functions, but it needs two things the hard cases do not have: a
reference program you compiled yourself, and a list of candidate function
entry points to test. Neither exists for a packed binary that has just been
dumped out of an emulator.

This takes the other route, suggested by the agent who reconstructed
CONTRAP.EXE (see knowledge/09-lessons-from-contrap.md): **the library archive
itself is the signature database.** An OMF `.LIB` contains every module's exact
bytes plus FIXUPP records that say precisely which bytes the linker will
overwrite with addresses. Blank those and you have a signature that is exact
rather than heuristic -- and you can scan the whole image with it instead of
only probing places you already believe are functions.

Three things fall out of one scan:

* **Which compiler.** A wrong library produces no matches, not bad ones.
* **Where the runtime is.** Matched modules bound a region; everything outside
  it is the program. On the reference build that removes about a fifth of the
  work list before any analysis starts.
* **The entry point.** Exactly one module in a C library declares a start
  address in its MODEND record -- the startup module. Match it and the entry
  point is a subtraction, not a guess.

That last one is the reason this exists. `unpack.py` recovers a packed image
but cannot recover its entry point, and a wrong entry point sends the
disassembler into the middle of a routine.

Measured (tests/libscan/CASE-STUDY.md), on four binaries across two compilers:
the entry point came back exactly right every time, including for one that had
been packed and dumped -- and the scan never reads the MZ header, so the header
is an independent oracle rather than the source of the answer. 201 symbols
recovered, none contradicted by the linker maps. Scanned against the *wrong*
compiler's library, it reports nothing at all rather than something plausible.

Note the entry point is *read*, not assumed. The MODEND record names a segment
and a displacement; the CONTRAP agent inferred "offset 0 of the startup
module's code segment" from one compiler, and for Microsoft C 5.0 that is
indeed what the record says -- but it is a field, so there is no need to
assume it. Exactly one module sets the flag in each library checked (CRT0 out
of 302 in MS C 5.0, dos\\crt0.asm out of 303 in MS C 5.1, cstart out of 1,218
in Open Watcom), so it identifies the startup module as well as locating the
entry point inside it.

Usage:
    python libscan.py IMAGE.EXE --lib SLIBC.LIB
    python libscan.py dumped.bin --raw --lib SLIBC.LIB --lib SLIBFP.LIB
    python libscan.py IMAGE.EXE --lib SLIBC.LIB --json hits.json \\
                                --exclude libregions.txt
"""

import argparse
import json
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# OMF record types we care about. Everything else is skipped by length.
# ---------------------------------------------------------------------------
THEADR, LHEADR = 0x80, 0x82
COMENT = 0x88
MODEND, MODEND32 = 0x8A, 0x8B
PUBDEF, PUBDEF32 = 0x90, 0x91
LNAMES = 0x96
SEGDEF, SEGDEF32 = 0x98, 0x99
LEDATA, LEDATA32 = 0xA0, 0xA1
LIDATA, LIDATA32 = 0xA2, 0xA3
FIXUPP, FIXUPP32 = 0x9C, 0x9D
LIBHDR, LIBEND = 0xF0, 0xF1

# How many bytes each fixup location occupies. These are the bytes the linker
# writes addresses into, and therefore the bytes that must be wildcards.
FIXUP_SIZE = {0: 1, 1: 2, 2: 2, 3: 4, 4: 1, 5: 2, 9: 4, 11: 4, 13: 4}

MIN_FIXED = 16          # below this a signature matches noise
PREFILTER = 4           # consecutive fixed bytes used as a search needle


def _index(buf, p):
    """OMF index field: one byte, or two with the high bit as a flag."""
    b = buf[p]
    if b & 0x80:
        return ((b & 0x7F) << 8) | buf[p + 1], p + 2
    return b, p + 1


class Module:
    """One object module out of a library, reduced to what a scan needs."""

    def __init__(self, name, library):
        self.name = name
        self.library = library
        self.lnames = [""]          # 1-based
        self.segs = {}              # index -> dict(name, cls, size, data, mask)
        self.start = None           # (segment index, displacement) or None
        self.pubs = []              # (segment index, offset, name)

    def code_segments(self):
        """Segments whose class is CODE, largest first.

        Data segments are deliberately not scanned. Their contents are often
        all zero or all pointers, both of which match everywhere.
        """
        out = [s for s in self.segs.values() if s["cls"].upper().endswith("CODE")]
        return sorted(out, key=lambda s: -sum(s["mask"]))


def parse_module(buf, pos, library):
    """Parse one object module starting at `pos`. Returns (Module, end_pos)."""
    mod = None
    seg_order = []
    cur = None              # segment index the last LEDATA/LIDATA wrote to
    cur_off = 0
    while pos < len(buf):
        rt = buf[pos]
        rl = struct.unpack_from("<H", buf, pos + 1)[0]
        body = buf[pos + 3:pos + 3 + rl - 1]
        end = pos + 3 + rl

        if rt in (THEADR, LHEADR):
            if mod is not None:
                break           # a second header means a new module
            mod = Module(body[1:1 + body[0]].decode("latin-1"), library)

        elif rt == LNAMES and mod:
            p = 0
            while p < len(body):
                n = body[p]
                mod.lnames.append(body[p + 1:p + 1 + n].decode("latin-1"))
                p += 1 + n

        elif rt in (SEGDEF, SEGDEF32) and mod:
            p = 0
            acbp = body[p]; p += 1
            if (acbp >> 5) == 0:                 # absolute segment
                p += 3
            if (acbp >> 5) == 6:                 # ...LTL alignment variant
                p += 0
            big = bool(acbp & 0x02)
            if rt == SEGDEF32:
                size = struct.unpack_from("<I", body, p)[0]; p += 4
            else:
                size = struct.unpack_from("<H", body, p)[0]; p += 2
                if big and size == 0:
                    size = 0x10000
            seg_n, p = _index(body, p)
            cls_n, p = _index(body, p)
            idx = len(seg_order) + 1
            seg_order.append(idx)
            mod.segs[idx] = {
                "index": idx,
                "name": mod.lnames[seg_n] if seg_n < len(mod.lnames) else "",
                "cls": mod.lnames[cls_n] if cls_n < len(mod.lnames) else "",
                "size": size,
                "data": bytearray(size),
                "mask": bytearray(size),      # 1 = byte must match
            }

        elif rt in (PUBDEF, PUBDEF32) and mod:
            # A matched module does not only say "this region is library". Its
            # publics say what each routine inside it is called, which is a
            # name backed by the archive rather than by anyone's judgement.
            p = 0
            _, p = _index(body, p)                      # base group
            seg, p = _index(body, p)
            if seg == 0:
                p += 2                                  # base frame
            while p < len(body) - 1:
                n = body[p]; p += 1
                nm = body[p:p + n].decode("latin-1"); p += n
                if rt == PUBDEF32:
                    off = struct.unpack_from("<I", body, p)[0]; p += 4
                else:
                    off = struct.unpack_from("<H", body, p)[0]; p += 2
                _, p = _index(body, p)                  # type index
                mod.pubs.append((seg, off, nm))

        elif rt in (LEDATA, LEDATA32) and mod:
            p = 0
            seg, p = _index(body, p)
            if rt == LEDATA32:
                off = struct.unpack_from("<I", body, p)[0]; p += 4
            else:
                off = struct.unpack_from("<H", body, p)[0]; p += 2
            _write(mod, seg, off, body[p:])
            cur, cur_off = seg, off

        elif rt in (LIDATA, LIDATA32) and mod:
            p = 0
            seg, p = _index(body, p)
            if rt == LIDATA32:
                off = struct.unpack_from("<I", body, p)[0]; p += 4
            else:
                off = struct.unpack_from("<H", body, p)[0]; p += 2
            data = _expand_lidata(body, p, rt == LIDATA32)
            _write(mod, seg, off, data)
            cur, cur_off = seg, off

        elif rt in (FIXUPP, FIXUPP32) and mod and cur is not None:
            _apply_fixups(mod, cur, cur_off, body, rt == FIXUPP32)

        elif rt in (MODEND, MODEND32) and mod:
            if body and (body[0] & 0x40):
                mod.start = _modend_start(body, rt == MODEND32)
            pos = end
            break

        pos = end
    return mod, pos


def _write(mod, seg, off, data):
    s = mod.segs.get(seg)
    if s is None:
        return
    n = min(len(data), max(0, len(s["data"]) - off))
    s["data"][off:off + n] = data[:n]
    for i in range(off, off + n):
        s["mask"][i] = 1


def _expand_lidata(body, p, is32):
    """Expand an iterated-data block into flat bytes.

    LIDATA is how a compiler emits repeated content compactly. It has to be
    expanded, not skipped: the bytes it produces are part of the module and a
    scan that omits them matches nothing.
    """
    out = bytearray()

    def block(p):
        nonlocal out
        if is32:
            rep = struct.unpack_from("<I", body, p)[0]; p += 4
        else:
            rep = struct.unpack_from("<H", body, p)[0]; p += 2
        cnt = struct.unpack_from("<H", body, p)[0]; p += 2
        if cnt == 0:
            n = body[p]; p += 1
            chunk = bytes(body[p:p + n]); p += n
            out += chunk * rep
            return p
        start = len(out)
        for _ in range(cnt):
            p = block(p)
        once = bytes(out[start:])
        out += once * (rep - 1)
        return p

    while p < len(body):
        p = block(p)
    return bytes(out)


def _apply_fixups(mod, seg, base, body, is32):
    """Mark every byte the linker will overwrite as a wildcard.

    This is the whole reason a library archive beats a compiled reference
    program as a signature source: the relocation positions are *declared*,
    not inferred from a disassembler's opinion of where an immediate sits.
    """
    s = mod.segs.get(seg)
    p = 0
    frame_thread_meth = {}
    targ_thread_meth = {}
    while p < len(body):
        b = body[p]
        if b & 0x80:                                    # FIXUP subrecord
            loc = (b >> 2) & 0x0F
            off = ((b & 0x03) << 8) | body[p + 1]
            p += 2
            fd = body[p]; p += 1
            if fd & 0x80:
                fmeth = frame_thread_meth.get((fd >> 4) & 0x03, 0)
            else:
                fmeth = (fd >> 4) & 0x07
                if fmeth in (0, 1, 2):
                    _, p = _index(body, p)
                elif fmeth == 3:
                    p += 2
            if fd & 0x08:
                tmeth = targ_thread_meth.get(fd & 0x03, 0) & 0x03
            else:
                tmeth = fd & 0x03
                _, p = _index(body, p)
            if not (fd & 0x04):                         # target displacement
                p += 4 if is32 else 2
            size = FIXUP_SIZE.get(loc, 2)
            if s is not None:
                for k in range(base + off, min(base + off + size, len(s["mask"]))):
                    s["mask"][k] = 0
        else:                                           # THREAD subrecord
            meth = (b >> 2) & 0x07
            thr = b & 0x03
            p += 1
            if b & 0x40:
                frame_thread_meth[thr] = meth
                if meth in (0, 1, 2):
                    _, p = _index(body, p)
                elif meth == 3:
                    p += 2
            else:
                targ_thread_meth[thr] = meth
                if meth in (0, 1, 2, 3):
                    _, p = _index(body, p)


def _modend_start(body, is32):
    """Read the start address a startup module declares.

    Exactly one module in a C runtime library carries this: the one the linker
    takes the program's entry point from.
    """
    p = 1
    ed = body[p]; p += 1
    fmeth = (ed >> 4) & 0x07
    if not (ed & 0x80):
        if fmeth in (0, 1, 2):
            _, p = _index(body, p)
        elif fmeth == 3:
            p += 2
    tmeth = ed & 0x03
    seg = None
    if not (ed & 0x08):
        seg, p = _index(body, p)
    disp = 0
    if not (ed & 0x04):
        if is32:
            disp = struct.unpack_from("<I", body, p)[0]
        else:
            disp = struct.unpack_from("<H", body, p)[0]
    return (seg, disp, tmeth)


def read_library(path):
    """Split an OMF library archive into modules."""
    buf = Path(path).read_bytes()
    name = Path(path).name
    if not buf or buf[0] != LIBHDR:
        # A bare .OBJ is a library of one module; accept it, it is useful for
        # the startup module when someone has C.OBJ but not the archive.
        mod, _ = parse_module(buf, 0, name)
        return [mod] if mod else []
    page = struct.unpack_from("<H", buf, 1)[0] + 3
    mods, pos = [], page
    while pos < len(buf) and buf[pos] != LIBEND:
        if buf[pos] not in (THEADR, LHEADR):
            break
        mod, end = parse_module(buf, pos, name)
        if mod:
            mods.append(mod)
        pos = (end + page - 1) // page * page
    return mods


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def needle(data, mask):
    """The first run of PREFILTER fixed bytes, and where it starts."""
    run = 0
    for i in range(len(mask)):
        if mask[i]:
            run += 1
            if run == PREFILTER:
                return bytes(data[i - PREFILTER + 1:i + 1]), i - PREFILTER + 1
        else:
            run = 0
    return None, 0


def find_all(image, data, mask, limit=8):
    """Offsets where `data` matches `image` on every byte `mask` requires."""
    nd, at = needle(data, mask)
    if nd is None:
        return []
    out, pos = [], 0
    while len(out) < limit:
        i = image.find(nd, pos)
        if i < 0:
            break
        pos = i + 1
        start = i - at
        if start < 0 or start + len(data) > len(image):
            continue
        for k in range(len(data)):
            if mask[k] and image[start + k] != data[k]:
                break
        else:
            out.append(start)
    return out


def scan(image, mods, min_fixed=MIN_FIXED):
    hits, ambiguous, entry = [], [], None
    for mod in mods:
        for s in mod.code_segments():
            fixed = sum(s["mask"])
            if fixed < min_fixed:
                continue
            found = find_all(image, s["data"], s["mask"])
            if not found:
                continue
            if len(found) > 1:
                # Two placements fit equally well. Reporting it is the point:
                # picking one would be a guess wearing a measurement's clothes.
                ambiguous.append((mod.name, s["name"], len(found)))
                continue
            off = found[0]
            hits.append({
                "module": mod.name,
                "library": mod.library,
                "segment": s["name"],
                "offset": off,
                "length": len(s["data"]),
                "fixed_bytes": fixed,
                "symbols": sorted((off + o, n) for si, o, n in mod.pubs
                                  if si == s["index"]),
            })
            if mod.start is not None:
                seg_i, disp, _ = mod.start
                # The start address names a segment index inside this module.
                # It is the code segment we just located in all the C runtimes
                # checked, but say so rather than assume it.
                if seg_i in mod.segs and mod.segs[seg_i] is s:
                    entry = {"file_offset": off + disp, "module": mod.name,
                             "segment": s["name"], "displacement": disp}
                elif entry is None:
                    entry = {"file_offset": off + disp, "module": mod.name,
                             "segment": s["name"], "displacement": disp,
                             "note": "start address names a different segment "
                                     "index; offset assumes the located one"}
            break       # one code segment per module is enough to place it

    # Two library modules can have byte-identical code segments -- MSC 5.0's
    # flushall.c and closeall.c do -- and then both match at the same offset.
    # The region is still certainly runtime, but the identity is not decided,
    # so the names are withheld rather than emitted as if independent. Left
    # unhandled this produced exactly one wrong name out of 117.
    by_off = {}
    for h in hits:
        by_off.setdefault(h["offset"], []).append(h)
    collisions = []
    kept = []
    for off, group in sorted(by_off.items()):
        if len(group) == 1:
            kept.append(group[0])
            continue
        first = group[0]
        first["also_matches"] = [g["module"] for g in group[1:]]
        first["symbols"] = []
        collisions.append((off, [g["module"] for g in group]))
        kept.append(first)
    return kept, ambiguous, entry, collisions


def mz_header_size(data):
    if data[:2] not in (b"MZ", b"ZM"):
        return None
    return struct.unpack_from("<H", data, 8)[0] * 16


def mz_entry(data):
    """(cs, ip) from the header, and the file offset it points at."""
    hdr = mz_header_size(data)
    ip = struct.unpack_from("<H", data, 20)[0]
    cs = struct.unpack_from("<H", data, 22)[0]
    return cs, ip, hdr + (cs << 4) + ip


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--lib", action="append", required=True,
                    help="OMF library archive or object file (repeatable)")
    ap.add_argument("--raw", action="store_true",
                    help="treat the file as a load image with no MZ header")
    ap.add_argument("--min-fixed", type=int, default=MIN_FIXED)
    ap.add_argument("--json", help="write hits here")
    ap.add_argument("--exclude", help="write matched regions as "
                                      "start-end lines, for match.py")
    ap.add_argument("--names", help="write recovered symbol names here, one "
                                    "'offset name' per line")
    args = ap.parse_args()

    data = Path(args.binary).read_bytes()
    hdr = 0 if args.raw else (mz_header_size(data) or 0)
    image = data[hdr:]

    mods = []
    for lib in args.lib:
        got = read_library(lib)
        print(f"{Path(lib).name}: {len(got)} modules")
        mods += got

    hits, ambiguous, entry, collisions = scan(image, mods, args.min_fixed)

    covered = sum(h["length"] for h in hits)
    named = sum(len(h["symbols"]) for h in hits)
    print(f"\nmatched {len(hits)} of {len(mods)} modules, "
          f"{covered} bytes ({covered * 100.0 / max(1, len(image)):.1f}% of the image), "
          f"{named} symbols named")
    if hits:
        lo = min(h["offset"] for h in hits)
        hi = max(h["offset"] + h["length"] for h in hits)
        print(f"runtime region: image 0x{lo:04X}-0x{hi:04X} "
              f"(file 0x{lo + hdr:04X}-0x{hi + hdr:04X})")
        for h in sorted(hits, key=lambda h: h["offset"])[:15]:
            print(f"  0x{h['offset']:05X}  {h['module']:<12} {h['segment']:<8} "
                  f"{h['length']:>5} bytes, {h['fixed_bytes']} fixed")
        if len(hits) > 15:
            print(f"  ... {len(hits) - 15} more")

    if ambiguous:
        print(f"\n{len(ambiguous)} modules matched in more than one place "
              f"and were not placed:")
        for name, seg, n in ambiguous[:10]:
            print(f"  {name:<12} {seg:<8} {n} sites")

    if collisions:
        print(f"\n{len(collisions)} regions where several modules have "
              f"identical code; names withheld:")
        for off, names in collisions[:10]:
            print(f"  0x{off:05X}  {', '.join(names)}")

    print()
    if entry:
        print(f"entry point: image 0x{entry['file_offset']:05X} "
              f"(file 0x{entry['file_offset'] + hdr:05X}) "
              f"from {entry['module']}+{entry['displacement']}")
        if not args.raw and mz_header_size(data) is not None:
            cs, ip, off = mz_entry(data)
            says = off - hdr
            ok = "MATCHES" if says == entry["file_offset"] else "DIFFERS FROM"
            print(f"  header says {cs:04X}:{ip:04X} -> image 0x{says:05X}"
                  f"   [{ok} the scan]")
    else:
        print("entry point: not recovered (no startup module matched)")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"hits": hits, "ambiguous": ambiguous, "collisions": collisions,
             "entry": entry, "header_size": hdr}, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    if args.exclude:
        lines = [f"{h['offset'] + hdr:#x}-{h['offset'] + h['length'] + hdr:#x}"
                 f"  {h['module']}" for h in sorted(hits, key=lambda h: h["offset"])]
        Path(args.exclude).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {args.exclude}")
    if args.names:
        syms = sorted((o + hdr, n) for h in hits for o, n in h["symbols"])
        Path(args.names).write_text(
            "\n".join(f"{o:#07x} {n}" for o, n in syms) + "\n", encoding="utf-8")
        print(f"wrote {args.names} ({len(syms)} names)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
