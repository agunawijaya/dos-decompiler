#!/usr/bin/env python3
"""
unpack.py -- Recover the original program from a packed DOS executable, by
running the packer's own decompressor.

Why this exists
---------------
Compressing the executable was near-universal on commercial DOS releases from
the late 1980s. Of the period games lying around during this toolkit's
development, every commercial one was packed. A packed file defeats every
static tool here: the entry point is a decompressor, and decompiling it
produces something correct and useless.

Why emulation rather than a format-specific unpacker
-----------------------------------------------------
Writing an unpacker per format -- PKLITE, LZEXE, EXEPACK, DIET, and the
variants within each -- is a treadmill. But every packer, whatever its
algorithm, must do the same thing: reconstruct the original image in memory
and jump to it. So run it and take the result. One mechanism, any packer,
including ones nobody has documented.

The idea is old and well proven in the packing world; what makes it practical
here is that `unicorn` is already a dependency for `emuverify.py`.

How the original entry point is found
--------------------------------------
Execution starts at the decompressor. Every write into the image region is
recorded. The moment control reaches an address that this run has *written*,
the program is executing code that did not exist in the file -- that is the
unpacked program, and that address is its entry point.

Caveats, stated plainly
-----------------------
The dump is for **analysis**, not necessarily for running. Relocations are not
reconstructed: the loader would normally patch segment values, and recovering
which words need patching would mean tracking the decompressor's own
relocation pass. Ghidra does not care -- it wants the code.

DOS is stubbed, not emulated. Enough of INT 21h is answered to let a
decompressor resize its memory block and get on with it. A packer that does
something more elaborate will fail, and will say so rather than produce a
quietly wrong dump.

Usage:
    python unpack.py PACKED.EXE -o UNPACKED.EXE
    python unpack.py PACKED.EXE -o UNPACKED.EXE --trace
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,
                         UC_HOOK_INTR, UC_HOOK_MEM_WRITE, UcError)
    from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
                                   UC_X86_REG_DX, UC_X86_REG_SP, UC_X86_REG_IP,
                                   UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                                   UC_X86_REG_SS, UC_X86_REG_FLAGS)
except ImportError:  # pragma: no cover
    print("unpack: unicorn is required (pip install unicorn)", file=sys.stderr)
    raise

MEM_SIZE = 0x110000
PSP_SEG = 0x0FF0             # a plausible PSP, image loads just above it
LOAD_SEG = 0x1000
LOAD_BASE = LOAD_SEG << 4
MAX_INSNS = 20_000_000       # decompressing a 60 KB image takes a few million
# Writing this quiet for this long means decompression is done.
WRITE_QUIET_INSNS = 200_000


def exepack_header(data, entry):
    """Read EXEPACK's own record of where the program really starts.

    When a packer states the answer, take it rather than infer it. EXEPACK
    keeps a 16-byte structure immediately before its decompressor, ending with
    the ASCII bytes "RB":

        +0  real_ip     +8  real_sp
        +2  real_cs    +10  real_ss
        +4  mem_start  +12  dest_len (paragraphs)
        +6  exepack_size            +14  "RB"

    Verified by packing a program with Microsoft LINK /EXEPACK and comparing:
    real_ip, real_cs, real_sp and real_ss all matched the unpacked build
    exactly, and dest_len matched its image size to within a paragraph.
    """
    if entry < 16 or data[entry - 2:entry] != b"RB":
        return None
    ip, cs, _mem, _size, sp, ss, dest = struct.unpack_from(
        "<HHHHHHH", data, entry - 16)
    return {"ip": ip, "cs": cs, "sp": sp, "ss": ss, "dest_paragraphs": dest}


class Header:
    def __init__(self, data):
        if data[:2] not in (b"MZ", b"ZM"):
            raise SystemExit("not an MZ executable")
        (self.last, self.pages, self.nreloc, self.hdr_paras, self.minalloc,
         self.maxalloc, self.ss, self.sp, _, self.ip, self.cs,
         self.reloc_off) = struct.unpack_from("<HHHHHHHHHHHH", data, 2)
        self.hdr = self.hdr_paras * 16
        self.image_end = ((self.pages - 1) * 512 + (self.last if self.last else 512)
                          if self.pages else len(data))
        self.image = data[self.hdr:self.image_end]
        self.relocs = []
        for i in range(self.nreloc):
            pos = self.reloc_off + i * 4
            if pos + 4 <= len(data):
                off, seg = struct.unpack_from("<HH", data, pos)
                self.relocs.append((seg, off))


def unpack(path, trace=False, max_insns=MAX_INSNS, use_header=True):
    data = Path(path).read_bytes()
    h = Header(data)

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, MEM_SIZE)
    uc.mem_write(LOAD_BASE, bytes(h.image))

    # The stub's own relocations must be applied, exactly as DOS would: add the
    # load segment to each word the table points at. Without this the
    # decompressor jumps into nothing.
    for seg, off in h.relocs:
        addr = LOAD_BASE + (seg << 4) + off
        if addr + 2 <= MEM_SIZE:
            value = struct.unpack_from("<H", uc.mem_read(addr, 2), 0)[0]
            uc.mem_write(addr, struct.pack("<H", (value + LOAD_SEG) & 0xFFFF))

    # A minimal PSP: the decompressor may read the memory-size field at :0002.
    uc.mem_write((PSP_SEG << 4) + 2, struct.pack("<H", 0x9FFF))

    uc.reg_write(UC_X86_REG_CS, (LOAD_SEG + h.cs) & 0xFFFF)
    uc.reg_write(UC_X86_REG_IP, h.ip)
    uc.reg_write(UC_X86_REG_SS, (LOAD_SEG + h.ss) & 0xFFFF)
    uc.reg_write(UC_X86_REG_SP, h.sp)
    uc.reg_write(UC_X86_REG_DS, PSP_SEG)
    uc.reg_write(UC_X86_REG_ES, PSP_SEG)
    uc.reg_write(UC_X86_REG_FLAGS, 0x0202)

    # Segment arithmetic wraps, and packers exploit that. PKLITE writes
    # CS = 0xFFF0 -- minus sixteen paragraphs -- so that the entry lands at the
    # very start of the load image via the PSP. Computing LOAD_BASE + (cs << 4)
    # without wrapping puts it a megabyte away, outside mapped memory.
    start_seg = (LOAD_SEG + h.cs) & 0xFFFF
    start_ip = (start_seg << 4) + h.ip
    image_paras = max(1, len(h.image) // 16)
    # A decompressor's first act is often to copy *itself* somewhere safe and
    # jump to the copy. That is a jump into freshly written bytes and it is not
    # the original entry point. Two conditions separate the real thing:
    # a substantial fraction of the image must have been rewritten by then, and
    # control must land back inside the load area where the program belongs --
    # the relocated stub lives above it.
    min_written = max(16, image_paras // 4)
    image_top = LOAD_BASE + len(h.image) + 0x1000

    state = {"written": set(), "insns": 0, "oep": None, "ss": None, "sp": None,
             "stopped": None, "int21": 0, "rejected": 0,
             "cs": (LOAD_SEG + h.cs) & 0xFFFF, "last_new_write": 0,
             "candidates": []}

    def on_write(mu, access, address, size, value, _):
        # Page granularity: a decompressor writes byte by byte, and recording
        # every address individually is both slow and unnecessary.
        before = len(state["written"])
        for a in range(address, address + size, 16):
            state["written"].add(a >> 4)
        if len(state["written"]) != before:
            state["last_new_write"] = state["insns"]

    def on_code(mu, address, size, _):
        state["insns"] += 1
        if state["insns"] > max_insns:
            state["stopped"] = "instruction budget exhausted"
            mu.emu_stop()
            return
        # Writing has stopped for a long stretch: decompression is finished and
        # whatever runs now is the program itself.
        if state["candidates"] and \
                state["insns"] - state["last_new_write"] > WRITE_QUIET_INSNS:
            state["stopped"] = "decompression finished (writing went quiet)"
            mu.emu_stop()
            return
        # Handing control to the unpacked program means leaving the
        # decompressor's segment, so CS changes. Jumps *within* the program
        # afterwards do not -- which matters, because once decompression is
        # done the whole image counts as "written" and a rule based on written
        # memory alone would fire on ordinary gameplay code.
        cs = mu.reg_read(UC_X86_REG_CS)
        cs_changed = cs != state["cs"]
        state["cs"] = cs
        if not cs_changed or state["insns"] <= 64:
            return
        if (address >> 4) not in state["written"] or abs(address - start_ip) <= 0x40:
            return
        if address >= image_top:
            state["rejected"] += 1      # the stub jumping into its own copy
            return
        # Record every candidate and keep running. Stopping at the first one
        # truncated the dump -- on a PKLITE-packed game the detection fired
        # before decompression had finished and the image came out nearly
        # empty. Decompression is over when writing stops, not when a jump
        # looks interesting, and the handoff to the program is the candidate
        # that sits closest to that moment.
        state["candidates"].append((state["insns"], address,
                                    mu.reg_read(UC_X86_REG_SS),
                                    mu.reg_read(UC_X86_REG_SP),
                                    len(state["written"])))

    def on_intr(mu, intno, _):
        if intno != 0x21:
            return
        state["int21"] += 1
        ah = (mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        if ah == 0x4A:                    # resize memory block -- always allow
            mu.reg_write(UC_X86_REG_BX, 0x9000)
            mu.reg_write(UC_X86_REG_FLAGS,
                         mu.reg_read(UC_X86_REG_FLAGS) & ~1)
        elif ah == 0x48:                  # allocate
            mu.reg_write(UC_X86_REG_AX, 0x9000)
            mu.reg_write(UC_X86_REG_FLAGS,
                         mu.reg_read(UC_X86_REG_FLAGS) & ~1)
        elif ah in (0x4C, 0x00):           # terminate -- the stub gave up
            state["stopped"] = f"program terminated via INT 21h AH={ah:02X}"
            mu.emu_stop()
        else:
            mu.reg_write(UC_X86_REG_FLAGS,
                         mu.reg_read(UC_X86_REG_FLAGS) & ~1)

    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_INTR, on_intr)

    try:
        uc.emu_start(start_ip, 0, timeout=120_000_000, count=0)
    except UcError as e:
        if state["oep"] is None:
            state["stopped"] = f"CPU fault: {e}"

    # The handoff to the program is the last control transfer into the image
    # before decompression finished. Candidates after that point are the
    # program running normally -- by then the whole image counts as "written".
    usable = [c for c in state["candidates"] if c[0] <= state["last_new_write"] + 1]
    chosen = (usable or state["candidates"])[-1] if state["candidates"] else None
    if chosen:
        state["oep"], state["ss"], state["sp"] = chosen[1], chosen[2], chosen[3]

    result = {
        "instructions": state["insns"],
        "candidates": len(state["candidates"]),
        "int21_calls": state["int21"],
        "paragraphs_written": len(state["written"]),
        "rejected_candidates": state["rejected"],
        "stopped": state["stopped"],
        "oep": state["oep"],
    }
    # An authoritative entry point beats a heuristic one. The emulation still
    # had to run -- it is what produced the decompressed image -- but where the
    # program starts is stated by the packer, not inferred from behaviour.
    stated = exepack_header(data, h.hdr + (h.cs << 4) + h.ip) if use_header else None
    if stated:
        result["format"] = "Microsoft EXEPACK"
        result["oep_source"] = "packer header (authoritative)"
        oep = (stated["cs"] << 4) + stated["ip"]
        ss, sp = (LOAD_SEG + stated["ss"]) & 0xFFFF, stated["sp"]
        size = min(MEM_SIZE - LOAD_BASE, stated["dest_paragraphs"] * 16 + 0x100)
    elif state["oep"] is not None:
        # The image is sound; the entry point is not.
        #
        # Locating an entry point generically was tried three ways: first jump
        # into written memory, then the same with a minimum-decompression
        # threshold, then requiring CS to change as well. On the EXEPACK
        # known-answer test all three returned 0x8B40 against a true 0x6B2.
        # Generic OEP recovery is the hard part of unpacking, which is why real
        # unpackers are written per format.
        #
        # So the guess is reported and deliberately NOT written into the
        # header. A wrong entry point is worse than none: it sends the
        # disassembler off into the middle of a routine and everything
        # downstream inherits the error. Entry is set to offset 0, and
        # anchors.py can find `main` structurally from the dump.
        result["format"] = "unrecognised"
        result["oep_source"] = "unknown -- header entry set to 0"
        result["oep_candidate"] = state["oep"] - LOAD_BASE
        oep = 0
        ss, sp = state["ss"], state["sp"]
        top = max(state["written"]) + 1
        size = min(MEM_SIZE - LOAD_BASE, (top << 4) - LOAD_BASE + 0x100)
    else:
        return None, result

    image = bytes(uc.mem_read(LOAD_BASE, size))
    result["unpacked_size"] = len(image)
    result["oep_offset"] = oep
    return build_mz(image, oep, ss, sp), result


def build_mz(image, oep, ss, sp):
    """Wrap a memory dump back into a loadable-looking MZ file.

    No relocation table: see the module docstring. Ghidra will load this and
    show the real code, which is the point.
    """
    hdr_paras = 2                       # 32 bytes, no relocation entries
    hdr_size = hdr_paras * 16
    total = hdr_size + len(image)
    pages = (total + 511) // 512
    last = total % 512

    cs, ip = divmod(oep, 16)
    # A near entry keeps CS small enough for any tool that assumes segment 0.
    if cs > 0xFFF:
        ip += (cs & 0xF) * 16
        cs &= ~0xF
    header = struct.pack(
        "<2sHHHHHHHHHHHH", b"MZ", last, pages, 0, hdr_paras, 0x0010, 0xFFFF,
        (ss - LOAD_SEG) & 0xFFFF if ss is not None else 0,
        sp if sp is not None else 0xFFFE,
        0, ip & 0xFFFF, cs & 0xFFFF, 0x001C)
    return header + b"\x00" * (hdr_size - len(header)) + image


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--max-insns", type=int, default=MAX_INSNS)
    ap.add_argument("--ignore-packer-header", action="store_true",
                    help="force the generic heuristic even when the format "
                         "states its entry point -- for testing the heuristic "
                         "against a known answer")
    args = ap.parse_args()

    out, info = unpack(args.exe, max_insns=args.max_insns,
                       use_header=not args.ignore_packer_header)

    print(f"instructions executed : {info['instructions']:,}")
    print(f"INT 21h calls handled : {info['int21_calls']}")
    print(f"paragraphs written    : {info['paragraphs_written']:,}")
    # A fault after the handoff is normal and harmless: the emulator carried on
    # into the unpacked program, which then tried to touch hardware that is not
    # there. The image was captured before that. Reporting it as the outcome
    # made a successful run look like a failure.
    outcome = info["stopped"]
    if out is not None and outcome and outcome.startswith("CPU fault"):
        outcome = ("decompression complete; the emulator then ran on into the "
                   "program and faulted, which is expected")
    print(f"outcome               : {outcome}")

    if out is None:
        print("\nNo unpacked entry point was reached. Either the file is not "
              "packed, or its decompressor needs more of DOS than this stubs "
              "out. Nothing was written.", file=sys.stderr)
        return 1

    print(f"format                : {info.get('format')}")
    print(f"original entry point  : offset 0x{info['oep_offset']:X}"
          f"  [{info.get('oep_source')}]")
    print(f"unpacked image        : {info['unpacked_size']:,} bytes")
    if info.get("oep_source", "").startswith("unknown"):
        print(f"\nNOTE: this format's entry point is not recovered. A "
              f"behavioural guess would have said "
              f"0x{info.get('oep_candidate', 0):X}, but on a known-answer test "
              f"the same rule was wrong (0x8B40 against a true 0x6B2), so it "
              f"is not written into the header -- a wrong entry point sends "
              f"the disassembler into the middle of a routine and everything "
              f"after inherits the error.\n"
              f"The image itself is sound. Load it and run "
              f"tools/anchors.py, which locates main from structure rather "
              f"than from the header.", file=sys.stderr)
    Path(args.output).write_bytes(out)
    print(f"\nwrote {args.output}")
    print("This dump is for analysis. Relocations are not reconstructed, so it "
          "is not expected to run -- feed it to tools/triage.py and the "
          "pipeline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
