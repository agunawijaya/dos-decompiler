#!/usr/bin/env python3
"""
emuverify.py -- Decide whether two functions are the same by running them.

Every other tool in this package *scores* a resemblance. This one tests an
equivalence: it executes both candidates on identical inputs under an 8086
emulator and compares what they actually did. A function that returns the same
values and writes the same bytes to the same places, over and over, on inputs
chosen to make it branch, is not merely similar.

That matters because resemblance saturates. Constants, strings, call-graph
position and control-flow shape between them reach about 0.88 precision on
Sopwith, and the remaining errors are pairs that genuinely look alike.
Behaviour distinguishes those.

What it is for
--------------
Carrying names from a binary you understand to one you do not: a rebuilt
binary to a shipped one, one release to the next, a DOS build to its Amiga
sibling. Emulation does not care that the compiler differed.

How a function is run
---------------------
  * The load image is mapped at segment 0x1000; DGROUP goes wherever the
    binary's own layout puts it, so global offsets line up between builds.
  * Small model, so SS == DS. Arguments are pushed right-to-left (cdecl) with
    a sentinel return address underneath; execution stops when it returns.
  * Calls are *not* followed. Each is skipped and given a deterministic stub
    return value, in call order. Two implementations of the same function make
    the same calls in the same order, so they see the same stubs -- and the
    callee's own behaviour stays out of the comparison.
  * Interrupts are skipped. Nothing here should reach real hardware.

What is compared
----------------
Return registers, the set of DGROUP writes (offset and value, stack frame
excluded), and the number of calls made -- across several input vectors. A
pair matches only if every vector agrees, and only if the function did
something observable: a routine that ignores its arguments and returns zero
matches every other such routine, so those are reported as indistinguishable
rather than as matches.

Usage:
    python emuverify.py a.exe a.map b.exe b.map --report out.md
    python emuverify.py a.exe a.map b.exe b.map --pairs candidates.json
"""

import argparse
import json
import struct
import sys
from pathlib import Path

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,
                         UC_HOOK_INTR, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                         UcError)
    from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
                                   UC_X86_REG_DX, UC_X86_REG_SI, UC_X86_REG_DI,
                                   UC_X86_REG_BP, UC_X86_REG_SP, UC_X86_REG_IP,
                                   UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                                   UC_X86_REG_SS, UC_X86_REG_FLAGS)
except ImportError:  # pragma: no cover
    print("emuverify: unicorn is required (pip install unicorn)", file=sys.stderr)
    raise

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
except ImportError:  # pragma: no cover
    print("emuverify: capstone is required (pip install capstone)", file=sys.stderr)
    raise

MEM_SIZE = 0x110000          # a little over 1 MB, so segment 0x1000 + 64K fits
IMAGE_SEG = 0x1000
IMAGE_BASE = IMAGE_SEG << 4
SENTINEL_IP = 0xFFF0         # return address that means "the function ended"
STACK_TOP = 0xFF00           # SP within DGROUP; small model puts SS == DS
FRAME_GUARD = 0xF000         # writes above this are stack frame, not globals
MAX_INSNS = 40000

# Input vectors, and there are deliberately only four.
#
# The obvious intuition -- more inputs means more discrimination means more
# matches -- is wrong here, and measurably so. Sweeping the count against
# Sopwith's two builds:
#
#     vectors    1    2    3    4    5    6    8   10   12
#     matches   93  107  110  110  110   98   97   97   97
#
# with zero incorrect matches throughout. One vector is genuinely too few:
# functions that ignore their arguments cannot be told apart, so they are
# filtered as uninformative. Past five it degrades, because the extra vectors
# were wilder -- values like 0x8000 and 0x5000 used as pointers -- and a wild
# access lands somewhere that depends on code generation. That breaks matches
# between two builds of the *same* function, which is exactly the thing we are
# trying not to do.
#
# So: keep arguments inside plausible data ranges. Zero and one separate
# functions branching on emptiness; 0xFFFF is -1 to signed code and a large
# bound to unsigned; the last vector points at modest DGROUP offsets so that
# pointer arguments dereference real globals.
VECTORS = [
    (0, 0, 0, 0),
    (1, 2, 3, 4),
    (0xFFFF, 1, 0, 7),
    (0x0100, 0x0200, 0x0300, 0x0400),
]


def load_image(exe_path):
    data = Path(exe_path).read_bytes()
    if data[:2] not in (b"MZ", b"ZM"):
        raise SystemExit(f"{exe_path}: not an MZ executable")
    hdr = struct.unpack_from("<H", data, 8)[0] * 16
    pages = struct.unpack_from("<H", data, 4)[0]
    last = struct.unpack_from("<H", data, 2)[0]
    end = (pages - 1) * 512 + (last if last else 512) if pages else len(data)
    return data[hdr:end]


def dgroup_paragraph(mapfile):
    """Paragraph of DGROUP, taken from any data symbol in the map."""
    import re
    pat = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+"
                     r"[A-Za-z_@$?][\w@$?.]*\s*$")
    for line in Path(mapfile).read_text(encoding="latin-1",
                                        errors="replace").splitlines():
        m = pat.match(line)
        if m:
            seg = int(m.group(1), 16)
            if seg != 0:
                return seg
    raise SystemExit(f"{mapfile}: no data segment found")


def code_symbols(mapfile):
    import re
    pat = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+"
                     r"([A-Za-z_@$?][\w@$?.]*)\s*$")
    out = {}
    for line in Path(mapfile).read_text(encoding="latin-1",
                                        errors="replace").splitlines():
        m = pat.match(line)
        if m and int(m.group(1), 16) == 0:
            name = m.group(3)
            out.setdefault(name, int(m.group(2), 16))
    return out


def dgroup_from_relocations(exe_path):
    """Recover the data segment from the MZ relocation table.

    A binary with no linker map still tells you where DGROUP is: in a
    small-model program the startup loads it from a relocated word, so the
    relocation targets hold the segment values the loader patches in. The
    lower of them is DGROUP; the higher is the stack.
    """
    data = Path(exe_path).read_bytes()
    hdr = struct.unpack_from("<H", data, 8)[0] * 16
    nreloc = struct.unpack_from("<H", data, 6)[0]
    table = struct.unpack_from("<H", data, 24)[0]
    values = []
    for i in range(nreloc):
        off, seg = struct.unpack_from("<HH", data, table + i * 4)
        pos = hdr + (seg << 4) + off
        if pos + 2 <= len(data):
            values.append(struct.unpack_from("<H", data, pos)[0])
    if not values:
        raise SystemExit(f"{exe_path}: no relocations, cannot locate DGROUP")
    return min(values)


def entries_from_functions_json(path):
    """Function offsets from the pipeline's export, for a binary with no map.

    Names are the Ghidra placeholders, so a match here transfers a name *to*
    this binary rather than confirming one it already has.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for f in data["functions"]:
        if f.get("thunk"):
            continue
        off = int(f["entry"].split(":")[1], 16)
        out.setdefault(f["entry"], off)
    return out


class Emulator:
    def __init__(self, exe, symbols_source, dgroup=None):
        self.image = load_image(exe)
        if str(symbols_source).lower().endswith(".json"):
            self.symbols = entries_from_functions_json(symbols_source)
            self.dgroup = dgroup if dgroup is not None \
                else dgroup_from_relocations(exe)
        else:
            self.symbols = code_symbols(symbols_source)
            self.dgroup = dgroup if dgroup is not None \
                else dgroup_paragraph(symbols_source)
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)

    def run(self, offset, args, max_insns=MAX_INSNS):
        """Execute one function. Returns an observation dict, or None if it
        could not be run to completion."""
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, MEM_SIZE)
        uc.mem_write(IMAGE_BASE, bytes(self.image))
        uc.mem_write(IMAGE_BASE + SENTINEL_IP, b"\xF4")     # HLT at the sentinel

        ds = self.dgroup + IMAGE_SEG
        uc.reg_write(UC_X86_REG_CS, IMAGE_SEG)
        uc.reg_write(UC_X86_REG_DS, ds)
        uc.reg_write(UC_X86_REG_ES, ds)
        uc.reg_write(UC_X86_REG_SS, ds)                     # small model
        uc.reg_write(UC_X86_REG_BP, 0)
        uc.reg_write(UC_X86_REG_FLAGS, 0x0202)

        dbase = ds << 4
        sp = STACK_TOP
        for value in reversed(args):                        # cdecl, right to left
            sp -= 2
            uc.mem_write(dbase + sp, struct.pack("<H", value & 0xFFFF))
        sp -= 2
        uc.mem_write(dbase + sp, struct.pack("<H", SENTINEL_IP))
        uc.reg_write(UC_X86_REG_SP, sp)

        # "budget" and "aborted" are different outcomes and must not be
        # conflated: running out of instructions is what a non-returning
        # function does and still yields usable evidence, while a CPU fault
        # means the run was meaningless.
        state = {"calls": 0, "writes": set(), "reads": set(), "insns": 0,
                 "done": False, "aborted": None, "budget": False}

        def on_code(mu, address, size, _):
            state["insns"] += 1
            if state["insns"] > max_insns:
                state["budget"] = True
                mu.emu_stop()
                return
            ip = address - IMAGE_BASE
            try:
                code = mu.mem_read(address, min(15, size + 14))
            except UcError:
                return
            insn = next(self.md.disasm(bytes(code), address), None)
            if insn is None:
                return
            if insn.mnemonic.startswith("call"):
                # Skip the call. Both implementations of a function make the
                # same calls in the same order, so a counter-derived stub
                # return keeps them comparable without executing the callee.
                state["calls"] += 1
                mu.reg_write(UC_X86_REG_AX, (0x1234 + state["calls"] * 7) & 0xFFFF)
                mu.reg_write(UC_X86_REG_IP, (ip + insn.size) & 0xFFFF)

        def on_intr(mu, intno, _):
            pass                                            # never reach hardware

        def on_write(mu, access, address, size, value, _):
            off = address - dbase
            if 0 <= off < FRAME_GUARD:                      # a global, not the frame
                state["writes"].add((off, size, value & 0xFFFF))

        def on_read(mu, access, address, size, value, _):
            # Which globals a function *reads* is nearly as identifying as
            # what it writes, and it rescues the large class of routines that
            # only inspect state. Without this, 80 of 173 functions were
            # behaviourally indistinguishable; with it, far fewer.
            off = address - dbase
            if 0 <= off < FRAME_GUARD:
                state["reads"].add((off, size))

        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.hook_add(UC_HOOK_INTR, on_intr)
        uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
        uc.hook_add(UC_HOOK_MEM_READ, on_read)

        try:
            uc.emu_start(IMAGE_BASE + offset, IMAGE_BASE + SENTINEL_IP,
                         timeout=2_000_000, count=0)
        except UcError as e:
            state["aborted"] = str(e)

        # emu_start stops *before* executing the `until` address, so the code
        # hook never fires there. Completion has to be read from IP afterwards.
        if (uc.reg_read(UC_X86_REG_IP) & 0xFFFF) == SENTINEL_IP:
            state["done"] = True

        if not state["done"] and not state["budget"]:
            return None                 # a fault, not a long-running function

        if not state["done"]:
            # The function never returned: an interrupt handler, a longjmp
            # target, or a main loop. Those are exactly the functions worth
            # identifying, so rather than discard them, compare what they
            # touched within the budget.
            #
            # Only the *set* of global offsets is kept -- no values, no counts,
            # no registers. Two builds of one function run a different number
            # of loop iterations in the same instruction budget, so anything
            # count-dependent would differ for reasons that say nothing about
            # what the function is.
            return {
                "partial": True,
                "ax": None, "dx": None, "calls": None,
                "writes": tuple(sorted({off for off, _, _ in state["writes"]})),
                "reads": tuple(sorted({off for off, _ in state["reads"]})),
            }

        return {
            "partial": False,
            "ax": uc.reg_read(UC_X86_REG_AX),
            "dx": uc.reg_read(UC_X86_REG_DX),
            "calls": state["calls"],
            "writes": tuple(sorted(state["writes"])),
            "reads": tuple(sorted(state["reads"])),
        }

    def profile(self, offset):
        """Observations across every input vector, or None if unrunnable."""
        obs = []
        for vec in VECTORS:
            r = self.run(offset, vec)
            if r is None:
                return None
            obs.append(r)
        return obs


MIN_PARTIAL_TOUCHES = 4     # a partial profile below this identifies nothing


def is_partial(obs):
    return any(o.get("partial") for o in obs)


def signature(obs):
    return tuple((o["ax"], o["dx"], o["calls"], o["writes"], o["reads"])
                 for o in obs)


def informative(obs):
    """True when the function did something an observer could distinguish.

    A routine that ignores its arguments, touches no globals and returns a
    constant is behaviourally identical to every other such routine. Calling
    those a match would be arithmetic, not evidence.
    """
    if is_partial(obs):
        # A non-returning function has no return value to compare, so the only
        # evidence is which globals it touched. Demand enough of them that the
        # set means something.
        touched = set()
        for o in obs:
            touched.update(o["writes"])
            touched.update(o["reads"])
        return len(touched) >= MIN_PARTIAL_TOUCHES
    if any(o["writes"] or o["reads"] for o in obs):
        return True
    outputs = {(o["ax"], o["dx"], o["calls"]) for o in obs}
    return len(outputs) > 1


def compare(a_emu, b_emu, a_offsets, b_offsets, progress=None):
    a_prof, b_prof = {}, {}
    for label, emu, offsets, store in (("A", a_emu, a_offsets, a_prof),
                                       ("B", b_emu, b_offsets, b_prof)):
        for i, (name, off) in enumerate(offsets.items()):
            if progress and i % 25 == 0:
                progress(f"profiling {label} {i}/{len(offsets)}")
            obs = emu.profile(off)
            if obs is not None:
                store[name] = obs

    index = {}
    for name, obs in b_prof.items():
        if informative(obs):
            index.setdefault(signature(obs), []).append(name)

    matches, ambiguous, uninformative, partial_matches = [], [], [], []
    for name, obs in a_prof.items():
        if not informative(obs):
            uninformative.append(name)
            continue
        hits = index.get(signature(obs), [])
        if len(hits) == 1:
            matches.append((name, hits[0]))
            if is_partial(obs):
                partial_matches.append(name)
        elif len(hits) > 1:
            ambiguous.append((name, hits))
    return {
        "profiled_a": len(a_prof), "profiled_b": len(b_prof),
        "matches": matches, "ambiguous": ambiguous,
        "uninformative": uninformative,
        # A partial profile compares only which globals were touched, because
        # the function never returned. Reported separately: it is weaker
        # evidence than a completed run, even when it is exact.
        "partial_matches": partial_matches,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe_a")
    ap.add_argument("map_a", help="linker map, or a functions.json from the pipeline")
    ap.add_argument("exe_b")
    ap.add_argument("map_b", help="linker map, or a functions.json from the pipeline")
    ap.add_argument("--dgroup-a", help="data segment paragraph for A, if known")
    ap.add_argument("--dgroup-b", help="data segment paragraph for B, if known")
    ap.add_argument("--limit", type=int, help="only the first N functions of each")
    ap.add_argument("--json", help="write results here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    a = Emulator(args.exe_a, args.map_a,
                 int(args.dgroup_a, 0) if args.dgroup_a else None)
    b = Emulator(args.exe_b, args.map_b,
                 int(args.dgroup_b, 0) if args.dgroup_b else None)

    a_offsets = dict(list(a.symbols.items())[:args.limit] if args.limit
                     else a.symbols.items())
    b_offsets = dict(list(b.symbols.items())[:args.limit] if args.limit
                     else b.symbols.items())

    def progress(msg):
        if not args.quiet:
            print(f"  {msg}", file=sys.stderr)

    res = compare(a, b, a_offsets, b_offsets, progress)

    print(f"functions profiled : {res['profiled_a']} in A, {res['profiled_b']} in B")
    print(f"unique matches     : {len(res['matches'])}"
          + (f" ({len(res['partial_matches'])} from non-returning functions)"
             if res.get("partial_matches") else ""))
    print(f"ambiguous          : {len(res['ambiguous'])}")
    print(f"uninformative      : {len(res['uninformative'])}")

    # When both sides carry real symbol names, agreement is checkable. When one
    # side is a functions.json its "names" are Ghidra placeholders, so the
    # comparison is meaningless and reporting a precision would be a fiction.
    checkable = not (str(args.map_a).lower().endswith(".json")
                     or str(args.map_b).lower().endswith(".json"))
    if res["matches"] and checkable:
        correct = sum(1 for x, y in res["matches"] if x == y)
        wrong = len(res["matches"]) - correct
        print(f"\nboth maps carry names, so the answer is checkable:")
        print(f"  correct   : {correct}")
        print(f"  incorrect : {wrong}")
        print(f"  precision : {correct / max(1, len(res['matches'])):.3f}")
        if wrong:
            print("\n  mismatches:")
            for x, y in res["matches"]:
                if x != y:
                    print(f"    {x} -> {y}")
    elif res["matches"]:
        print("\nnames carried across (first 20):")
        for x, y in res["matches"][:20]:
            print(f"  {x:<22} -> {y}")

    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
