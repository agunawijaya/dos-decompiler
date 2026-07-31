#!/usr/bin/env python3
"""
bindiff.py -- Compare a reconstruction against the original, instruction by
instruction, tolerating layout differences.

This is the oracle the extended workflow turns on. Readable decompilation asks
"can a person follow this?", which no tool can answer. Reconstruction asks "does
my source compile to the same code?", which is a question a machine can settle,
and this settles it.

Why not just compare bytes
--------------------------
Because a reconstruction almost never lands at the same addresses. Add one
instruction near the top and every branch displacement after it shifts, every
absolute reference moves, and a byte comparison reports thousands of
differences that mean nothing. What matters is whether the *instructions* are
the same, allowing for having been placed somewhere else.

So each instruction is reduced to a form that survives relocation:

  * mnemonic and operand shapes are compared exactly
  * relative branch targets become distances, not addresses -- `jmp +7` equals
    `jmp +7` wherever it sits
  * segment values are wildcarded, because the linker chooses them
  * everything else, including displacements and immediates, is compared
    literally -- those are the program's own constants and a difference is
    real

What it reports
---------------
Per function: identical, or the index of the first instruction that differs and
both renderings of it. Overall: how many functions match. That number is the
progress bar for a reconstruction -- it only goes up when the source gets
closer, and it cannot be talked up.

Usage:
    python bindiff.py original.exe rebuilt.exe --map-a a.map --map-b b.map
    python bindiff.py original.exe rebuilt.exe --map-a a.map --map-b b.map \\
                      --report diff.md --show 5
"""

import argparse
import re
import struct
import sys
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
except ImportError:  # pragma: no cover
    print("bindiff: capstone is required (pip install capstone)", file=sys.stderr)
    raise

# Branches whose operand is a distance rather than a place.
RELATIVE = {
    "jmp", "call", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg",
    "jge", "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "loop",
    "loope", "loopne",
}

SYMBOL_LINE = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+"
                         r"([A-Za-z_@$?][\w@$?.]*)\s*$")


def load_image(path):
    data = Path(path).read_bytes()
    if data[:2] not in (b"MZ", b"ZM"):
        raise SystemExit(f"{path}: not an MZ executable")
    hdr = struct.unpack_from("<H", data, 8)[0] * 16
    pages = struct.unpack_from("<H", data, 4)[0]
    last = struct.unpack_from("<H", data, 2)[0]
    end = (pages - 1) * 512 + (last if last else 512) if pages else len(data)
    return data[hdr:end]


def code_symbols(mapfile):
    """{name: offset} for the code segment, in address order."""
    out = {}
    for line in Path(mapfile).read_text(encoding="latin-1",
                                        errors="replace").splitlines():
        m = SYMBOL_LINE.match(line)
        if m and int(m.group(1), 16) == 0:
            out.setdefault(m.group(3).lstrip("_").rstrip("_"),
                           int(m.group(2), 16))
    return out


def resolve(symbols, offset):
    """Which function contains this offset, and how far into it."""
    best = None
    for name, start in symbols.items():
        if start <= offset and (best is None or start > best[1]):
            best = (name, start)
    if best is None:
        return None
    return f"{best[0]}+{offset - best[1]}"


def normalise(insn, symbols=None, own=None):
    """Reduce an instruction to what should survive being relocated.

    The subtlety is inter-function calls. Turning an absolute target into a
    distance is not enough: two builds of the same function call the same
    callee, but if anything between them changed size the distance differs, and
    a naive comparison reports a difference that is purely about layout --
    which is the thing we set out to tolerate.

    So a branch leaving the current function is resolved through the symbol
    table to `callee+offset`, which is stable. A branch staying inside is
    compared as a distance, which is stable too because the function's own
    internals moved together.
    """
    mn = insn.mnemonic
    ops = insn.op_str

    if mn in RELATIVE and ops.startswith("0x"):
        try:
            target = int(ops, 16)
        except ValueError:
            target = None
        if target is not None:
            inside = own is not None and own[0] <= target < own[1]
            if inside or symbols is None:
                return f"{mn} rel{target - (insn.address + insn.size):+d}"
            named = resolve(symbols, target)
            return f"{mn} {named}" if named else \
                   f"{mn} rel{target - (insn.address + insn.size):+d}"

    # Segment values are the linker's business, not the program's. A four-digit
    # hex immediate loaded into a segment register is wildcarded; anything else
    # is the program's own constant and stays.
    if mn == "mov" and re.match(r"^(ds|es|ss|cs),", ops):
        ops = re.sub(r"0x[0-9a-f]{1,4}", "<seg>", ops)

    return f"{mn} {ops}".strip()


def disassemble(image, offset, limit=4096):
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    out = []
    for insn in md.disasm(bytes(image[offset:offset + limit]), offset):
        out.append(insn)
        if insn.mnemonic in ("ret", "retf", "iret", "jmp") and len(out) > 1:
            break
    return out


def compare_function(a_img, a_off, b_img, b_off, max_insns=2048,
                     a_sym=None, b_sym=None, a_span=None, b_span=None):
    """Walk both, stopping at the first difference."""
    ia = disassemble(a_img, a_off)
    ib = disassemble(b_img, b_off)
    n = min(len(ia), len(ib), max_insns)
    for i in range(n):
        na = normalise(ia[i], a_sym, a_span)
        nb = normalise(ib[i], b_sym, b_span)
        if na != nb:
            return {"identical": False, "index": i, "a": na, "b": nb,
                    "a_insns": len(ia), "b_insns": len(ib)}
    if len(ia) != len(ib):
        return {"identical": False, "index": n,
                "a": f"(ends after {len(ia)})", "b": f"(ends after {len(ib)})",
                "a_insns": len(ia), "b_insns": len(ib)}
    return {"identical": True, "insns": len(ia)}


def run(exe_a, map_a, exe_b, map_b):
    a_img, b_img = load_image(exe_a), load_image(exe_b)
    a_sym, b_sym = code_symbols(map_a), code_symbols(map_b)
    common = sorted(set(a_sym) & set(b_sym), key=lambda n: a_sym[n])

    def span(symbols, name):
        """Where this function starts and where the next symbol begins."""
        start = symbols[name]
        later = [o for o in symbols.values() if o > start]
        return start, (min(later) if later else start + 0x1000)

    results = []
    for name in common:
        r = compare_function(a_img, a_sym[name], b_img, b_sym[name],
                             a_sym=a_sym, b_sym=b_sym,
                             a_span=span(a_sym, name), b_span=span(b_sym, name))
        r["name"] = name
        r["a_offset"] = a_sym[name]
        r["b_offset"] = b_sym[name]
        results.append(r)

    matched = [r for r in results if r["identical"]]
    return {
        "functions_compared": len(results),
        "identical": len(matched),
        "differing": len(results) - len(matched),
        "only_in_a": sorted(set(a_sym) - set(b_sym)),
        "only_in_b": sorted(set(b_sym) - set(a_sym)),
        "results": results,
    }


def render(res, show):
    out = []
    A = out.append
    total = res["functions_compared"]
    pct = res["identical"] / total if total else 0
    A("# Reconstruction diff")
    A("")
    A(f"- functions in both builds : {total}")
    A(f"- instruction-identical    : **{res['identical']}**  ({pct:.1%})")
    A(f"- differing                : {res['differing']}")
    if res["only_in_a"]:
        A(f"- only in the original     : {len(res['only_in_a'])} "
          f"({', '.join(res['only_in_a'][:8])}"
          f"{'...' if len(res['only_in_a']) > 8 else ''})")
    if res["only_in_b"]:
        A(f"- only in the reconstruction: {len(res['only_in_b'])} "
          f"({', '.join(res['only_in_b'][:8])}"
          f"{'...' if len(res['only_in_b']) > 8 else ''})")
    A("")

    diffs = [r for r in res["results"] if not r["identical"]]
    if diffs:
        A("## Where they first diverge")
        A("")
        A("| function | at instruction | original | reconstruction |")
        A("|---|---:|---|---|")
        for r in diffs[:show]:
            A(f"| `{r['name']}` | {r['index']} | `{r['a']}` | `{r['b']}` |")
        if len(diffs) > show:
            A(f"| ... | | {len(diffs) - show} more | |")
        A("")
    if res["identical"]:
        A("## Already identical")
        A("")
        names = [r["name"] for r in res["results"] if r["identical"]]
        A(", ".join(f"`{n}`" for n in names[:40])
          + (f" ... and {len(names) - 40} more" if len(names) > 40 else ""))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("original")
    ap.add_argument("rebuilt")
    ap.add_argument("--map-a", required=True, help="linker map for the original")
    ap.add_argument("--map-b", required=True, help="linker map for the rebuild")
    ap.add_argument("--show", type=int, default=15,
                    help="how many divergences to list")
    ap.add_argument("--report", help="write the report here")
    args = ap.parse_args()

    res = run(args.original, args.map_a, args.rebuilt, args.map_b)
    text = render(res, args.show)
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
        print(f"wrote {args.report}")
    print(f"functions compared    : {res['functions_compared']}")
    print(f"instruction-identical : {res['identical']}")
    print(f"differing             : {res['differing']}")
    if not args.report:
        print()
        print(text)
    # Non-zero while anything still differs: usable directly in a build loop.
    return 0 if res["differing"] == 0 and res["functions_compared"] else 1


if __name__ == "__main__":
    sys.exit(main())
