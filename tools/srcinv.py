#!/usr/bin/env python3
"""
srcinv.py -- Inventory the functions and globals in 1980s C and MASM sources.

Used two ways:

  1. When ground-truth source exists (validation / regression testing), this
     produces the reference list that the scoring harness compares against.
  2. When decompiling a game whose source is lost, run it over any *related*
     source you do have (a later port, a sibling product, leaked headers) to
     seed the symbol and structure catalog.

Parsing target is deliberately narrow: pre-ANSI K&R C as compiled by
Microsoft C 4/5 and Lattice C, plus MASM 5 assembly. It is regex-driven, not a
real parser -- 1980s sources predate anything a modern parser expects, and a
heuristic that reports its own uncertainty is more useful here than a strict
parser that refuses the file.

Usage:
    python srcinv.py SRCDIR                 # report
    python srcinv.py SRCDIR --json out.json # machine-readable
"""

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- C parsing

# A K&R definition looks like:
#       main( argc, argv )        <- no types in the parameter list
#       int argc;                 <- parameter declarations follow
#       char *argv[];
#       {
# and an early-ANSI one like:
#       void swmove( void )
#       {
# Both end with a brace in column 0. Matching "identifier(...)" followed
# eventually by a line that is just "{" catches both without needing to
# understand types.
C_FUNC = re.compile(
    r"""^
    # Optional return type. It must end in whitespace or a '*', otherwise the
    # regex happily eats the first letter of the function name itself.
    (?P<prefix>[A-Za-z_][A-Za-z0-9_ \t\*]*[ \t\*])?
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)            # function name
    [ \t]*\(                                    # open paren
    (?P<args>[^;{}]*?)                          # parameter list, no ; or braces
    \)[ \t]*$                                   # close paren, end of line
    """,
    re.VERBOSE)

# Declarations we must NOT count as definitions.
C_PROTO = re.compile(r"\)\s*;")

C_GLOBAL = re.compile(
    r"""^(?P<type>(?:extern[ \t]+|static[ \t]+|unsigned[ \t]+|struct[ \t]+\w+[ \t]+
        |int|char|long|short|float|double|void|BOOL|BIOFD|[A-Z][A-Z0-9_]*)
        [ \t\*]+)
        (?P<name>[A-Za-z_][A-Za-z0-9_]*)
        (?P<rest>[^;=]*)[;=]""",
    re.VERBOSE)

C_DEFINE = re.compile(r"^#[ \t]*define[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
                      r"(?P<params>\([^)]*\))?[ \t]+(?P<value>.+?)[ \t]*$")

C_TYPEDEF_END = re.compile(r"^\}[ \t]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*;")

# ------------------------------------------------------------- ASM parsing

ASM_PROC = re.compile(r"^(?P<name>[A-Za-z_@$?][A-Za-z0-9_@$?]*)[ \t]+PROC\b",
                      re.IGNORECASE)
ASM_PUBLIC = re.compile(r"^[ \t]*PUBLIC[ \t]+(?P<names>.+?)[ \t]*(?:;.*)?$",
                        re.IGNORECASE)
ASM_EXTRN = re.compile(r"^[ \t]*EXTRN[ \t]+(?P<names>.+?)[ \t]*(?:;.*)?$",
                       re.IGNORECASE)
ASM_SEGMENT = re.compile(r"^(?P<name>[A-Za-z_@$?][A-Za-z0-9_@$?]*)[ \t]+SEGMENT\b",
                         re.IGNORECASE)
ASM_LABEL = re.compile(r"^(?P<name>[A-Za-z_@$?][A-Za-z0-9_@$?]*):")

# Keywords that a "identifier(" line might start with but which are not
# function definitions.
C_KEYWORDS = {
    "if", "while", "for", "switch", "return", "sizeof", "do", "else",
    "typedef", "struct", "union", "enum", "case", "default", "goto",
    "printf", "define", "include", "ifdef", "ifndef", "endif",
}


def strip_comments(text):
    """Remove /* */ comments but keep line count intact."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j == -1:
                # unterminated: keep newlines so line numbers stay right
                out.append("\n" * text.count("\n", i))
                break
            out.append("\n" * text.count("\n", i, j))
            i = j + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


INT_LITERAL = re.compile(r"\b(0[xX][0-9a-fA-F]+|\d+)\b")
CALL_SITE = re.compile(r"\b([A-Za-z_]\w*)[ \t]*\(")


def resolve_defines(defines):
    """Build name -> integer map for object-like #defines.

    1980s sources encode meaningful magic numbers as #defines (SCR_SEGM
    0xB800, KEYINT 0x09). Resolving them is what lets a source function and a
    binary function be compared on constants, which is the single most
    discriminating signal available when symbols are gone.
    """
    raw = {d["name"]: d["value"] for d in defines if not d["function_like"]}
    out = {}
    for _ in range(4):  # a few passes resolve defines written in terms of others
        progress = False
        for name, value in raw.items():
            if name in out:
                continue
            expr = value.split("/*")[0].strip().rstrip(";")
            substituted = re.sub(
                r"\b[A-Za-z_]\w*\b",
                lambda m: str(out[m.group(0)]) if m.group(0) in out else m.group(0),
                expr)
            if not re.fullmatch(r"[0-9xXa-fA-F+\-*/%()<>& \t]*", substituted):
                continue
            if not substituted.strip():
                continue
            try:
                # Only arithmetic on literals reaches here, so eval is
                # evaluating a closed numeric expression, not source code.
                val = eval(substituted, {"__builtins__": {}}, {})
            except Exception:
                continue
            if isinstance(val, int):
                out[name] = val
                progress = True
        if not progress:
            break
    return out


def control_shape(text):
    """Count the decision structure of a C function body.

    These are the features a compiler cannot discard. An `if` must become a
    conditional branch; a loop must become a back edge. So the same quantities
    can be counted in the binary (see ExportDecompiledC.java) and compared,
    which gives a similarity signal that survives optimisation far better than
    constants or strings do.

    Counting is textual and therefore approximate -- a `for` inside a string
    literal would be counted -- but comments are already stripped by the
    caller and the error is small relative to the signal.
    """
    def count(pattern):
        return len(re.findall(pattern, text))

    ifs = count(r"\bif\s*\(")
    elses = count(r"\belse\b")
    fors = count(r"\bfor\s*\(")
    whiles = count(r"\bwhile\s*\(")
    dos = count(r"\bdo\b")
    switches = count(r"\bswitch\s*\(")
    cases = count(r"\bcase\b") + count(r"\bdefault\s*:")
    returns = count(r"\breturn\b")
    gotos = count(r"\bgoto\b")
    ands = count(r"&&")
    ors = count(r"\|\|")
    ternaries = count(r"\?")
    loops = fors + whiles + dos

    # McCabe complexity, counted the standard way: one plus every point at
    # which control can diverge.
    cyclomatic = 1 + ifs + loops + cases + ands + ors + ternaries

    depth = maxdepth = 0
    for ch in text:
        if ch == "{":
            depth += 1
            maxdepth = max(maxdepth, depth)
        elif ch == "}":
            depth -= 1

    return {
        "ifs": ifs, "elses": elses, "loops": loops, "switches": switches,
        "cases": cases, "returns": returns, "gotos": gotos,
        "cyclomatic": cyclomatic, "max_depth": maxdepth,
    }


def body_facts(lines, brace_line, defines_map):
    """Extract call targets and notable constants from a function body."""
    depth, i, body = 0, brace_line, []
    started = False
    while i < len(lines):
        line = lines[i]
        body.append(line)
        depth += line.count("{") - line.count("}")
        if "{" in line:
            started = True
        if started and depth <= 0:
            break
        i += 1
    text = "\n".join(body)

    calls = sorted({m.group(1) for m in CALL_SITE.finditer(text)
                    if m.group(1) not in C_KEYWORDS})

    # String literals survive compilation untouched, which makes them the
    # single most reliable link between a source function and a binary one.
    strings = sorted({s for s in re.findall(r'"((?:[^"\\]|\\.)*)"', text)
                      if len(s) >= 3})

    shape = control_shape(text)

    constants = set()
    for m in INT_LITERAL.finditer(text):
        tok = m.group(1)
        val = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
        if val >= 0x10:
            constants.add(val)
    for m in re.finditer(r"\b([A-Z][A-Z0-9_]{2,})\b", text):
        if m.group(1) in defines_map:
            val = defines_map[m.group(1)]
            if val >= 0x10:
                constants.add(val)

    return calls, sorted(constants), len(body), i, strings, shape


def parse_c(path, defines_map=None):
    defines_map = defines_map or {}
    raw = path.read_text(encoding="latin-1")
    text = strip_comments(raw)
    lines = text.splitlines()

    funcs, globals_, defines, types = [], [], [], []

    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#"):
            m = C_DEFINE.match(stripped)
            if m:
                defines.append({
                    "name": m.group("name"),
                    "value": m.group("value").strip(),
                    "function_like": bool(m.group("params")),
                    "line": i + 1,
                })
            continue

        m = C_TYPEDEF_END.match(stripped)
        if m:
            types.append({"name": m.group("name"), "line": i + 1})
            continue

        # Function definition: "name(args)" on its own line, and the next
        # non-blank lines eventually reach a "{" in column 0, possibly after
        # K&R parameter declarations.
        m = C_FUNC.match(stripped)
        if m and not C_PROTO.search(stripped) and m.group("name") not in C_KEYWORDS:
            kr_decls = []
            j = i + 1
            is_def = False
            while j < len(lines) and j < i + 40:
                nxt = lines[j].rstrip()
                if not nxt:
                    j += 1
                    continue
                if nxt.startswith("{"):
                    is_def = True
                    break
                # K&R parameter declaration lines end in ';' and are indented
                # or start at column 0 with a type keyword.
                if nxt.endswith(";") and not nxt.lstrip().startswith("#"):
                    kr_decls.append(nxt.strip())
                    j += 1
                    continue
                break
            if is_def:
                args = m.group("args").strip()
                if args in ("", "void"):
                    params = []
                else:
                    params = [a.strip() for a in args.split(",") if a.strip()]
                calls, consts, nlines, _, strings, shape = body_facts(
                    lines, j, defines_map)
                funcs.append({
                    "name": m.group("name"),
                    "file": path.name,
                    "line": i + 1,
                    "kind": "c",
                    "style": "knr" if kr_decls else "ansi",
                    "param_count": len(params),
                    "params": params,
                    "param_decls": kr_decls,
                    "return_hint": (m.group("prefix") or "").strip() or "int",
                    "body_lines": nlines,
                    "calls": calls,
                    "constants": consts,
                    "strings": strings,
                    "shape": shape,
                })
            continue

        # File-scope variable: only when the line starts in column 0.
        if line and not line[0].isspace():
            g = C_GLOBAL.match(stripped)
            if g and "(" not in g.group("name"):
                funcs_names = {f["name"] for f in funcs}
                if g.group("name") not in funcs_names:
                    globals_.append({
                        "name": g.group("name"),
                        "type": g.group("type").strip(),
                        "file": path.name,
                        "line": i + 1,
                        "extern": stripped.startswith("extern"),
                        "array": "[" in g.group("rest"),
                    })

    return funcs, globals_, defines, types


ASM_ENDP = re.compile(r"^(?P<name>[A-Za-z_@$?][A-Za-z0-9_@$?]*)[ \t]+ENDP\b",
                      re.IGNORECASE)
ASM_CALL = re.compile(r"^[ \t]*call[ \t]+(?:near[ \t]+ptr[ \t]+|far[ \t]+ptr[ \t]+)?"
                      r"(?P<name>[A-Za-z_@$?][A-Za-z0-9_@$?]*)", re.IGNORECASE)
ASM_INT = re.compile(r"^[ \t]*int[ \t]+(?P<num>[0-9a-fA-F]+)h?\b", re.IGNORECASE)
ASM_NUM = re.compile(r"\b(?P<num>[0-9][0-9a-fA-F]*)h\b|\b(?P<dec>\d+)\b",
                     re.IGNORECASE)


def parse_asm(path):
    raw = path.read_text(encoding="latin-1")
    funcs, publics, externs, segments = [], set(), set(), []
    current = None

    for i, line in enumerate(raw.splitlines()):
        line = line.split(";")[0].rstrip()
        if not line:
            continue

        if current is not None:
            m = ASM_ENDP.match(line)
            if m:
                current["calls"] = sorted(set(current["calls"]))
                current["constants"] = sorted(set(current["constants"]))
                current = None
            else:
                mc = ASM_CALL.match(line)
                if mc:
                    current["calls"].append(mc.group("name"))
                mi = ASM_INT.match(line)
                if mi:
                    current["interrupts"].append(int(mi.group("num"), 16))
                for mn in ASM_NUM.finditer(line):
                    tok, dec = mn.group("num"), mn.group("dec")
                    val = int(tok, 16) if tok else int(dec)
                    if val >= 0x10:
                        current["constants"].append(val)
                current["body_lines"] += 1

        m = ASM_PROC.match(line)
        if m:
            current = {
                "name": m.group("name"),
                "file": path.name,
                "line": i + 1,
                "kind": "asm",
                "style": "proc",
                "param_count": None,
                "params": [],
                "param_decls": [],
                "return_hint": None,
                "body_lines": 0,
                "calls": [],
                "constants": [],
                "interrupts": [],
            }
            funcs.append(current)
            continue
        m = ASM_SEGMENT.match(line)
        if m:
            segments.append({"name": m.group("name"), "line": i + 1})
            continue
        m = ASM_PUBLIC.match(line)
        if m:
            for nm in re.split(r"[,\s]+", m.group("names")):
                if nm:
                    publics.add(nm)
            continue
        m = ASM_EXTRN.match(line)
        if m:
            for item in m.group("names").split(","):
                nm = item.split(":")[0].strip()
                if nm:
                    externs.add(nm)

    # A PUBLIC symbol with no PROC is usually a near label used as an entry
    # point -- still a function as far as the binary is concerned.
    proc_names = {f["name"] for f in funcs}
    for nm in sorted(publics - proc_names):
        funcs.append({
            "name": nm, "file": path.name, "line": None, "kind": "asm",
            "style": "public-label", "param_count": None, "params": [],
            "param_decls": [], "return_hint": None, "body_lines": 0,
            "calls": [], "constants": [], "interrupts": [],
        })

    return funcs, sorted(publics), sorted(externs), segments


def scan(srcdir):
    srcdir = Path(srcdir)
    result = {
        "source_dir": str(srcdir),
        "files": [],
        "functions": [],
        "globals": [],
        "defines": [],
        "types": [],
        "asm_publics": [],
        "asm_externs": [],
        "asm_segments": [],
    }

    # Pass 1: collect every #define in the tree, headers included, so that
    # constants inside function bodies can be resolved to numbers in pass 2.
    all_defines = []
    for path in sorted(srcdir.iterdir()):
        if path.is_file() and path.suffix.lower() in (".c", ".h", ".ha"):
            all_defines.extend(parse_c(path)[2])
    defines_map = resolve_defines(all_defines)
    result["defines_resolved"] = len(defines_map)

    # Pass 2: the real inventory.
    for path in sorted(srcdir.iterdir()):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix == ".c":
            f, g, d, t = parse_c(path, defines_map)
            result["functions"].extend(f)
            result["globals"].extend(g)
            result["defines"].extend(d)
            result["types"].extend(t)
            result["files"].append({"name": path.name, "kind": "c",
                                    "functions": len(f)})
        elif suffix in (".h", ".ha"):
            f, g, d, t = parse_c(path, defines_map)
            result["globals"].extend(g)
            result["defines"].extend(d)
            result["types"].extend(t)
            result["files"].append({"name": path.name, "kind": "header",
                                    "functions": 0})
        elif suffix == ".asm":
            f, pub, ext, seg = parse_asm(path)
            result["functions"].extend(f)
            result["asm_publics"].extend(pub)
            result["asm_externs"].extend(ext)
            result["asm_segments"].extend(seg)
            result["files"].append({"name": path.name, "kind": "asm",
                                    "functions": len(f)})
    return result


def report(r):
    out = []
    A = out.append
    c_funcs = [f for f in r["functions"] if f["kind"] == "c"]
    a_funcs = [f for f in r["functions"] if f["kind"] == "asm"]
    knr = [f for f in c_funcs if f["style"] == "knr"]

    A(f"Source directory : {r['source_dir']}")
    A(f"Files            : {len(r['files'])}  "
      f"({sum(1 for f in r['files'] if f['kind'] == 'c')} C, "
      f"{sum(1 for f in r['files'] if f['kind'] == 'asm')} ASM, "
      f"{sum(1 for f in r['files'] if f['kind'] == 'header')} headers)")
    A("")
    A("-- Ground-truth symbol counts -------------------------------------")
    A(f"  C functions        {len(c_funcs)}   (K&R style: {len(knr)}, "
      f"ANSI style: {len(c_funcs) - len(knr)})")
    A(f"  ASM entry points   {len(a_funcs)}")
    A(f"  TOTAL functions    {len(r['functions'])}")
    A(f"  file-scope globals {len(r['globals'])}")
    A(f"  #defines           {len(r['defines'])}")
    A(f"  typedefs           {len(r['types'])}")
    A("")
    A("-- Functions per file ---------------------------------------------")
    for f in r["files"]:
        if f["functions"]:
            A(f"  {f['name']:<16} {f['kind']:<7} {f['functions']:>3}")
    A("")
    if r["asm_segments"]:
        segs = sorted({s["name"] for s in r["asm_segments"]})
        A("-- Segments declared in assembly ----------------------------------")
        A("  " + ", ".join(segs))
        A("")
    A("-- Notes ----------------------------------------------------------")
    if knr:
        A(f"  {len(knr)} function(s) use K&R parameter declarations. The")
        A("  compiler therefore applied default argument promotion (char/short")
        A("  -> int, float -> double). Decompiled parameter types will look")
        A("  wider than the source says; that is the compiler's doing, not the")
        A("  decompiler's error.")
    longnames = [f["name"] for f in r["functions"] if len(f["name"]) > 8]
    if longnames:
        A(f"  {len(longnames)} symbol(s) exceed 8 characters. Linkers of this era")
        A("  often truncated to 8; if the binary has a symbol table, expect")
        A("  collisions and truncation.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("srcdir")
    ap.add_argument("--json", metavar="FILE", help="write full inventory as JSON")
    args = ap.parse_args()

    r = scan(args.srcdir)
    print(report(r))
    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
