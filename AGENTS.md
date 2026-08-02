# Working on a DOS binary with this toolkit

Instructions for any coding agent — or any person — driving `DOS-Decompiler`.
This is the canonical method; `SKILL.md` is a thin wrapper for Claude Code that
points here.

The toolkit is a set of ordinary command-line programs. They do the work that
must be done by code: parsing headers, emulating 8086, computing signatures,
diffing instruction streams. This document covers the other half — deciding
what the evidence means, and refusing to claim more than it supports.

Every number quoted was measured on **one** program: Sopwith (1984), whose
original source survives and serves as the regression fixture in
`tests/sopwith/`. That makes the claims checkable rather than folklore, and it
also bounds them. Sopwith is MZ, C-compiled, small memory model, unpacked, not
overlaid. Outside that shape the figures do not apply, and some tools mislead
rather than fail.

## Running the tools

- **Python tools** (`tools/*.py`) run anywhere Python 3 does. Each takes
  `--help`.
- **PowerShell tools** (`tools/*.ps1`) need PowerShell 7+, which runs on Linux
  and macOS as well as Windows.
- Tool locations come from environment variables. `env.example.ps1` documents
  them; copy it to `env.ps1` and source it. Every script fails with a clear
  message rather than a wrong default if one is missing.

## What to tell the user before starting

Be explicit about what this can and cannot produce. The gap between expectation
and reality is where retro decompilation projects go wrong.

| Goal | Realistic? |
|---|---|
| Readable C with recovered control flow | Yes, essentially all functions |
| Meaningful names for functions and data | Partly automatic, mostly by reading |
| Separating C runtime code from game code | precision 1.00, recall 0.76–0.91 |
| Automatic identification against known source | precision 0.94, recall 0.72 |
| Carrying names between two builds of one program | precision 1.00, 110 of 202 |
| **Source resembling the original** | **No** — see below |
| Byte-identical recompilable source | Not from decompilation; see the extended workflow |
| Working, modifiable port | Yes, but that is a rewrite informed by the decompilation |

**Say the "source resembling the original" row out loud**, because it is the row
everyone assumes the other way. Those accuracy figures are about *identifying
which function is which*. They say nothing about the decompiled C resembling the
original source, and it does not: no variable names, no structs (an `OBJECTS *`
arrives as `undefined2 *` and raw offsets), no comments, no macros, hand-written
assembly that does not decompile sensibly, and pure data tables that never
appear as code at all.

If the goal really is source that matches, that is the extended workflow —
`knowledge/07-extended-reconstruction.md`.

---

## Step 0 — What were you actually given?

If you were handed a **folder** rather than a single file, start here:

```
python tools/survey.py path/to/game/folder
```

A DOS release is rarely one file. There is a game, usually a setup or install
program, sometimes drivers, often overlays loaded at run time, and data spread
across subdirectories. `survey.py` walks the whole tree, triages *every*
executable it finds, reads any batch files for the real entry point, and says
which executable looks like the game and why.

This matters because picking the wrong executable wastes a day, and it is easy
to do: a setup program decompiles just as willingly as the game. On one 1988
release the folder held five executables — the game, two logo players, a setup
stub and `MODE.COM` — and only the batch file distinguished them.

It also catches what `triage.py` alone cannot see: overlay modules, a second
executable hiding in a subfolder, and the interpreted-engine pattern judged
across the whole tree rather than one directory.

Then triage the executable it points at.

## Step 0a — Is that program in scope?

```
python tools/triage.py GAME.EXE
```

**Never skip this, and report its verdict before promising anything.** Common
DOS programs that fall outside the toolkit:

- **Packed** executables — LZEXE, PKLITE, EXEPACK, DIET. Decompiling gets you
  the decompressor. Run `tools/unpack.py` first.
- **Overlaid** programs. Several functions share the same addresses at different
  times; nothing here handles that.
- **Protected-mode DOS-extender binaries.** A different format entirely.
- **`.COM` files** do not go through this pipeline, but they are not out of
  scope: they take a separate and stronger route. See below.
- **Interpreted engines** — Sierra SCI and AGI, LucasArts SCUMM, DAAD. The
  executable is a virtual machine and the game is in the data files beside it.
  Decompiling succeeds and tells you nothing you wanted. This is the expensive
  mistake; triage checks for it.
- **Non-small memory models.** `emuverify.py` assumes `SS == DS` and one data
  group. On a far-pointer program it produces nonsense *without saying so*.

`knowledge/00-scope.md` has the full matrix and separates failures that are loud
from failures that are silent.

### If it is a .COM

```
python tools/comrec.py GAME.COM --out src/game.asm
```

A `.COM` has no header, no relocations, and no separation between file and
memory image, so the whole MZ pipeline is beside the point. What replaces it is
stronger: `comrec.py` rebuilds the file as NASM source and **proves** the
result by reassembling it and comparing bytes. It prints `BYTE-IDENTICAL` or
it prints why not. There is no middle answer to interpret.

Confirm it yourself rather than taking the tool's word:

```
nasm -f bin -o rebuilt.com src/game.asm
# then compare SHA-256 of rebuilt.com against the original
```

Two things to know before reporting results:

- **It produces assembly, not C.** Check for stack-frame prologues first
  (`tools/triage.py` reports prologue density). A program with none was written
  in assembly and has no C to recover — say so rather than implying otherwise.
- **Quote the code-region figure, not the whole-file one.** These games are
  mostly artwork and lookup tables. ParaTrooper comes back at 28.6% of the file
  but 87.7% of the region that actually holds code; the first number describes
  the game, the second describes the recovery.

A `.COM` reconstruction is static: nothing is executed. When you need a
reference to check a static reading against — a screen drawn from the file, a
table you think you have decoded — `tools/comrun.py` runs the binary under
emulation and dumps the framebuffer. It has just enough BIOS to get a game to
its first frame, including a keyboard queue (`--keys`) and a clock that
advances, both of which exist because without them a title screen waits
forever. `--stop-at ADDR --stop-after N` stops on the Nth arrival, which is how
you look at a frame other than the first.

`knowledge/08-com-reconstruction.md` covers the traps — chiefly a stub that
reloads CS so that half the file is addressed from a different base, which
fails silently and confusingly if missed, and which is not always at offset 0:
Zaxxon hides it behind a `jmp` over a crack group's text banner, and reading
the file naively recovered nine instructions out of 20,736 bytes while still
reporting `BYTE-IDENTICAL`.

### If it is packed

```
python tools/unpack.py GAME.EXE -o unpacked.exe
python tools/triage.py unpacked.exe
```

`unpack.py` runs the packer's own decompressor under emulation and dumps the
result — one mechanism for any packer. Verify that it worked rather than
assuming: compare printable-string counts before and after. On a PKLITE'd 1988
game the dump gained 181 strings of real game text, which is proof; a low
density of stack frames in the dump is not evidence of failure, it usually means
the program is hand-written assembly.

EXEPACK's entry point is read from its own header and is exact. Other formats do
not state theirs, so the dumped header's entry is set to 0 deliberately — a
wrong entry point sends the disassembler into the middle of a routine and
everything after inherits the error.

If the program was written in C and you have the compiler's library, recover it
instead of guessing:

```
python tools/libscan.py unpacked.exe --lib C:\path\to\compiler\LIB
```

Pass the **directory**, not the `.LIB`. Not every toolchain keeps its startup
code in the archive — Microsoft C 1.04 ships it as a loose `C.OBJ` named on the
link line, and none of `MC.LIB`'s 75 modules declares a start address at all.

The startup module of a C runtime declares the entry point in its MODEND
record. `libscan.py` matches library modules against the image with the FIXUPP
relocation slots as wildcards, and reads the entry point out of the one that
matched — measured exact on four binaries across two compilers, including a
packed-and-dumped one, without ever reading the MZ header
(`tests/libscan/CASE-STUDY.md`). Scanned with the wrong compiler's library it
reports nothing rather than something plausible, so a match is meaningful.

Read the failure message, because there are two of them. *"None of the modules
loaded declares a start address"* is a fact about what you passed in — look for
the startup object outside the archive. *"X declares a start address but did
not match"* is a fact about the binary.

The same run tells you which compiler it is, bounds the runtime region so it
can be excluded from matching, and names the runtime's functions from the
archive's PUBDEF records. Do it early; it removes work rather than adding it.

Without the library, use `anchors.py` to find `main` structurally instead.

### If it is Turbo Pascal

`libscan.py` will find nothing, correctly: TP compiles to `.TPU` units and binds
its runtime with its own linker, so there is no OMF archive to match. Run this
instead:

```
python tools/tpscan.py unpacked.exe
```

It recognises the compiler from the System unit's initialisation, reports
`DGROUP` — the code/data boundary, which nothing else recovers for a Pascal
program — and lists the units, because **every TP unit is its own code segment
and every call between units is a far call with a literal segment word**. One
linear scan gives up the module structure of a 200 KB program.

For the *version*, give it Borland's own runtime libraries — no string tells
you, because the runtime error format is identical from 4.0 to 6.0, but the
runtime's code does:

```
python tools/tpscan.py unpacked.exe --tpl <5.0>/TURBO.TPL --tpl <5.5>/TURBO.TPL
```

It ranks them by the longest run of identical code and **refuses to answer**
unless one wins by half again, because any two Turbo Pascal runtimes have a lot
in common. Both libraries are on the Internet Archive; `fatextract.py` opens the
floppy images. See `knowledge/02-compiler-fingerprints.md`.

---

## Step 0b — Ask which workflow the user wants

Two different projects share the first few steps and then diverge. **Ask; do not
assume.**

| | **Standard** | **Extended** |
|---|---|---|
| Deliverable | annotated pseudocode + architecture notes | source that rebuilds the binary |
| Verified by | reading it | `bindiff.py`, mechanically |
| Needs the period compiler | no | **yes** |
| Effort | hours to days | weeks, iterative |
| Ends when | you understand it | the diff is clean |

Standard suits "what does this game do", "how does its file format work", "I
want to port it". Extended suits "I want source that provably matches", which is
what people usually mean by "decompile it properly".

Steps 1–5 are the standard workflow. The extended workflow continues from there:
`knowledge/07-extended-reconstruction.md`.

Say which rung of the verification ladder the result will sit on:

| Rung | Oracle | Proves |
|---|---|---|
| 1a | byte-identical **functions**, relocation slots wildcarded | each function's code is right — **not** which symbols it references |
| 1b | byte-identical **linked image** | the source is right |
| 2 | instruction-identical, layout-tolerant — `bindiff.py` | the code is right |
| 3a | per-function behavioural equivalence — `emuverify.py` | this function is that function |
| 3b | instruction-trace equivalence under identical input | control flow is the same, and a divergence localises to one instruction |
| 4 | pixel-identical frames under identical input | the program behaves the same |
| 5 | "looks right" | nothing |

Do not report 1a as 1b. A per-function comparison must wildcard relocation
slots, so a function that references the wrong symbol still compares as
identical; only the linked image catches it.

---

## Step 1 — Establish what the file actually is

```
python tools/mzinfo.py GAME.EXE
```

Answers, before any decompiler runs: is it packed, are there overlays or data
past the load image, which segments does the loader actually build, and where is
the true entry point — `CS:IP` is relative to the load image, not the file.

Read the FINDINGS section. A `few-relocations` note on a small-model program is
normal (Sopwith has exactly 2 for 60 KB); the same on a large-model program
means something is hiding.

---

## Step 2 — Load into Ghidra and recover the missing functions

```
analyzeHeadless <proj_dir> <proj> -import GAME.EXE -overwrite
analyzeHeadless <proj_dir> <proj> -process GAME.EXE -noanalysis \
    -scriptPath tools/ghidra_scripts -postScript RecoverFunctions.java
analyzeHeadless <proj_dir> <proj> -process GAME.EXE -noanalysis \
    -scriptPath tools/ghidra_scripts -postScript ExportDecompiledC.java OUTDIR
```

Or just `tools/pipeline.ps1 -Exe GAME.EXE -OutDir out`, which does all three.

**Run these as three separate invocations.** Chaining two `-postScript` flags in
one command silently loses the first script's changes.

`RecoverFunctions.java` exists because Ghidra's auto-analysis is not enough here.
Games dispatch through function-pointer tables and install interrupt handlers by
address, and Ghidra never follows an integer. On Sopwith it left **48 real
functions completely undisassembled** — the movement handlers, the drawing
handlers, the keyboard and timer ISRs. Scanning for immediates that point into
the code segment recovered them and took the function count from 232 to 289.

---

## Step 3 — Identify what the evidence establishes

Do this first, always. It needs no reference source, and what it finds is fact
rather than inference.

```
python tools/anchors.py OUTDIR/functions.json --entry <CS:IP from mzinfo> \
       --report anchors.txt --names names.json
```

It reports every function carrying identifying evidence — interrupts, I/O ports,
string references, video constants — and writes names that claim only what was
established. `bios_video_3` says the function executes `INT 10h`; it does not
pretend to know it is `drawsprite`.

Names are scored by **corroboration**: two independent kinds of evidence agreeing
earns confidence, one kind stays provisional. Apply them and re-export:

```
analyzeHeadless <proj_dir> <proj> -process GAME.EXE -noanalysis \
    -scriptPath tools/ghidra_scripts -postScript ApplyNames.java names.json
analyzeHeadless <proj_dir> <proj> -process GAME.EXE -noanalysis \
    -scriptPath tools/ghidra_scripts -postScript ExportDecompiledC.java OUT2
```

Provisional names get a `__maybe` suffix and a warning comment, so uncertainty
stays visible in the code instead of being quietly forgotten. Names applied to
routines of 200+ bytes are flagged separately.

---

## Step 3b — Identify by matching, when reference source exists

Only useful when the source genuinely corresponds to this binary — a later port,
a sibling game, leaked headers.

**Exclude the C runtime first.** It needs no reference source and no makefile,
and removing that noise is a large gain:

```
python tools/libsig.py apply GAME.EXE OUTDIR/functions.json \
       --db signatures/msc50-16bit-small.json --json lib.json
```

Try each database in `signatures/` — the one that matches tells you which
compiler built the binary. If none match and you are confident of the compiler,
the program brought its own runtime; that means none of the binary can be
dismissed as library noise.

Then match:

```
python tools/srcinv.py SRCDIR --json src.json
python tools/match.py src.json OUTDIR/functions.json --align \
       --exclude-library lib.json [--module-order order.json] --report ident.md
```

**Check the score distribution before believing any of it.** Against a
correctly corresponding binary, matches reach 0.9+ precision. Run against a
different version of the same game and nothing scored above 0.453 while `main`
landed in the wrong place. A run where nothing clears 0.7 is telling you the
reference is wrong, not that the binary is hard.

Cumulative effect on Sopwith, each row adding to the one above:

| configuration | precision | recall |
|---|---|---|
| constants and strings only | 0.696 | 0.325 |
| + C runtime excluded | 0.826 | 0.475 |
| + control-flow shape compared | 0.875 | 0.583 |
| + link order known from the makefile | 0.897 | 0.583 |
| (same pipeline, period-correct ground truth) | **0.935** | **0.717** |

`tools/modcluster.py` segments the binary into probable modules. Useful for
reading and for building `--module-order` by hand. It is deliberately *not*
wired into the matcher: feeding its segments into the ordering was measured and
made identification worse.

---

## Step 4 — Read, name, annotate

This is where the work actually gets done, and it is not automatable.

**Never commit a name on one source of evidence.** This is the most expensive
lesson available and someone else paid for it: a sibling project reconstructing
Tapper kept a table of 35 conclusions it had to retract, and stated the pattern
plainly — a conclusion from a single source almost always needs correcting; what
survived had two independent sources.

Three specific ways it goes wrong, all observed:

- Naming a field from its **writer** without reading its **readers**.
- Naming a long routine from its **first few lines**. Two routines were named
  that way and both did far more further down, including killing the player —
  and being a plausible-looking *pair* made each seem to confirm the other.
- Naming something from its **effect** rather than its cause, which can invert
  the meaning while sounding reasonable.

**Find `main` by reading, not by rule.** `anchors.py` guesses it by walking the
startup chain, and that was right on only one of two test binaries. The shape is
unmistakable and takes a minute to confirm: a call taking `(argc, argv)` followed
by an endless loop.

Then work outward. The loop body of `main` is the game's phase order, so its
callees are the top-level subsystems.

**Check every hypothesis against the fingerprint before committing to it.**
`functions.json` carries instruction counts, call counts, interrupts, ports and
constants for exactly this. Working through Sopwith's game loop, the guess that
one callee was the collision routine was killed immediately by its own data: 6
instructions, no calls. A wrong name is worse than no name, because it survives
into every later reading as though it were established.

High-yield anchors, in order of reliability: string references, interrupt
numbers (`INT 10h` video, `16h` keyboard, `21h` DOS, `1Ch` timer hook, `09h`
keyboard ISR), I/O ports (`40h–43h` PIT, `60h` keyboard, `3D4h/3D8h` CGA, `201h`
joystick, `388h` AdLib), and magic constants (`0xB800` CGA, `0xA000` VGA,
`0x2000` CGA bank offset).

---

## Step 5 — Verify, do not assume

Decompiler output is a hypothesis. Confirm the ones that matter.

**If you have a second binary of the same program, settle it by execution:**

```
python tools/emuverify.py known.exe known.map target.exe OUTDIR/functions.json
```

It runs both candidates under an 8086 emulator on identical inputs and compares
return registers, global reads and writes, and call counts. It decides
equivalence rather than scoring resemblance. Validated against two builds of
Sopwith from one source with different code generation: **110 matches, zero
wrong.** Any name it carries across can be trusted outright.

Functions that never return — interrupt handlers, `longjmp` targets, the main
loop — are still profiled, on a bounded run comparing only which globals they
touched. That accounts for 9 of the 110 and is flagged separately.

Its limits:

- It needs both binaries to implement the *same algorithm*. Pointed at a
  different release of the game it found 2 matches out of 202 — correctly, the
  code genuinely differs.
- Some functions are behaviourally identical and always will be (`intson` is
  `sti; ret`, `intsoff` is `cli; ret`). It reports these rather than guessing.

That failure mode is the point. Statistical matching on a mismatched pair
produces dozens of confident-looking scores and gets `main` wrong; emulation
produces almost nothing. Loud failure is safer than quiet failure when the output
becomes names you will read for weeks.

Also: run the game in DOSBox-X and check the behaviour you claim to have found.
If Ghidra and radare2 disagree about an instruction, look at the bytes.

**State clearly which parts of your output are verified and which are
inference.**

---

## Validating a change to the toolkit

Sopwith is the regression fixture. `tests/sopwith/` has the build recipes that
produce a ground-truth binary plus a linker map, so any change can be scored
against a known-correct answer:

```
python tests/sopwith/regress.py --build-dir work/build --decompiled work/decomp \
       --source <sopwith-source> --variant-dir work/variant
```

Floors: library detection precision 0.95 (a false positive deletes real game
code), library recall 0.80, identification precision 0.85 with a known module
order and 0.83 with an inferred one, recall 0.52, emulation precision 1.0 with
at least 100 matches. Below any of those, the change made things worse. Do not
ship it.

**Measure; do not reason.** Three confident predictions in this repo's history
were contradicted by measurement: module segmentation made identification worse,
iterative refinement of the module order changed nothing, and *more* emulator
input vectors reduced matches. And watch a second metric — a passing test does
not mean nothing got worse.

---

## Reference

- `knowledge/00-scope.md` — what this handles and what it does not
- `knowledge/01-dos-binaries.md` — MZ format, memory models, segments, packers, hardware
- `knowledge/02-compiler-fingerprints.md` — identifying and exploiting the compiler
- `knowledge/03-what-works.md` — measured results, including what failed
- `knowledge/04-pitfalls.md` — traps that cost real time, with the fix for each
- `knowledge/05-prior-art.md` — other projects covering this ground, one of them
  heavily. If the goal is a faithful reconstruction rather than a readable one,
  mzretools is the better starting point.
- `knowledge/06-lessons-from-siblings.md` — corrections paid for by two other
  reconstructions
- `knowledge/07-extended-reconstruction.md` — the verified-reconstruction workflow
- `knowledge/08-com-reconstruction.md` — the `.COM` route, which reaches
  byte-identity in one run
- `tests/sopwith/CASE-STUDY.md` — the whole method worked through, including the
  hypotheses that turned out wrong
- `tests/com/CASE-STUDY.md` — a 1982 `.COM` game rebuilt byte-for-byte, and the
  four bugs the attempt exposed
