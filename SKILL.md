---
name: dos-decompile
description: Decompile and reverse-engineer 1980s DOS programs — 16-bit real-mode MZ executables for the 8086/8088. Use when asked to decompile, reverse engineer, unpack, or analyse a DOS .EXE, a retro/vintage/abandonware PC game, or any 8086 real-mode binary. Covers scope triage, unpacking compressed executables, Ghidra headless decompilation, function identification, verified reconstruction, and measured accuracy.
---

# Decompiling 1980s DOS programs

**Read `AGENTS.md` in this directory and follow it.** That is the method; this
file exists only to register the skill with Claude Code, and keeping the
instructions in one place is what stops the two from drifting apart.

## The three things to get right

Everything else is detail, but these decide whether the work is worth anything.

**1. Run `python tools/triage.py GAME.EXE` before promising the user anything,
and report its verdict.** Packed executables, overlaid programs and
protected-mode binaries are out of scope. `.COM` files take a separate and
stronger route — `python tools/comrec.py GAME.COM --out src/game.asm` rebuilds
them byte-for-byte and proves it — but the result is assembly, not C, so check
for stack-frame prologues before promising any. Interpreted engines — Sierra
SCI and AGI, LucasArts SCUMM, DAAD — are the expensive case: decompiling one
succeeds and produces a correct rendering of a virtual machine with none of the
game in it.

**2. Ask which workflow the user wants before starting.** *Standard* produces
readable pseudocode, verified by a person reading it, in hours to days.
*Extended* produces source that compiles back to the original binary, verified
mechanically by `bindiff.py`, over weeks. They are different projects and the
wrong choice wastes days in either direction.

**3. Never commit a function name on one source of evidence.** Two independent
kinds of evidence agreeing earns confidence; one kind stays provisional and gets
a `__maybe` suffix. This is enforced by `anchors.py` and it is not fussiness — a
sibling project kept a table of 35 conclusions it had to retract, and the
pattern was explicit: single-source conclusions almost always need correcting.

## What to tell the user up front

The decompiled C will **not** resemble the original source. The compiler
destroyed the names decades ago and they are not in the file, so no decompiler
can recover them. Control flow comes back essentially perfectly; names, types,
structs, comments and macros do not. The accuracy figures in `AGENTS.md` are
about knowing *which function is which*, not about the C looking like the C that
was written.

If the user wants source that provably matches, that is the extended workflow —
reconstruction, not decompilation.
