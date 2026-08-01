# Lessons from a reconstruction done without this toolkit

`06-lessons-from-siblings.md` records what could be learned from Creative
Contraptions (CONTRAP.EXE, Bantam, 1988) while that work was still running. It
has since finished, and its author was asked directly what a toolkit like this
one should have done for them. Their reply is the source for everything below.

Their result, for calibration: **46,531 of 46,532 bytes of the load module
identical to the original**, produced by compiling reconstructed C with the
original compiler and linking with the original linker. 83 of 83 functions
byte-exact, DATA segment 9,556 of 9,556. The one remaining byte is the high
byte of a garbage immediate the compiler emits for a broken `long` comparison;
they demonstrated by experiment that it tracks the build environment rather
than the source, and no source-level change reaches it.

They also state the caveat plainly, and it matters when reading the rest: they
had the original compiler and library (Microsoft C 1.04, `MC.LIB`, `LINK.EXE`).
Several of their techniques assume that.

## What changed here as a result

Four things, in order of how much they cost us to be wrong about.

### 1. Rung 1 was too weak, and we split it

Their strongest contradiction, and it is a real one:

> Byte-identical *functions* is a strictly weaker claim than byte-identical
> *linked image*, and the difference is exactly the class of error that
> per-function comparison is structurally blind to.

The mechanism: inside an `.OBJ`, addresses in relocation slots are not filled
in yet, so any per-function comparison must treat those bytes as wildcards.
Code that references *the wrong symbol* therefore compares as identical.

`[verified]` by them, not hypothetically. After reporting 83/83 functions
byte-identical they linked the image, compared it against the original, and
found **24 differing bytes in four functions that all had "byte-identical"
status** — two globals stored in the wrong order in `main`, the same pair
swapped at six sites in an animation interpreter, three source and three
destination globals rotated by one in a drawing routine, two globals swapped in
an addition in a loader. Every one was a symbol-identity error. Every one was
invisible to per-function comparison.

The ladder now distinguishes rung 1a from rung 1b. See
`07-extended-reconstruction.md`. The `.COM` route was always rung 1b — a `.COM`
reconstruction *is* the whole image — so the split costs it nothing and makes
the MZ route's weaker claim visible.

### 2. There is a rung between 3 and 4

Per-function behavioural equivalence proves a function; pixel-identical frames
prove the program. Between them sits **instruction-trace equivalence**: run
both binaries under the same harness and compare executed addresses step by
step, normalising for known layout shifts.

Their argument for it is a failure it caught and frame comparison could not.
The reconstructed EXE ran and exited cleanly, drawing nothing — no crash, no
error. The data group had started at `0x9064` instead of `0x9070`, not on a
paragraph boundary, so `DS` pointed one paragraph low and every data address
was off by 4. The program opened a file whose name had been shifted into
garbage, took a different branch in the runtime, and terminated normally.
Frame comparison said only "nothing was drawn". The trace comparison localised
it to one instruction.

Cheaper than frame comparison and more diagnostic. It is now rung 3b.

### 3. Subtract the library before doing anything else

They split `MC.LIB` into modules and matched each against the image with
relocation slots as wildcards: **23 modules, 9,935 bytes, byte-for-byte**, a
hard boundary at `0x69D7`, and 27% of the code removed from the work list. They
rank this above better function detection, and put it first in "what I would
check next time".

The same scan gives the entry point, which is the gap `unpack.py` documented as
unsolved. Their route: fingerprint the startup module with relocation slots as
wildcards; the entry point is at a fixed offset inside it. For CONTRAP the
startup module is 116 bytes with only 7 differing bytes, and all 7 are
relocation slots.

This is now `tools/libscan.py`, and it goes one step further than their
description: the entry point does not have to be assumed to sit at offset 0 of
the startup module's code segment, because the MODEND record of that module
*states* the segment and displacement. Measured on four binaries across two
compilers, the recovered entry point is exact every time, including for a
packed-and-dumped image — see `tests/libscan/CASE-STUDY.md`. They then checked
the record against Microsoft C 1.04, a generation we have no copy of, and it
reads correctly there too: segment 3, displacement 0, which is the offset they
had originally observed empirically. Four compiler generations, earliest 1983.

**And they found the heuristic we built on top of it, wrong.** We had said that
exactly one module sets the start-address flag, so the flag identifies the
startup module without needing its name. True in MS C 5.0, 5.1 and Open Watcom.
In MS C 1.04 the count is zero of 75 modules, because the startup code is not
in `MC.LIB` at all — it ships as a loose `C.OBJ` named on the link line ahead
of the library.

The failure mode is the lesson, not the fact. A scanner that reports "no module
declares a start address" as "entry point not recovered" has made a claim about
the binary from a fact about what the caller passed in. `libscan.py` now takes
a directory, and distinguishes *nothing declared one* from *the one that
declared it did not match*. The regression test reproduces the layout with Open
Watcom so the case is tested rather than described.

`[inferred]`, theirs: pre-1985 toolchains generally may separate crt0 from the
library, since that is what makes it replaceable. One compiler is the whole
basis for it.

### 4. Naming: the risk is confidence, not uncertainty

We refuse to commit a name on one source of evidence and suffix the provisional
ones `__maybe`. Their comment:

> The risk is not "I am unsure and should mark it provisional". The risk is
> "I am sure and I am wrong", and the only thing that catches that is an oracle
> that does not care what you called it.

Two failures of theirs, both confidently wrong rather than uncertain:

- **One name, two addresses.** The same name used for a table at `0x0A` in one
  file and at `0x1AE` in another. The linker resolves by name, so the second
  reference silently bound to the first — an error of 0x1A4 bytes, invisible to
  per-function comparison because the reference sits in a relocation slot.
- **A name that described the wrong thing.** A symbol called `sndbuf` and
  declared `char sndbuf[16]` was in fact the address of a timer interrupt
  handler. The evidence was in the consumer: it writes the argument into the
  vector at `0:0x70` with `CS` as the segment, so the argument is a code
  address. The wrong name installed the offset of an empty array as the timer
  ISR and added 16 bytes of DGROUP that do not exist in the original.

What they used instead of a confidence suffix is an **invariant enforced by a
tool**: one address gets exactly one name, one name refers to exactly one
address, checked across all source files after every build. That is worth
adding alongside `__maybe`, not instead of it — the two catch different errors.

`libscan.py` contributes here too: a matched library module names its functions
from the archive's PUBDEF records, which is a name backed by the toolchain
rather than by anyone's judgement.

## Negative results worth keeping

Recorded because they cost someone real time.

**"All N variants produce identical bytes" means the question is at the wrong
level, not that the site is uncontrollable.** They lost the single largest
block of time to this, three separate times. Functions differed by a register
choice — `mov bx` where the original had `mov si` — which they attributed to
compiler register allocation and attacked by trying dozens of *statement forms*:
loop shapes, operand order, `goto` versus `break`, nesting, `continue` versus a
guard. All identical. The controlling factor was **type**:

```c
extern int   p;  ...  (buf[j] * 0xc + (char *)p)[1]   /* mov bx,[p] */
extern char *p;  ...  (buf[j] * 0xc + p)[1]           /* mov si,[p] */
```

A genuine pointer type loads directly into an index register; an `int` plus a
cast goes through the accumulator. Check types before forms.

**A global similarity metric punishes correct fixes.** With one length-changing
error remaining, everything downstream is misaligned, so a correct fix
elsewhere can lower the score. They applied one and watched 687 drop to 682,
and nearly reverted it — two errors in the same function had been *cancelling
in length*, so the total looked right while both were wrong. The fix is a
measurement change: compare the aligned prefix separately from the
shift-compensated tail. On the prefix the same change read 528→562 out of 563.

This is the same shape as the negative result already recorded here about
releasing instruction pins in bulk (`08-com-reconstruction.md`): a metric
computed over a region that has shifted is measuring the shift.

**Two independent implementations of one rule are two chances to be wrong
separately, not redundancy.** A catalogue renderer and a screen renderer
implemented the same placement rule twice; the catalogue drew only the first
record of a multi-record part. Both outputs looked plausible in isolation and
the discrepancy survived for months, caught in the end by a human comparing two
of the agent's own images. Either derive both from one implementation or
cross-check them automatically.

**Sign-extension thresholds are not global.** Two different thresholds coexisted
in one binary and both were correct in their own path — `>= 0x80` for static
placement, `>= 0xC8` when drawing from the animation script. Do not unify two
code paths that look like they do the same thing until you have checked both.

**Believing your own harness.** Twice, a shell helper passed arguments in the
wrong order, so every "variant" measured the same stale object file. The output
was a clean table of identical numbers, which reads exactly like a genuine
negative result, and a conclusion was drawn from it before the defect was
noticed. Related: a build script *printed* a compile failure without stopping,
and the linker silently used the previous object file — which is how 16 phantom
bytes of data segment survived for a while. The rules that came out of it:

- If a compile fails, delete the stale object and fail the build.
- Any measurement harness deletes its output before rebuilding, and refuses to
  report at all if the build failed.
- After linking, assert segment and group alignment invariants and fail loudly.
  One assertion — the data group starts on a paragraph boundary — would have
  saved hours (see rung 3b above).

**Ghidra's decompiled C is a hypothesis generator, never evidence.** Useful for
orientation, misleading for structure: function sizes ended early at embedded
jump tables, a chain of `||` conditions appeared as nested `if`s, and it
reported "removing unreachable block" for code that is genuinely in the binary
and had to be reproduced. `[inferred]` by them: this is inherent to decompiling
toward *readable* C rather than toward *the C that was actually written*.

Their function-boundary rule is worth having alongside our prologue scan: a
function's real end is the `add sp,N / pop bp / ret` that matches the prologue's
`sub sp,N`, not the first `ret` — Ghidra repeatedly ended functions early at a
`ret` inside a switch arm.

## The oracle we should copy next

Their strongest verification device is not a tool but a framing, and it applies
directly to work we are doing now on sprite and level formats.

> Given a hypothesis about a data format, generate the program's output from the
> data files alone, then check every operation the real program performed
> against what the hypothesis can produce. Report the fraction explained.

Their measurement is `197/197 (100.0%)` — 197 sprite-blit operations captured
from the running program under emulation, across every goal and structural
variant, all of them reproduced by an independent renderer from the data files
plus reconstructed placement rules.

The reason it works where "the format looks right" does not: it survives
randomness. The game picks variants with `rnd()`, so a run cannot be predicted.
The check instead asks, for each captured operation, *does there exist a
(component, variant, chain-link) combination that produces exactly this
(x, y, w, h)?* Falsifiable without being brittle.

What it caught that reading the code did not, in their words — every one of
these looked right until the reconstruction failed:

| bug | symptom |
|---|---|
| two fields read in the wrong order | sprites a few pixels off, invisible to the eye |
| a type match that ignored the high bit | every mechanism with id ≥ 128 vanished |
| one sign threshold used everywhere | four parts landed off-screen |
| a part drawn as two chained records treated as one | parts silently truncated |

That table is the same lesson this toolkit reached from the other direction
while rendering Hard Hat Mack: four errors were caught by drawing the data, not
by reading the code. Drawing is a form of proof. Counting what the drawing
fails to explain is a better one.

## Things they did not solve either

Stated so they are not mistaken for gaps in their write-up:

- **Functions reached only through function pointers.** No technique. Their
  substitute — reconstruct the whole image, then look for gaps in a complete
  address map — turns "find functions reached only through pointers" into "find
  gaps", which is mechanical, but only works for whole-image reconstruction.
  Our 28 unfound Sopwith entry points are the same problem, still open.
- **One data structure remains unidentified.** A length-prefixed array that
  parses correctly at every site, so its length is certain and its meaning is
  not.
- **A scoring bonus documented in the game's manual** was never located in the
  code.
- **Repacking.** They reproduce the program image, not the shipped PKLITE file.

## Credit

Everything in this file comes from the agent who reconstructed CONTRAP.EXE,
answering a written request (`ASK-CONTRAP-AGENT.md`). Quotations are theirs.
The measurements attributed to `libscan.py` and the ladder wording are this
toolkit's; the ideas behind both are not.
