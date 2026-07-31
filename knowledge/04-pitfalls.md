# Pitfalls, and the fix for each

Every entry was hit for real while building this method. None are theoretical.

## Tooling

**Chaining two `-postScript` flags in one headless run loses the first
script's work.** `RecoverFunctions` reported creating 100 functions; the
exporter that ran immediately after saw 232, the pre-recovery count. Run each
script as its own `analyzeHeadless` invocation against the saved project.

**Ghidra's MZ loader marks every segment executable, including data.** Any
scan that trusts `block.isExecute()` will happily create functions inside
sprite bitmaps. Filter to blocks that contain the entry point or already
contain defined functions.

**Ghidra auto-analysis under-reports functions on game binaries.** It follows
control flow, and games dispatch through function pointers in data. Expect to
lose roughly a third of the functions, concentrated in the gameplay code, and
recover them explicitly.

**The Open Watcom Windows installer crashed twice** (heap corruption, then an
access violation), leaving a half-populated tree without `wcc` or `lib286` —
the 16-bit pieces. The `ow-snapshot.tar.xz` release asset contains the same
build as a plain archive and extracts cleanly. Prefer it.

## 1980s source archaeology

**Ctrl-Z (0x1A) inside source files.** `SWDEVE.H` ends with a DOS end-of-file
marker followed by more bytes. Period compilers stopped reading at it; modern
ones do not, and report a syntax error on a line that looks blank. Strip from
the first 0x1A onward.

**Duplicate `EQU` definitions.** `SW.HA` defines `K_ASYNACK equ 40H` twice,
two lines apart. MASM 5 tolerated it; `wasm` rejects it. Stack-frame offsets
that are legitimately redefined per procedure (`OB equ @AB`) need the
redefinable form `=` instead.

**Mixed `return;` and `return(value);` in one function.** Standard K&R
practice, an error for a modern compiler. Decide what the bare `return` was
returning — usually nothing the caller reads — and make it explicit.

**Files the release forgot.** Sopwith's GPL drop is missing `SW.LNK` (the link
script), `mixed.inc` (an assembly include), and the whole "BMB" block-I/O
library (`bopen`/`bread`/`bwrite`/`bseek`/`bioerr`, referenced but defined
nowhere). Reconstruct what you can — `SW.MAK` listed its objects in link
order, which *is* the content of `SW.LNK` that matters — and stub the rest,
loudly.

**Some source files contain no code at all.** `SWPLANES.C`, `SWSYMBOL.C`,
`SWGROUND.C` and `SWGAMES.C` are ~60 KB of pure data tables: sprite bitmaps,
terrain, game configurations. Do not go looking for their functions. Do find
their data in the binary — a distinctive table is a reliable landmark. The
16-entry sine table in `SWMAIN.C` was located by byte pattern in seconds and
confirmed the data segment's position.

**The shipped binary may not match the source you were given.** Sopwith's
`SOPWITH.EXE` decompiles to a `main()` with five calls in its loop; the source
drop's `main()` has `malloc`, `setjmp`, a `movetick` busy-wait and a
print-screen block that are simply absent from the binary. They are different
versions. Rebuild from source to get a binary whose mapping you can trust, and
keep the shipped one as the realistic no-source test case.

## Toolchain conventions

**Calling convention decides symbol decoration.** Microsoft C put the
underscore in front (`_swmove`); Open Watcom's default register convention
puts it behind (`swmove_`). Mixing them produces a wall of undefined
references. Compiling with `-ecc` (`__cdecl`) restores the Microsoft
convention and made every C-to-assembly reference in Sopwith resolve at once.

**`#pragma aux` functions emit no linkable symbol.** They inline. If another
module calls one, wrap it in a real function.

**wasm parses `push CS:label` as an immediate push** (a 186+ instruction) where
MASM read it as `PUSH m16`. Write `push word ptr CS:label`. The same applies
to `push variable`.

## Confidence reporting

**Do not report an internal weight as a confidence.** The sequence alignment
pins anchor pairs to a similarity of 1.0 so the alignment stays attached to
what the greedy pass already believes. An early version then reported that
pinned value as the match's confidence, which turned "the greedy pass picked
this" into "this is certain". On the shipped Sopwith it produced 28 matches at
exactly 1.000 while `main` — the one answer independently verified by reading
the code — was mapped wrongly at 0.268. The pinned value now drives the
dynamic program only; the reported score is the unpinned similarity.

The symptom is recognisable: a run where many matches share an identical top
score is reporting a constant, not a measurement.

## Analysis

**Small model explains suspiciously few relocations.** Sopwith has 2
relocations for a 60 KB image, which looks like a packer until you notice both
sit within a few bytes of the entry point: they are the startup code loading
`DGROUP` and the stack segment. Code that never forms a far pointer needs no
fixups. Check where the relocations are before concluding anything.

**A linker map lists data symbols alongside functions.** Scoring
identification accuracy against the raw map understates it badly — of 330
symbols in Sopwith's map, 183 are variables. Filter to names the source
declares as functions.

**Ghidra addresses are biased.** Its MZ loader places the image at segment
`0x1000`, while a linker map numbers segments from zero. Add the bias before
comparing, or nothing will line up and the cause is not obvious.
