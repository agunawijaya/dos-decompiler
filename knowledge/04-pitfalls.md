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

## Driving a program under emulation

**A queue of keystrokes vanishes in one screen.** The Oregon Trail consumed 88
keys in 88 reads without ever pausing. Turbo Pascal opens most prompts with
`while KeyPressed do ReadKey` to throw away type-ahead, and an emulator that
answers "yes, a key is waiting" hands that loop the entire queue. Answering
"no" instead hangs the opposite idiom, `repeat until KeyPressed`. Both are
`INT 16h AH=01` and no fixed answer is right — what separates them is
persistence, so `--poll-patience N` says "nothing waiting" until the question
has been repeated N times since the last blocking read. Feeding *more* keys
makes it strictly worse, which is the wrong direction to reach for first.

**Two screens can look like one broken one.** Every hunting-screen capture came
back with two screens overlapping and the text unreadable, which reads like a
renderer bug. It was not: the program was frozen mid-redraw, and the give-away
was that three runs with different budgets and different keystrokes produced
**pixel-identical** images. A frozen frame is a symptom to trace, not a picture
to publish.

**Raising the budget is almost never the fix.** If a longer run produces the
same distinct-address count, the same read count and the same frame, it stopped
making progress long before either limit. Report *where* the budget ran out,
not just that it did — the difference between "budget exhausted" and "budget
exhausted at 15FD:1784" was three runs and four and a half billion instructions
against one disassembly.

**Do not enter a compiled routine in the middle to look at its screen.** It gets
you the code without the state. The Oregon Trail's hunting routine, called
directly with every plausible variable poked, died in a far call through a null
driver vector — because the BGI driver is installed on the way in, and there is
no way in but the menu. The general form: a `--call` gives you a routine whose
caller never ran, and the failures it produces are all consequences of that one
fact.

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

**Asking for callers of an address in the middle of a routine always answers
none.** This document's own author published "the joystick routine at 0x425E,
and nothing in the image calls it" — a finding on both counts, and wrong on
both. `0x42EC` was not an entry point at all; it was a `call` instruction
*inside* the routine that begins at `0x42D1`, so a scan for `E8` displacements
landing on it could only ever return zero. And `0x425E` was not the joystick:
it writes ports `0x3BA` and `0x3BF`, which is Hercules display detection.

Before concluding that nothing reaches an address, check that the address is
somewhere anything *could* reach — a prologue, a jump target, or a word
appearing in the data. An interior address is none of those, and "no callers"
about one is not a finding, it is a category error.

**A counter's meaning is in what it is compared against, not what sets it.**
Two globals in Karateka are both initialised to 32 and both decremented, which
reads as a pair of hit-point counters and was written up as one twice. They are
a timer: the branch above them is `cmp ax, 0x14a` — a distance of 330 pixels —
and no health counter cares how far away the other fighter is. The assignment
and the decrement are the two least informative instructions about a variable;
the comparison is where the meaning is.

**A table's address may never appear in the program.** Two games here have hit
this, in two different languages, six years apart. If a subscript range does not
start at zero — `array[3..8] of string[10]` in Pascal, or the same trick written
by hand in assembly — the compiler folds the lower bound into the base *once*,
at compile time, so indexing costs a multiply and an add instead of a multiply,
a subtract and an add. What the code then contains is `base − low × stride`,
which points at nothing:

    0013C61  mov al, [bp-0x103]        ; The Oregon Trail: an illness code, 3..8
    0013C67  mov dx, 0x000B / mul dx
    0013C6E  add di, 0x0CB5            ; the table is at 0x0CD6 -- 33 bytes later

`0x0CB5` lands in the middle of the previous string. Searching the image for
`0x0CD6` finds nothing at all, and the natural conclusion — that the table is
unused — is wrong. Zaxxon does the same with two tables, four bytes early, and
its notes say *"it looks like a bug and is not."*

**So enumerate the mechanism, not the address.** Scan for the *stride* instead:
every `mov dx, <n> / mul dx` followed by an `add di, imm16` is a table access,
and the list is short enough to read — 42 of them in a 200 KB program, with the
answer sitting in plain sight. The same move solved a second problem in the same
binary, where a whole missing segment made a subsystem look as though it
addressed its data by magic.

The general rule, and it is worth more than either case: **when a search with a
good positive control still comes back empty, change the question rather than
the thresholds.** A control proves the search works; it cannot tell you the
search is asking for the right thing.
