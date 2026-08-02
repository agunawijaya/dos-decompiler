# What actually works, measured

Everything here was measured on Sopwith. The setup: the 2003 GPL source
release rebuilt with Open Watcom into a binary whose linker map gives the
correct address of every function, then decompiled with Ghidra 12.1.2 and
matched back against the source. Because the answer key is exact, the numbers
are real rather than impressions.

Scope note: one program, one compiler, one architecture. Treat the numbers as
calibration for expectations, not as universal constants.

## Headline results

| Stage | Result |
|---|---|
| Ghidra decompiles 16-bit real mode | 289 of 289 functions, 0 failures |
| Function entry points found by auto-analysis alone | 99 of 148 known (67%) |
| After `RecoverFunctions.java` | 120 of 148 (81%) |
| C runtime library detection | **precision 1.000, recall 0.905** |
| Identification, Watcom ground truth, inferred order | precision 0.875, recall 0.583 |
| **Identification, Microsoft C 5.0 ground truth** | **precision 0.935, recall 0.717** |
| Emulation-decided equivalence, two builds of one source | **110 matches, precision 1.000** |

Ghidra's decompiler itself is not the weak link. It handled segmented 16-bit
real mode without a single refusal. Everything hard is upstream of it:
deciding what is a function, and downstream of it: deciding what a function is
*called*.

### And on the `.COM` route, where the answer is a rebuild

| | code region | as instructions | + pinned | residue |
|---|---|---|---|---|
| Karateka (1984), 87,990 B | 27,805 | **91.9%** | 99.1% | 252 B |
| Hard Hat Mack (1983) | 27,787 | 78.2% | 80.6% | 5,394 B |
| ParaTrooper (1982) | 5,328 | 90.9% | 97.7% | 125 B |
| Zaxxon (1984) | 8,413 | 75.8% | 78.7% | 1,796 B |

All four rebuild **byte-identically**, checked by SHA-256 outside the tool that
produced them, and all four now report *nothing in it looks like unreached
code* — which is the claim worth making. The percentages differ mostly because
of how much data each program keeps *between* its routines: Hard Hat Mack's
residue is 1,201 bytes of CGA scanline offsets, 1,171 of artwork and 793 of HUD
strings, none of it lost.

### Reconstruction is not reading

Karateka's reconstruction is finished in every sense the tools can measure, and
finishing the *reading* was a separate job that took its own sitting: **80 of
its 120 routines are named**, and the split is the interesting part. Every
routine that touches a game global is named. The remaining 40 are the C
library, separated mechanically — no game global, and DOS reached only through
twelve identified primitives — and left unnamed because their shapes do not
discriminate. `libscan.py` would name them given the library; guessing would
only produce names the next reader believes.

That gap is worth stating plainly whenever a percentage is quoted, because
"91.9% recovered" and "we understand this program" are different claims and the
first is much easier to reach. A byte-identical rebuild proves the *bytes* were
read correctly. It says nothing about whether anybody understood them.

## Validate against a period-correct compiler, not a convenient one

The Watcom rebuild was the cheap ground truth: free, scriptable, no licensing
question. It is also a poor stand-in for a 1980s binary, and using it alone
understates what the pipeline can do.

Rebuilding the same source with Microsoft C 5.0 -- the compiler `SW.MAK`
actually names -- changed the numbers substantially:

| ground truth built with | prologues found | identification precision | recall |
|---|---|---|---|
| Open Watcom V2 | 25 | 0.875 | 0.583 |
| **Microsoft C 5.0** | **208** | **0.935** | **0.717** |

Two reasons. Microsoft C emits a stack frame for nearly every function, so
boundaries are recoverable where Watcom's frame-pointer omission hides them
(the shipped 1987 binary has 243 prologues, squarely in Microsoft territory).
And its code generation tracks the source structure closely enough that
control-flow shape comparison works far better.

The lesson generalises: **the compiler you validate against decides what your
figures mean.** Quote the period-correct number.

Getting there needs two capabilities the package now has. `fatextract.py`
reads files out of raw FAT12 floppy images, which is how these toolchains are
archived. `dosrun.ps1` drives DOSBox-X headlessly through a generated config
file with an `[autoexec]` section -- its `-c` arguments are unreliable and it
has no host stdout, so output is redirected inside DOS to a file on a mounted
drive and read back from Windows.

## When a game has no C runtime at all

Applying Microsoft C signatures to the shipped 1987 SOPWITH.EXE matched
**zero** of 325 functions. That is not a failure of the method; it is a finding
about the binary.

The entry points tell the story:

```
shipped SOPWITH.EXE   db e3 b8 31 0b 8e d8 8c 06 5b 08 26 a1 02 00 ...
                      FNINIT; mov ax,0B31h; mov ds,ax; ... mov ax,es:[2]
MS C 5.0 startup      b4 30 cd 21 3c 02 73 02 cd 20 bf 70 08 ...
MS C 5.1 startup      b4 30 cd 21 3c 02 73 02 cd 20 bf 60 07 ...
```

The two Microsoft startups are nearly identical to each other and share
nothing with the shipped game. Sopwith opens by initialising the coprocessor,
loading DGROUP from an immediate, and reading the PSP directly — a
hand-written startup. `SW.MAK` compiles with `-Zl`, which suppresses default
library records, and the unreleased "BMB" library evidently supplied the
runtime.

Rebuilding the same source with Microsoft C 5.0 produces the standard
`b4 30 cd 21` startup, which confirms it: the difference is the runtime, not
the compiler.

**Diagnostic value:** a signature database that matches nothing, when you are
confident of the compiler, means the program brought its own runtime. That is
worth knowing early — it tells you every function in the binary is the
developer's, and none of it can be dismissed as library noise.

## Deciding equivalence instead of scoring resemblance

Every technique above scores a resemblance, and resemblance saturates: with
constants, strings, call-graph position and control-flow shape all combined,
precision tops out near 0.88 and the errors that remain are pairs that
genuinely look alike.

Running the code settles it. `emuverify.py` executes both candidates under an
8086 emulator on identical inputs and compares what they actually did — return
registers, the set of DGROUP reads and writes, the number of calls made.

Validated with full ground truth by building Sopwith twice from the same
source with different code generation (8086 speed-optimised versus 286
size-optimised). Both builds have linker maps, so every correspondence is
known; only 45 of 202 functions land at the same address, so the matching
problem is real:

| observation set | profiled | matches | precision |
|---|---|---|---|
| return registers + writes + call count | 173 | 60 | **1.000** |
| + memory reads | 173 | 89 | **1.000** |
| + partial profiles, input vectors tuned | **202** | **110** | **1.000** |

**Zero incorrect matches, every time.** Two extensions earned the last row:

*Memory reads.* A routine that only inspects state writes nothing, so without
reads it looks identical to every other such routine. Including them dropped
the behaviourally indistinguishable count from 80 to 51.

*Partial profiles.* A function that never returns used to be discarded — and
those are exactly the interesting ones: interrupt service routines, `longjmp`
targets, the main loop. Instead of demanding a return value, the run is
bounded and only the **set of global offsets touched** is compared: no values,
no counts, no registers, because two builds run a different number of loop
iterations inside the same instruction budget and anything count-dependent
would differ for reasons that say nothing about the function. That rescued 27
functions from unprofilable and produced **9 matches among functions that
never return**, still with no errors.

Getting there needed one correction worth recording: exhausting the
instruction budget and faulting are different outcomes. Conflating them made
the partial path unreachable, and the feature silently did nothing until they
were separated.

**And more input vectors turned out to be worse, not better.** The intuition
that more inputs means more discrimination is wrong here. Sweeping the count:

| vectors | 1 | 2 | 3 | 4 | 5 | 6 | 8 | 10 | 12 |
|---|---|---|---|---|---|---|---|---|---|
| matches | 93 | 107 | **110** | **110** | **110** | 98 | 97 | 97 | 97 |

Zero incorrect matches at every setting. One vector really is too few —
functions that ignore their arguments cannot be separated and get filtered as
uninformative — so this is not simply "less is more". It peaks at three to
five and then degrades, because the vectors added beyond that were wilder:
values like `0x8000` and `0x5000` used as pointers. A wild access lands
somewhere that depends on code generation, which breaks matches between two
builds of the *same* function.

The rule that falls out: **keep synthetic arguments inside plausible data
ranges.** Extreme values do not probe harder, they just add build-dependent
noise. Four vectors ship.

How the runs are set up: the image is mapped at segment 0x1000, DGROUP goes
where the binary's own layout puts it (so global offsets line up between
builds — verified: all 125 data symbols share offsets across the two builds),
arguments are pushed cdecl-style under a sentinel return address, calls are
skipped with a deterministic stub return in call order, and interrupts are
ignored.

### What it cannot do

**Some functions are behaviourally indistinguishable, and always will be.**
`intson` is `sti; ret` and `intsoff` is `cli; ret`; no amount of input
variation separates them. The tool reports these rather than guessing, which
is the point.

**A function may return in one build and not the other.** Different code
generation means a different instruction count against the same budget, so one
side gets a complete profile and the other a partial one, and they will not
match. That is a missed match, never a wrong one — the two profile kinds
cannot collide, because a partial profile has no return value to compare.

**It needs the two binaries to implement the same algorithm.** Pointed at the
shipped SOPWITH.EXE — a different version of the game, built by a different
compiler — it found **2 matches**, both disk I/O helpers that plausibly did
not change between releases.

That last result is worth sitting with. Statistical matching, run on the same
pair, produced dozens of confident-looking scores and got `main` wrong.
Emulation produced almost nothing. **The failure mode is loud rather than
quiet**, and for a technique whose output becomes function names in source
you will read for weeks, loud failure is the safer property.

## Compare shape, not content

The most transferable feature turned out to be the one a compiler is least
free to alter. It can fold constants, pool string literals, reorder data and
inline whatever it likes — but an `if` in the source has to become a
conditional branch, and a loop has to become a back edge. Decision structure
survives compilation in a way that byte-level features do not.

So both sides now count the same three quantities: cyclomatic complexity,
loop count and return count. The source side counts them textually in
`srcinv.py`; the binary side derives them from Ghidra's basic-block graph in
`ExportDecompiledC.java` (McCabe = edges − blocks + 2, loops = back edges).

Sweeping the weight of that term, with the C library already excluded:

| shape weight | inferred order | known order |
|---|---|---|
| 0.0 (off) | 0.826 / 0.475 | 0.838 / 0.517 |
| 0.6 | 0.866 / 0.592 | 0.857 / 0.600 |
| 0.9 | 0.869 / 0.608 | 0.867 / 0.600 |
| **1.2** | **0.875 / 0.583** | **0.897 / 0.583** |
| 2.0 | 0.808 / 0.525 | 0.895 / 0.567 |
| 2.5 | 0.800 / 0.500 | 0.907 / 0.567 |

(precision / recall)

1.2 is shipped. 0.9 gives the best F1, but precision is worth more than recall
here: a wrong name propagates into every later reading of the code, a missing
one does not. Past 1.5 the term starts to dominate the score and drags the
inferred-order case down with it.

The gain is large and it is largest exactly where it matters — the realistic
configuration, with no makefile to reveal the link order, went from 0.826 to
0.875 precision and from 0.475 to 0.583 recall.

## The other large win: get the C library out of the way

A linked program is part game and part C runtime, and nothing in a stripped
binary says which is which. Every library routine competes for attention in
the decompiled output and, worse, competes for *matches* — a source function
can be scored against a library routine it merely resembles.

`libsig.py` recognises them the way FLIRT does: store each library function's
opening bytes together with a mask marking the displacement and immediate
fields, which change when the same routine is linked at a different address.
The mask comes from disassembling with capstone and blanking every field the
instruction encoding declares.

Building the database needs a program compiled with the same toolchain; the
package ships `signatures/libref.c`, written purely to reference as
much of the library as possible. Applying signatures built from *that* program
to Sopwith is a genuine held-out test:

| toolchain | precision | recall |
|---|---|---|
| Open Watcom, first attempt | 1.000 | 0.667 |
| Open Watcom, after adding DOS interrupt helpers to libref.c | **1.000** | **0.905** |
| **Microsoft C 5.0** | **1.000** | **0.762** |

The Microsoft figure is the one that matters for real games of the era, and it
is a genuine held-out test: signatures built from `libref.exe`, applied to a
Sopwith compiled by the same toolchain. Zero false positives in every run.

Perfect precision is the property that matters. A false positive would delete
real game code from consideration; a false negative merely leaves noise in.

The effect on identification, measured as a clean 2×2 (before the
control-flow shape term was added):

| module order | library excluded | precision | recall |
|---|---|---|---|
| inferred | no | 0.696 | 0.325 |
| inferred | **yes** | **0.826** | 0.475 |
| known | no | 0.800 | 0.433 |
| known | **yes** | **0.838** | **0.517** |

Read the middle rows against each other. **Excluding the library is worth more
than knowing the link order** — +0.13 precision against +0.10 — and the two
compose. It is also the more practical of the two, because it needs no
surviving makefile: build a signature database once per toolchain and it
applies to every binary that toolchain produced.

Caveat worth stating plainly: signatures are toolchain-specific, and strictly
so. Applying the Open Watcom database to a Microsoft C binary matches **zero**
functions. That is the safe failure mode — no false positives across compilers
— but it means a database is useless outside the toolchain it was built from.

Three databases ship in `signatures/`: Open Watcom V2, Microsoft C 5.0,
and Microsoft C 5.1, all 16-bit small model. They are masked byte fingerprints,
not code. To cover another compiler or memory model, compile
`signatures/libref.c` with it and run `build-sigs.ps1`.

One format wrinkle: Microsoft LINK's map has no `Module:` lines, so library
code cannot be told from the reference program's own. `libsig.py` detects that
and takes every symbol, relying on `--exclude-symbol` for the handful that
belong to `libref.c` itself. Watcom's `wlink` does record modules, so there the
split is exact.

## Module order beats content

The strongest signal available is not what a function contains. It is where it
sits.

A linker places modules in the order the link script lists them, and a
compiler emits each module's functions in source order. So the binary read by
increasing address is very nearly the source read file-by-file, top to bottom.
Exploiting that with a sequence alignment instead of independent pairwise
scoring is worth more than every content heuristic combined:

| Configuration (library not yet excluded) | precision | recall |
|---|---|---|
| Greedy pairwise scoring only | 0.65 | 0.33 |
| + alignment, order inferred from anchors | 0.70 | 0.33 |
| + alignment, order taken from the makefile | **0.80** | **0.43** |
| Alignment with true order and *no* anchors at all | **0.86** | 0.41 |

Read the last row carefully. Given the correct module order, throwing away the
content-based anchors entirely produced the **highest precision of any
configuration tested**. Position alone identifies functions better than
content does. Anchors help only because they are how you estimate the order in
the first place.

**Practical consequence.** Before tuning any similarity heuristic, hunt for
anything that reveals the link order: a `.MAK`, a `.LNK` response file, a
build batch file, a README naming the modules. On Sopwith, `SW.MAK` listed its
objects in link order — the recovered order came free from a file sitting in
plain sight.

## What failed, and why it is recorded here

**Iterative refinement of the module order.** Feed the alignment's output back
as anchors, re-infer the order, re-align, repeat. It sounds obviously right
and it does not work: it converged to exactly the same mapping as one pass
(precision 0.70), and starting it without anchors made things worse (0.49). It
reinforces whatever order error it began with instead of correcting it. The
code is kept in `match.py` with this result in its docstring so nobody spends
an afternoon rediscovering it.

**Prologue scanning as the primary way to find functions.** Scanning for
`55 8B EC` (`push bp; mov bp,sp`) is the textbook technique and it found
**25 prologues in the entire binary**. Open Watcom omits the frame pointer
under optimisation, so the pattern barely occurs. Microsoft C 5.x emits it
faithfully, so the technique's value depends entirely on the compiler — check
before relying on it.

**Constants as the primary identifier.** Weighted by rarity, shared constants
between a source function and a binary function gave precision around 0.65 on
their own. Useful as one term among several, not as a decision procedure.

## What worked better than expected

**Immediate-operand scanning for function pointers.** Any 16-bit immediate
that lands inside the code segment is a candidate function entry, because in a
small-model real-mode program a function pointer *is* a 16-bit offset loaded
as an immediate. This recovered 56 functions that no other technique found.

Restrict it to blocks that genuinely hold code. Ghidra's MZ loader marks every
segment executable, data included; without that filter the scan defines
"functions" inside sprite tables.

**String literals as anchors.** Where both sides have them and they agree, the
match is effectively certain. The limitation is coverage — in a game like
Sopwith only a handful of functions touch strings at all.

## Recovering module boundaries from the binary alone

Since module order is the dominant signal, the obvious next move is to recover
it without needing a surviving makefile. Functions from one source file sit
together in the binary and share file-scope data, so a boundary should be
visible as a change in which globals are being touched.

Ghidra creates almost no data references on this architecture -- in real mode
`mov ax,[0x1234]` has its segment in DS at run time, so there is no resolvable
target (measured: 2 of 289 functions had any). The raw displacement works
just as well as an identity for the variable, and `modcluster.py` uses that.

**The premise holds.** Of the 204 distinct globals touched by functions whose
module is known, 141 (69%) are touched from exactly one module.

**A second premise does not.** Only **9% of call edges stay inside their
module** -- 28 internal against 269 crossing. Sopwith's modules are organised
by role (movement, display, collision, sound), so they call each other
constantly. Do not assume module-internal cohesion in call graphs of games
from this era.

Boundary detection, against the linker map, on 27 true boundaries:

| Signal | precision | recall |
|---|---|---|
| random baseline | 0.19 | — |
| data-reference cohesion alone | 0.32 | 0.26 |
| call-graph minimum cut alone | 0.44 | 0.59 |
| both combined (call weight 0.65) | 0.52 | 0.67 |
| **combined, cut normalised locally** | **0.52** | **0.70** |

The min-cut wins despite only 9% of edges being internal, because what matters
is the *local* dip in edge density at a seam, not the global ratio. For the
same reason the cut must be scored against its neighbourhood rather than
against the global maximum: densely-called game code and the sparsely-called
library tail have completely different absolute cut counts, and a global scale
puts every boundary in the sparse region. On the shipped Sopwith that produced
one segment of 257 functions and twenty-five of two.

Cut spacing needs a light hand. Forcing boundaries `n/(2*expected)` apart
dropped precision to 0.32 and recall to 0.41, because real modules are
frequently only two or three functions long. `n/(4*expected)` keeps the full
score while capping the worst segment at a readable size.

**But it does not improve identification.** Feeding the recovered segments
into the module ordering made things worse, both ways it was tried:

| Ordering method | precision |
|---|---|
| median position of each file's anchors (baseline) | **0.696** |
| order files by the first segment that voted for them | 0.405 |
| drop anchors that disagree with their segment's majority | 0.225 |

With ~25 segments over ~290 functions there are only one to three anchors per
segment, so a "majority" is noise, and discarding minority anchors throws away
the aggregate position evidence the median ordering depends on. The
segmentation is real; the anchors are too sparse to exploit it. The bottleneck
is anchor accuracy.

`modcluster.py` is therefore kept as an analysis tool -- a human reading the
segment list gets a genuinely useful map of the binary -- but it is not wired
into the matcher.

## Finding main

`anchors.py` walks down from the entry point while each step has essentially
one callee that accounts for everything below it. A C runtime startup is a
straight chain; main is where the program fans out.

**Measured: correct on 1 of the 2 Sopwith builds.** Right on the Watcom
ground truth (`1000:7771 -> 1000:7ccd -> 1000:1459`, exactly what the linker
map calls main). Wrong on the shipped Microsoft C binary, where the startup
reaches main through a call Ghidra could not resolve, so the walk stops early.

Reading beats the heuristic and takes a minute: main is `init(argc,argv)`
followed by an endless loop. In the shipped binary that shape identified
`1000:0000` immediately and unambiguously.

## Matching across versions or compilers does not work

Run against the *shipped* SOPWITH.EXE rather than the rebuilt one, with the
same source as reference, the matcher produced **no match above 0.70
confidence at all**, a best score of 0.453, and put `main` in the wrong place
at 0.25. Against the rebuilt binary the same code reaches 0.80 precision.

Two differences account for it: the shipped binary is an older version of the
game (its `main` lacks the `malloc`, `setjmp`, `movetick` wait and
print-screen block the source has), and it was built by a different compiler.

So: statistical matching needs source that genuinely corresponds to the
binary. When it does not, the scores collapse, and — usefully — they collapse
visibly.

Adding the control-flow shape term later lifted the shipped binary's best
score to 0.892 and produced a handful of plausible-looking mid-confidence
matches, mostly in `SWMOVE.C` and at addresses adjacent to each other, which
is at least consistent with a real module. But `main` is *still* mapped
wrongly, at 0.268, against an answer established by reading the code. Treat
the whole set as unverified leads. Structural similarity narrows the gap
between versions; it does not close it.

## Where the remaining error lives

Of 148 known functions, 28 still have no matching Ghidra entry point after
recovery. These are reached only through paths the analysis cannot see.

The bottleneck for identification is **anchor accuracy**. Everything
downstream — the alignment, the module ordering, the segment voting — is
limited by the fact that the greedy first pass is right about two thirds of
the time. Module segmentation was the obvious way around it and measured
worse (above), because sparse anchors cannot support per-segment voting.

Two items from the original list are now done, and both delivered roughly what
was predicted. Library exclusion took the realistic configuration from 0.696
to 0.826 precision; control-flow shape took it from 0.826 to 0.875 and lifted
recall from 0.475 to 0.583. Together they moved identification from "generates
leads" to "usually right".

All three items from the original list are now done. Emulation was the last,
and it did not so much raise precision as replace the question: instead of
pushing resemblance past 0.9, it decides equivalence outright at 1.000 for the
subset it can run.

The Microsoft C database is now built and validated too, and validating against
a period-correct binary raised the headline figures from 0.875/0.583 to
0.935/0.717.

What remains, in rough order of value:

1. **Widening the emulator's reach.** The 51 indistinguishable functions might
   shrink with input vectors chosen to make each one branch differently, and
   the 28 that never return — interrupt handlers and endless loops — could be
   compared on a bounded execution trace instead of a return value. Both are
   unmeasured ideas, not predictions.
2. **Databases for other period toolchains** — Lattice C, Turbo C, Microsoft C
   4.0. The machinery is done; each needs the compiler and one run of
   `build-sigs.ps1`. Note that Microsoft C 1.0–3.0 were rebadged Lattice C, so
   a Lattice database would cover early-1980s Microsoft-built games too.
3. **The functions with no recovered entry point.** They cap recall no matter
   how good any matcher gets.
