# Sopwith, worked end to end

Sopwith (David L. Clark, 1984; GPL'd 2003) is this package's reference case
because both halves survive: a shipped DOS binary and the original C and
assembly source. That makes it possible to check answers instead of admiring
them.

Two targets are used, and the difference between them is the point.

| | shipped `SOPWITH.EXE` | rebuilt `sopwith.exe` |
|---|---|---|
| size | 60,928 bytes | 46,578 bytes |
| compiler | Microsoft C 5.x (per `SW.MAK`) | Open Watcom V2 |
| version | older than the source drop | exactly the source drop |
| answer key | none | linker map, every function |
| role | realistic case: no usable source | validation: measure accuracy |

## Establishing that the shipped binary is not the source

`main()` in the source reads:

```c
nobjects = (OBJECTS *)malloc( 100 * sizeof( OBJECTS ) );
swinit( argc, argv );
setjmp( envrestart );
FOREVER {
    while ( movetick < movemax );
    intsoff(); movetick -= movemax; intson();
    swmove(); swgetjoy(); swdisp(); swgetjoy(); swcollsn(); swgetjoy();
    intsoff();
    if ( printflg ) { ... }
    intson();
    swsound();
}
```

`main` in the shipped binary, decompiled:

```c
void main(undefined2 param_1, undefined2 param_2)
{
  FUN_1000_2089(param_1, param_2);
  do {
    FUN_1000_02f6(); FUN_1000_3bef(); FUN_1000_0185();
    FUN_1000_3bd5(); FUN_1000_1886();
  } while( true );
}
```

No `malloc`, no `setjmp`, no `movetick` wait, no print-screen block. These are
different versions of the game. The source's modification history explains it:
entries run to 1996, while the shipped binary predates them.

The consequence is measurable. Matching the source against the shipped binary
produced **no result above 0.70 confidence**, a best score of 0.453, and put
`main` at the wrong address with score 0.25. Against the rebuilt binary the
same code reaches precision 0.80.

## Rebuilding, and what the release is missing

`build/build.ps1` rebuilds from pristine source. Five modern-toolchain fixes
are applied to a working copy; none touch the original. Each is documented in
`knowledge/04-pitfalls.md`. Three items are simply absent from the GPL
release:

- **`SW.LNK`**, the link script. Recovered: `SW.MAK` lists its objects in link
  order, which is the part that matters, and that order is `module-order.json`.
- **`mixed.inc`**, an assembly include. Recreated empty after checking that
  Sopwith uses no macros from it — the 101 apparent CMACROS hits in the
  assembly turned out to be the ordinary word "save".
- **The BMB block-I/O library** (`bopen`/`bread`/`bwrite`/`bseek`/`bioerr`),
  referenced by `SWMULTIO.C` and defined nowhere. Stubbed in `compat.c`;
  multiplayer therefore does not work in the rebuilt binary.

The build is reproducible: same source, same 46,578-byte output.

## What the numbers came out as

```
function entry points recovered   120 of 148 known   (81%)
library detection                 precision 1.000  recall 0.905
identification, inferred order    precision 0.875  recall 0.583
identification, known link order  precision 0.897  recall 0.583
```

`regress.py` reproduces these and fails if they regress. How they got there,
each step adding to the last:

| configuration | precision | recall |
|---|---|---|
| constants and strings only | 0.696 | 0.325 |
| + C runtime excluded | 0.826 | 0.475 |
| + control-flow shape compared | 0.875 | 0.583 |
| + link order known | 0.897 | 0.583 |

Six results shaped the method more than any tuning did:

**The compiler you validate against decides what your numbers mean.** The
Watcom rebuild was the cheap ground truth. Rebuilding the same source with
Microsoft C 5.0 — the compiler `SW.MAK` actually names — moved identification
from 0.875/0.583 to **0.935/0.717**, because Microsoft C emits a stack frame
for nearly every function (208 prologues against Watcom's 25) and its output
tracks the source structure far more closely. Quote the period-correct figure.

**Sopwith has no Microsoft C runtime in it.** Library signatures built from
Microsoft C 5.0 and 5.1 match zero of the shipped binary's 325 functions. The
entry point begins `FNINIT; mov ax,0B31h; mov ds,ax; mov ax,es:[2]` — reading
the PSP by hand — where both Microsoft startups begin `mov ah,30h; int 21h`.
Rebuilding the same source with Microsoft C 5.0 produces the Microsoft startup,
which settles it: `SW.MAK` compiles with `-Zl` and the unreleased BMB library
supplied the runtime. A signature database matching nothing, when you are sure
of the compiler, means the program brought its own.

**Running the code beats scoring it.** Building Sopwith a second time from the
same source with different code generation gave two binaries with complete
symbol maps and almost no shared addresses — a real matching problem with a
known answer. Executing candidate pairs under an 8086 emulator and comparing
what they did produced **110 matches with zero errors**, nine of them functions
that never return at all — interrupt handlers and the main loop, compared on
which globals they touched within a bounded run. No resemblance metric gets
near that. It works only where both binaries implement the same
algorithm, and it says so loudly when they do not: pointed at the shipped
binary, a different release, it found 2 matches instead of pretending.

**Compare shape, not content.** A compiler may fold constants and pool
strings, but an `if` must become a branch and a loop must become a back edge.
Counting cyclomatic complexity, loops and returns on both sides — textually in
the source, from the basic-block graph in the binary — was the single largest
gain of all: 0.826 to 0.875 precision, 0.475 to 0.583 recall.

**Getting the C runtime out of the way comes next.** A linked program is part
game and part library, and the library competes for matches. Recognising it
with masked byte signatures — built from a reference program compiled with the
same toolchain, so the test is held-out — raised precision from 0.696 to
0.826. That is a larger gain than knowing the link order, and it requires no
surviving makefile.

**Module order beats content-by-similarity.** Before the shape term existed,
alignment against the true link order with *no* content anchors at all reached
0.86 precision — better than any content-based configuration of the time.
Position identifies functions better than resemblance does.

**Ghidra misses a third of the functions.** Auto-analysis found 232; 48 real
functions were never disassembled, because they are reached only through
function pointers stored in object structures (`ob_movef`, `ob_drawf`) and
through interrupt vectors. Scanning for immediates that land in the code
segment recovered 56 of them, bringing the total to 289. Those 48 were the
movement handlers, the drawing handlers, and the keyboard and timer ISRs —
the whole of the gameplay code.

## The shipped binary, treated as a real target

With no usable source, the evidence-based route applies. `anchors.py` found 44
of 325 functions carrying identifying evidence, and 20 earned a name that
states only what was established — `bios_video`, `dos_svc`, `pic_ack`,
`cga_access`, `crt_startup`.

`main` was found by reading rather than by rule: the automated startup-chain
walk pointed at `1000:8b21`, but the shape `init(argc,argv)` followed by an
endless loop identified `1000:0000` unambiguously.

Working outward from there, the loop's five callees are the game's phase
order. Naming them from the source's loop was tempting and would have been
wrong: the candidate for `swcollsn` has **6 instructions and no calls**, which
no collision routine has. That hypothesis was dropped rather than shipped, and
the functions remain unnamed. The fingerprint data in `functions.json` exists
to make that kind of check cheap.

## Confirmed facts about the binary

Established, not inferred:

- Small memory model. Two relocations for 60 KB, both within 0x30 bytes of the
  entry point — the startup loading `DGROUP` (`0B31h`) and the stack
  (`15CAh`), and nothing else needing a fixup.
- The data segment begins at image offset `0xB310`. Confirmed independently by
  locating `sintab[]` — the 16-entry sine table from `SWMAIN.C`, values
  `0, 98, 181, 237, 256, ...` — by byte pattern at image offset `0xBB80`.
- 243 stack-frame prologues (`55 8B EC`), against 25 in the Watcom rebuild.
  Microsoft C emits frame pointers faithfully; Watcom omits them under
  optimisation. This is why prologue scanning is a compiler-dependent
  technique rather than a universal one.
- Four source files — `SWPLANES.C`, `SWSYMBOL.C`, `SWGROUND.C`, `SWGAMES.C` —
  contain no functions at all. They are ~60 KB of sprite bitmaps, terrain and
  game configuration. Their data is findable in the binary by pattern and
  makes excellent landmarks.
