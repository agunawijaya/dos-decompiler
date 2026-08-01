# Identifying the compiler, and why it pays

Knowing which compiler built a binary tells you what its function prologues
look like, how arguments are passed, how symbols are decorated, and which
"weird" constructs are just idiom. Establish it early.

## Identifying the compiler

Signature strings are the easy case, and often absent — Sopwith's `SOPWITH.EXE`
contains no compiler banner at all. When strings fail, use behaviour:

| Evidence | Suggests |
|---|---|
| `push bp; mov bp,sp` on nearly every function | Microsoft C 4/5, Lattice C, Turbo C |
| Frame pointer frequently omitted | Open Watcom, later Borland with optimisation |
| Arguments pushed right-to-left, caller cleans (`add sp,N`) | `__cdecl` — C convention |
| Callee cleans (`ret N`) | Pascal convention — common in Borland-built tools |
| Arguments arriving in `AX`/`DX`/`BX`/`CX` | Watcom register convention |
| Leading underscore on symbols | Microsoft C, Borland |
| Trailing underscore | Open Watcom default |

Sopwith's `SW.MAK` states it outright: `cl -c -Gs -Zl -FPc -AS -Osa` with
`masm` and Microsoft `link`. `-AS` is small model, `-Gs` disables stack
probes, `-Zl` omits default library records, `-Osa` optimises for speed.

## Why the prologue matters more than it looks

Scanning for `55 8B EC` is the textbook way to find function starts. Its yield
depends entirely on the compiler:

- Microsoft C 5.x: emits it for essentially every function.
- Open Watcom with optimisation: omits the frame pointer aggressively. A scan
  of a Watcom-built Sopwith found **25 prologues in the whole binary**.

So check a handful of known function starts before trusting the technique. If
the count is implausibly low, the compiler is not using frame pointers and you
need call targets and code-pointer immediates instead.

## K&R C, and the type information it destroys

Pre-ANSI C has no prototypes. Sopwith's source is 144 K&R definitions against
103 in the newer style:

```c
main( argc, argv )
int   argc;
char *argv[];
{
```

Consequences for decompilation, all of which look like decompiler errors and
are not:

- **Default argument promotion.** `char` and `short` arrive as `int`, `float`
  as `double`. A function the source says takes a `char` genuinely receives a
  16-bit value. The decompiler is right; the source is misleading.
- **Implicit `int`.** A function with no declared return type returns `int`,
  and the value is often ignored. Expect `undefined2` returns nobody reads.
- **No parameter count checking.** Callers may pass more or fewer arguments
  than the definition declares. Stack cleanup at the call site is the truth.
- **8-character symbols.** Linkers of the era truncated names. Sopwith has 30
  symbols longer than 8 characters, so collisions and truncation are possible
  in any symbol table you find.

## Runtime startup

The entry point is not `main`. It is the C runtime startup, which sets up
`DGROUP`, the stack, `argc`/`argv`, and then calls `main`. In a small-model
program the two relocations you see are usually exactly this: loading the data
segment and the stack segment.

Startup code is the most standardised part of a runtime, which makes it a good
compiler fingerprint. Microsoft C 5.0 and 5.1 both begin:

```
b4 30 cd 21    mov ah,30h; int 21h      ; ask DOS its version
3c 02 73 02    cmp al,2; jae ...
cd 20          int 20h                  ; too old: terminate
```

**But some games replace the runtime entirely.** Sopwith's shipped 1987 binary
starts with `db e3` (`FNINIT`), then loads `DGROUP` from an immediate and reads
the PSP directly — nothing in common with Microsoft's startup, even though the
makefile names Microsoft C. The `-Zl` flag suppresses default library records,
and the developer's own library supplied the runtime.

So a startup you do not recognise does not mean you have the compiler wrong. It
may mean there is no stock runtime in the binary at all — in which case every
function belongs to the program, and none of it can be written off as library
noise.

**The first function the startup calls is almost always `main`.** On Sopwith
this identified `main` immediately and correctly, and its body — an
initialisation call followed by an infinite loop of five calls — confirmed it
beyond doubt.

Library functions inflate the function count and match nothing in the game's
source. Identify them by their standard shapes (`printf` family, string and
memory routines, integer division helpers such as `__aNulmul`, `__aFldiv`) and
set them aside rather than trying to name them as game code.

## Inline assembly and hand-written modules

Over a quarter of Sopwith is hand-written MASM. Assembly modules do not obey C
conventions and will not decompile into sensible C:

- They read parameters directly off `BP` with hand-computed offsets
  (`OB equ @AB`, `X equ @AB+2`).
- They preserve and clobber registers by their own rules.
- Interrupt service routines end in `IRET`, not `RET`, and have no callers.

Expect these to decompile into something with too many `unaff_` variables and
implausible control flow. That is the signal to read the disassembly directly
rather than the pseudocode.

## Turbo Pascal, where none of the above applies

Everything above assumes a C compiler: a prologue convention, an OMF runtime
that `libscan.py` can subtract, a startup module that states the entry point.
Turbo Pascal has none of those. It compiles to `.TPU` units, binds its runtime
with its own linker, and emits no OMF at all — so there is no archive to match
and no PUBDEF records to read names from. `libscan.py` finds nothing, which is
the correct answer to the wrong question.

What replaces a signature database is a structural fact, and it is stronger
than a database because it needs no reference files:

> **In Turbo Pascal every unit is its own code segment, and every call between
> units is a far call carrying a literal segment word.**

So the segments that are far-called *are* the units. `tools/tpscan.py` does one
linear scan for `9A`/`EA` with an in-image destination, and a 200 KB program
gives up its module structure with nothing downloaded.

Two rules keep it honest, and both are facts about the machine rather than
thresholds: an 8086 code segment cannot exceed 64 KB, and every offset called
into a segment must lie before the next segment begins. When those disagree,
**drop the candidate with fewer calls behind it, not the one the scan reached
first.** Getting that backwards deleted a unit with 175 calls in favour of a
stray `0x9A` byte with one — the byte sat between two real segments, shrank the
earlier one's apparent span, and the earlier one was blamed.

### Recognising it at all, and finding the code/data boundary

The System unit's initialisation has a fixed shape across 4.0 to 6.0. Matched
as a byte pattern with the two segment words wildcarded:

```nasm
    mov dx, DGROUP
    mov ds, dx
    mov [PrefixSeg], es         ; ES holds the PSP on entry
    xor bp, bp
    mov ax, sp
    add ax, 0x13                ; round the stack top up ...
    mov cl, 4
    shr ax, cl                  ; ... to a paragraph
    mov dx, ss
    add ax, dx                  ; and that is where the heap starts
```

That is worth more than a yes/no: `DGROUP` is the boundary between code and
data, which nothing else recovers for a Pascal program.

### Measured, on The Oregon Trail (MECC, 1990)

201,184 bytes unpacked from an LZEXE'd 81,896:

| | |
|---|---|
| code | 144,512 bytes, in 11 segments |
| data and stack | 56,672 bytes |
| Borland's System unit | 6,800 bytes — **4.7% of the code** |
| far calls into System | 1,500 of 3,080 — **48% of all calls** |
| the program's own segment | 31,584 bytes, far-called by nobody |

The last row is the one to notice. The program's own code is invisible to the
call graph, because nothing calls it — it is entered from the MZ header. Its
absence *is* the evidence for what it is, and a tool that only reports what it
found would leave a 31 KB hole and not say so.

Two independent confirmations that the segment list is right, which is this
package's standard for believing one:

* the sizes sum to exactly 144,512, the code/data boundary found separately
  from `DGROUP` — no gaps and no overlaps;
* the six far calls at the entry point, which are Turbo Pascal's chain of unit
  initialisers, all land on segments the scan found independently.

### Identifying the version, which needs Borland's own library

This section previously said the version could not be determined and left it as
an open problem. **It is determinable, and the answer for Oregon Trail was not
the one assumed here.**

The runtime error message format really is identical across 4.0, 5.0, 5.5 and
6.0, so no string separates them. What does is the runtime's *code*, compared
against `TURBO.TPL` — the library of compiled standard units that ships with
each version. `tpscan.py --tpl` does it.

It needed a different technique from `libscan.py`. For C, `libscan` matches OMF
modules with their FIXUPP relocation slots wildcarded, because the OMF records
say where the relocations are. A `.TPL` carries no such map, and Turbo Pascal
**smart-links**: unused procedures are dropped and everything after them
shifts. So neither alignment nor whole-module comparison survives contact.

Coverage does. Take every run of sixteen bytes or more from the linked runtime
segment that occurs anywhere in the library, and measure what fraction of the
segment they cover, plus the longest single run. Relocated words break a run
but only locally; smart-linked gaps cost nothing, because each surviving block
is found on its own.

Measured on The Oregon Trail's 6,800-byte runtime segment:

| library | signature | covered | longest run |
|---|---|---|---|
| **Turbo Pascal 5.0** | `TPU5` | **86%** | **1,587 bytes** |
| Turbo Pascal 5.5 | `TPU6` | 74% | 545 bytes |
| `TPC.EXE` — right product, wrong file | — | 2% | — |
| Zaxxon — not Pascal at all | — | 0% | — |

A 1,587-byte unbroken identical run is not a coincidence, and the program is
5.0. The four-byte signature at the head of a `.TPL` (`TPU5`, `TPU6`) names the
format version and is worth reading, but it describes the *library* you are
holding, not the program you are examining.

**The controls are the argument, not the top row.** Any two Turbo Pascal
runtimes share a great deal — 5.0 and 5.5 cover only 62% of each other, which
is enough difference for the comparison to mean something but not so much that
one library alone would settle it. So the tool refuses to name a version unless
the best longest-run beats the runner-up by half again, and given a single
library it declines outright and says why. A version identification from one
reference file is the kind of confident wrong answer this package exists to
avoid.

Both libraries came from the Internet Archive — 5.5 from Embarcadero's own
Antique Software release, 5.0 from a floppy image set that `fatextract.py`
opened directly. Point `--tpl` at as many as you can find.

### Naming the calls, once you have the compiler

Knowing the version buys something better than a label: **the compiler runs**,
and a compiler you can run is an oracle. `TPC.EXE` under DOSBox-X compiles in a
second or two, so the way to find out what `lcall 0x2DB8:0x017E` is, is to write
Pascal that calls the routine you suspect and see where the compiler puts it.

Write a probe that calls each candidate once, in a known order:

```pascal
program Off;
uses Dos;
begin
  Assign(f,'X'); Reset(f,350); Close(f);
  n := IOResult;    L := MemAvail;
  n := DosVersion;  MsDos(r);
  GetDate(a,b,c,d); GetTime(a,b,c,d);
  FindFirst('X',63,sr); UnpackTime(L,dt); PackTime(dt,L); SetFTime(f,L);
  Halt(1);
end.
```

then read the `9A` far calls out of the compiled `.EXE` in address order and zip
them against the source order. On The Oregon Trail this named `DosVersion`,
`MsDos`, `GetDate`, `GetTime`, `GetCBreak` and `SetCBreak` outright: identical
offsets in the probe and in the game.

**And then it failed, usefully.** Every offset above `Dos+0x00F5` was wrong by
exactly `0x34`:

| | probe | game | difference |
|---|---|---|---|
| `FindFirst` | `0x014A` | `0x017E` | `0x34` |
| `SetFTime` | `0x012B` | `0x015F` | `0x34` |
| `UnpackTime` | `0x01C5` | `0x01F9` | `0x34` |
| `PackTime` | `0x0209` | `0x023D` | `0x34` |

A constant shift is a measurement. Smart-linking means the game contains fifty-two
bytes of routine that the probe does not, somewhere between `SetCBreak` and
`SetFTime`. Adding `GetVerify`/`SetVerify` to the probe moved things by `0x1D` —
right mechanism, wrong routines. Adding `DiskFree`/`DiskSize` moved them by
exactly `0x34`, and then **all fourteen offsets matched**.

That is a prediction with a cheap test: if those two are linked, the program must
call one of them. It does, once. A third probe calling only `DiskFree` put
`DiskFree` at that offset, and the same run named `GetIntVec`, `SetIntVec` and
`SwapVectors`, which had no argument shape to guess from at all.

**The negative result is the part to carry forward.** A table of runtime-call
offsets is *not* portable between two programs built by the same compiler. Only
the prefix up to the first omitted routine is stable, so these are usable as
anchors for TP 5.0 and nothing above them is:

| | |
|---|---|
| `System+0x00D8` | `Halt` |
| `System+0x0207` | `IOResult` |
| `System+0x020E` | the automatic `{$I+}` I/O check after every I/O statement |
| `Dos+0x0000` | `DosVersion` |
| `Dos+0x0005` | `MsDos` |
| `Dos+0x0071` | `GetDate` |
| `Dos+0x00A7` | `GetTime` |
| `Dos+0x00E3` | `GetCBreak` |
| `Dos+0x00F5` | `SetCBreak` |

Everything above must be re-derived per program. The good news is that
re-deriving it is a two-minute compile, and the alignment either matches
completely or tells you which routine you are missing.

**What transfers beyond Pascal.** This is differential compilation, and it beats
signature matching whenever the compiler is obtainable, because it replaces a
judgement with an equality test. `libscan.py` matches against libraries someone
shipped; this generates the reference on demand, for exactly the routines you
care about, in exactly the configuration the program used.

### One trap when you check the result by running it

A Turbo Pascal program that says `uses Crt` cannot be observed with shell
redirection. The `Crt` unit's initialiser replaces the device driver behind
`Output` with one that writes straight into video memory — that is what makes it
fast — so DOS never sees the text and there is nothing to redirect. `PROG > OUT`
produces an empty file, every time, and it looks like the program printed
nothing.

Read the screen back instead. The text is still in video RAM after the program
halts, so a second program run immediately afterwards can dump it:

```pascal
var scr : array[0..24, 0..79, 0..1] of Byte absolute $B800:0000;
```

Twenty lines, and it recovers the messages verbatim. This is the difference
between "the program exited with code 1" and knowing which of five branches
printed which words, and on The Oregon Trail it was what turned a licence check
into a traced one.

The complementary trick, when a program is silent and you only need to know
*which* path it took: DOS `ERRORLEVEL`. A batch file with a descending ladder of
`IF ERRORLEVEL n` reports the exact exit code, and Turbo Pascal's runtime errors
come through as their own numbers — 2 is file-not-found, 203 is heap overflow.
