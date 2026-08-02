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

## Lattice C 2.1, which announces itself

Karateka (1984) settles the question without being asked. The first string in
its data segment is the compiler's name, and the next five are its runtime's
own start-up failures:

```
DS:0x0002   Lattice C 2.1
DS:0x0082   Invalid stack size
DS:0x0096   Invalid I/O redirection
DS:0x00B0   Insufficient memory
DS:0x00C6   *** STACK OVERFLOW ***
```

Three fingerprints agree with it, and any one of them alone would be worth
acting on:

- **The prologue carries a stack check.** Not every routine has it — 30 of 120
  in Karateka — but where it appears the shape is unmistakable, and the branch
  target is shared by all of them:

  ```nasm
      push bp
      sub  sp, 6
      jb   .overflow
      cmp  sp, word [0x17]        ; the runtime's stack limit, a global
      ja   .ok
  .overflow:
      jmp  stack_error            ; prints *** STACK OVERFLOW *** and exits 0x4C01
  ```

- **`fopen` walks a fixed FILE table.** Lattice's is an array between two
  absolute addresses with a **stride of 14 bytes**, scanned for a slot whose
  byte at +8 is zero. Recognising it stops you following a filename into the
  runtime and back out again, which cost an hour here.

- **The exit code is `0x4C01`**, not `0x4C00`, on every runtime error path.

**A caution that cost a retraction.** Prologue density was measured at 0.4 per
KB and read as "hand-written assembly". That figure is over the *whole file*,
and 68% of Karateka is data; over the code region it is about four per KB,
which is ordinary for a compiler. **Compute density over the code region the
walk found, never over the file.**

And the conclusion still has to be *mixed*: Karateka's blitter and its
run-length decoder have no prologue at all, use every register and keep their
state in globals. C for the game, assembly for the inner loops — which is what
the density was really telling us before it was misread.

### Confirmed against the library, and what a point release costs

Lattice C 2.12 for DOS (1984) was fetched and scanned against Karateka with
`libscan.py`. **It matched 3 modules of 625 — 0.2% of the image** — and that
figure understates the result to the point of being misleading.

Those three modules carry seven symbols, and all seven land on addresses that
had already been named from behaviour alone, months of reasoning earlier:

| | named from behaviour | the library's own name |
|---|---|---|
| `0x5DBB` | `getch`, from `bdos(AH=0x08)` | `_CGET` |
| `0x5DCF` | `getche`, `AH=0x01` | `_CGETE` |
| `0x5DE3` | `putch`, `AH=0x02` | `_CPUT` |
| `0x5DF7` | `aux_getc`, `AH=0x03` | `_AGET` |
| `0x5E0B` | `aux_putc`, `AH=0x04` | `_APUT` |
| `0x5E1F` | `prn_putc`, `AH=0x05` | `_LPUT` |
| `0x6B84` | `bdos`, AH from `[bp+4]` | `BDOS` |

**Seven for seven.** Reading what a routine does, and naming it for that,
produced exactly the names its author used.

The 0.2% is worth understanding rather than lamenting. Karateka names Lattice C
**2.1**; the obtainable release is **2.12**. The library was rebuilt between
those point releases, so most modules differ by a byte or two, and an
exact-bytes scan refuses them — *correctly*. The three that matched are the
small ones nobody had reason to touch.

Two things follow for the next program:

- **A near-miss version is still worth scanning.** 0.2% coverage bought
  seven confirmations and settled the memory model: `LCS.LIB` matched nothing,
  `LCD.LIB` matched all three, so Karateka is the **D** model, which agrees
  with an entry stub that sets DS once while addressing code from zero.
- **Do not read a low match rate as a failed identification.** It is a
  statement about how far apart two builds of the library are, not about
  whether the compiler was identified. The compiler was already certain — the
  binary says `Lattice C 2.1` in its own data segment.

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
