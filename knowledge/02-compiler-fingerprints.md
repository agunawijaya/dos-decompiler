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
