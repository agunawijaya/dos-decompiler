# 14 — Recognising a translated binary

Hard Hat Mack's PC version is not 8086 code that somebody wrote. It is 6502
code that a program turned into 8086, instruction by instruction, and once you
see that, everything odd about it stops being odd.

The game was an Apple II title first. Electronic Arts shipped the PC version in
1983, and two strings sit in the middle of the data — `MICHAEL'S DEDICATION`
and `MATTHEW'S DEDICATION` — where the authors left them.

## The measurement

Four games, all reconstructed by this toolkit. Three were written by hand for
the 8086 and one was compiled from C. Every marker below is at zero for all
four except one.

| | instructions | `cmc` after `cmp` | load-then-flags | carry saved round a logic op | AL touched | 16-bit arithmetic | register push/pop |
|---|---|---|---|---|---|---|---|
| **Hard Hat Mack** | 9,062 | **93%** | **511** | **42** | **51%** | **0%** | **0%** |
| Karateka (Lattice C) | 10,586 | 0% | 0 | 3 | 4% | 5% | 8% |
| ParaTrooper | 2,018 | 0% | 0 | 0 | 8% | 11% | 1% |
| Zaxxon | 2,655 | 0% | 0 | 0 | 13% | 7% | 6% |

This is not a style that shades into other styles. It is a different machine
showing through.

## What each marker is

**`cmc` after 93% of every `cmp`.** The 6502's `CMP` sets carry when A ≥ M —
carry means *no borrow*. The 8086's sets it when the subtraction borrowed, the
opposite sense. A translator that wants `BCS` to keep meaning "branch if
greater or equal" has to invert the flag after every comparison, so it emits
`cmp` and then `cmc`, forever. No human writes that twice, let alone 287 times.

**`mov al, X` followed by `inc al` / `dec al`, 511 times.** `LDA` sets N and Z
from the value it loaded. `mov` sets nothing. Incrementing and decrementing
gets the value back where it started with the flags a 6502 would have left, in
four bytes instead of two.

**`rcl ah, 1` … `rcr ah, 1` wrapped round an `and`, `or` or shift, 42 times.**
The 6502's `AND`, `ORA` and `EOR` leave carry alone. The 8086's clear it. If
the next 6502 instruction was `ROL` or `ADC`, the carry has to survive, so the
translator parks it in a spare register's top bit and puts it back afterwards.

**AL in half of all instructions, and no 16-bit arithmetic at all.** The 6502
has one 8-bit accumulator. Every value in this 42K program moves through AL.
Sixteen-bit quantities are done the 6502 way, as a byte and a byte with an
explicit `adc`: `add al, 2 / mov [ptr], al / mov al, [ptr+1] / adc al, 0`.
The 8086 could do that in one instruction and never does.

**No register push or pop in 9,062 instructions.** The 6502's stack is one page
and its instructions are `PHA` and `PLA`. State goes in fixed memory instead —
which is why the game's 436 variables sit in 132 clusters scattered between the
routines that own them, exactly where a 6502 assembler's `.byte` directives
would have put them.

**BL and CL are X and Y.** Every indexed read is `mov bl, n` then
`mov al, [bx + table]`, which is `LDX #n` / `LDA table,X`; or `mov cl, n` /
`mov si, cx` / `mov al, [si + table]`, which is the same with Y.

## What it explains

The oddities stop needing explanations of their own:

* **221 call targets for perhaps eighty behaviours.** The translator emitted a
  routine per `JSR` target in the original. Ten of Hard Hat Mack's routines are
  four instructions long and draw one sprite.
* **The scanline table.** 200 words giving the address of each screen row.
  The Apple II's hi-res screen is interleaved in a way that makes arithmetic
  useless, so its programs all carry a line table. CGA is interleaved too, less
  badly, and the translated table works unchanged.
* **The pixel plotter.** `plot_pixel` XORs one pixel through a four-entry mask,
  which is what an Apple II `HPLOT` does. The whole turtle-graphics
  interpreter at 0x1A7E — nine opcodes stepping a pen one pixel and optionally
  plotting — is Applesoft's shape-table mechanism, carried across.
* **Why `probelib.py` finds nothing.** There is no C runtime because there was
  never a C compiler. Zero of 250 entry points matched, and that was the
  correct answer.

## How to test for it

Cheap, and worth doing before reading a line:

1. Count `cmc` immediately after `cmp`. Above about 20% and you are looking at
   a translation from a carry-inverted machine — 6502, or 6800.
2. Count `mov reg, imm` followed by something that only sets flags.
3. Look at the ratio of 8-bit to 16-bit arithmetic. A translated 8-bit program
   has almost no 16-bit arithmetic even where it would be free.
4. Count register pushes. A translator from a machine with no register stack
   will not use one.

If it is a translation, read it as the original machine. `al` is the
accumulator, `bl` and `cl` are the index registers, every global is a fixed
address, and a routine that looks pointlessly small is one `JSR` target. Trying
to read it as 8086 written by a person will make every routine look worse than
it is.
