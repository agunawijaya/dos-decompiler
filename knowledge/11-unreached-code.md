# 11 — Code that nothing reaches

Karateka's reconstruction sat at **85.0% of its code region** and stayed there.
The remaining 15% was not artwork, not a table, and not a format anybody had
failed to work out. It was code — ordinary compiled C, prologue and all — that
the walk had no way to arrive at.

This note is about how that happens, why the number looked like a property of
the binary when it was a property of the reader, and what it cost to find out.

The end of it: **85.0% → 91.9%**, with the other four games in this toolkit
measuring exactly what they measured before.

## Reachability is not the same thing as being code

Recursive descent finds what something branches to. A program can hold code that
nothing branches to, for three quite different reasons:

| | |
|---|---|
| **linked and never called** | the linker pulls a whole `.OBJ`; one function used, six along for the ride |
| **reached through a pointer** | an interrupt vector, a dispatch variable — both already handled, see `detect_interrupt_handlers` and `detect_dispatch_targets` |
| **reached through a table** | `detect_jump_tables` handles this, *when it can see the jump* |

The third row is where Karateka lives, and the qualifier is the whole story.

## The circle

`detect_jump_tables` finds a table because it has already decoded the
`jmp word [cs:bp]` that reads it. Zaxxon's level script works that way and the
pass is worth 13 points of its code region.

It cannot work when the jump is *itself* in unreached code. Then the reader and
the table are unreachable together, and neither one can be used to find the
other. A C compiler puts a `switch` table immediately behind the function that
switches, so this is not a corner case — it is the ordinary arrangement:

```
0x1364  the arms, 738 bytes of them, one after another
0x163E  ce 14 e0 14 14 15 26 15 ...   the table, flush against the last arm
0x165A  the next thing the walk already knew about
```

`sweep_gaps` cannot rescue it either, and is right not to. It disassembles the
run linearly and vetoes it on hitting an instruction no game executes — and the
table's own bytes contain several. But the veto is all-or-nothing, so **twenty
bytes of table discard the 738 bytes of arms in front of them.** Karateka lost
four runs that way, 2,318 bytes.

## The detour, which was the useful part

Before any of that was understood, the gaps were closed by brute force: take
every run the map calls data, keep the ones that disassemble cleanly end to end,
feed them back as entry points, repeat. Sixteen rounds, forty-five hand-fed
addresses, 85.0% → 91.6%, byte-identical at every step.

Then the tails of the gaps got read, and the table at `0x163E` turned out to
hold:

```
0x1364, 0x1398, 0x13CC, 0x1447, 0x14CE, 0x14E0, 0x1514,
0x1526, 0x1538, 0x156C, 0x157E, 0x15BE, 0x15FA, 0x162D
```

**Those were the addresses the loop had been discovering, one per round, for
sixteen rounds.** The program had written the list down and put it fourteen
bytes past where the search kept stopping.

The lesson is not "read the file first" — the loop is what produced the gaps
worth reading. It is that **a search which converges slowly and monotonically is
usually re-deriving something the program states outright.** Sixteen rounds each
finding one more address is not a search, it is a list being read the hard way.

## Recognising a table by its contents

The circle breaks from the other end. Four constraints, and the first two alone
are not enough — each of the last two was bought with a false positive.

1. **Every slot is a code address that walks to a return.** The test
   `detect_jump_tables` already leans on; it is what refuses a table of *data*
   pointers.
2. **The table ends where the run ends.** The compiler emits it behind the
   function, so the run's far end is the table's far end. This removes the
   sliding window — without it, any three plausible words anywhere qualify.
3. **At least three *distinct* targets.** Hard Hat Mack has fourteen `02` bytes
   in a row. Based at `0x0100`, `0x0202` is a valid address that walks to a
   return, so seven identical slots passed 1 and 2 and a constant array was
   claimed as a jump table.
4. **Code in front of it, landing exactly on the table.** This one carries the
   argument. What the pass may claim is not *a table found anywhere* but **a run
   `sweep_gaps` would have taken but for its tail** — so the front must pass the
   sweep's own landing test and the tail is split off rather than guessed at.
   Data with a plausible-looking end has no such prefix.

And one more, from Zaxxon: **a target may not be the program's own entry point.**
Zaxxon has a segment based at zero, which makes a word of `00 00` inside a data
record read as a perfectly good address that walks to a return — and it is one,
it is the entry stub. Nothing reaches a program's entry by branching to it.

A stride-4 `(case, target)` table checks itself: the slot beside each address
has to be a small number, and two random words rarely oblige. A bare list of
addresses has no second opinion, so it buys one with **locality** — its targets
must lie in the same run. Without that the backwards scan swallows one slot too
many; the `eb 2a` of a default arm sits directly in front of Karateka's
fourteen-entry table and reads as `0x2AEB`, which is a real address elsewhere.

## Two bugs found underneath it

**`gaps()` is built on `coverage()`, which excludes pinned instructions.** A
pinned instruction is emitted as `db`, so a run of unclaimed bytes appears to
extend straight through it. Karateka has a two-byte pinned instruction directly
behind the fourteen-entry table, so the run read as ending two bytes late, which
put a pinned opcode in the table's last slot and lost all 758 bytes behind it.
Anything asking *where the unclaimed bytes stop* wants `decoded_gaps()`, which
counts a pinned instruction as what it is: code, spelled in bytes.

**The round budget was a constant where it needed to scale.** `run()` allowed 40
rounds, which was enough for every game this toolkit was built on. Each
discovery costs a round — the sweep and the table scan can only see the *next*
gap after the walk has been re-run over the last one — so the budget has to
scale with how much unreached code a program has, not with how big it is.
Karateka needs 49 and stopped at 85.0% with 40. **That is what the missing 15%
was, in the end: a loop that ran out of turns and reported the result as a
measurement.** A limit that terminates a search should not be reported in the
same voice as a finding — `comrec` now says so in as many words when it stops
on the limit.

## The budget was also in the wrong loop

Raising it worked and made the tool unusable: 59 rounds, each re-emitting a
700 KB listing and running NASM over it, **52 minutes** for an 87 KB game.

The iteration was wrapped around the assembler when it only ever needed to be
wrapped around the walk. Discovery is genuinely iterative — a pass sees the next
run only after the walk has covered the last — but *verification* is not. Let
the passes run to exhaustion first, then verify:

```python
while self.detect_case_tables() or self.sweep_gaps():
    self.disassemble()
```

**52 minutes → 26 seconds**, 59 rounds → 12, and the output is identical to the
byte: same 10,589 instructions, same 987 pins, same 91.9%.

Nothing was taken on trust for the speed. Byte-identity is exactly as strong a
check of fifty claims as of one; what batching gives up is only *attribution* —
a bad claim is still caught, just not immediately named — and the demotion
machinery already handles that. The general form: **when a verified loop is
slow, check whether the verification is inside the loop that needs to iterate
or merely next to it.**

## Three more ways code hides, found by asking the same question of four games

**A displacement written in hex.** `detect_jump_tables` matched
`jmp word [cs:si + (\d+)]` while the disassembler prints `0x163e`, so the
instruction failed to match and the pass said nothing at all. Karateka has six
tables in that form — the shape a C compiler emits for a dense `switch`, where
the table *is* the displacement and the register is the index — and the most
direct evidence a program can offer about where its tables are was being skipped
in silence. Worse than lost: the gap sweep then claimed one of those tables as
code, which is wrong quietly. `tests/com/fixtures/indexed.asm` holds it open.

**A callback passed in a register.** Hard Hat Mack's joystick calibration hands
two routine addresses to a helper that calls them between its own prompts:

```
09EE  mov ax, 0x9fa      ; two routines, by address
09F1  mov bx, 0x9ff
09F4  call 0xa12
0A12  push bx / push ax / ... / pop bx / call bx
```

Looking back from `call bx` finds only the `pop`, because the value was set by
the caller — no reasoning local to the callee can work. `detect_register_callbacks`
goes the other way: any `mov reg, imm` whose immediate lands in an unclaimed run
that *disassembles as plausible code*, in a program that contains `call reg` at
all. The middle clause is what stops it treating every 16-bit constant as an
entry point.

**"It disassembles" is worth nothing on its own.** The first version of the
residue classifier reported 98 bytes across the four games as worth a look, and
almost all of it was noise: `add byte [bx+si], al` is what `00 00` looks like
through a disassembler, `pushaw` is 80186 and `fisttp` is SSE3 in games that are
8088, and two of Zaxxon's candidates were straight-line arithmetic on random
operands with no branch anywhere. Requiring no zero-pair, no instruction the CPU
never had, and *some* control flow cut those 98 bytes to the eight that were
real.

## Say what the rest of the region is

A bare "78.2% recovered" reads as "21.8% missing", and for three of these four
games that is wrong. The code region is found by trimming large data blocks off
the *ends* of the file, so data that lives between the routines stays inside it
and counts against the figure. Hard Hat Mack keeps 1,201 bytes of CGA scanline
offsets — `0x0000, 0x2000, 0x0050, 0x2050, …`, two banks interleaved — 1,171 of
artwork and 793 of HUD strings in among its code. None of it is lost.

`comrec` now names the kinds:

```
  not code  : 5,394 bytes (19.4% of the region, counting a pinned instruction
              as code), being 3,006 other mostly artwork, 1,368 pointer table,
              793 text, 227 zero fill
              nothing in it looks like unreached code
```

That last line is the one worth having. **All four games now print it.**

## What it measures

| | before | after | residue |
|---|---|---|---|
| **Karateka** | 85.0% | **91.9%** | 252 bytes, all tables and padding |
| Hard Hat Mack | 78.2% | 78.2% | 5,394 bytes, all data |
| ParaTrooper | 90.9% | 90.9% | 125 bytes, all data |
| Zaxxon | 75.8% | 75.8% | 1,796 bytes, all data |

Three of those four percentages did not move, and the work was still worth
doing: **the question "what is the other 22%?" now has an answer, and the answer
is not "code we failed to find".**

All five still rebuild byte-identically, and Karateka's `.EXE` was SHA-256
checked outside the tool that produced it. `tests/com` is 10 fixtures, of which
`casetable.asm` is new: three arms behind a table, plus a **negative control** —
a well-formed table with no function in front of it, which passes every content
test and must still be refused.

The principled pass also beat the brute force it replaced, 91.9% against 91.6%,
which is the outcome to expect when a search is replaced by reading.

## Where it stops, and why that is the right place

254 bytes of Karateka's code region are still data. Read them and almost all are
data:

```
0x2247  46 00 31 22 42 00 18 22 ...   (case, target) pairs
0x6303  73 00 bc 62 63 00 61 62 ...   cases 's' 'c' 'h' 'x' -- a printf dispatch
0x51B6  1a 00 5e 51 08 00 3b 51 ...   cases 0x1A 0x08 0x0D 0x0A -- Ctrl-Z, BS, CR, LF
0x163E  64 13 98 13 cc 13 47 14 ...   the fourteen arms
```

Eleven of the twenty-three runs are a single `0x90` — alignment padding between
functions, which the program never executes. About thirty bytes are genuinely
unread code, including a five-byte function that is `push bp / mov bp, sp /
pop bp / ret` and does nothing at all.

**So the residue is now identified rather than unexplained**, and that is the
real change. 99.1% of the code region carries a decoded instruction. Chasing the
last 254 bytes would mean claiming tables as code, which is the direction this
toolkit exists not to go.

## What transfers

- **An unexplained percentage is a question, not a measurement.** "85% of the
  code region" said nothing about *which* 15%, and the answer turned out to be
  four contiguous runs with a common cause.
- **A veto that is right can still be too coarse.** `sweep_gaps` was correct to
  refuse those runs and wrong to refuse all of each one. When a rule rejects a
  large object for a small reason, ask whether the object should be split.
- **Slow monotonic convergence means a list is being re-derived.** Look for
  where the program wrote it down.
- **A search limit is not a result.** Report "ran out of rounds" differently
  from "found everything there is", or the first will be read as the second for
  as long as nobody checks.
