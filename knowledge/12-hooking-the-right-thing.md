# 12 — Hooking the right thing

Running a program under `comrun.py` and watching what it touches is the method
that has settled every hard question in this toolkit: Hard Hat Mack's scanline
table, Karateka's sprite format, and now Karateka's fight AI. It is also the
method that wastes the most time when the hook is chosen badly, and the two
cases sit close enough together to compare.

## The bad hook and the good one, on the same program

**"Who draws sprites?"** — hook the sprite dispatcher, record the caller.

```
2,176 sprite draws, 2 distinct callers
  0x00C0A   2172
  0x00F39      4
```

One routine, and it taught nothing, because *everything* draws sprites. The
answer was true and useless: the dispatcher is a funnel, and a funnel tells you
about the funnel. Walking back up the stack gave five-deep trails and a slightly
larger fog.

**"Who writes the move cursor?"** — hook one two-byte global.

```
280 move changes
  0x0245C   82  advances the player one frame
  0x025C8   82  advances the guard one frame
  0x0248B   64  starts a guard move
  0x0234D   38  starts a player move
```

Four instructions, and two of them had the AI call sitting directly above them.
The question was answered in a single run.

## What made the difference

Not effort, and not the tooling — both hooks are six lines. The second variable
**can only be written for one reason.** A frame cursor changes when, and only
when, a move starts or advances; nothing else in the program has any use for it.
The sprite dispatcher, by contrast, is reached for every reason the program has.

So the rule is not "hook the interesting routine". It is:

> **Hook the narrowest piece of state that can only change for one reason, and
> record who changed it.**

A corollary that saved a second run: pick something whose *value* is
self-identifying. The cursor holds a byte-code offset, and the index table maps
offsets back to move numbers, so every event decoded itself into "actor X
started move 19" with no further work.

## Three practical notes

**Hook the emit, not the buffer.** To find where a compiler puts its output,
hooking the one instruction that writes an opcode — `mov byte [si], 0x14` — beats
working out which argument of which caller holds the destination. One address,
no reasoning.

**A hook fires at an instant, and the instant may be off by a stage.** Sampling
the frame cursor at the moment x changed gave 58% agreement with the frame's own
travel byte, which looks like a failed hypothesis and was not: the cursor had
already been bumped. Restricting to samples whose bytes were still in phase gave
**38 of 40**. When a check comes back at "mostly", ask whether the sampling is
out of step before you doubt the reading.

**Two passes cost nothing.** Run once to learn an address, run again to watch
it. Trying to do both in one pass means wrapping the DOS handler and guessing at
register conventions; two runs of the same twenty seconds needs neither.

## And the cheapest hook of all is `head`

Karateka's fighting was recorded as unread through four documents. Three of the
files beside the executable are **plain ASCII**. Nobody looked, because the
sprite format next door had been genuinely hard and set the expectation.

Before any of this: open the file.

## The follow-up: three tiny globals beat one big routine

The same handle, turned three more times, read the rest of Karateka's fight:

* **`[0xD5AE]` and `[0xD5B0]`** — each written once and *pushed* once. Two grep
  hits apiece, and the push sites were the hit test's call sites. A routine of
  450 bytes had resisted reading; a variable with two references gave it up.
* **`[0x116]`** — assigned three literals, 13, 12 and 10, in three consecutive
  branches. A constant repeated at a difficulty fork is a difficulty setting,
  and the `dec` that follows it elsewhere is damage.
* **`[0x156]`** — four references: set to 1 on one path, 0 on the other, tested
  twice. Which of two choosers is the human's was a one-line question once the
  right line was found.

The pattern is the same each time: **a global with few references is worth more
than a routine with many instructions**, because each reference is a sentence
about what the global means and there are few enough of them to read.

`grep -c` on a variable name is a two-second triage. Under about six hits, read
them all; over about fifty, the variable is infrastructure and will not
localise anything.

## And a claim can be wrong twice before it is right

`[0x118]` and `[0x11A]` were called health here, twice, on the strength of both
being set to 32 and both being decremented. They are a patience timer: they
count down while the *player stays away* and reset when he closes. What settled
it was neither the assignment nor the decrement but the branch above them —
`cmp ax, 0x14a`, a distance of 330 pixels — which no health counter would care
about.

**Read what a counter is compared against, not only what sets it.** The
comparison is where the meaning is.

## Identify a library by calling it, not by looking at it

Karateka's forty library routines had no discriminating shape -- no FILE
pointers, no format-string walks, no divides -- and this repository recorded
that as "cannot be named without a copy of Lattice C 2.1". That was one
question too early. Reading a routine answers *what does this look like*;
calling it answers *what does this do*, and only the second can be wrong in a
way you notice.

`probelib.py` pushes what `strlen` would take and checks that 5 comes back for
"hello", 3 for "abc" and 0 for "". Nine routines fell out in an afternoon --
strlen, strcpy, strcat, strcmp, strncmp, a bounded copy, two allocators -- and
the call sites then confirmed them: `strcpy` and `strcat` are called in pairs
from four places, each one building `"ks0"` + `".dat"`, and `strncmp` is called
from the script compiler matching its fourteen command names.

**A probe must be able to fail, and three of the first ones could not.**

* *Two calls returning two different non-zero values* matched six routines as
  `malloc`. Every counter passes it. Demanding non-overlapping blocks and a
  refusal for a large enough request cut it to one.
* Six routines matched `max` because every pair in the battery had `x > y`, so
  *returns its first argument* passed. One reversed pair fixed it.
* `stricmp` matched a routine that is case-*sensitive*: the test pushed two
  arguments, the routine was `strncmp`, and the third argument it read off the
  stack was garbage that happened to mean "compare zero bytes". **If the family
  has a three-argument member, push three.**

And a harness bug that produced fifty-nine confident wrong answers at once:
`comrun.call` writes its return sentinel at `BASE + SP`, which is segment zero.
Karateka's SS after start-up is 0x16DA, so every routine returned into nothing
and reported a fault at the same address. **Fifty-nine identical failures are a
fact about the harness, never about fifty-nine routines.**

The thirty that still have no name are printf's internal helpers and their kin.
They take state blocks rather than arguments a specification names, so there is
nothing to probe them against. That is a different and much smaller claim than
the one this file used to make.

## And when there is no specification to probe against, watch it work

Probing settled nine of Karateka's library routines and stalled on the rest,
which I wrote up as "printf's internal helpers take state blocks, not arguments
a specification names, so there is nothing to test them against". True, and
still the wrong conclusion: those routines are *called*, every second, by a
program that works. The arguments they actually receive are evidence nobody has
to invent.

Hooking each one's entry and recording the three words above the return address
named twenty-six more in a single twenty-million-instruction run:

```
0x05E33   4806 calls   a0 varies (2440 of them text), a1 = 0x5879 constant
0x05879  16496 calls   -- 3.4 per call to 0x5E33
0x04B0A   2602 calls   a0 text, a1 = 0x0050, a2 = 0xE1DA
```

`0x5E33` takes a *constant* as its second argument, and that constant is another
routine called once per character. That is `_doscan(string, getchar_fn)` and
nothing else. `0x4B0A` is handed a buffer, the number 80, and a pointer that
sits exactly on slot 3 of the FILE table — `fgets`, 2,602 times, once per line
of script the compiler read.

Three signals do most of the work:

* **A constant argument is a pointer to something.** A function pointer, a mode
  string, a FILE. Follow it.
* **Call counts have ratios.** 16,496 to 4,806 is characters per string.
* **An argument that lands on a table's stride boundary is an element of that
  table.** `0xE1DA - 0xE1B0 = 42 = 3 x 14`, and the stride is 14.

The general rule, and the reason this section exists after two rounds of giving
up: **"there is nothing to test it against" is a statement about the test you
thought of, not about the routine.** A routine with no specification still has
callers, and callers are a specification written by someone who knew.

## Name a global by what its values do, not only by who writes them

Who-touches-what named 134 of Karateka's globals and stalled. A global used
twice gives two data points and no shape. But the attract sequence is the demo
*playing the game* -- `[0x156]` selects the AI chooser and the whole fight
machinery runs -- so every one of them is being exercised. What was missing was
not access to the program; it was watching the *values* rather than the
instructions.

Recording every write and classifying the sequence separates the kinds cheaply:

    flag         two values, one of them zero
    counter      rises by one and resets
    countdown    falls by one and reloads to the same number
    coordinate   small steps in both directions
    pointer      large, always inside one span
    constant     written repeatedly with the same value -- a reset, not a store

The shape does not name anything by itself. It cuts the candidates down far
enough that the routines touching it decide, which is what the previous pass
could not do.

**Two traps, and the second is the more useful.**

`SS` and `DS` had the same base -- `0x16DA << 4` is exactly the data segment --
so a hook on "the data segment" caught every stack push. Seventeen thousand
addresses of noise. Track only what the code names as an *absolute* global,
which is a fixed list you can extract from the listing first.

And the finding that moved the number most was not a naming technique at all.
Fourteen "globals" were only ever written with `0x5555` or `0x2055`, at
addresses eighty bytes apart. Those are CGA pixel patterns and eighty is a
scanline: `DS:0x0337` is a **16,000-byte off-screen frame**, and it ends at
`0x4217`, exactly where the blitter's own globals begin. Forty addresses that
looked like separate variables were rows inside one buffer.

**When a set of addresses share a stride and a value vocabulary, they are one
object.** `[di + 0x337]` is not a global with a displacement; it is the screen.

## Where to stop

113 of Karateka's globals are still unnamed and 94 of them are referenced twice
or fewer. That is the honest floor: two uses cannot distinguish a flag from a
counter, let alone say what it counts.

Quote both figures whenever you quote either. 64% of the addresses and 90% of
the references are the same fact seen from two ends, and the gap between them
is the shape of what is left.

## The enumerator has to match the language, and a blind one reports zero

Karateka is Lattice C and its routines open `push bp`. That enumerator, pointed
at the other three games in this repository, finds **none** -- and `probelib.py`
duly reported *0 of 0 matched a specification*, which reads exactly like "there
is no C library in here" and is a different statement altogether. It had nothing
to probe.

| | prologues | call targets |
|---|---|---|
| Karateka (Lattice C) | 120 | — |
| Hard Hat Mack | **0** | 250 |
| Zaxxon | **0** | 87 |
| ParaTrooper | **0** | 28 |

All three are hand-written assembly, and Hard Hat Mack is a mechanical 6502
translation on top of that -- 427 `cmc` instructions to reconcile two processors
that disagree about the carry flag. Enumerating by *call target* instead finds
their routines, and probing those 250 gives a clean **0 of 250**: a real
negative result. There is no C runtime in it.

That prediction was written down before the run, which is the only reason the
zero means anything. `probelib.py` now says which case it is in rather than
printing a zero that could be either.

**A tool built on one program's conventions will fail silently on the next one,
and the failure will look like a measurement.** Check that the enumerator found
candidates before believing what the battery says about them.

## Count bytes, not references

Karateka's globals reached "312 of 312 addresses named, all 1,642 references"
and I reported it as complete. It was true and it was the wrong denominator.

The data segment is 59,670 bytes. Naming every address the code *mentions* says
nothing about the bytes *between* those mentions, and measured by byte the
segment was **40% accounted for** at the moment the reference count hit 100%.

Mapping it as spans took it to 98.7%, and the shape of what was missing is the
lesson:

| | |
|---|---|
| 31,392 bytes | pure zero — buffers files are read into |
| 16,000 | the off-screen frame, already known |
| ~5,000 | byte code, tables, strings |
| 1,447 | genuinely unidentified, in gaps under 200 bytes |

**Half the data segment is empty.** The largest single object in the program is
24,260 bytes of nothing, waiting for sprites. Empty is *finished*; unread is
*work*; and a reference count cannot tell them apart because nothing references
the middle of a buffer.

Two rules, and the second is the one that keeps catching me:

- **A percentage needs its denominator stated in the same sentence.** "100% of
  references" and "40% of bytes" were simultaneously true of the same program.
- **When a metric reaches 100%, that is the moment to ask what it is measuring**
  — not the moment to stop. Every completion claim in this repository that had
  to be withdrawn was a real number with an unstated denominator.

## Hook the difference, not the total

The referee that compares a static reading against the running program had been
saying this for three sessions:

```
overall: 172 of 193 placements reproduced -- recall 89%, precision 93%
missed (13):
   x1  ('place', 28, 191, 0)
   x1  ('place', 20, 191, 0)
   ...
```

Twenty-one wrong placements, listed by value. Correct, checkable, and nothing
was done about it for three sessions, because a list of coordinates is not a
list of anything you can go and read. It was written up as "three groups: four
rivets along a bottom row, a vertical run of five, and a column of three" —
which is a description of the *picture*, and the picture is not where the bug
is.

The hook already stopped at the drawing routine's first instruction. At that
point the return address is one word down `SS:SP`, before anything has been
pushed, and the routine that owns it is a lookup in the symbol file. Six extra
lines:

```
missed (13), by the routine that made them:
   x4  draw_beams
   x4  draw_rivets
   x3  draw_toolboxes
   x1  spawn_lunchbox
   x1  draw_hoist_car
```

Five names. Three sessions of "twenty-one placements" became an afternoon, and
six bugs in the static extractor came out of it:

- **A counted loop that runs up.** `mov bl, 1` / `mov byte [V], bl` … `inc byte
  [V]` / `cmp bl, 5` was read as the count-down shape every other loop in the
  program uses. Indices 1 and 0 instead of 1, 2, 3, 4. Every iteration still
  produced *a* placement, so no error was raised and the coverage metric did
  not move.
- **A zero immediate written in decimal.** NASM prints `mov word [sel], 0`, not
  `mov word [sel], 0x0000`, and the store pattern required the `0x` form. One
  routine sets its shape that way and nothing else, so four beams took whatever
  shape the previous routine had left behind.
- **A global that outlives the routine that set it.** Callee state was
  deliberately isolated from the caller — with good reason, an earlier bug had
  two calls to the same routine reading each other's leftovers — so a routine
  that writes no shape selector had none at all. It is now carried in walk
  order, separately from the isolated state, because walk order is the order
  the program writes it in.

- **A loop kept entirely in memory.** `draw_conveyor` counts down in one
  variable and steps across in another, and never puts either in a register
  except to index a table. With no `mov bl, imm` there is no loop to see, so
  one of its four segments was drawn and three were not.
- **…and a placement that is in that loop without touching the index.** A
  `place_pair` erases the previous cell before drawing the new one, and the
  erase reads only the stepped column and two constants. Deciding whether to
  unroll on "does this use BX" unrolled the draw four times and the erase once.
- **Callee state that is game state.** Writes inside a callee were isolated
  from the caller wholesale, to stop two calls to the same routine reading each
  other's leftovers. But the thing being protected against is *scratch* — the
  drawer's parameter block, written fresh before every call — and `hoist_y` is
  not scratch: one routine sets it and another reads it three calls later. The
  rule has to be by address, not by direction.

None of the six would have been found from the coordinates. All six are obvious
in the twenty instructions of the routine that the caller attribution names.

**Where it ended.** 172 of 193 placements to 186, recall 89% to 96%. The seven
that remain are one fact: a routine picks its shape with `random() & 3` from a
table of four *different* entries, so there is no shape in the file to read,
and a second routine that writes no selector of its own inherits that pick.
That is the boundary of static extraction — and the point is that it is now
*established per placement* rather than asserted about the method. It had been
asserted through two revisions of an architecture document while six ordinary
bugs sat behind it.

**The rule.** When a comparison produces a difference, spend the next hook on
attributing the difference rather than on measuring the total more precisely.
A total tells you how far you have to go. An attribution tells you where to
stand. And the cost is usually a stack read: the caller is already on the
stack at the moment you are already stopped.
