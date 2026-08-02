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
