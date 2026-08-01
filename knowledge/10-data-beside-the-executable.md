# 10 — The data beside the executable

Every game this toolkit was built on keeps its content inside its executable.
Sopwith, ParaTrooper, Hard Hat Mack, Zaxxon — one file each, artwork and tables
in the same image as the code. So every tool here takes *an offset into one
file*, and the question "what are the other ninety files for?" had no answer
because it had never been asked.

**Karateka (1984) asked it.** 87,990 bytes of executable and ninety data files
beside it. `survey.py` looked at that folder, named the executable, and said
nothing whatever about the rest.

## Why it said nothing, which is the more useful failure

The threshold was `16 KB`: a data file smaller than that was assumed to be
configuration or a saved game rather than content. Karateka's largest data file
is 9 KB.

So the tool was not confused — it was **correct about each file and wrong about
the folder**. Ninety small files are a stronger signal than one large one, and
that signal was being thrown away one file at a time.

The general shape of the mistake: *a threshold applied per item cannot see a
pattern across items.*

## What a paired index and heap looks like

A program too big to keep its artwork inside itself puts the artwork in a heap
and the offsets in an index. This is not one studio's invention; it is what
anyone does with variable-length records and 1980s memory.

```
KM0.IND    (uint16 id, uint16 offset) pairs, both ascending
           terminated by 0xFFFF followed by the total length
           padded to a fixed size with 0x80

KM0.DAT    the records back to back, then 128 bytes of 0x80 padding
```

A record's length is the next record's offset minus its own. It is the same idea
as Hard Hat Mack's sprite pointer table, moved out of the executable.

**The test is what makes it a finding rather than a guess.** Two files, same
stem. Read one as offsets; they must ascend, and the last must land inside the
other. Karateka satisfies that on all twenty-eight pairs at once, and the
leftover is a constant **128 bytes on every one of them** — a constant repeated
twenty-eight times is not a coincidence, it is the format.

`survey.py` now runs that test automatically and reports the slack, which is how
the padding announces itself:

```
KM0.IND        indexes KM0.DAT          11 entries, 4-byte stride
               last offset 841 of 969, 128 bytes over
```

It also groups data files by extension and totals them, and recognises a handful
of container magics on sight:

```
-- The data beside the executable ---
  .PCL          2 files     510,970 bytes
  .REC          4 files      14,885 bytes

-- Formats recognised on sight ---
  OTMCGA.PCL   321,139  Genus Microprogramming pcxLib -- a container of ZSoft
                        PCX images, and PCX is documented
```

That second line is worth more than it looks. The Oregon Trail's artwork is
**PCX**, an open format from 1985. Two games running, a sprite format had to be
guessed from a pointer table's stride and confirmed by rendering; here the
answer is a magic string. **Check for a known format before reverse engineering
a bespoke one** — the cost of looking is a second and the cost of not looking is
a day.

## Where this stops, deliberately

Finding the container is not decoding the records, and the two should not be
confused in a report.

Karateka's records open with three bytes that read like `(width, height, ?)` and
continue with something compressed. `0x7B` as *escape, value, count* decodes 282
of 284 records without running off the end — which sounds convincing and proves
very little, because almost any rule decodes *something*. The test that matters
is whether the decoded length equals `width × height`, and it does so for **10
of 284**.

So the rule is close and wrong, and close is the dangerous kind of wrong: a
compression rule that is nearly right produces pictures that are nearly right,
and nothing in the output says which. It is recorded as undecoded.

The way to settle it is not to guess harder. Run the program under `comrun.py`,
capture what it puts on the screen, and work backwards — the same route that
settled Hard Hat Mack's scanline table after static reasoning had stalled.

## What to do when you are handed a folder

1. `survey.py` — which file is the game, and **what is the shape of the data
   beside it**.
2. If a container magic is recognised, find the format's documentation before
   writing a decoder.
3. If index/heap pairs are reported, the container is settled and the *record*
   is the open question.
4. If neither, the data is inside the executable and `gfxdump.py` applies.
