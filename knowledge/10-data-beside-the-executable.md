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

## Finding the container is not decoding the records

The two should not be confused in a report, and here they were separated by
about a day of being wrong in public.

Karateka's records open with three bytes that read like `(width, height, ?)` and
continue with something compressed. `0x7B` as *escape, value, count* decoded 282
of 284 records without running off the end — which sounds convincing and proves
very little, because almost any rule decodes *something*. The test that looked
like it mattered was whether the decoded length equals `width × height`, and
that held for **10 of 284**.

So the rule was recorded as close and wrong, and close is the dangerous kind of
wrong: a compression rule that is nearly right produces pictures that are nearly
right, and nothing in the output says which.

**Both halves of that turned out to be mistaken, in opposite directions.** The
rule was right apart from an off-by-one — `0x7B v c` emits `v` and then `c` more,
so `c + 1` bytes — and the *test* was malformed. The game's decoder yields one
byte per call and stops when the caller stops asking, so a record routinely
carries more than any one drawing consumes; one 90-byte record supplied 21 bytes
and that was correct. Asking "does this record decode to exactly `w × h`?" is a
question about a particular drawing, not about the format. With the off-by-one
fixed and the question dropped, all **666 records decode**.

Two things generalise, and the second is the expensive one:

- A decoder that yields one byte per call has no notion of *decoding a record*.
  Do not write a validator that insists on consuming one.
- **A stalled metric is sometimes measuring the wrong thing.** The count sat at
  338 and could be curve-fitted up to 491 by trying `(w+1)*h` and its relatives.
  Fitting moved the number and taught nothing; reading the routine moved it to
  666. When a score plateaus and only responds to tweaks in the *scoring*, that
  is the signal to stop scoring and go read.

The way to settle it was not to guess harder. Running the program under
`comrun.py`, hooking the buffer a `.DAT` loads into and asking which
instructions read it named the decoder in four passes — the same route that
settled Hard Hat Mack's scanline table after static reasoning had stalled.

## Open the files before decoding them

Karateka's fighting was recorded as unread through four documents. It is not in
the executable at all. It ships beside it as **plain ASCII**, in three files
totalling 150 blocks of animation script, one block per move:

```
set_pos,11 12 pal08
inc_x,4
set_tune,0
set_fig,2 -4 165
set_fig,47 15 131
```

Nothing had to be reverse engineered to read that. `survey.py` reported the
files, `head` would have shown what was in them, and the reason nobody looked is
that the folder's *hard* format — the run-length sprite records — had set the
expectation that everything else would be hard too.

Two habits follow, and they cost seconds each:

* **`head` every unknown file before writing a decoder for it.** Text announces
  itself instantly and no amount of static analysis substitutes for looking.
* **Having just cracked a hard format, assume nothing about the next file.**
  The same folder holds run-length column-major sprites, a raw uncompressed
  bitmap (`.BCG`: a length word, then 80 bytes per scanline), and readable
  source text. Three formats, one directory, sharing no assumptions.

The related trap is the mirror image: the scripts turned out to be *compiled* at
load into a byte code, so the routine that reads them is a compiler and not,
as this repository had it for a while, an interpreter. **A program that ships
text still need not interpret text.**

## What to do when you are handed a folder

1. `survey.py` — which file is the game, and **what is the shape of the data
   beside it**.
2. If a container magic is recognised, find the format's documentation before
   writing a decoder.
3. If index/heap pairs are reported, the container is settled and the *record*
   is the open question.
4. If neither, the data is inside the executable and `gfxdump.py` applies.
