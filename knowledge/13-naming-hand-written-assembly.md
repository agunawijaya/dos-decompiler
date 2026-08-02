# 13 — Naming hand-written assembly

Karateka was compiled C. Everything the toolkit learned there — prologues,
library signatures, a FILE table with a stride — assumed a compiler had been
through the code first. ParaTrooper, Zaxxon and Hard Hat Mack were written by
hand. Between them they have zero `push bp` prologues and no runtime, so
`probelib.py` returns nothing on all three: 0 of 250 entry points in Hard Hat
Mack, which is a measurement, not a failure.

What follows is what worked instead.

## The caller count is not evidence, and it fails the same way every time

Across the three games, fourteen routine names had been assigned from how many
callers a routine had. **Every one of them was wrong.** Not most: all of them.

| game | the name | what the bytes do |
|---|---|---|
| ParaTrooper | `draw_sprite`, 7 callers | `state = state * 0x7781 + 0x64C9` — an LCG |
| ParaTrooper | `move_actor` | walks eight countdown timers and pokes port 0x42 |
| ParaTrooper | `spawn` | ten rows of a bitmap into video memory |
| Zaxxon | `draw_cell`, 13 callers | returns a pointer to the current player's context |
| Zaxxon | `port_write` | zeroes 0x2000 words of the frame buffer |
| Zaxxon | `level_step` | prints a string |
| Hard Hat Mack | `shift_history`, 16 callers | saves the position in a tune |

The failure is structural, not careless. A high caller count means a routine is
*central*, and a plausible story about what a central routine does is easy to
write and impossible to check. The name then propagates: `input_latch` and
`input_latch_2` in Hard Hat Mack were named after `shift_history` wrote to them,
so one guess produced three wrong names and a wrong mental model of the sound
code, which is in fact a software pulse-width modulator on a one-bit speaker.

Name from what a routine does to what. If you cannot say that, leave it
unnamed — `symbols.json` supports an `_unread` list for exactly this, and a
count of 35 honest names reads better than 221 dishonest ones.

## Find the program's own account of its variables

ParaTrooper's start-up zeroes its state from a table at `ds:0x1A30`: seventeen
`(address, length)` pairs. Every entry landed on something already named from
behaviour, with the matching width. That table turned a reading into a
cross-check, and it cost nothing to look for.

Programs of this era almost always have one, because clearing the BSS by hand
is cheaper than clearing it in code. Look for a short run of ascending word
pairs where the first of each pair is a plausible data address, near the
start-up path.

## A table usually ends where the thing it points into begins

Zaxxon's tile table starts at `cs:0x1FDD` and its first entry is `cs:0x2099`.
Ninety-four entries later the table ends — at `cs:0x2099`. The sprite table at
`cs:0x2613` ends at `cs:0x269B`, which is its own first bitmap. Neither
boundary was chosen; both were measured, and their agreeing is what makes the
extents facts rather than estimates.

This gives a free length for any pointer table whose targets follow it, which
in hand-written assembly is most of them. It also gives a check: if the count
you derive from the first entry disagrees with the largest index the code can
produce, one of the two is wrong.

## Two segments mean two namespaces

Zaxxon patches its own `mov ax, imm16` at load time so DS sits 0x5200 bytes
past CS — past the end of the 20,736-byte file. Every table it reads is
`[cs:...]` and inside the image; every variable it writes is `[...]` and in
memory the file never described. `[0x0055]` and `[cs:0x0055]` are two different
addresses.

`annotate.py` now takes a segment prefix on a key (`"cs:0x04E8"`), and a
prefixed reference matches only a prefixed key. Without that, one name would
have covered both — a lie that still assembles, which is the specific kind of
mistake the byte-identity rule exists to catch and cannot.

It also now names `[bx + 0x052d]`. Compiled code addresses a global directly;
hand-written code puts the base in a register, so the bare-bracket form the
tool started with matched almost nothing in these three games. Hard Hat Mack's
`scanline_table` had been in its symbol file for a whole session without ever
being substituted. BP- and SP-relative displacements are excluded, because
`[bp + 0x08]` is an argument and not whatever global happens to live at 8.

## Data that decodes is still data

Six bracketed constants in Hard Hat Mack survived every other check and are
not addresses. `and bx, word [0x001E]` is a run of table bytes that happens to
encode as an instruction, inside a run comrec classified as code because it
decoded cleanly all the way through. NASM re-emits the same bytes, so
byte-identity says nothing about it either way.

This is the mirror of the question `knowledge/11` answers. There: are unreached
bytes code? Here: are reached bytes that decode actually data? Both come down to
what refers to them, and nothing referred to these. The reason it matters is
that a naming pass will happily invent a variable for each one, and six
plausible variables in a symbol file are six things the next reader will
believe.

The tell is that the "address" is referenced exactly once, from inside a run
with no incoming branch, and nothing writes it.

## Count call targets, not prologues

Karateka is compiled C, and its symbol file said "nothing is unnamed" against
the only denominator that seemed natural: 120 `push bp` prologues, all named.
The listing has **165 call targets**. Fifty-six routines the program calls had
no name while the figure read 100%.

They were not exotic. Lattice C's runtime is hand-written assembly with no
prologue at all -- `lmul`, the console poll, the CRTC programming -- and the
compiler generates tail entry points inside its own functions that are called
directly and never prologued. A prologue count sees none of it.

This is the denominator problem from `knowledge/12` in a second costume, and it
is worth stating as a rule: **the set you must cover is the set of addresses
something transfers control to.** Direct calls, jump-table entries, and the
targets of any `call word [...]` your reconstruction resolved. Prologues are a
way of *finding* routines, never a way of counting them.

The check is two lines against the listing, and it belongs in the build:

    calls = {addr for every `call L_xxxxx`}
    unnamed = calls - set(symbols["routines"])

## Corollary: check what coordinate a key is in

The same `scanline_table` entry was recorded as `0x042d`, its **file offset**,
while every other key in that file was an **address**. It was also recorded as
600 words when the loops that walk it count 200. Nothing caught either, because
a symbol that never substitutes cannot fail loudly.

Add the check to the build: every routine key should match a label in the
listing, and every bracketed address in the listing should either have a name
or be on a list of ones you decided not to name.

## One address, two prefixes, one variable

Hard Hat Mack's keyboard handler reads `[cs:0x0781]` while everything else
reads `[0x0781]`. The game sets DS = CS, so those are one variable, and the
prefix is there only because an interrupt cannot trust DS. Zaxxon's `cs:` and
bare addresses, by contrast, are genuinely different memory.

So the duplicate-name check has to be on the *number*, not the prefix: two keys
may share a name when they resolve to the same address, and must not when they
do not. Getting that backwards either forces two names onto one variable or
lets one name cover two.
