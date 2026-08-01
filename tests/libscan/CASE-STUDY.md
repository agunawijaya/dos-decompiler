# Case study — recovering an entry point from a library archive

`unpack.py` can pull the image out of a packed executable, but it cannot tell
you where the program starts. The packer's stub jumps to the original entry
point at run time; nothing in the dumped file records it. The toolkit's answer
had been to write 0 and say so, because a wrong entry point sends the
disassembler into the middle of a routine and every later address inherits the
error.

This closes that gap, using a technique proposed by the agent who reconstructed
CONTRAP.EXE. Their insight, in one line: **the compiler's own library archive
is a better signature database than anything you can infer from a binary**, and
one module in it declares the entry point.

## Why the archive beats a compiled reference

`libsig.py` builds signatures by compiling a reference program and blanking
every byte capstone says is an immediate or a displacement. That is a guess
about which bytes the linker will change, made by a disassembler.

An OMF `.LIB` does not require the guess. Each module carries FIXUPP records
that state, exactly, which bytes the linker will overwrite with addresses.
Blank those and the signature is exact. Two further things fall out:

- **MODEND.** The startup module sets a "start address" flag in its MODEND
  record and names a segment and a displacement. That is the entry point, as a
  field, not an inference. Read correctly on four compiler generations, the
  earliest 1983: Microsoft C 1.04, 5.0 and 5.1, and Open Watcom.
- **PUBDEF.** Every module lists its public symbols and their offsets, so a
  match does not just say "runtime code here", it says `_strncmp`.

## Result

```
python tools/libscan.py IMAGE.EXE --lib SLIBC.LIB
```

| case | modules | runtime bytes | names | contradicted by the map | entry point |
|---|---|---|---|---|---|
| libref, MSC 5.0, linked normally | 92 | 17,202 | 115 | 0 | **0x006B2 — matches the header** |
| libref, MSC 5.0, packed then dumped | 92 | 17,202 | 115 | 0 | **0x006B2 — matches** |
| Sopwith, MSC 5.0 | 24 | 2,929 | 41 | 0 | **0x07362 — matches** |
| Sopwith, Open Watcom | 26 | 4,826 | 45 | 0 | **0x07738 — matches** |
| Sopwith (Watcom) scanned with the *Microsoft* library | 0 | 0 | 0 | — | not recovered |
| CONTRAP (Microsoft C 1.04) scanned with the MSC 5.0 library | 0 | 0 | 0 | — | not recovered |

The entry point is the measurement that matters, and the oracle is independent:
**libscan never reads the MZ header.** It reports an offset derived only from
the library; the header is then used to check it. Four binaries, two compilers,
four exact matches, including one that had been packed and dumped.

Names were checked against the linker map, not merely against each other: of
201 symbols recovered across the three distinct programs, **none contradicts
the map** — 42 of the 45 Watcom names sit at offsets the `wlink` map lists, and
the other 3 at offsets it does not list at all. On
the Microsoft builds every map symbol lying inside a matched region was named
(39/39 on Sopwith, 113/114 on libref — the one exception is described below).

## The two negative rows are the point

A signature scheme that produced *plausible* matches against the wrong compiler
would be worse than none, because the runtime boundary it drew would be
believed. Both wrong-library scans return nothing at all — no modules, no
names, and explicitly no entry point. The failure is silent in the right
direction.

The CONTRAP row is a real case rather than a constructed one: that binary was
built with Microsoft C 1.04, whose library we do not have, so the correct
output is exactly what the tool produced.

## The heuristic that did not survive contact with 1983

This case study first claimed something stronger, and it was wrong:

> Exactly one module sets the start-address flag in each library checked, so
> the flag also *finds* the startup module without needing to know its name.

True for MS C 5.0 (`CRT0`, 1 of 302), MS C 5.1 (`dos\crt0.asm`, 1 of 303) and
Open Watcom (`cstart`, 1 of 1,218) — and false for **Microsoft C 1.04**, where
the count is **zero of 75**. Its startup code is not in `MC.LIB` at all: it
ships as a loose `C.OBJ` that the link line names ahead of the library.
Reported by the agent who reconstructed CONTRAP, who has that compiler and
checked.

The failure mode is what makes it worth a section. A scanner handed only the
archive finds no start-address module and, if it reports that as "entry point
not recovered", has made a claim about the *binary* on the basis of what the
*caller passed in*. Two fixes:

- `--lib` accepts a directory and reads every `.LIB` and `.OBJ` in it. On MS C
  1.04 the startup object sits beside `MC.LIB`, so this costs one directory
  listing. It is now the recommended form — on MS C 5.0 it also found 2 more
  modules and 3 more names than the single archive.
- "Nothing loaded declares a start address" and "the startup module declared
  one but did not match" are reported as different outcomes, in different
  words.

The layout is reproduced in the regression test with Open Watcom, by extracting
`cstart` from `clibs.lib` — so the case is tested, not merely described, by
anyone with the free toolchain.

`[inferred]`, from them: early Lattice C and other pre-1985 toolchains probably
share the layout, since separating crt0 from the library is what makes it
replaceable. One compiler is the whole basis for that.

## What it got wrong first, and what that taught

MSC 5.0's `flushall.c` and `closeall.c` have byte-identical code segments.
Both matched at the same offset, and the first version of the tool emitted both
`_flushall` and `_fcloseall` as names for that address — **one wrong name out of
117**, and the only wrong name in the whole measurement.

Bytes cannot separate two modules that have the same bytes. So the tool now
detects the collision, keeps the region (which is certainly runtime either way)
and withholds the names. This is the same rule the toolkit already applies to
naming: one source of evidence is not enough to commit.

It also fixed a quieter defect. Counting both modules had been double-counting
their 50 bytes in the "runtime bytes" total.

## Reproducing it

The regression test needs only Open Watcom, which is free:

```
python tests/libscan/regress.py --watcom C:\Applications\watcom-snap
```

It compiles a small program, links it, scans the result against the library it
was linked with, and asserts the recovered entry point equals the header's. It
then takes the startup module out of the archive to reproduce the MS C 1.04
layout, and asserts that the archive alone reports *no start address declared*
rather than *no entry point*, and that adding the loose object — or just naming
the directory — recovers it exactly. With `MSC_HOME` set it also scans against
a different compiler's library and asserts nothing is found.

```
built probe.exe with Open Watcom, small model
  archive holding its own startup module     47 modules, entry 0x00312 vs header 0x00312   PASS
  archive with the startup module removed    46 modules, 0 declaring a start address       PASS
  ...plus the startup object, loose          47 modules, entry 0x00312 vs header 0x00312   PASS
  ...or just the directory holding both      47 modules, entry 0x00312 vs header 0x00312   PASS
  the wrong compiler's library entirely       0 modules, entry none                        PASS

PASS  5/5 checks
```

## Where this changes the workflow

Identifying the compiler and subtracting its runtime should be **step one**, not
something discovered halfway through. On the reference build the matched
modules account for 17,202 of the 24,881 bytes of `_TEXT` (69.1%); on Sopwith,
24 modules and 41 named functions that no longer compete for matches — 2,929 of
32,671 bytes (9.0%), which is the honest figure for a real game rather than for
a program written to pull in library code. The CONTRAP agent put it more strongly than we
would have, having measured it on their own binary: the runtime was 27% of the
code, and finding it early would have removed a quarter of the work list before
any analysis began.

The limits are worth stating plainly:

- It needs the actual library archive. No archive, no matches — this does not
  identify a compiler it has never been given.
- The startup object is not always in the archive. Point `--lib` at the
  directory, not the `.LIB`.
- It matches code segments only. Data segments are frequently all zero or all
  pointers, and match everywhere.
- ALIAS records are not followed, so a symbol the linker bound by alias appears
  under the module's own name for it. Both names are correct; only one is
  reported.
- A module linked in twice, or whose code appears verbatim elsewhere, is
  reported as ambiguous and not placed.

## Credit

The technique — split the library into modules, wildcard the FIXUPP slots,
subtract the runtime first, and read the entry point out of the startup module
— comes from the agent who reconstructed CONTRAP.EXE, written up in
`knowledge/09-lessons-from-contrap.md`. The implementation, the MODEND and
PUBDEF handling, and the measurements above are this toolkit's.
