# Scope: which DOS programs this handles, and which it does not

Read this before pointing the tools at anything. The measured accuracy figures
elsewhere in `knowledge/` were obtained on one narrow class of binary, and they
do not transfer outside it.

## The class this was built for

**16-bit real-mode MZ executables, compiled from C, small memory model, not
packed, not overlaid.**

That is a real and reasonably populous class — a lot of 1984–1990 commercial
and shareware games are exactly this — but it is a fraction of "DOS games".

Everything was validated on Sopwith (1984, Microsoft C + MASM, small model,
CGA). Where a tool assumes something, it assumes what Sopwith does.

## Compatibility, honestly

| Program shape | Verdict | What actually happens |
|---|---|---|
| MZ, C-compiled, small model | **Works** | this is the validated case |
| MZ, C-compiled, medium model | **Mostly** | multiple code segments; `emuverify` needs work |
| MZ, C-compiled, compact/large/huge | **Partly** | far pointers and multiple data segments break `emuverify` and weaken `modcluster` |
| MZ, hand-written assembly | **Partly** | `mzinfo` and `anchors` fine; no C runtime to strip, no C source to match |
| Turbo/Borland Pascal | **Poorly** | different calling convention and runtime; needs its own signature database |
| Borland C / Turbo C | **Mostly** | cdecl is fine, but no signature database ships for it |
| Packed, Microsoft EXEPACK | **Yes, via `unpack.py`** | validated: entry point exact, image 99.7% of a known-good unpacked build |
| Packed, PKLITE | **Image yes, entry point no** | decompression verified on a 1988 game; the format does not state its entry point and no heuristic found it |
| Packed, other (LZEXE, DIET) | **Probably the same** | untested; the mechanism is format-independent |
| Overlaid (FBOV, Borland/Microsoft overlays) | **No** | detected and warned about; nothing here handles them |
| `.COM` files | **Yes, by a separate route** | no MZ header to interpret, so `comrec.py` reconstructs the file directly and proves it byte-for-byte — but the result is assembly, not C. See [08-com-reconstruction.md](08-com-reconstruction.md) |
| Self-modifying or copy-protected | **No** | static analysis and emulation both mislead |
| DOS extender / protected mode (DOS4GW, PMODE/W) | **No** | LE/LX executables, a different format and era |
| Interpreted engines (SCI, SCUMM, AGI, DAAD, Z-machine) | **Wrong tool** | see below — this is the trap |

## The trap worth naming: interpreted engines

A large share of DOS adventure games — Sierra's SCI and AGI, LucasArts' SCUMM,
DAAD and other authoring systems — ship an executable that is an *interpreter*.
The game itself is bytecode and assets in the data files beside it.

Decompiling the executable will work fine and tell you nothing you wanted. You
will get a correct, readable rendering of a virtual machine, a resource loader
and a parser. The game's rooms, dialogue and puzzles are not in there.

Symptoms to check for before starting: a small executable next to large opaque
data files; strings in the data files rather than the binary; a main loop that
dispatches on bytes read from a file. If you see that, stop and look for an
existing engine-specific tool — ScummVM's documentation, SCI Companion,
`unDRC` for DAAD. Those communities have decoded the formats already.

## Memory model is the assumption that bites hardest

`emuverify.py` sets `SS = DS` and maps one 64 KB data group, because that is
what small model means. Point it at a large-model program and it will run
functions with a wrong stack segment and produce nonsense — silently, since it
has no way to know.

`mzinfo.py` reports the evidence for the model (relocation count and where the
relocations sit) in its findings. **Read that before using `emuverify`.** A
program with dozens of relocations spread through the image is not small model.

`modcluster.py` and the data-reference fingerprints in `match.py` also assume a
single DGROUP: they treat a 16-bit displacement as a unique variable identity,
which stops being true when there are several data segments.

## What degrades gracefully, and what fails silently

Graceful — these tell you when they have nothing:

- `mzinfo.py` reports packers, overlays and odd layouts as findings rather than
  guessing past them.
- `libsig.py` matches nothing rather than matching wrongly when the compiler
  differs. Zero matches is informative, not broken.
- `emuverify.py` reports "uninformative" instead of inventing equivalences.
- `match.py`'s score distribution collapses visibly when the reference source
  does not correspond to the binary.

Fails silently — be careful:

- `emuverify.py` on a non-small-model program, as above.
- `match.py` against source from a different version: it still produces
  plausible-looking mid-confidence matches. Check whether anything clears 0.7.
- `anchors.py`'s `main` heuristic, which was right on one of two test binaries.

## Where the numbers come from

Every figure in `03-what-works.md` is from Sopwith: one game, one compiler
family, small model, ~200 functions, no overlays, no packing. Treat them as
calibration for a program of that shape, not as universal constants. A larger
program with overlays and far pointers will do worse, and nothing here has
measured how much worse.

## What triage found on real files

Not hypothetical. Run against binaries lying around on one developer's machine:

| File | Verdict | Why |
|---|---|---|
| `SOPWITH.EXE` (1984) | in scope | small model, 242 prologues/4.1 per KB — compiled C |
| `CONTRAP.EXE` (Bantam, 1988) | **blocked** | PKLITE-packed |
| `BANTLOGO.EXE` (Bantam, 1988) | **blocked** | PKLITE-packed |
| `MODE.COM` | routed to `comrec.py` | not an MZ executable, and does not need to be |
| `UNZIP.EXE` | **blocked** | UPX-packed, 87 KB past the load image |
| `ParaTrooper.1982.com` (Orion, 1982) | rebuilt byte-for-byte | hand-written assembly, so assembly is all there is to recover |
| a Watcom rebuild of Sopwith | workable, caveats | frame pointers omitted, so boundary recovery suffers |

Two of the six are period commercial games, and **both are packed**. That is
representative: compressing the executable was near-universal on commercial
DOS releases from the late 1980s, since it saved floppies and slowed casual
copying. Expect to unpack more often than not — which is why `unpack.py`
exists rather than a note telling you to find another tool.

## Unpacking: what works and what is guessed

`unpack.py` runs the packer's own decompressor under emulation and dumps the
result. One mechanism, any packer, including undocumented ones — because
whatever the algorithm, a packer must rebuild the image in memory and jump to
it.

Validated with a self-made known-answer test: the same object file linked
twice with Microsoft LINK, once with `/EXEPACK` and once without. Unpacking
the packed one recovered the original entry point **exactly** (`0x6B2`) and an
image **99.7% byte-identical** to the plain build — the 106 differing bytes
are segment words the loader had already patched.

The part that is *not* solved is finding the original entry point generically.
The obvious rule — "control reaches bytes this run wrote" — fires on the
decompressor relocating itself, and on the known-answer test it returned
`0x8B40` against a true `0x6B2`. Tightening it (require a substantial fraction
of the image rewritten, require the target inside the load area) moved the
answer but did not make it right.

So the tool prefers what the packer *states* over what its behaviour implies.
EXEPACK keeps a 16-byte header ending in `RB` immediately before its
decompressor, carrying the real `CS:IP` and `SS:SP`; all four fields matched
the plain build exactly. Formats without such a header fall back to the
heuristic, and the tool says which it used and warns when it guessed.

**PKLITE has now been tested**, on a PKLITE 1990-92 build of a 1988 commercial
game. The decompression works, and there is direct evidence rather than an
impression: the packed file contains 83 printable strings, the dump contains
223, and the 181 new ones are the game's own text —

```
'Now press ENTER to see the contraption.'
'Press SPACE BAR to run the contraption.'
'THERE ARE SIMPLE MECHANISMS MISSING'
```

That is decompression, confirmed by content that could not have come from
anywhere else.

Its entry point is not recovered, and inspecting the file shows why: PKLITE
writes only a copyright string (`PKLITE Copr. 1990-92 PKWARE Inc.`) into the
header area. There is no field stating the original `CS:IP` the way EXEPACK
has one. Recovering it would mean pattern-matching each stub version, which is
the treadmill this tool exists to avoid.

That same file also exposed a real bug worth recording: PKLITE sets `CS` to
`0xFFF0` — *minus* sixteen paragraphs — so the entry resolves through the PSP
to the very start of the image. Computing the start address without wrapping
the segment addition put it a megabyte out of range. **Segment arithmetic
wraps, and packers rely on it.**

A low density of stack frames in a dump does not mean decompression failed.
The same game shows 15 prologues across 100 KB, which says it is largely
hand-written assembly — a fact about the game, not a fault in the unpacker.
Check strings before concluding anything.

Relocations are not reconstructed either way. The dump is for analysis, not
for running.

The Bantam case also exposed a weakness worth recording. PKLITE puts its
marker in the header area, far from the entry point, so a proximity test alone
rated it a warning rather than a blocker. The corroborating evidence is
decisive and cheap: a packed file has almost no relocations, because the
payload has not been relocated yet, and almost no stack frames, because the
visible code is a decompressor. Triage now requires that combination.

## Before you start: triage

`python tools/triage.py GAME.EXE` answers "is this in scope?" from the binary
itself — format, packing, overlays, apparent memory model, whether it looks
C-compiled, and whether it smells like an interpreter with its data elsewhere.
It is the first thing to run.
