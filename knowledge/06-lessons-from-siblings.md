# Lessons taken from two sibling reconstructions

Two other reverse-engineering efforts ran alongside this one on the same
machine, on different games and with different goals. Both kept honest records
of what they got wrong. Those records are the cheapest material available for
strengthening a method, because someone else already paid for them.

- **Tapper** (1984, IBM PC): hand-written assembly, `.COM`, reconstructed to
  **byte-identical** source. Achieved. 578 named routines, build verifies
  against the original binary by SHA256.
- **Creative Contraptions** (Bantam, 1988): PKLITE-packed, C-compiled,
  reconstructed as a **modern port verified frame-by-frame**.

Neither is in this toolkit's validated class — Tapper is `.COM` and pure
assembly, Contraptions is packed — which is itself informative about how narrow
that class is.

## 1. A conclusion from one source of evidence is usually wrong

Tapper's project keeps a table of every claim it had to retract: **35 entries**,
each with its root cause. The authors state the pattern outright, and the
entries bear it out:

> A conclusion drawn from a single source of evidence almost always needs
> correcting later. What survived was what had two independent sources.

Examples of the failure mode, all from that table:

- A field named from its *writer* without checking its *readers* — twice, the
  second time repeating a mistake already in the table.
- A routine named from its **first four lines**; further down it also moved
  entities, scored catches, and could kill the player.
- Its neighbour named the same wrong way. Being a plausible-looking *pair*
  made each seem to confirm the other.
- A flag named from its **effect** (`slow_machine_flag`) rather than from who
  wrote it (`is_pcjr`) — which inverted the meaning, and sounded reasonable
  enough that nobody questioned it.

**Applied here.** `anchors.py` now counts *distinct kinds* of evidence per
address — interrupt, I/O port, string, constant, entry point — and only scores
a name as confident when at least two agree. A function whose sole evidence is
"it executes INT 10h" now stays provisional, gets a `__maybe` suffix from
`ApplyNames.java`, and carries a warning comment.

The effect on the shipped Sopwith binary: of 20 evidence-based names, **2 are
corroborated and 18 are provisional.** Previously all 20 were applied as
though established. One of the provisional ones is `main`, which independent
reading shows is at the wrong address — exactly the error the demotion is
there to contain.

Two interrupts inside one function count as *one* kind, not two. They come
from the same observation and can be wrong together.

**Applied here, second.** `ApplyNames.java` flags any name applied to a
routine of 200 bytes or more, in the comment it writes: evidence found
somewhere inside a long routine says little about the rest of it.

## 2. Absence of a result is not absence of a fact

The single most repeated root cause in Tapper's correction table:

- `grep` found no reference to an address → concluded no path reached it. The
  entry was two bytes earlier, through a label that had been named for weeks.
- The emulator never executed a code path → concluded the opcode was unused.
  The path simply was never reached under the inputs given.
- No runtime request for an asset → concluded the catalogue was incomplete.
  The data was there, RLE-compressed.

**Applied here.** Tools that can return nothing now say what nothing means.
`libsig.py` reporting zero matches already explains that a program may have
brought its own runtime. `emuverify.py` reports "uninformative" rather than
silently dropping functions. `triage.py` distinguishes "no packer signature"
from "not packed".

When one of these tools returns empty, the question to ask is *what else would
produce this same emptiness*, not *what is missing*.

## 3. Move the axis of proof — but never to "looks right"

Contraptions could not reach byte-identity: the original is packed and the
period compiler was a blocker. Rather than retreat to "it looks the same", it
**moved the axis**: feed the original under DOSBox-X and the port the *same
recorded input script*, dump both framebuffers per frame, and require a
**zero-pixel difference**.

That is the generalisable idea, and it is worth stating as a ladder. Every
reconstruction claim should sit on one of these rungs, and you should always
know which:

| Rung | Oracle | Proves | Cost |
|---|---|---|---|
| 1 | byte-identical rebuild | the source is right | needs the period toolchain |
| 2 | instruction-identical, layout-tolerant (`mzdiff`) | the code is right | needs a compiling reconstruction |
| 3 | per-function behavioural equivalence (`emuverify.py`) | this function is that function | needs two binaries |
| 4 | pixel-identical frames under identical input | the program behaves the same | needs a runnable port |
| 5 | "looks right" | **nothing** | free, and worthless |

This toolkit lives on rung 3 and had never articulated the others. Rungs 1 and
2 are what `knowledge/05-prior-art.md` points at; rung 4 is what a port should
be held to.

> The ladder has since been refined — rung 1 split into 1a/1b, and rung 3b
> added — after the Contraptions reconstruction finished and reported what its
> per-function comparison had been unable to see. The current version is in
> `07-extended-reconstruction.md`; the reason is in
> `09-lessons-from-contrap.md`. The five-rung version is kept here because this
> file is a record of what was learned when.

Two supporting details from that plan, both transferable:

- **Assets faithful by construction, not by effort.** The port reads the
  original data files at runtime and decodes them in memory. Exporting to PNG
  and reading the PNG back would insert a transformation that *can* drift —
  palette, rounding, frame order. Reading the original bits makes drift
  impossible rather than unlikely.
- **Keep the reconstruction structurally parallel to the decompilation**,
  function for function. Rewriting in idiomatic modern style destroys the
  ability to line the two up — and that alignment is itself the strongest
  verification tool available.

## 4. `int` is 16 bits in period C and 32 bits in yours

Called out in the Contraptions plan as the most dangerous porting trap, and it
is not in this toolkit's documentation anywhere. It does not crash. It quietly
changes behaviour: a score that should wrap at 32,767 keeps climbing, a
coordinate that should fold runs straight on. The bug surfaces forty minutes
into play.

Anything reconstructed from a 16-bit binary must use explicit `int16_t` and
`uint16_t`. A bare `int` in reconstructed code is a defect regardless of
whether it currently misbehaves.

The same applies to reading decompiler output: Ghidra renders 16-bit
quantities as `undefined2`/`uint`, and the arithmetic around them wraps at 16
bits whatever the C on screen suggests.

## 5. A longer run is not broader coverage

Tapper raised its emulator budget from 12 million instructions to 40 million
and gained **56 addresses** — no new subsystem. Bonus rounds, tip popups,
joystick calibration all stayed at zero executions.

What worked instead was **injecting state directly** at a chosen execution
point, which only became possible once the controlling variables had been
named. Naming, which looked cosmetic, is what unlocked it.

**Relevant here directly.** `emuverify.py` runs functions with synthetic
arguments — the same manoeuvre at function scale, and the reason it reaches
routines nothing calls. The lesson to carry is the negative one: when it
cannot reach something, raising `MAX_INSNS` is not the answer. Choosing
arguments that steer the function is.

This matches a result measured independently here: adding *more* input vectors
made matching worse, not better (`03-what-works.md`). Both projects arrived at
the same place — steer, do not flood.

## 6. Measure, do not reason, about your own tooling

Tapper tried twice to improve displacement encoding. The general rule demoted
59 instructions to data; the restricted version, which *should have been
safer*, demoted 118. The second was worse than the first, so the problem was
not the rule being too broad.

Three results in this toolkit have the same shape: module segmentation looked
obviously helpful and made identification worse; iterative refinement of the
module order converged to the same answer or worse; more emulator input
vectors reduced matches. Every one contradicted a confident prediction.

A corollary from Tapper worth stealing: **watch a second metric.** Their build
hash stayed green through both failed encoding attempts — correctness was
preserved while quality dropped, and only a separate "bytes as code" figure
caught it. A passing test does not mean nothing got worse.

## 7. Scale decides the tool

Tapper rejected Ghidra and IDA and wrote its own Python disassembler and 8086
interpreter, because for a **17 KB** binary custom tooling was more effective
than fighting a decompiler's weak 16-bit segmentation.

That is the right call at that size and the wrong one at 60 KB with 300
functions and a C runtime, where Ghidra's decompiler earns its place. Neither
is a general answer:

- Under ~30 KB, hand-written assembly, one data file: custom tooling wins.
- Above that, compiled from C, many library routines: Ghidra plus this
  toolkit's recovery and signature layers wins.

Tapper also rejected `mzretools` for a stated reason worth repeating: its
README says `.COM` is unsupported, and its workflow assumes a C-compiled
target. **Read the prior art's own limitations before adopting it** — which is
the mistake this toolkit made in the other direction, by not reading the prior
art at all.
