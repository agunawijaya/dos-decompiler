# The extended workflow: verified reconstruction

The standard workflow produces C you can read. It never claims the C is right,
because nothing checks it — a person reads the output and forms an opinion.

The extended workflow produces source that **compiles back to the original
program**, and proves it. It is more work, needs more from you, and answers a
question the standard workflow cannot.

Offer the choice explicitly. They are different projects.

| | Standard | Extended |
|---|---|---|
| Deliverable | annotated pseudocode + architecture notes | source that rebuilds the binary |
| Verified by | reading | `bindiff.py`, mechanically |
| Needs a period compiler | no | **yes** |
| Effort | hours to days | weeks, and it is iterative |
| Ends when | you understand it | the diff is clean |
| Fails by | producing something plausible | refusing to converge, visibly |

## Which rung are you standing on

Every claim about a reconstruction sits somewhere on this ladder. Know which,
and say so:

| Rung | Oracle | Proves |
|---|---|---|
| 1 | byte-identical rebuild | the source is right |
| 2 | **instruction-identical, layout-tolerant** (`bindiff.py`) | the code is right |
| 3 | per-function behavioural equivalence (`emuverify.py`) | this function is that function |
| 4 | pixel-identical frames under identical input | the program behaves the same |
| 5 | "looks right" | nothing |

The standard workflow reaches rung 3 at best. The extended workflow targets
rung 2, and rung 1 if the original toolchain is available and configured
identically.

Rung 4 is the right target when byte-identity is out of reach — a packed
original, a lost compiler, or a deliberate port to a modern language. It is
not a lesser goal, just a different observable: feed the original and the port
the same recorded input and require the framebuffers to match exactly.

## The loop

```
   write / correct source
            |
      compile + link          <- the period toolchain
            |
      bindiff.py              <- against the original
            |
   +--------+--------+
   |                 |
 clean            differs
   |                 |
 done       read the first divergence, fix, repeat
```

`bindiff.py` reports, per function, whether the instructions match and where
they first differ. That count is the progress bar, and it has the property
that matters: **it cannot be talked up.** A function is instruction-identical
or it is not.

```
python tools/bindiff.py original.exe rebuilt.exe \
       --map-a original.map --map-b rebuilt.map --report diff.md
```

Exit status is non-zero while anything differs, so it drops straight into a
build script.

## What "layout-tolerant" means, and why it is essential

A reconstruction almost never lands at the same addresses. Insert one
instruction near the top and every branch displacement after it shifts. A byte
comparison would report thousands of differences that mean nothing at all.

`bindiff.py` compares instructions, reduced to a form that survives being
moved:

- **Branches leaving the function** resolve through the symbol table to
  `callee+offset`. Two builds of one function call the same callee even when
  the distance between them changed.
- **Branches staying inside** compare as distances, which is stable because a
  function's internals move together.
- **Segment values** loaded into segment registers are wildcarded — the linker
  chooses those.
- **Everything else**, including displacements and immediates, compares
  literally. Those are the program's own constants and a difference is real.

Resolving inter-function call targets rather than comparing distances is not a
refinement. Measured on two Sopwith builds, it took the match from 80 of 201
functions to **117 of 201** — the 37 difference was entirely layout noise
being reported as divergence.

## Validation

Two controls, both run:

- **A build against itself: 201 of 201 identical.** If this is not 100%, the
  comparison is broken, not the reconstruction.
- **Two builds of the same source with different code generation** (8086
  speed-optimised versus 286 size-optimised): 117 of 201 identical, and the
  reported divergences are genuine compiler choices —

  ```
  intsetup   xor si, si       vs   xor di, di      (register allocation)
  asynget    push bp          vs   enter 2, 0      (286 instruction available)
  init2asy   xor ax, ax       vs   push 0          (286 immediate push)
  ```

  Exactly the shape of difference those flags produce, and nothing else.

## What the extended workflow needs from you

**The period compiler.** Rung 2 means compiling, and a modern compiler
produces different code for the same source. `SW.MAK`-style build files name
the toolchain; `knowledge/02-compiler-fingerprints.md` covers identifying it
from the binary when they do not.

**Tolerance for a long middle.** The count climbs unevenly. Whole groups of
functions go clean at once when a shared header or calling convention is
corrected; then nothing moves for a while.

**Willingness to leave things as data.** Not every byte needs to become code.
A reconstruction with some regions emitted as literal bytes still rebuilds
correctly, and chasing the last few instructions has poor returns — a sibling
project spent two attempts on displacement encoding, both of which made things
worse.

## When to refuse the extended workflow

- **The original is packed** and cannot be unpacked cleanly. You would be
  reconstructing the packed form.
- **The program is hand-written assembly.** Then the target is assembly
  source, not C, and the loop is the same but the deliverable is different —
  say so at the start rather than promising "clean C".
- **The period compiler is unavailable.** Move to rung 4 and verify by
  behaviour instead. That is a real answer, not a consolation prize.
- **The goal was understanding.** The standard workflow is faster and answers
  the question actually asked.
