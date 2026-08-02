#!/usr/bin/env python3
"""Checks for tpscan's segment detection.

The case that motivated these: The Oregon Trail's store is a Turbo Pascal unit
of 9,056 bytes that is far-called exactly once, at offset 0x22B8. `segments()`
keeps a candidate on two calls, or on one if that call is to offset zero and so
is an initialiser. A unit called once at a non-zero offset satisfies neither
rule, and four of them were being folded into their neighbour -- which made the
store's string references resolve against the wrong base and look as though
nothing in the program addressed the store's text at all.

The rescue tests the base directly, using the string idiom rather than the call
graph that already failed. These checks pin both directions: a real segment is
restored, and a stray 0x9A byte is not.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import tpscan                                              # noqa: E402

CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


def pstr(s):
    return bytes([len(s)]) + s.encode("ascii")


def build(base_para, n_refs, string_at=0x0400):
    """An image with one segment whose code references its own strings.

    Each reference is the TP 5.0 idiom -- `mov di, off` / `push cs` / `push di`
    -- and they all point at one string, which is enough: the score counts
    references that resolve, not distinct targets.
    """
    img = bytearray(0x8000)
    base = base_para << 4
    img[base + string_at:base + string_at + 32] = pstr("a string constant").ljust(32, b"\0")
    at = base + 0x40
    for _ in range(n_refs):
        img[at] = 0xBF
        img[at + 1:at + 3] = string_at.to_bytes(2, "little")
        img[at + 3] = 0x0E
        img[at + 4] = 0x57
        at += 5
    return bytes(img)


@case("a segment called once at a non-zero offset is restored")
def _():
    img = build(0x100, 20)
    calls = {0x000: 5, 0x100: 1, 0x200: 4}
    keep = {0x000, 0x200}
    restored = tpscan.rescue_by_strings(img, calls, keep, 0x300)
    if 0x100 not in keep:
        raise AssertionError("the real segment was not restored")
    _, mine, theirs = restored[0]
    return f"restored on {mine[0]}/{mine[1]} references against the neighbour's {theirs[0]}"


@case("a stray candidate with no strings behind it is not restored")
def _():
    img = build(0x100, 20)                 # strings belong to 0x100 ...
    calls = {0x000: 5, 0x180: 1, 0x200: 4}  # ... but 0x180 claims the span
    keep = {0x000, 0x200}
    tpscan.rescue_by_strings(img, calls, keep, 0x300)
    if 0x180 in keep:
        raise AssertionError("a candidate with no evidence was restored")
    return "refused, as it must"


@case("the wrong base scores near zero on the same references")
def _():
    img = build(0x100, 20)
    right = tpscan.string_ref_score(img, 0x100 << 4, 0x100 << 4, 0x200 << 4)
    wrong = tpscan.string_ref_score(img, 0x0C0 << 4, 0x100 << 4, 0x200 << 4)
    if right[0] < 20:
        raise AssertionError(f"the right base only scored {right[0]}")
    if wrong[0] * 3 >= right[0]:
        raise AssertionError(f"the wrong base scored {wrong[0]} against {right[0]}")
    return f"{right[0]}/{right[1]} against {wrong[0]}/{wrong[1]}"


@case("restoring one segment does not hide the next")
def _():
    # Two single-call units in a row: the second is only judgeable once the
    # first has been restored, which is why the rescue iterates.
    # Different string offsets in the two units on purpose: if both put their
    # constant at the same offset, the wrong base resolves by coincidence and
    # the check would be measuring the fixture rather than the tool.
    img = bytearray(build(0x100, 20))
    second = build(0x180, 20, string_at=0x600)
    for i in range(0x180 << 4, 0x200 << 4):
        img[i] = second[i]
    calls = {0x000: 5, 0x100: 1, 0x180: 1, 0x200: 4}
    keep = {0x000, 0x200}
    tpscan.rescue_by_strings(bytes(img), calls, keep, 0x300)
    if 0x100 not in keep or 0x180 not in keep:
        raise AssertionError(f"restored only {sorted(keep)}")
    return "both restored"


def main():
    failures = 0
    for name, fn in CASES:
        try:
            print(f"  PASS  {name:<58} {fn()}")
        except AssertionError as e:
            print(f"  FAIL  {name:<58} {e}")
            failures += 1
    print()
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    print(f"All {len(CASES)} tpscan checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
