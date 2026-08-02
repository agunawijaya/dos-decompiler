#!/usr/bin/env python3
"""Checks for comrun's keyboard, and for --poll-patience in particular.

The case that motivated these: a queue of keystrokes meant to drive a whole
game vanished in a single screen. The Oregon Trail consumed 88 keys in 88
reads without ever pausing, because Turbo Pascal opens most prompts with

    while KeyPressed do ReadKey;        { throw away type-ahead }

and an emulator that answers "yes, a key is waiting" hands the flush loop the
entire queue. Answering "no" instead breaks the opposite idiom,

    repeat until KeyPressed;            { wait for the player }

which then spins for ever. Both loops ask the same question and want opposite
answers, so no fixed answer is right.

What separates them is persistence: a flush asks a few times and gives up, a
wait asks until the answer changes. --poll-patience answers "nothing waiting"
until the question has been repeated N times since the last real read. These
build both loops as tiny .COM programs and check each one gets what it needs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import comrun                                                # noqa: E402

CASES = []
KEY = 0x41                       # what INT 16h hands out, and what we look for
WHERE = 0x0200                   # where the program stores what it read


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


# Both programs end in `jmp $`, so the run stops on the budget rather than on
# an exit; 200,000 instructions is far more than either needs and far less
# than a spin would consume before the test noticed.
FLUSH = bytes((
    0xB4, 0x01, 0xCD, 0x16,      # 0100  mov ah,1 / int 16h   -- KeyPressed
    0x74, 0x06,                  # 0104  jz 010C              -- nothing there
    0xB4, 0x00, 0xCD, 0x16,      # 0106  mov ah,0 / int 16h   -- eat it
    0xEB, 0xF4,                  # 010A  jmp 0100
    0xB4, 0x00, 0xCD, 0x16,      # 010C  mov ah,0 / int 16h   -- the real read
    0xA3, 0x00, 0x02,            # 0110  mov [0200], ax
    0xEB, 0xFE,                  # 0113  jmp $
))

WAIT = bytes((
    0xB4, 0x01, 0xCD, 0x16,      # 0100  mov ah,1 / int 16h   -- KeyPressed
    0x74, 0xFA,                  # 0104  jz 0100              -- keep waiting
    0xB4, 0x00, 0xCD, 0x16,      # 0106  mov ah,0 / int 16h   -- then read
    0xA3, 0x00, 0x02,            # 010A  mov [0200], ax
    0xEB, 0xFE,                  # 010D  jmp $
))


def run(image, patience=None, budget=200_000):
    m = comrun.Machine(image, keys=[KEY])
    if patience is not None:
        m.poll_patience = patience
    m.run(budget=budget)
    got = int.from_bytes(m.uc.mem_read(comrun.BASE + WHERE, 2), "little")
    return got, m


@case("a flush loop swallows the queue when every poll says yes")
def _():
    got, m = run(FLUSH)
    if got == KEY:
        raise AssertionError("the fixture does not reproduce the bug at all")
    if got != 0:
        raise AssertionError(f"expected nothing to be read, got {got:#06x}")
    return f"read {m.keys_read} keys, stored nothing -- the bug, reproduced"


@case("--poll-patience gets the key past the flush loop")
def _():
    got, _ = run(FLUSH, patience=8)
    if got != KEY:
        raise AssertionError(f"the key did not survive the flush: {got:#06x}")
    return f"stored {got:#04x}"


@case("a wait loop still terminates under --poll-patience")
def _():
    got, _ = run(WAIT, patience=8)
    if got != KEY:
        raise AssertionError(
            "the wait loop never saw a key -- patience starved it")
    return f"waited, then stored {got:#04x}"


@case("patience is off by default, so old runs are unchanged")
def _():
    m = comrun.Machine(b"\xEB\xFE", keys=[KEY])
    if m.poll_patience is not None:
        raise AssertionError(f"default patience is {m.poll_patience}, not None")
    return "None"


@case("the poll counter is reset by a real read, not by the run")
def _():
    # Otherwise the first prompt would be patient and every later one would
    # not, which is the shape of bug that looks like flaky input.
    _, m = run(WAIT, patience=8)
    if m.polls != 0:
        raise AssertionError(f"polls left at {m.polls} after a blocking read")
    return "reset to 0"


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
    print(f"All {len(CASES)} comrun checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
