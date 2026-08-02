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
import struct
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


# A program that waits on a word only an interrupt handler ever changes. This
# is The Oregon Trail's hunting loop in miniature: it hooks the timer, its
# handler increments a counter, and the game spins until the counter moves.
# Ticking 0040:006C does nothing for it, because nothing reads 0040:006C.
SPIN = bytes((
    0x83, 0x3E, 0x00, 0x02, 0x00,   # 0100  cmp word [0200], 0
    0x74, 0xF9,                     # 0105  je 0100
    0xEB, 0xFE,                     # 0107  jmp $
)) + bytes(0x17) + bytes((
    0xFF, 0x06, 0x00, 0x02,         # 0120  inc word [0200]
    0xCF,                           # 0124  iret
))


TIMER = 0x1C                     # the BIOS user timer tick


def spin_run(with_isr, budget=200_000, hooked=True):
    m = comrun.Machine(SPIN)
    if hooked:
        # What the program itself would do: put the handler in the vector.
        m.uc.mem_write(TIMER * 4,
                       struct.pack("<HH", comrun.LOAD + 0x20, comrun.SEG))
    if with_isr:
        m.isr_vector = TIMER
        m.isr_every = 5_000
    m.run(budget=budget)
    counter = int.from_bytes(m.uc.mem_read(comrun.BASE + 0x200, 2), "little")
    return counter, m


@case("a program waiting on its own timer handler spins for ever")
def _():
    counter, m = spin_run(with_isr=False)
    if counter:
        raise AssertionError("the counter moved with no handler running")
    return "counter 0, as the bug behaves"


@case("--timer-isr delivers the interrupt and the wait ends")
def _():
    counter, m = spin_run(with_isr=True)
    if counter == 0:
        raise AssertionError("the handler never ran")
    if m.isr_fired == 0:
        raise AssertionError("isr_fired was not counted")
    return f"counter {counter}, {m.isr_fired} interrupts delivered"


@case("the iret frame resumes the interrupted instruction")
def _():
    # If FLAGS/CS/IP were pushed in the wrong order the iret returns to
    # rubbish, and the give-away is that the program never reaches its
    # jmp $ -- so check the counter stopped growing once it escaped.
    counter, m = spin_run(with_isr=True, budget=400_000)
    ip = m.uc.reg_read(comrun.UC_X86_REG_IP)
    if ip != 0x107:
        raise AssertionError(f"resumed wrong: IP is {ip:#06x}, not 0x0107")
    return "back at jmp $, so the frame was correct"


@case("nothing is delivered until the program hooks the vector")
def _():
    # The Oregon Trail ships packed. Twenty thousand instructions in, the
    # handler's address still holds compressed bytes, and an earlier version
    # that took an address rather than an interrupt number jumped into them:
    # 99,999 interrupts delivered, no interrupts requested, no ports written,
    # no keys read, and a run that left the image.
    counter, m = spin_run(with_isr=True, hooked=False)
    if m.isr_fired:
        raise AssertionError(
            f"{m.isr_fired} interrupts sent to an unhooked vector")
    if counter:
        raise AssertionError("the counter moved with no handler installed")
    return "0 delivered, as it must be"


@case("a handler below the interrupted segment is entered correctly")
def _():
    """The geometry that actually breaks, and it took a second attempt to find.

    An earlier fixture put the handler in a segment *above* the code it
    interrupted and passed whether or not comrun moved CS with the jump --
    a check that cannot fail, wearing the name of a guard. This one puts the
    interrupted code at 2000:0000 and the handler at 1000:0130, which is the
    real program's arrangement: the handler's linear address is BELOW the
    interrupted CS base, so leaving CS alone underflows Unicorn's EIP and
    the handler never runs. The counter stays at zero and execution wanders
    out of the image -- which is what The Oregon Trail did, at 26,900,030
    instructions, every time.
    """
    HIGH = 0x2000
    m = comrun.Machine(bytes((0xEB, 0xFE)))
    m.uc.mem_write(HIGH << 4, bytes((
        0x83, 0x3E, 0x00, 0x02, 0x00,   # cmp word [0200], 0
        0x74, 0xF9,                     # je  back  -- wait for the handler
        0xEB, 0xFE)))                   # jmp $     -- escaped
    m.uc.mem_write(comrun.BASE + 0x130, bytes((
        0xFF, 0x06, 0x00, 0x02,         # inc word [0200]
        0xCF)))                         # iret
    m.uc.mem_write(TIMER * 4, struct.pack("<HH", 0x130, comrun.SEG))
    for r in (comrun.UC_X86_REG_DS, comrun.UC_X86_REG_SS):
        m.uc.reg_write(r, comrun.SEG)
    m.uc.reg_write(comrun.UC_X86_REG_CS, HIGH)
    m.uc.reg_write(comrun.UC_X86_REG_SP, 0xFFFE)
    m.isr_vector, m.isr_every = TIMER, 3_000
    m.run(start=(HIGH << 4) - comrun.BASE - comrun.LOAD, budget=60_000)

    counter = int.from_bytes(m.uc.mem_read(comrun.BASE + 0x200, 2), "little")
    if counter == 0:
        raise AssertionError(
            "the handler never incremented -- CS did not move with the jump")
    if m.uc.reg_read(comrun.UC_X86_REG_IP) != 0x0007:
        raise AssertionError("the program did not escape its wait loop")
    return f"counter {counter}, escaped to jmp $"


@case("no timer ISR by default")
def _():
    m = comrun.Machine(b"\xEB\xFE")
    if m.isr_vector is not None:
        raise AssertionError(f"default vector is {m.isr_vector}")
    return "None"


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
