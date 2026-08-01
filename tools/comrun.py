#!/usr/bin/env python3
"""
comrun.py -- Run a .COM under emulation and capture what it draws.

Why this exists
---------------
Everything else here reads a binary without executing it, and that discipline
is worth keeping: a screen drawn from the file alone is a claim about the file.
But it leaves one thing unmeasurable. A static reader can count what it failed
to explain; it cannot tell whether what it *did* explain is right, because it
has nothing to compare against.

That gap is not hypothetical. Hard Hat Mack's placement extraction reached
100% of the calls it reached while laying a fourteen-girder floor out as a
diagonal staircase, and the number was identical before and after the fix.

This supplies the missing reference. It runs the program, lets its start-up
code do whatever it does -- including patching its own tables, which Hard Hat
Mack does and which no amount of reading the file will reveal -- then calls a
chosen routine and dumps the framebuffer.

The static render remains the deliverable. This is the referee.

What it emulates, and what it refuses to
----------------------------------------
Enough DOS and BIOS to get a game to its first screen, and no more:

  * INT 10h  video mode set and a few calls, recorded and otherwise ignored
  * INT 21h  the handful of functions a game uses before drawing
  * INT 20h  terminate
  * IN/OUT   port reads return a value that keeps timing loops moving, writes
             are logged; there is no hardware here

It does not emulate a disk or a timer. It does emulate a keyboard, but only
because it has to: a title screen that asks for one or two players never
reaches the game otherwise, and `--call` cannot substitute, because the routine
you would call reads state that the title screen was supposed to set. Zaxxon
arrives at its game loop with an empty object table and draws a black frame
until something answers `INT 16h`.

`--keys` is that answer -- a queue consumed by `INT 16h`, one entry per read,
after which the program is told the keyboard is empty again. Each entry is
either a character (`1`) or a full `AX` as scancode:ASCII (`0x4800` for the up
arrow, which has no character at all).

Usage:
    python comrun.py GAME.COM --png screen.png
    python comrun.py GAME.COM --keys 1 --stop-at 0x3B1 --png frame.png
    python comrun.py GAME.COM --call 0x14D8 --png level1.png
    python comrun.py GAME.COM --call 0x14D8 --watch 0x217,0x268,0x2b1 \\
                              --json blits.json
"""

import argparse
import json
import struct
import sys
from pathlib import Path

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,
                         UC_HOOK_INTR, UC_HOOK_INSN, UC_PROT_ALL,
                         UcError)
    from unicorn.x86_const import (
        UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
        UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP, UC_X86_REG_SP,
        UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
        UC_X86_REG_IP, UC_X86_REG_AL, UC_X86_REG_EFLAGS,
        UC_X86_INS_IN, UC_X86_INS_OUT)
except ImportError:  # pragma: no cover
    print("comrun: unicorn is required (pip install unicorn)", file=sys.stderr)
    raise

SEG = 0x1000                    # where the program is loaded
BASE = SEG << 4
VIDEO = 0xB800 << 4             # CGA framebuffer
MEMSZ = 0x200000                # 2 MB flat, covers the program and the screen
LOAD = 0x100                    # a .COM starts here, after its PSP

# CGA mode 4 palette 1, high intensity -- the one nearly every game used.
PALETTES = {
    "0": [(0, 0, 0), (0, 170, 0), (170, 0, 0), (170, 85, 0)],
    "1": [(0, 0, 0), (85, 255, 255), (255, 85, 255), (255, 255, 255)],
}


ZF = 0x40                       # the zero flag, bit 6 of FLAGS


class Machine:
    def __init__(self, image, trace=False, keys=()):
        self.image = image
        self.trace = trace
        self.keys = list(keys)  # AX values INT 16h will hand out, in order
        self.keys_read = 0
        self.ticks = 0          # what INT 1Ah reports, one per call
        self.stop_off = None    # --stop-at, counted rather than first-hit
        self.stop_after = 1
        self.stop_hits = 0
        self.ints = []          # (int number, AH) as they were requested
        self.ports = []         # (direction, port, value)
        self.blits = []         # whatever --watch asked for
        self.watch = {}
        self.steps = 0
        self.stopped = None
        self.pending_key = None     # what port 0x60 should hand over next

        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MEMSZ, UC_PROT_ALL)
        self.uc.mem_write(BASE + LOAD, bytes(image))

        # A plausible PSP. Programs read the command tail and the exit address
        # from it, and a zero page reads as "no arguments", which is right.
        self.uc.mem_write(BASE, b"\xCD\x20" + b"\x00" * 0xFE)

        for r in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            self.uc.reg_write(r, SEG)
        self.uc.reg_write(UC_X86_REG_SP, 0xFFFE)

        self.uc.hook_add(UC_HOOK_INTR, self._on_int)
        self.uc.hook_add(UC_HOOK_INSN, self._on_in, None, 1, 0, UC_X86_INS_IN)
        self.uc.hook_add(UC_HOOK_INSN, self._on_out, None, 1, 0, UC_X86_INS_OUT)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)

    # -- hooks ---------------------------------------------------------------

    def _on_code(self, uc, addr, size, _):
        self.steps += 1
        off = addr - BASE - LOAD
        if off in self.watch:
            self.watch[off](off)
        # Stopping on the *nth* arrival, not the first, is what makes a game
        # loop inspectable: the interesting frame is rarely the opening one.
        if off == self.stop_off:
            self.stop_hits += 1
            if self.stop_hits >= self.stop_after:
                self.stopped = f"reached 0x{off:X} for the {self.stop_hits}. time"
                uc.emu_stop()

    def _on_int(self, uc, num, _):
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        self.ints.append((num, ah))
        if num == 0x20:
            self.stopped = "int 0x20"
            uc.emu_stop()
        elif num == 0x21 and ah in (0x4C, 0x00):
            self.stopped = "int 0x21 exit"
            uc.emu_stop()
        elif num == 0x1A and ah == 0x00:
            # The BIOS tick count. Answering with a constant is not "no
            # effect": `int 0x1a / cmp dl, [last] / je` is how a game waits for
            # the clock to move, and a constant makes it wait forever. Zaxxon
            # spends its whole instruction budget in that loop between the
            # title screen and the game. Advance it by one per call, for the
            # same reason the port reads alternate.
            self.ticks += 1
            uc.reg_write(UC_X86_REG_CX, self.ticks >> 16)
            uc.reg_write(UC_X86_REG_DX, self.ticks & 0xFFFF)
        elif num == 0x16 and ah in (0x00, 0x10):
            # Read a key, blocking. There is nothing to block on here, so an
            # empty queue returns zero rather than hanging.
            uc.reg_write(UC_X86_REG_AX, self.keys.pop(0) if self.keys else 0)
            self.keys_read += 1
        elif num == 0x16 and ah in (0x01, 0x11):
            # Peek. The answer is in the zero flag: set means nothing waiting.
            # Unicorn's interrupt hook does not run a real interrupt sequence,
            # so no FLAGS word is pushed and none is popped by an iret -- what
            # is written here is what the program sees.
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            if self.keys:
                uc.reg_write(UC_X86_REG_AX, self.keys[0])
                flags &= ~ZF
            else:
                flags |= ZF
            uc.reg_write(UC_X86_REG_EFLAGS, flags)
        # Everything else is acknowledged by doing nothing. Setting a video
        # mode, printing a string and reading the clock all have the same
        # effect on what we are measuring: none.

    def _on_in(self, uc, port, size, _=None):
        """Value for an IN instruction.

        Unicorn takes the *return value* of this hook as the byte read, not a
        success flag. Returning True therefore feeds 1 into every port read,
        which is not obviously wrong until a keyboard handler translates
        scancode 1 instead of the key you delivered and stores it happily.
        """
        if port == 0x60 and self.pending_key is not None:
            # The keyboard data port. A handler reads it once per interrupt,
            # so the value is consumed rather than repeated.
            v = self.pending_key
            self.pending_key = None
            self.ports.append(("in", port, v))
            return v
        # Timing loops read a port until a bit changes. Alternating the value
        # keeps them moving instead of spinning forever; a constant is how an
        # emulator hangs on 1980s code.
        self.ports.append(("in", port, None))
        return len(self.ports) & 0xFF

    def _on_out(self, uc, port, size, value, _=None):
        self.ports.append(("out", port, value))
        return True

    # -- running -------------------------------------------------------------

    def run(self, start, stop=None, budget=20_000_000):
        """Execute from a file offset until it returns, exits or runs out."""
        try:
            self.uc.emu_start(BASE + LOAD + start,
                              BASE + LOAD + stop if stop is not None
                              else BASE + 0xFFFF,
                              count=budget)
        except UcError as e:
            self.stopped = self.stopped or f"fault: {e}"
        if self.stopped is None:
            self.stopped = ("reached the stop address" if stop is not None
                            else "budget exhausted")
        return self.stopped

    def call(self, off, budget=20_000_000):
        """Call a routine and stop when it returns.

        A sentinel return address is pushed and used as the stop point, so a
        routine that returns normally ends the run rather than falling into
        whatever follows it.
        """
        sentinel = 0xFFF0
        sp = self.uc.reg_read(UC_X86_REG_SP) - 2
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.uc.mem_write(BASE + sp, struct.pack("<H", sentinel))
        self.stopped = None
        try:
            self.uc.emu_start(BASE + LOAD + off, BASE + sentinel,
                              count=budget)
        except UcError as e:
            self.stopped = self.stopped or f"fault: {e}"
        return self.stopped or "returned"

    def key(self, scancode, handler):
        """Deliver one keypress through the program's own INT 9 handler.

        Writing the translated key straight into the game's variable would be
        easier and would prove less: the handler is where the scancode is
        filtered, acknowledged and translated, and a game that reads the
        keyboard itself keeps its own idea of what is held down. So the
        interrupt is staged the way the hardware stages it -- flags, CS and the
        *current* IP pushed -- and the handler runs to its own `iret`, which
        lands execution back exactly where it was.

        Pushing a sentinel return address instead is the obvious shortcut and
        it destroys the thing you were driving: the program resumes at an
        address it never came from and faults on the first fetch.
        """
        cs = self.uc.reg_read(UC_X86_REG_CS)
        ip = self.uc.reg_read(UC_X86_REG_IP)
        self.pending_key = scancode
        sp = self.uc.reg_read(UC_X86_REG_SP)
        for word in (0x0202, cs, ip):           # FLAGS, CS, IP
            sp -= 2
            self.uc.mem_write(BASE + sp, struct.pack("<H", word))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.stopped = None
        try:
            self.uc.emu_start((cs << 4) + handler + LOAD, (cs << 4) + ip,
                              count=200_000)
        except UcError as e:
            self.stopped = f"fault in the key handler: {e}"
        return self.stopped or "handled"

    def play(self, handler, keys, slice_len=400_000, slices=40):
        """Let the program run, delivering a key between slices.

        Calling a game's routines by hand gets you a screen; it does not get
        you a game. A title loop is waiting for a keypress and the only way
        past it is to keep running and keep pressing. Execution resumes from
        wherever each slice ended, so the program follows its own control flow
        throughout -- this drives it, it does not simulate it.
        """
        for n in range(slices):
            cs = self.uc.reg_read(UC_X86_REG_CS)
            ip = self.uc.reg_read(UC_X86_REG_IP)
            self.stopped = None
            try:
                self.uc.emu_start((cs << 4) + ip, BASE + 0xFFFF,
                                  count=slice_len)
            except UcError as e:
                return f"fault after {n} slices: {e}"
            if self.stopped:
                return self.stopped
            if keys:
                self.key(keys[n % len(keys)], handler)
        return f"ran {slices} slices"

    def framebuffer(self):
        return self.uc.mem_read(VIDEO, 0x4000)

    def read(self, off, n):
        """Memory at a *file* offset -- a .COM's byte 0 lives at 0x100."""
        return self.uc.mem_read(BASE + LOAD + off, n)


def to_png(fb, path, palette="1", scale=3):
    from PIL import Image
    pal = PALETTES[palette]
    img = Image.new("RGB", (320, 200))
    px = img.load()
    for row in range(200):
        # The two banks: even scanlines at 0x0000, odd at 0x2000.
        base = (row & 1) * 0x2000 + (row >> 1) * 80
        for b in range(80):
            v = fb[base + b]
            for k in range(4):
                px[b * 4 + k, row] = pal[(v >> (6 - k * 2)) & 3]
    img.resize((320 * scale, 200 * scale), Image.NEAREST).save(path)
    return img


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--call", help="after start-up, call this file offset")
    ap.add_argument("--stop-at", help="stop the start-up run at this offset "
                                      "instead of letting it reach its budget")
    ap.add_argument("--stop-after", type=int, default=1, metavar="N",
                    help="stop on the Nth arrival at --stop-at, not the first")
    ap.add_argument("--watch", help="log calls arriving at these offsets")
    ap.add_argument("--vars", default="0x6d9b,0x6d9c,0x6d97",
                    help="variables to record at each watched call")
    ap.add_argument("--keys", help="keystrokes for INT 16h, comma separated: "
                                   "a character, or a full AX as 0xSSCC "
                                   "(scancode:ASCII)")
    ap.add_argument("--ax", help="value to put in AX before --call")
    ap.add_argument("--handler", help="INT 9 handler offset, for --scancodes")
    ap.add_argument("--scancodes",
                    help="raw scancodes to deliver through the program's own "
                         "INT 9 handler after --call, comma separated hex. "
                         "Use this for a game that reads the keyboard port "
                         "itself; --keys is for one that asks DOS or the BIOS")
    ap.add_argument("--budget", type=int, default=20_000_000)
    ap.add_argument("--png")
    ap.add_argument("--palette", default="1", choices=sorted(PALETTES))
    ap.add_argument("--json")
    ap.add_argument("--dump", help="write a memory range as OFF:LEN")
    args = ap.parse_args()

    keys = []
    for k in (args.keys.split(",") if args.keys else []):
        keys.append(int(k, 0) if k.lower().startswith("0x") else ord(k[0]))

    image = Path(args.binary).read_bytes()
    m = Machine(image, keys=keys)

    watch = [int(x, 16) for x in args.watch.split(",")] if args.watch else []
    varlist = [int(x, 16) for x in args.vars.split(",")] if args.vars else []
    if watch:
        def make(off):
            def hit(_o):
                vals = {}
                for v in varlist:
                    vals[f"{v:#06x}"] = m.read(v - 0x100, 2)[0]
                m.blits.append({"routine": f"0x{off:05X}", "vars": vals})
            return hit
        for w in watch:
            m.watch[w] = make(w)

    stop = int(args.stop_at, 16) if args.stop_at else None
    if stop is not None:
        m.stop_off, m.stop_after = stop, args.stop_after
    why = m.run(0, stop=None, budget=args.budget)
    print(f"start-up: {m.steps:,} instructions, stopped: {why}")
    print(f"  interrupts requested: "
          + ", ".join(sorted({f"{n:02X}h" for n, _ in m.ints})) or "  none")
    outs = sorted({p for d, p, _ in m.ports if d == "out"})
    if outs:
        print("  ports written: " + ", ".join(f"{p:#04x}" for p in outs))
    if args.keys:
        print(f"  keyboard: {m.keys_read} reads, {len(m.keys)} of "
              f"{len(keys)} keys unused")

    if args.call:
        if args.ax:
            m.uc.reg_write(UC_X86_REG_AX, int(args.ax, 0))
        before = m.steps
        why = m.call(int(args.call, 16), budget=args.budget)
        print(f"call {args.call}: {m.steps - before:,} instructions, {why}")

    if args.scancodes and args.handler:
        h = int(args.handler, 16)
        for k in args.scancodes.split(","):
            why = m.key(int(k, 16), h)
            print(f"key {k}: {why}")

    if m.blits:
        print(f"\n{len(m.blits)} watched calls")
        for b in m.blits[:10]:
            print(f"  {b['routine']}  "
                  + "  ".join(f"[{k}]={v}" for k, v in b["vars"].items()))
        if len(m.blits) > 10:
            print(f"  ... {len(m.blits) - 10} more")

    if args.dump:
        off, n = args.dump.split(":")
        data = bytes(m.read(int(off, 16), int(n, 0)))
        print(f"\nmemory at {off}, {n} bytes:")
        print("  " + data.hex(" "))

    if args.png:
        to_png(m.framebuffer(), args.png, args.palette)
        print(f"\nwrote {args.png}")
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"stopped": why, "steps": m.steps, "blits": m.blits}, indent=2),
            encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
