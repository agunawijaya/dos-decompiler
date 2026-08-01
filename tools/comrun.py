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

It does not emulate a keyboard, a disk or a timer. A program that waits for
input will sit in its loop until the instruction budget runs out, which is why
`--call` exists: run the start-up, then jump straight to the routine you want
to see.

Usage:
    python comrun.py GAME.COM --png screen.png
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
        UC_X86_REG_IP, UC_X86_REG_AL, UC_X86_INS_IN, UC_X86_INS_OUT)
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


class Machine:
    def __init__(self, image, trace=False):
        self.image = image
        self.trace = trace
        self.ints = []          # (int number, AH) as they were requested
        self.ports = []         # (direction, port, value)
        self.blits = []         # whatever --watch asked for
        self.watch = {}
        self.steps = 0
        self.stopped = None

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

    def _on_int(self, uc, num, _):
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        self.ints.append((num, ah))
        if num == 0x20:
            self.stopped = "int 0x20"
            uc.emu_stop()
        elif num == 0x21 and ah in (0x4C, 0x00):
            self.stopped = "int 0x21 exit"
            uc.emu_stop()
        # Everything else is acknowledged by doing nothing. Setting a video
        # mode, printing a string and reading the clock all have the same
        # effect on what we are measuring: none.

    def _on_in(self, uc, port, size, _=None):
        # Timing loops read a port until a bit changes. Alternating the value
        # each time keeps them moving instead of spinning forever; returning a
        # constant is how an emulator hangs on 1980s code.
        self.ports.append(("in", port, None))
        uc.reg_write(UC_X86_REG_AL, len(self.ports) & 0xFF)
        return True

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
    ap.add_argument("--watch", help="log calls arriving at these offsets")
    ap.add_argument("--vars", default="0x6d9b,0x6d9c,0x6d97",
                    help="variables to record at each watched call")
    ap.add_argument("--ax", help="value to put in AX before --call")
    ap.add_argument("--budget", type=int, default=20_000_000)
    ap.add_argument("--png")
    ap.add_argument("--palette", default="1", choices=sorted(PALETTES))
    ap.add_argument("--json")
    ap.add_argument("--dump", help="write a memory range as OFF:LEN")
    args = ap.parse_args()

    image = Path(args.binary).read_bytes()
    m = Machine(image)

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
    why = m.run(0, stop=stop, budget=args.budget)
    print(f"start-up: {m.steps:,} instructions, stopped: {why}")
    print(f"  interrupts requested: "
          + ", ".join(sorted({f"{n:02X}h" for n, _ in m.ints})) or "  none")
    outs = sorted({p for d, p, _ in m.ports if d == "out"})
    if outs:
        print("  ports written: " + ", ".join(f"{p:#04x}" for p in outs))

    if args.call:
        if args.ax:
            m.uc.reg_write(UC_X86_REG_AX, int(args.ax, 0))
        before = m.steps
        why = m.call(int(args.call, 16), budget=args.budget)
        print(f"call {args.call}: {m.steps - before:,} instructions, {why}")

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
