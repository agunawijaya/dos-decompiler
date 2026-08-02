#!/usr/bin/env python3
"""
comrun.py -- Run a DOS program under emulation and capture what it draws.

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

What it loads
-------------
`.COM` and MZ. An MZ needs a loader rather than a memcpy -- the header says
where the image ends, every relocation entry names a segment word that has the
load segment added to it, and CS:IP and SS:SP come from the header. Skipping
any of that gives a program that starts and then behaves inexplicably.

It also answers enough of DOS to reach a first screen: the version, memory
allocation, and file open/read/seek/close against `--files`. That last one is
not a nicety. Karateka keeps its artwork in ninety files beside the
executable, and a game that cannot find its data does not fail loudly -- it
prints a line and exits, which looks exactly like a harness bug.

Compiled languages need more than a game written in assembly does, because
their runtimes ask DOS questions a game never would. A Turbo Pascal program's
`Dos` unit reaches for the directory search calls, the clock, the file
timestamp and the drive-is-remote IOCTL before it draws anything, so those are
answered too -- The Oregon Trail checks a licence file's age against the clock
on its fourth statement.

And it fills in the interrupt vector table, which matters more than it sounds.
Trapping the `int` instruction only catches programs that use it; Turbo
Pascal's `MsDos` and `Intr` read the vector out of the table and far-call it
instead. Against a zeroed table that is a call to 0000:0000, and the program
wanders off without ever raising an interrupt anyone could see. Every vector
points at an `int n` / `iret` stub, so both routes arrive at the same place.

Usage:
    python comrun.py GAME.COM --png screen.png
    python comrun.py GAME.EXE --files . --png screen.png
    python comrun.py GAME.COM --keys 1 --stop-at 0x3B1 --png frame.png
    python comrun.py GAME.COM --call 0x14D8 --png level1.png
    python comrun.py GAME.COM --call 0x14D8 --watch 0x217,0x268,0x2b1 \\
                              --json blits.json
"""

import argparse
import json
import struct
import sys
from fnmatch import fnmatch
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
STUBS = 0x0F000                 # interrupt stubs, just below the program

# CGA mode 4 palette 1, high intensity -- the one nearly every game used.
PALETTES = {
    "0": [(0, 0, 0), (0, 170, 0), (170, 0, 0), (170, 85, 0)],
    "1": [(0, 0, 0), (85, 255, 255), (255, 85, 255), (255, 255, 255)],
}


ZF = 0x40                       # the zero flag, bit 6 of FLAGS
IF = 0x200                      # the interrupt flag, bit 9 -- see _fire_isr
CF = 0x01                       # the carry flag -- DOS's error flag

# One fixed timestamp for every file, packed the way DOS packs them: the date
# is (year-1980)<<9 | month<<5 | day and the time is hour<<11 | minute<<5 |
# second/2. It must agree with what INT 21h AH=2Ah and AH=2Ch report, because
# programs compare the two -- The Oregon Trail decides whether a network
# licence is stale by subtracting a file's timestamp from the clock, and a
# harness whose clock disagrees with its filesystem answers that question at
# random.
DOS_DATE = ((1990 - 1980) << 9) | (6 << 5) | 1          # 1 June 1990
DOS_TIME = (10 << 11) | (30 << 5) | 0                   # 10:30:00


def mz_header(data):
    """The fields a loader needs, or None if this is not an MZ."""
    if len(data) < 0x20 or data[:2] not in (b"MZ", b"ZM"):
        return None
    last, pages, nreloc, hdr_paras = struct.unpack_from("<HHHH", data, 2)
    minalloc = struct.unpack_from("<H", data, 10)[0]
    ss, sp, _, ip, cs, reloc = struct.unpack_from("<HHHHHH", data, 14)
    hdr = hdr_paras * 16
    end = (pages - 1) * 512 + (last or 512)
    if not (0 < hdr <= len(data)):
        return None
    return {"hdr": hdr, "end": min(end, len(data)), "nreloc": nreloc,
            "reloc": reloc, "cs": cs, "ip": ip, "ss": ss, "sp": sp,
            "minalloc": minalloc}


class Machine:
    def __init__(self, image, trace=False, keys=(), files=None):
        self.image = image
        # Image offsets are `flat - BASE - LOAD` for both .COM and MZ, because
        # this loader places an MZ image after the PSP as well.
        #
        # A note against repeating a mistake: this was "corrected" once to
        # `BASE` for MZ, on the theory that an MZ image starts at BASE and the
        # extra 0x100 was why --stop-at never fired on a hunting routine. Both
        # halves were wrong. --stop-at never fired because the routine returns
        # before reaching that address, and the change dropped the agreement
        # between a listing and an execution trace from 99.6% to 31.6%. The
        # 31.6% run is the one that identified the error: its unmatched
        # addresses were all exactly 0x100 above decoded ones.
        self.img_bias = BASE + LOAD
        self.trace = trace
        self.keys = list(keys)  # AX values INT 16h will hand out, in order
        self.keys_read = 0
        # Polls of INT 16h AH=01 since the last blocking read, and how many to
        # answer "nothing waiting" before admitting there is. None disables it
        # and restores the old behaviour, which is right for a game with no
        # flush loops. See the AH=01 handler for why this exists.
        self.polls = 0
        self.poll_patience = None
        # The interrupt NUMBER to deliver periodically, and how often. None
        # means do not -- right for a program that reads 0040:006C rather than
        # hooking the vector. A number, not an address, so that nothing is
        # delivered until the program has installed a handler. See _fire_isr.
        self.isr_vector = None
        self.isr_every = 20_000
        self.isr_fired = 0
        self.isr_masked = 0     # deliveries skipped because IF was clear
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
        self.recent = [0] * 512
        # Every image offset the program actually executed. Off by
        # default: a set with a million entries costs real time, and
        # it is only wanted when something is being checked against
        # a static reading.
        self.exec_map = None
        # ADDR -> [AX, ...]: keys handed over only when the program reaches a
        # chosen instruction. `--keys` alone is a blind queue, and a game that
        # polls the keyboard eats it: The Oregon Trail issues 81,665 INT 16h
        # reads while consuming 73 queued keys, so a sequence meant for its
        # prompts is swallowed by an animation loop long before the prompt
        # appears. Triggering on an address puts the key where it is wanted.
        self.at_keys = {}
        # A gated queue: keys wait here and one is released whenever execution
        # reaches any address in `self.gates`. --at ties a key to one place;
        # this ties the whole sequence to "wherever the program actually reads
        # a key", which is what you want when a program has nine such places
        # and polls the keyboard tens of thousands of times between them.
        self.gates = set()
        self.gated = []
        self.gate_every = 400_000        # instructions between releases
        self.last_release = 0
        # Every file read, when asked for. A short read is a silent failure in
        # a program that checks the byte count: Genus's container reader treats
        # 83 bytes where it asked for 84 as a corrupt archive and returns an
        # error its caller turns into a blank screen.
        # Addresses at which to dump DS:SI and ES:DI. A watch that only reads
        # globals cannot see a string being compared on the stack, which is
        # where the interesting ones live.
        self.ptr_watch = {}
        self.trace_io = False
        self.io_log = []
        self.pending_key = None     # what port 0x60 should hand over next
        self.files = Path(files) if files else None
        self.open_files = {}        # handle -> [bytes, position, name]
        self.next_handle = 5        # 0-4 are the standard ones
        # Where INT 21h AH=48 hands out memory. This is set properly once the
        # image is loaded; a fixed 0x4000 was fine while every program here was
        # a .COM under 64 KB, and quietly wrong for anything larger. The
        # Oregon Trail unpacks to 201 KB, so DOS was handing its font library a
        # buffer that overlapped the program's own stack, and the corruption
        # only surfaced 1.16 million instructions later as a `retf` to nowhere.
        self.next_para = 0x4000
        self.file_reads = []        # what the program opened
        self.file_misses = []       # and what it looked for and did not find
        self.dta = BASE + 0x80
        self.find_pending = []      # what FindNext still has to hand back
        self.output = []            # whatever the program printed

        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MEMSZ, UC_PROT_ALL)
        # A plausible PSP. Mostly zero is right -- no command tail, no
        # arguments -- but two words are not optional.
        #
        # PSP+2 is the segment one past the memory DOS gave the program,
        # and a zero there means it was given none. Karateka reads it,
        # prints "Insufficient memory" and exits twenty-three instructions
        # in. That is not a crash and does not look like a bug in the
        # harness; it looks like a game that refuses to run.
        psp = bytearray(0x100)
        psp[0:2] = b"\xCD\x20"          # int 20h, the ancient exit path
        psp[2:4] = struct.pack("<H", 0x9FFF)   # top of a 640 KB machine
        psp[0x2C:0x2E] = struct.pack("<H", 0)  # no environment
        self.uc.mem_write(BASE, bytes(psp))

        # An interrupt vector table that points somewhere.
        #
        # Trapping the `int` instruction is not enough, because not every
        # program uses it. Turbo Pascal's `MsDos` and `Intr` read the vector
        # out of the table and *far-call it*:
        #
        #     lds bx, [bx]        ; the handler, from 0000:0084 for INT 21h
        #     push ds / push bx   ; and call it, with flags already pushed
        #
        # With a zeroed table that is a call to 0000:0000, and the program
        # disappears into the interrupt vector table itself. The Oregon Trail
        # does this on its fourth statement and the run ends in `int 20h`
        # 1.17 million instructions later, looking for all the world like a
        # program that decided not to start.
        #
        # So every vector gets a two-instruction stub -- `int n` then `iret` --
        # in the paragraph below the program. Reached by `int`, the stub is
        # never used; reached by a far call, it raises the interrupt the
        # normal way and returns through the frame the caller pushed, which is
        # already an iret frame because it pushed the flags first.
        self.uc.mem_write(STUBS, b"".join(
            bytes([0xCD, n, 0xCF, 0x90]) for n in range(256)))
        self.uc.mem_write(0, b"".join(
            struct.pack("<HH", n * 4, STUBS >> 4) for n in range(256)))

        self.mz = mz_header(image)
        if self.mz is None:
            # A .COM: the whole file is the image and it runs from 0x100, with
            # every segment register pointing at the PSP.
            self.uc.mem_write(BASE + LOAD, bytes(image))
            for r in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                      UC_X86_REG_SS):
                self.uc.reg_write(r, SEG)
            self.uc.reg_write(UC_X86_REG_SP, 0xFFFE)
            self.next_para = SEG + ((len(image) + 0xFFF) >> 4)
            self._enable_interrupts()
        else:
            self._load_mz(image, self.mz)
            self._enable_interrupts()
            # Above the block DOS would have given the program: the image plus
            # whatever `minalloc` demanded, which for a packed file covers the
            # room the decompressor needs.
            span = self.mz["end"] - self.mz["hdr"] + self.mz.get("minalloc", 0) * 16
            self.next_para = SEG + ((span + 0xFFF) >> 4)

        self.uc.hook_add(UC_HOOK_INTR, self._on_int)
        self.uc.hook_add(UC_HOOK_INSN, self._on_in, None, 1, 0, UC_X86_INS_IN)
        self.uc.hook_add(UC_HOOK_INSN, self._on_out, None, 1, 0, UC_X86_INS_OUT)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)

    def _load_mz(self, image, h):
        """Load an MZ the way DOS does, relocations and all.

        A `.COM` needs no loader: the file is the image, it goes at 0x100, and
        every segment register points at the PSP. An MZ needs four things done
        to it, and skipping any of them gives a program that starts and then
        behaves inexplicably rather than one that fails:

          * the load image is the file minus its header, and no more -- the
            page count and last-page size say where it ends, and anything after
            is the linker's or the packer's, not the program's;
          * every entry in the relocation table names a word holding a segment
            that was written as if the program loaded at zero. Each one has the
            real load segment added to it. Miss this and far calls go to
            wherever the program would have been on a machine that does not
            exist;
          * CS:IP and SS:SP come from the header, not from convention;
          * DS and ES point at the PSP, which is one paragraph *before* the
            image. Programs read the command tail through them and set DS
            themselves when they are ready.
        """
        hdr, end, nreloc, reloc_off = h["hdr"], h["end"], h["nreloc"], h["reloc"]
        load = SEG + (LOAD >> 4)          # the image sits after the PSP
        body = image[hdr:end]
        self.uc.mem_write(BASE + LOAD, bytes(body))

        for k in range(nreloc):
            off, seg = struct.unpack_from("<HH", image, reloc_off + k * 4)
            at = ((load + seg) << 4) + off
            cur = struct.unpack_from("<H", bytes(self.uc.mem_read(at, 2)), 0)[0]
            self.uc.mem_write(at, struct.pack("<H", (cur + load) & 0xFFFF))

        self.uc.reg_write(UC_X86_REG_CS, (load + h["cs"]) & 0xFFFF)
        self.uc.reg_write(UC_X86_REG_IP, h["ip"])
        self.uc.reg_write(UC_X86_REG_SS, (load + h["ss"]) & 0xFFFF)
        self.uc.reg_write(UC_X86_REG_SP, h["sp"])
        self.uc.reg_write(UC_X86_REG_DS, SEG)
        self.uc.reg_write(UC_X86_REG_ES, SEG)
        self.mz_entry = (h["cs"] << 4) + h["ip"]

    # -- hooks ---------------------------------------------------------------

    # The BIOS keeps its 18.2 Hz tick count at 0040:006C, and a game that wants
    # to wait reads it there rather than asking through INT 1Ah -- reading two
    # words is cheaper than an interrupt. Karateka spins on it in its start-up:
    #
    #     xor ax, ax / mov ds, ax / mov bx, 0x46c
    #     mov si, [bx] / inc si
    #     .wait: cmp si, [bx] / jne .wait
    #
    # Answering INT 1Ah is not enough, because nothing here asks. Leave the
    # counter at zero and the program waits for a tick that never comes: no
    # crash, no message, a black screen and the whole instruction budget spent
    # on two instructions.
    TICK_EVERY = 20_000

    def _on_code(self, uc, addr, size, _):
        self.steps += 1
        # A ring of the last few addresses. A fault reports where it landed;
        # what you need is where it came from, and by then the registers no
        # longer say. Sixteen entries is enough to see the far call that did it.
        self.recent[self.steps & 511] = addr
        if self.exec_map is not None:
            self.exec_map.add(addr - self.img_bias)
        if self.steps % self.TICK_EVERY == 0:
            self.ticks += 1
            uc.mem_write(0x46C, struct.pack("<I", self.ticks))
        off = addr - self.img_bias
        if off in self.ptr_watch:
            def rd(seg, ofs, n=16):
                try:
                    return bytes(uc.mem_read((seg << 4) + ofs, n))
                except UcError:
                    return b""
            ds = uc.reg_read(UC_X86_REG_DS)
            es = uc.reg_read(UC_X86_REG_ES)
            si = uc.reg_read(UC_X86_REG_SI)
            di = uc.reg_read(UC_X86_REG_DI)
            self.io_log.append(
                f"at {off:#07x}  DS:SI={ds:04X}:{si:04X} {rd(ds, si)!r}"
                f"  ES:DI={es:04X}:{di:04X} {rd(es, di)!r}")
            self.ptr_watch[off] -= 1
            if self.ptr_watch[off] <= 0:
                del self.ptr_watch[off]

        if self.gated and off in self.gates:
            self.keys.append(self.gated.pop(0))
            self._sync_kbd()
        elif (self.gated and not self.keys and not self.gates
                and self.steps - self.last_release > self.gate_every):
            # No gates named: make a key available at a steady interval and
            # let the program take it when it next looks.
            #
            # When gates *are* named, none of these fallbacks fire, and that is
            # essential rather than tidy. A prompt commonly begins by draining
            # the keyboard -- `while KeyPressed do ReadKey` -- to throw away
            # anything typed ahead. A harness that hands out a key whenever the
            # queue runs dry feeds that loop for ever and the screen never
            # advances, which is exactly how The Oregon Trail's landmark
            # screens looked for eleven attempts.
            self.last_release = self.steps
            self.keys.append(self.gated.pop(0))
            self._sync_kbd()
        pending = self.at_keys.get(off)
        if pending:
            self.keys.append(pending.pop(0))
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
        elif num == 0x21:
            self._dos(uc, ah)
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
            # And on a blocking read too. A screen that calls ReadKey without
            # polling first would otherwise wait for ever: the gate fires on
            # the poll, and there is no poll.
            if not self.keys and self.gated and not self.gates:
                self.keys.append(self.gated.pop(0))
            self._sync_kbd()
            # Read a key, blocking. There is nothing to block on here, so an
            # empty queue returns zero rather than hanging.
            uc.reg_write(UC_X86_REG_AX, self.keys.pop(0) if self.keys else 0)
            self.keys_read += 1
            self.polls = 0
        elif num == 0x16 and ah in (0x01, 0x11):
            # Release one gated key when the program *asks whether* a key is
            # waiting, not when it reads one. Gating on the read alone
            # deadlocks any `repeat until KeyPressed` loop: the poll never sees
            # a key, so the read is never reached, so the key is never
            # released. Releasing on an empty queue gives exactly one key per
            # read, which is what a prompt expects.
            if not self.keys and self.gated:
                self.keys.append(self.gated.pop(0))
            # Peek. The answer is in the zero flag: set means nothing waiting.
            # Unicorn's interrupt hook does not run a real interrupt sequence,
            # so no FLAGS word is pushed and none is popped by an iret -- what
            # is written here is what the program sees.
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            # Two loops ask this question and they want opposite answers.
            #
            #   while KeyPressed do ReadKey;      { throw away type-ahead }
            #   repeat until KeyPressed;          { wait for the player }
            #
            # Answering "yes, a key is waiting" satisfies the second and is
            # eaten by the first, which is why a queue meant for a whole game
            # vanishes in one screen: The Oregon Trail consumed 88 keys in 88
            # reads without ever pausing. Answering "no" does the reverse and
            # hangs the wait.
            #
            # What separates them is persistence. A flush asks a handful of
            # times and gives up; a wait asks until the answer changes. So say
            # no until the question has been repeated `poll_patience` times
            # since the last real read, then say yes. The threshold is a
            # measurement of the program's behaviour, not of ours -- if a game
            # flushed with a longer loop than it waits with, this would be the
            # wrong way round, and the symptom would be visible as keys
            # disappearing again.
            self.polls += 1
            if self.poll_patience is not None and self.polls < self.poll_patience:
                uc.reg_write(UC_X86_REG_EFLAGS, flags | ZF)
                return
            if self.keys:
                uc.reg_write(UC_X86_REG_AX, self.keys[0])
                flags &= ~ZF
            else:
                flags |= ZF
            uc.reg_write(UC_X86_REG_EFLAGS, flags)
        # Everything else is acknowledged by doing nothing. Setting a video
        # mode, printing a string and reading the clock all have the same
        # effect on what we are measuring: none.

    # ---------------------------------------------------------------- DOS
    #
    # Enough of INT 21h to get a game with external data files to its first
    # screen. Karateka needs it: ninety data files beside the executable, and
    # without file I/O the program reaches its first `open` and stops being a
    # game. Answering "no such file" is not neutral either -- a game that
    # cannot find its artwork usually prints a message and exits, which looks
    # exactly like a program that crashed.
    #
    # Carry is the error flag throughout: clear for success, set for failure
    # with the code in AX. Unicorn's interrupt hook does not push or pop FLAGS,
    # so whatever is written here is what the program reads.

    def _fail(self, uc, code):
        uc.reg_write(UC_X86_REG_AX, code)
        uc.reg_write(UC_X86_REG_EFLAGS,
                     uc.reg_read(UC_X86_REG_EFLAGS) | CF)

    def _ok(self, uc, ax=0):
        uc.reg_write(UC_X86_REG_AX, ax)
        uc.reg_write(UC_X86_REG_EFLAGS,
                     uc.reg_read(UC_X86_REG_EFLAGS) & ~CF)

    def _str_at(self, uc, seg, off, limit=128):
        addr = (seg << 4) + off
        raw = bytes(uc.mem_read(addr, limit))
        return raw.split(b"\x00")[0].decode("latin-1")

    def _resolve(self, name):
        r"""A DOS path, against the directory the game's files are in.

        Case matters here and does not on DOS, so the match is case-insensitive
        and the drive and directory parts are dropped: a game that opens
        `C:\KARATEKA\KM0.DAT` means the file called KM0.DAT.
        """
        if self.files is None:
            return None
        leaf = name.replace("/", "\\").split("\\")[-1].strip().upper()
        for f in self.files.iterdir():
            if f.is_file() and f.name.upper() == leaf:
                return f
        return None

    def _find(self, pattern):
        """The files a DOS `FindFirst` pattern matches, in directory order.

        Only the leaf is used, for the same reason `_resolve` drops the path:
        a program that searches `C:\\OT\\*.PCL` means the .PCL files in the
        directory it was given.
        """
        if self.files is None:
            return []
        leaf = pattern.replace("/", "\\").split("\\")[-1].strip().upper()
        return sorted(
            (f for f in self.files.iterdir()
             if f.is_file() and fnmatch(f.name.upper(), leaf or "*.*")),
            key=lambda f: f.name.upper())

    def _write_dta(self, uc, path):
        """Fill the disk transfer area with one DOS directory entry.

        21 reserved bytes, then attribute, time, date, size and an ASCIIZ name.
        Turbo Pascal's `SearchRec` is laid over this same 43 bytes, which is why
        its `Fill` field is exactly 21 long and its `Time` is a `LongInt`: the
        time and date words are adjacent and it reads both at once.
        """
        entry = (b"\x00" * 21
                 + bytes([0x20])                        # archive
                 + struct.pack("<HH", DOS_TIME, DOS_DATE)
                 + struct.pack("<I", path.stat().st_size)
                 + path.name.upper().encode("ascii", "replace")[:12] + b"\x00")
        uc.mem_write(self.dta, entry)

    # The BIOS keyboard buffer, at 0040:001A onward. Turbo Pascal's Crt unit
    # does not call INT 16h to answer KeyPressed -- it compares the buffer's
    # head and tail pointers in the BIOS data area directly. A harness that
    # only answers the interrupt is invisible to it, and any `repeat until
    # KeyPressed` loop waits for ever. The Oregon Trail sits on its landmark
    # screens exactly that way.
    KB_HEAD, KB_TAIL, KB_BUF = 0x41A, 0x41C, 0x41E

    def _sync_kbd(self):
        """Make the BIOS buffer agree with the queue: one key waiting, or none."""
        if self.keys:
            self.uc.mem_write(self.KB_BUF, struct.pack("<H", self.keys[0]))
            self.uc.mem_write(self.KB_HEAD, struct.pack("<H", 0x1E))
            self.uc.mem_write(self.KB_TAIL, struct.pack("<H", 0x20))
        else:
            self.uc.mem_write(self.KB_HEAD, struct.pack("<H", 0x1E))
            self.uc.mem_write(self.KB_TAIL, struct.pack("<H", 0x1E))


    def _dos(self, uc, ah):
        ax = uc.reg_read(UC_X86_REG_AX)
        ds = uc.reg_read(UC_X86_REG_DS)
        dx = uc.reg_read(UC_X86_REG_DX)

        if ah == 0x09:                      # print a $-terminated string
            # Worth capturing rather than ignoring: when a game refuses to run,
            # this is where it says why, and the message is usually the fastest
            # route to the reason.
            raw = bytes(uc.mem_read((ds << 4) + dx, 512))
            self.output.append(raw.split(b"$")[0].decode("latin-1"))
            return
        if ah == 0x02:                      # print one character
            self.output.append(chr(uc.reg_read(UC_X86_REG_DX) & 0xFF))
            return
        if ah in (0x06, 0x07, 0x08, 0x0B):
            # Console I/O. AH=06h with DL=FF is the classic non-blocking key
            # check: a character in AL with ZF clear, or nothing with ZF set.
            #
            # Answering it as a generic success is worse than not answering at
            # all. Karateka's start-up is `call check_key / jne again`, so a
            # handler that leaves ZF alone spins forever -- three million
            # iterations of six instructions, no output, black screen. It looks
            # like a hang and is a question nobody answered.
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            if ah == 0x06 and (dx & 0xFF) != 0xFF:
                self.output.append(chr(dx & 0xFF))
                return
            if self.keys:
                ch = self.keys.pop(0) & 0xFF
                self.keys_read += 1
                uc.reg_write(UC_X86_REG_AX,
                             (uc.reg_read(UC_X86_REG_AX) & 0xFF00) | ch)
                flags &= ~ZF
            else:
                uc.reg_write(UC_X86_REG_AX,
                             uc.reg_read(UC_X86_REG_AX) & 0xFF00)
                flags |= ZF
            uc.reg_write(UC_X86_REG_EFLAGS, flags)
            return
        if ah == 0x30:                      # get DOS version
            # A program that asks and is told 0 concludes it is on DOS 1 and
            # refuses to run. Karateka does exactly that, in its first twenty
            # instructions.
            uc.reg_write(UC_X86_REG_AX, 0x1E03)     # 3.30, major in AL
            return
        if ah in (0x25, 0x35):              # set / get interrupt vector
            # Against a real table, so SwapVectors round-trips: a program that
            # saves the vectors, installs its own and puts them back gets its
            # own values returned rather than zero.
            n = (ax & 0xFF) * 4
            if ah == 0x35:
                off, seg = struct.unpack("<HH", uc.mem_read(n, 4))
                uc.reg_write(UC_X86_REG_BX, off)
                uc.reg_write(UC_X86_REG_ES, seg)
            else:
                uc.mem_write(n, struct.pack("<HH", dx, ds))
            return
        if ah == 0x1A:                      # set disk transfer address
            self.dta = ((ds << 4) + dx)
            return
        if ah == 0x2A:                      # get date
            uc.reg_write(UC_X86_REG_CX, 1990)
            uc.reg_write(UC_X86_REG_DX, 0x0601)     # 1 June
            uc.reg_write(UC_X86_REG_AX, 5)          # a Friday
            return
        if ah in (0x48,):                   # allocate memory
            # Hand out a block above everything, and never reuse it. Nothing
            # here frees anything, and a game that allocates once at start-up
            # -- which is nearly all of them -- never notices.
            uc.reg_write(UC_X86_REG_AX, self.next_para)
            self.next_para += uc.reg_read(UC_X86_REG_BX)
            self._ok(uc, self.next_para)
            return
        if ah in (0x49, 0x4A):              # free / resize
            self._ok(uc)
            return

        if ah in (0x3D, 0x3C, 0x6C):        # open / create
            name = self._str_at(uc, ds, dx)
            path = self._resolve(name)
            if path is None:
                self.file_misses.append(name)
                self._fail(uc, 2)           # file not found
                return
            h = self.next_handle
            self.next_handle += 1
            self.open_files[h] = [path.read_bytes(), 0, path.name]
            self.file_reads.append(path.name)
            if self.trace_io:
                self.io_log.append(f"open {path.name} -> handle {h}, "
                                   f"{len(self.open_files[h][0]):,} bytes")
            self._ok(uc, h)
            return
        if ah == 0x3E:                      # close
            self.open_files.pop(uc.reg_read(UC_X86_REG_BX), None)
            self._ok(uc)
            return
        if ah == 0x3F:                      # read
            bx = uc.reg_read(UC_X86_REG_BX)
            n = uc.reg_read(UC_X86_REG_CX)
            f = self.open_files.get(bx)
            if f is None:
                self._fail(uc, 6)           # invalid handle
                return
            data, pos, fname = f
            chunk = data[pos:pos + n]
            f[1] = pos + len(chunk)
            if self.trace_io:
                short = "  SHORT" if len(chunk) < n else ""
                self.io_log.append(
                    f"read {fname} handle {bx} at {pos} want {n} got "
                    f"{len(chunk)}{short}")
            uc.mem_write((ds << 4) + dx, chunk)
            self._ok(uc, len(chunk))
            return
        # The five below are what a Turbo Pascal program's `Dos` unit calls,
        # and without them a Pascal program stops at its own first statement.
        # The Oregon Trail opens PRODUCT.PF, stats it, reads its timestamp and
        # asks whether the drive is a network drive -- all before it draws
        # anything -- and answering none of them looks exactly like a crash.
        if ah == 0x2C:                      # get time
            uc.reg_write(UC_X86_REG_CX, (10 << 8) | 30)     # 10:30
            uc.reg_write(UC_X86_REG_DX, 0)                  # 00.00 seconds
            return
        if ah == 0x44:                      # IOCTL
            al = ax & 0xFF
            if al == 0x09:                  # is this drive remote?
                # Say local. A network drive is the unusual answer, and it is
                # the one that turns licence checks on: The Oregon Trail asks
                # exactly this and only enforces its lab licence if the bit is
                # set. Anything that wants to test the other branch should say
                # so deliberately rather than inherit it from a default.
                uc.reg_write(UC_X86_REG_DX, 0x0800)
                self._ok(uc)
                return
            self._ok(uc)
            return
        if ah in (0x4E, 0x4F):              # find first / find next
            if ah == 0x4E:
                self.find_pending = self._find(self._str_at(uc, ds, dx))
            entry = self.find_pending.pop(0) if self.find_pending else None
            if entry is None:
                self._fail(uc, 18)          # no more files
                return
            self._write_dta(uc, entry)
            self._ok(uc)
            return
        if ah == 0x57:                      # get / set a file's timestamp
            al = ax & 0xFF
            if al == 0x00:
                uc.reg_write(UC_X86_REG_CX, DOS_TIME)
                uc.reg_write(UC_X86_REG_DX, DOS_DATE)
            # AL=1 sets it; nothing here writes to disk, so accept and forget.
            self._ok(uc)
            return
        if ah == 0x36:                      # free space on a drive
            uc.reg_write(UC_X86_REG_AX, 4)          # sectors per cluster
            uc.reg_write(UC_X86_REG_BX, 0x2000)     # free clusters
            uc.reg_write(UC_X86_REG_CX, 512)        # bytes per sector
            uc.reg_write(UC_X86_REG_DX, 0x4000)     # clusters on the drive
            return

        if ah == 0x42:                      # seek
            bx = uc.reg_read(UC_X86_REG_BX)
            f = self.open_files.get(bx)
            if f is None:
                self._fail(uc, 6)
                return
            cx = uc.reg_read(UC_X86_REG_CX)
            off = ((cx << 16) | dx) & 0xFFFFFFFF
            whence = ax & 0xFF
            base = {0: 0, 1: f[1], 2: len(f[0])}.get(whence, 0)
            f[1] = max(0, min(len(f[0]), base + off))
            if self.trace_io:
                self.io_log.append(f"seek {f[2]} handle {bx} whence {whence} "
                                   f"-> {f[1]}")
            uc.reg_write(UC_X86_REG_DX, (f[1] >> 16) & 0xFFFF)
            self._ok(uc, f[1] & 0xFFFF)
            return

        # Anything else is acknowledged as success. Saying "unsupported" would
        # be more honest and less useful: most of what is left is console
        # output, and a game that cannot print does not stop being a game.
        self._ok(uc)

    # A warning about the port reads below, paid for on Zaxxon. Alternating
    # values keep timing loops moving, which is what they are for -- but a
    # *joystick* is detected by writing to port 0x201 and counting how long a
    # bit stays set, and an alternating bit answers that probe successfully.
    # So an emulated Zaxxon decides a joystick is attached, ignores the
    # keyboard queue, and plays a different game from the one you asked for.
    # The state it reaches is real, it is simply not the state a keyboard
    # player reaches. Check the flags byte before trusting a captured frame.

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

    def run(self, start=None, stop=None, budget=20_000_000):
        """Execute from an image offset until it returns, exits or runs out.

        `start=None` means the program's own entry point: 0 for a `.COM`, and
        for an MZ whatever `CS:IP` in the header says, which is frequently not
        the beginning of the image.
        """
        if start is None:
            start = getattr(self, "mz_entry", 0)
        addr = BASE + LOAD + start
        end = BASE + LOAD + stop if stop is not None else BASE + 0xFFFF
        left = budget
        while left > 0:
            n = min(left, self.isr_every) if self.isr_vector else left
            try:
                self.uc.emu_start(addr, end, count=n)
            except UcError as e:
                self.stopped = self.stopped or f"fault: {e} at {self._where()}"
                break
            left -= n
            if self.stopped is not None:
                break
            cs = self.uc.reg_read(UC_X86_REG_CS)
            ip = self.uc.reg_read(UC_X86_REG_IP)
            addr = (cs << 4) + ip
            if addr == end or not self.isr_vector or left <= 0:
                break
            addr = self._fire_isr(cs, ip)
        if self.stopped is None:
            if stop is not None:
                self.stopped = "reached the stop address"
            else:
                # Say WHERE the budget ran out, not just that it did. A run
                # that ends on the budget is usually a run stuck in a loop,
                # and without an address the only move left is to raise the
                # budget -- which is the wrong move, and an expensive one:
                # The Oregon Trail was given 1.5 then 3 billion instructions
                # and produced byte-identical results both times, because it
                # had stopped making progress long before either limit.
                self.stopped = f"budget exhausted at {self._where()}"
        return self.stopped

    def _enable_interrupts(self):
        """Start with IF set, the way DOS hands a program control.

        Unicorn starts with FLAGS at 0x0002 -- interrupts disabled -- which no
        real program has ever seen. It went unnoticed while nothing here
        delivered an interrupt; the moment something did, every delivery was
        correctly refused and the timer never ticked.
        """
        self.uc.reg_write(UC_X86_REG_EFLAGS,
                          self.uc.reg_read(UC_X86_REG_EFLAGS) | IF)

    def _fire_isr(self, cs, ip):
        """Deliver a timer interrupt to the handler the program installed.

        Ticking the BIOS word at 0040:006C is not enough for a game that hooks
        the timer itself. The Oregon Trail installs this at image 0x10441:

            push ax..bp / mov ax, 0x3348 / mov ds, ax   ; DGROUP, hardcoded
            les ax, [0x16B2] / add ax, 1 / adc dx, 0    ; a 32-bit counter
            mov [0x16B2], ax / mov [0x16B4], dx
            iret

        and its hunting mini-game then waits for that counter to become
        non-zero, in five instructions at image 0x764F. Nothing in an emulator
        that only answers interrupts ever runs the handler, so the counter
        stays at zero and the loop spins for ever -- 3,000,000,000 instructions
        produced byte-identical output to 1,500,000,000, which is what a run
        that has stopped making progress looks like.

        So do what the hardware does: push FLAGS, CS and IP, and continue at
        the handler. Its own `iret` pops the frame and resumes exactly where
        the program was interrupted, which is the whole point of the frame.

        Take an interrupt *number* and read the live vector, rather than an
        address. An earlier version took the address and was wrong in a way
        worth keeping: The Oregon Trail ships packed with LZEXE, so twenty
        thousand instructions in, the handler's address still holds compressed
        bytes. Jumping there destroyed the run -- no interrupts requested, no
        ports written, no keys read, and 99,999 timer interrupts delivered
        into rubbish. Reading the vector each time waits for the program to
        install its handler, because until it does the slot still points at
        our own stub and there is nothing to deliver.
        """
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        if not flags & IF:
            # Hardware does not deliver a maskable interrupt while IF is
            # clear, and neither may this. Ignoring that broke a run after
            # 26.9 million instructions with two interrupts delivered: Turbo
            # Pascal's Crt closes `cli` around the port writes in Sound and
            # Delay, and a frame pushed inside one of those leaves the routine
            # somewhere it cannot return from. Respecting IF is not politeness,
            # it is the contract the program was written against.
            self.isr_masked += 1
            return (cs << 4) + ip
        vec = self.uc.mem_read(self.isr_vector * 4, 4)
        off, seg = struct.unpack("<HH", vec)
        if seg == (STUBS >> 4) or (seg == 0 and off == 0):
            return (cs << 4) + ip          # not hooked yet -- nothing to do
        sp = self.uc.reg_read(UC_X86_REG_SP)
        ss = self.uc.reg_read(UC_X86_REG_SS)
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        sp = (sp - 6) & 0xFFFF
        self.uc.mem_write((ss << 4) + sp, struct.pack("<HHH", ip, cs, flags))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        # CS must move with the jump. Unicorn keeps a segment base and a
        # 16-bit IP separately, so restarting at the handler's linear address
        # while CS still names the interrupted segment leaves the two
        # disagreeing -- and one delivery was enough to end a run 26.9 million
        # instructions in, every time, at the same instruction. Frequency was
        # never the variable: 20,000 crashed after two deliveries and 200,000
        # after one.
        self.uc.reg_write(UC_X86_REG_CS, seg)
        self.isr_fired += 1
        return (seg << 4) + off

    def _where(self):
        """CS:IP and the bytes there, because a fault without an address is not
        a diagnosis. The image offset is what every document quotes, so give
        that too rather than making the reader do the arithmetic."""
        cs = self.uc.reg_read(UC_X86_REG_CS)
        ip = self.uc.reg_read(UC_X86_REG_IP)
        flat = (cs << 4) + ip
        try:
            raw = bytes(self.uc.mem_read(flat, 8)).hex(" ")
        except UcError:
            raw = "unreadable"
        hist = [self.recent[(self.steps + i) & 511] for i in range(1, 513)]
        hist = [a - self.img_bias for a in hist if a]
        # The interesting moment is not the fault, it is the step that left the
        # program. A fault deep in low memory has already lost the trail, so
        # report the last instructions that were still inside the image.
        top = len(self.image) + 0x10000
        inside = [a for a in hist if 0 <= a < top]
        left = ""
        for i, a in enumerate(hist):
            if not (0 <= a < top) and i:
                left = f"\n  left the image after {hist[i - 1]:#x}"
                break
        return (f"{cs:04X}:{ip:04X} (image {flat - self.img_bias:#08x}) "
                f"[{raw}]{left}\n  last inside: "
                + (" -> ".join(f"{a:#x}" for a in inside[-8:])
                   or "(nothing in range)"))

    def call(self, off, budget=20_000_000, seg=None):
        """Call a routine and stop when it returns.

        A sentinel return address is pushed and used as the stop point, so a
        routine that returns normally ends the run rather than falling into
        whatever follows it.

        `seg` makes it a *far* call, which a compiled program needs. Every unit
        of a Turbo Pascal program is its own segment and every entry point into
        one is `lcall seg:off`; calling such a routine at a flat image offset
        runs it with the wrong CS, so its string constants resolve to garbage
        and it usually returns immediately having drawn nothing. That is what
        an attempt to photograph The Oregon Trail's hunting screen did -- it
        landed back on the main menu and looked like the routine had declined
        to run.
        """
        sentinel = 0xFFF0
        sp = self.uc.reg_read(UC_X86_REG_SP)
        if seg is not None:
            sp -= 2                       # a far return needs CS as well
            self.uc.mem_write(BASE + sp, struct.pack("<H", SEG))
        sp -= 2
        self.uc.mem_write(BASE + sp, struct.pack("<H", sentinel))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.stopped = None
        if seg is not None:
            self.uc.reg_write(UC_X86_REG_CS, seg)
            start = (seg << 4) + off
        else:
            start = BASE + LOAD + off
        try:
            self.uc.emu_start(start, BASE + sentinel, count=budget)
        except UcError as e:
            self.stopped = self.stopped or f"fault: {e} at {self._where()}"
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
    ap.add_argument("--gate", metavar="ADDR[,ADDR...]", default="",
                    help="release one --keys entry each time execution reaches "
                         "any of these addresses -- typically every call site "
                         "of the routine that reads a key")
    ap.add_argument("--watch-ptr", metavar="ADDR[:N]", default="",
                    help="dump DS:SI and ES:DI when an address is reached, "
                         "N times (default 4)")
    ap.add_argument("--trace-io", action="store_true",
                    help="log every file open, read and seek")
    ap.add_argument("--at", metavar="ADDR=KEY[,...]", default="",
                    help="hand a key over when the program reaches an address, "
                         "rather than queueing it blind. Repeat an address to "
                         "deliver several, in order.")
    ap.add_argument("--poke", metavar="OFF=VAL[,...]", default="",
                    help="write a word at an image offset before --call. A "
                         "routine usually refuses to run without the state a "
                         "real game would have reached first: The Oregon "
                         "Trail's hunting screen tests the bullet count and "
                         "returns immediately when it is zero.")
    ap.add_argument("--call", metavar="OFF|SEG:OFF", help="after start-up, call this file offset")
    ap.add_argument("--stop-at", help="stop the start-up run at this offset "
                                      "instead of letting it reach its budget")
    ap.add_argument("--stop-after", type=int, default=1, metavar="N",
                    help="stop on the Nth arrival at --stop-at, not the first")
    ap.add_argument("--watch", help="log calls arriving at these offsets")
    ap.add_argument("--vars", default="0x6d9b,0x6d9c,0x6d97",
                    help="variables to record at each watched call")
    ap.add_argument("--timer-isr", metavar="INT[,N]",
                    help="deliver interrupt INT (hex, e.g. 1c) to whatever "
                         "handler the program has installed, every N "
                         "instructions (default 20000), pushing a real "
                         "FLAGS/CS/IP frame so its iret resumes correctly. "
                         "For a game that hooks the timer and waits on a "
                         "counter its own handler increments. The vector is "
                         "read at each delivery, so nothing is sent until the "
                         "program has hooked it")
    ap.add_argument("--poll-patience", type=int, metavar="N",
                    help="answer INT 16h AH=01 with 'nothing waiting' until it "
                         "has been asked N times since the last real read. "
                         "Defeats a `while KeyPressed do ReadKey` flush loop, "
                         "which otherwise swallows the whole --keys queue")
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
    ap.add_argument("--files", metavar="DIR",
                    help="directory the program's data files are in; "
                         "without it every open fails, and a game that "
                         "cannot find its artwork usually prints a "
                         "message and exits")
    ap.add_argument("--budget", type=int, default=20_000_000)
    ap.add_argument("--png")
    ap.add_argument("--palette", default="1", choices=sorted(PALETTES))
    ap.add_argument("--json")
    ap.add_argument("--exec-map", metavar="FILE",
                    help="write every image offset the program executed, "
                         "for checking a disassembly against a run")
    ap.add_argument("--dump", help="write a memory range as OFF:LEN")
    args = ap.parse_args()

    keys = []
    for k in (args.keys.split(",") if args.keys else []):
        keys.append(int(k, 0) if k.lower().startswith("0x") else ord(k[0]))

    image = Path(args.binary).read_bytes()
    m = Machine(image, keys=keys,
                files=args.files or Path(args.binary).parent)
    if args.exec_map:
        m.exec_map = set()

    if args.timer_isr:
        spec = args.timer_isr.split(",")
        m.isr_vector = int(spec[0], 16)
        if len(spec) > 1:
            m.isr_every = int(spec[1], 0)
        print(f"timer ISR: INT {m.isr_vector:02X}h every "
              f"{m.isr_every} instructions, once the program hooks it")
    if args.poll_patience is not None:
        m.poll_patience = args.poll_patience
        print(f"poll patience: {args.poll_patience} (a flush loop sees an "
              "empty keyboard)")
    if args.gate:
        m.gates = {int(a, 16) for a in args.gate.split(",") if a.strip()}
        m.gated, m.keys = m.keys, []
        print(f"gated: {len(m.gated)} keys, released at "
              f"{len(m.gates)} addresses")
    m.trace_io = args.trace_io
    for item in (x for x in args.watch_ptr.split(",") if x.strip()):
        a, _, n = item.partition(":")
        m.ptr_watch[int(a, 16)] = int(n) if n else 4
        m.trace_io = True


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
    if m.mz is not None:
        print(f"format    : MZ, {m.mz['hdr']}-byte header, "
              f"{m.mz['nreloc']} relocations applied; "
              f"entry CS:IP {m.mz['cs']:04X}:{m.mz['ip']:04X} "
              f"-> image offset 0x{m.mz_entry:X}")
    why = m.run(None, stop=None, budget=args.budget)
    print(f"start-up: {m.steps:,} instructions, stopped: {why}")
    print(f"  interrupts requested: "
          + ", ".join(sorted({f"{n:02X}h" for n, _ in m.ints})) or "  none")
    outs = sorted({p for d, p, _ in m.ports if d == "out"})
    if outs:
        print("  ports written: " + ", ".join(f"{p:#04x}" for p in outs))
    if m.isr_fired or m.isr_masked:
        print(f"  timer interrupts delivered: {m.isr_fired:,}"
              + (f", {m.isr_masked:,} skipped with interrupts disabled"
                 if m.isr_masked else ""))
    if args.keys:
        print(f"  keyboard: {m.keys_read} reads, {len(m.keys)} of "
              f"{len(keys)} keys unused")

    # These three were collected and then thrown away, which was the wrong
    # trade: when a program stops early it usually says why, and what it went
    # looking for is the other half of the answer. A run that ends at int 20h
    # with a file miss in the list has already diagnosed itself.
    if m.file_reads:
        print("  files opened: " + ", ".join(dict.fromkeys(m.file_reads)))
    if m.file_misses:
        print("  files NOT found: " + ", ".join(dict.fromkeys(m.file_misses))
              + ("" if m.files else "   (no --files given)"))
    if m.output:
        text = "".join(m.output).replace("\r\n", "\n").strip()
        if text:
            print("  the program printed:")
            for line in text.split("\n"):
                print(f"      {line}")

    for item in (x for x in args.at.split(",") if x.strip()):
        a, _, k = item.partition("=")
        # Same convention as --keys: 0x.. is a full AX, anything else is the
        # character itself.
        val = int(k, 0) if k.lower().startswith("0x") else ord(k[0])
        m.at_keys.setdefault(int(a, 16), []).append(val)
    if m.at_keys:
        print("keys on arrival: " + ", ".join(
            f"{a:#x} -> {len(v)}" for a, v in sorted(m.at_keys.items())))

    for item in (x for x in args.poke.split(",") if x.strip()):
        off, _, val = item.partition("=")
        at, v = int(off, 0), int(val, 0)
        m.uc.mem_write(BASE + at, struct.pack("<H", v))
        print(f"poked image {at:#07x} = {v}")

    if args.call:
        if args.ax:
            m.uc.reg_write(UC_X86_REG_AX, int(args.ax, 0))
        before = m.steps
        if ":" in args.call:
            cseg, coff = (int(x, 16) for x in args.call.split(":"))
            why = m.call(coff, budget=args.budget, seg=cseg)
        else:
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
    if m.trace_io and m.io_log:
        print("")
        print(f"file activity ({len(m.io_log)} operations):")
        for line in m.io_log:
            print("   " + line)

    if args.exec_map:
        hit = sorted(a for a in m.exec_map if a >= 0)
        Path(args.exec_map).write_text(chr(10).join(f"{a:x}" for a in hit))
        print(f"executed {len(hit):,} distinct addresses -> {args.exec_map}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
