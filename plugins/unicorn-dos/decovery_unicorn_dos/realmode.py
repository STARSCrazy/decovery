"""Real-mode DOS host: runs plain 16-bit MZ and COM programs (Turbo C 2.0's TCC.EXE and TLINK.EXE) in unicorn,
with DOS and the few BIOS services they use emulated in Python.

Memory (1 MiB + 64 KiB, segment:offset as on a PC):
    0000:0000   interrupt vectors, all pointing into the stub segment until the program sets one
    0040:0000   BIOS data (tick counter at 0:46C)
    ENV_SEG     environment block (own memory block)
    PSP_SEG     PSP, followed by the program (MZ load module with relocations applied, or the COM image at PSP:100)
    ...A000     memory blocks (MCB chain from FIRST_MCB) for AH=48h/49h/4Ah
    STUB_SEG    `int nn; iret` per vector: a program that chains to the previous vector reaches the host there

A software interrupt whose vector the program set (AH=25h or a direct write) is delivered to the program (FLAGS, CS
and IP pushed); every other one is served here. Any service the emulation does not know ends the run with an
`EmulatorError` naming it, the address and the registers; it never continues silently.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from functools import lru_cache

from .dosfs import DosFs
from .errors import DosError, EmulatorError, EmulatorTimeout, Unsupported
from .pharlap import STOP_MARGIN, Result
from .services import ZERO, DosServices, Regs

MEMORY_SIZE = 0x110000
PAGE = 0x1000
STUB_SEG = 0xF000
ENV_SEG = 0x0080
PSP_SEG = 0x0100
FIRST_MCB = ENV_SEG - 1
ENV_PARAS = PSP_SEG - 1 - ENV_SEG
MEMORY_TOP = 0xA000
LOAD_SEG = PSP_SEG + 0x10
MAX_COMMAND_TAIL = 126
INTERRUPT_FLAGS = 0x0300  # IF and TF, cleared when an interrupt is delivered
TICKS_PER_SECOND = 1193180 / 65536

NOT_ENOUGH_MEMORY = 8
BAD_BLOCK = 9
ARENA_TRASHED = 7


@dataclass(frozen=True)
class MzImage:
    """What DOS needs to load a program. A COM program has `com` set and no header."""

    module: bytes
    relocations: tuple[tuple[int, int], ...]  # (segment, offset) relative to the load segment
    cs: int
    ip: int
    ss: int
    sp: int
    min_alloc: int  # paragraphs after the module
    max_alloc: int
    com: bool = False


def load_mz(data: bytes) -> MzImage:
    """Parse an MZ program (or take `data` as a COM image)."""
    if data[:2] not in (b"MZ", b"ZM"):
        if len(data) > 0xFF00:
            raise EmulatorError("COM program larger than 0xFF00 bytes")
        return MzImage(data, (), 0, 0x100, 0, 0xFFFE, 0, 0xFFFF, com=True)
    if len(data) < 0x1C:
        raise EmulatorError("truncated MZ header")
    last_page, pages, count, header_paras, min_alloc, max_alloc, ss, sp, _, ip, cs, table = struct.unpack_from(
        "<12H", data, 2
    )
    size = pages * 512 - ((512 - last_page) if last_page else 0)
    start = header_paras * 16
    if size > len(data) or start > size:
        raise EmulatorError(f"MZ header at offset 2: load module {start:#x}..{size:#x} outside the file")
    if table + 4 * count > len(data):
        raise EmulatorError(f"MZ relocation table at offset {table:#x} outside the file")
    relocations = tuple(
        (seg, off) for off, seg in (struct.unpack_from("<HH", data, table + 4 * i) for i in range(count))
    )
    return MzImage(data[start:size], relocations, cs, ip, ss, sp, min_alloc, max_alloc)


@lru_cache(maxsize=4)
def read_exe_file(path: str, size: int, mtime_ns: int) -> bytes:
    """Contents of a program file, cached by path, size and modification time."""
    with open(path, "rb") as f:
        return f.read()


@lru_cache(maxsize=None)
def _reg(name: str) -> int:
    from unicorn import x86_const

    return getattr(x86_const, f"UC_X86_REG_{name}")


def _mcb(kind: bytes, owner: int, size: int) -> bytes:
    return kind + struct.pack("<HH", owner, size) + bytes(11)


class RealModeMachine:
    """unicorn CPU in real mode with one program loaded, reusable: `reset()` restores the loaded state (only the
    4 KiB pages that changed are written back). Not thread-safe: one machine per thread or process."""

    def __init__(self, exe: bytes):
        from unicorn import UC_ARCH_X86, UC_HOOK_INTR, UC_HOOK_MEM_INVALID, UC_MODE_16, Uc

        self.exe = exe
        self.image = exe  # identity for the machine cache
        mz = load_mz(exe)
        self.active: RealModeEmu | None = None
        self.spent = False
        self.runs = 0
        memory = bytearray(MEMORY_SIZE)
        for n in range(256):
            struct.pack_into("<HH", memory, 4 * n, 4 * n, STUB_SEG)
            memory[(STUB_SEG << 4) + 4 * n : (STUB_SEG << 4) + 4 * n + 4] = bytes([0xCD, n, 0xCF, 0x90])
        struct.pack_into("<BH", memory, 0x449, 3, 80)  # BIOS: video mode 3, 80 columns

        # memory blocks: environment, program, rest free
        available = MEMORY_TOP - PSP_SEG
        module_paras = (len(mz.module) + 15) // 16 + 0x10
        if mz.com:
            size = available
        else:
            needed = module_paras + mz.min_alloc
            if needed > available:
                raise EmulatorError(
                    f"not enough memory for the program: needs {needed:#x} paragraphs, DOS has {available:#x}"
                )
            size = min(available, module_paras + max(mz.min_alloc, mz.max_alloc))
            if available - size < 1:
                size = available
        memory[FIRST_MCB << 4 : (FIRST_MCB << 4) + 16] = _mcb(b"M", PSP_SEG, ENV_PARAS)
        last = size == available
        memory[(PSP_SEG - 1) << 4 : PSP_SEG << 4] = _mcb(b"Z" if last else b"M", PSP_SEG, size)
        if not last:
            free = PSP_SEG + size
            memory[free << 4 : (free << 4) + 16] = _mcb(b"Z", 0, MEMORY_TOP - free - 1)

        # PSP without the command tail (written per run)
        psp = PSP_SEG << 4
        memory[psp : psp + 2] = b"\xcd\x20"
        struct.pack_into("<H", memory, psp + 2, PSP_SEG + size)  # first segment after the program's memory
        struct.pack_into("<H", memory, psp + 0x16, PSP_SEG)  # parent: itself, like COMMAND.COM
        memory[psp + 0x18 : psp + 0x2C] = bytes([1, 1, 1, 0, 2]) + b"\xff" * 15  # job file table
        struct.pack_into("<H", memory, psp + 0x2C, ENV_SEG)
        struct.pack_into("<HHH", memory, psp + 0x32, 20, 0x18, PSP_SEG)
        memory[psp + 0x50 : psp + 0x53] = b"\xcd\x21\xcb"
        for fcb in (0x5C, 0x6C):
            memory[psp + fcb + 1 : psp + fcb + 12] = b" " * 11

        # program
        load = LOAD_SEG << 4
        memory[load : load + len(mz.module)] = mz.module
        for seg, off in mz.relocations:
            at = load + (seg << 4) + off
            if at + 2 > MEMORY_SIZE:
                raise EmulatorError(f"MZ relocation {seg:04X}:{off:04X} outside memory")
            value = (struct.unpack_from("<H", memory, at)[0] + LOAD_SEG) & 0xFFFF
            struct.pack_into("<H", memory, at, value)

        mu = Uc(UC_ARCH_X86, UC_MODE_16)
        self.mu = mu
        mu.mem_map(0, MEMORY_SIZE)
        self.original = bytes(memory)
        mu.mem_write(0, self.original)
        if mz.com:
            cs = ss = PSP_SEG
        else:
            cs, ss = (mz.cs + LOAD_SEG) & 0xFFFF, (mz.ss + LOAD_SEG) & 0xFFFF
        for name, value in (
            ("CS", cs), ("SS", ss), ("DS", PSP_SEG), ("ES", PSP_SEG),
            ("IP", mz.ip), ("SP", mz.sp), ("EFLAGS", 0x0202),
        ):  # fmt: skip
            mu.reg_write(_reg(name), value)
        self.start = mu.context_save()
        mu.hook_add(UC_HOOK_INTR, lambda m, number, _: self.active._interrupt(number))
        mu.hook_add(UC_HOOK_MEM_INVALID, lambda m, access, address, size, value, _: self.active._memory_fault(
            access, address, size))
        self.fresh = True

    def reset(self, emu: RealModeEmu) -> None:
        if self.spent:
            raise EmulatorError("machine not reusable after a failed run")
        if self.active is not None:
            raise EmulatorError("machine is already running")
        self.active = emu
        self.runs += 1
        if self.fresh:
            self.fresh = False
            return
        mu = self.mu
        now = bytes(mu.mem_read(0, MEMORY_SIZE))
        original = self.original
        for a in range(0, MEMORY_SIZE, PAGE):
            if now[a : a + PAGE] != original[a : a + PAGE]:
                mu.mem_write(a, original[a : a + PAGE])
        mu.context_restore(self.start)


class _RealModeRegs(Regs):
    wide = False

    def __init__(self, mu):
        self.mu = mu

    def get(self, name: str) -> int:
        return self.mu.reg_read(_reg(name))

    def set(self, name: str, value: int) -> None:
        self.mu.reg_write(_reg(name), value)

    def linear(self, seg: int, off: int) -> int:
        return ((seg & 0xFFFF) << 4) + (off & 0xFFFF)

    def read_linear(self, address: int, n: int) -> bytes:
        return bytes(self.mu.mem_read(address, n))

    def write_linear(self, address: int, data: bytes) -> None:
        self.mu.mem_write(address, data)


class Arena:
    """DOS memory blocks: the MCB chain in emulated memory from FIRST_MCB up to MEMORY_TOP (first fit). Blocks
    are [mcb segment, owner, paragraphs]; owner 0 is free."""

    def __init__(self, regs: Regs):
        self.regs = regs

    def _chain(self) -> list[list[int]]:
        blocks: list[list[int]] = []
        mcb = FIRST_MCB
        while True:
            head = self.regs.read_linear(mcb << 4, 5)
            if head[0] not in b"MZ":
                raise DosError(ARENA_TRASHED)
            owner, size = struct.unpack_from("<HH", head, 1)
            if blocks and blocks[-1][1] == 0 and owner == 0:  # neighbouring free blocks become one
                blocks[-1][2] += size + 1
            else:
                blocks.append([mcb, owner, size])
            if head[0] == ord("Z"):
                return blocks
            mcb += size + 1
            if mcb >= MEMORY_TOP:
                raise DosError(ARENA_TRASHED)

    def _store(self, blocks: list[list[int]]) -> None:
        for i, (mcb, owner, size) in enumerate(blocks):
            kind = b"Z" if i == len(blocks) - 1 else b"M"
            self.regs.write_linear(mcb << 4, kind + struct.pack("<HH", owner, size))

    @staticmethod
    def _split(blocks: list[list[int]], i: int, size: int) -> None:
        """Cut block `i` to `size` paragraphs; the rest (if any room for an MCB) becomes a free block."""
        mcb, _, total = blocks[i]
        if total - size >= 1:
            blocks[i][2] = size
            blocks.insert(i + 1, [mcb + 1 + size, 0, total - size - 1])
            if i + 2 < len(blocks) and blocks[i + 2][1] == 0:
                blocks[i + 1][2] += blocks.pop(i + 2)[2] + 1

    def _index(self, blocks: list[list[int]], segment: int) -> int:
        for i, block in enumerate(blocks):
            if block[0] == segment - 1:
                return i
        raise DosError(BAD_BLOCK)

    def allocate(self, size: int, owner: int) -> tuple[int | None, int]:
        """(segment or None, largest free block)."""
        blocks = self._chain()
        for i, (mcb, block_owner, total) in enumerate(blocks):
            if block_owner == 0 and total >= size:
                blocks[i][1] = owner
                self._split(blocks, i, size)
                self._store(blocks)
                return mcb + 1, total
        return None, max((b[2] for b in blocks if b[1] == 0), default=0)

    def free(self, segment: int) -> None:
        blocks = self._chain()
        blocks[self._index(blocks, segment)][1] = 0
        self._store(blocks)

    def resize(self, segment: int, size: int) -> int | None:
        """None on success, else the largest size possible (the block is grown to it, as DOS 3-6 do)."""
        blocks = self._chain()
        i = self._index(blocks, segment)
        if i + 1 < len(blocks) and blocks[i + 1][1] == 0 and size > blocks[i][2]:
            blocks[i][2] += blocks.pop(i + 1)[2] + 1  # take the following free block, give back the rest
        largest = blocks[i][2]
        self._split(blocks, i, min(size, largest))
        self._store(blocks)
        return None if size <= largest else largest


class RealModeEmu:
    """One run of a real-mode program on `fs`. `env`: environment in order; `program`: DOS path of the program
    (end of the environment block)."""

    def __init__(
        self,
        exe: bytes,
        fs: DosFs,
        args: str,
        env: list[tuple[str, str]],
        program: str,
        timeout_s: float = 120.0,
    ):
        self.exe = exe
        self.fs = fs
        self.args = args
        self.env = env
        self.program = program
        self.timeout_s = timeout_s
        self.error: EmulatorError | None = None
        self.calls: dict[str, int] = {}
        self.machine: RealModeMachine | None = None

    # --- setup ---------------------------------------------------------------------------------------------------
    def _command_tail(self) -> bytes:
        tail = self.args.encode("cp437")
        if tail and not tail.startswith(b" "):
            tail = b" " + tail
        if len(tail) > MAX_COMMAND_TAIL:
            raise EmulatorError(f"command line too long for DOS ({len(tail)} characters)")
        return bytes([len(tail)]) + tail + b"\r"

    def _environment(self) -> bytes:
        block = b"".join(f"{k}={v}".encode("cp437") + b"\0" for k, v in self.env) + b"\0"
        block += struct.pack("<H", 1) + self.program.encode("cp437") + b"\0"
        if len(block) > ENV_PARAS * 16:
            raise EmulatorError("environment too large")
        return block

    def begin(self, machine: RealModeMachine | None = None) -> None:
        """Bring the machine to the loaded state and write command tail and environment."""
        tail, environment = self._command_tail(), self._environment()
        self.machine = machine or RealModeMachine(self.exe)
        if self.machine.exe is not self.exe and self.machine.exe != self.exe:
            raise EmulatorError("machine belongs to another program")
        self.machine.reset(self)
        self.mu = self.machine.mu
        self.regs = _RealModeRegs(self.mu)
        self.services = DosServices(self.fs, self.regs)
        self.services.dta = self.regs.linear(PSP_SEG, 0x80)
        self.services.dta_far = (PSP_SEG, 0x80)
        self.arena = Arena(self.regs)
        self.mu.mem_write((PSP_SEG << 4) + 0x80, tail)
        self.mu.mem_write(ENV_SEG << 4, environment)

    def execute(self, timeout_us: int = 0) -> None:
        """Run from CS:IP until the program ends, a hook stops it or the time (µs, 0 = none) is up. CPU faults land
        in `self.error`."""
        from unicorn import UcError

        start = self.regs.linear(self.regs.get("CS"), self.regs.get("IP"))
        try:
            self.mu.emu_start(start, 0xFFFFFFFF, timeout=timeout_us)
        except UcError as e:
            if self.error is None:
                self.error = EmulatorError(f"CPU fault {e} at {self._location()} ({self._registers()})")

    def finish(self) -> None:
        """Close files and release the machine; after a failure or without an end it is not reusable."""
        self.fs.close_all()
        self.machine.active = None
        if self.error is not None or self.services.exit_code is None:
            self.machine.spent = True

    def run(self, machine: RealModeMachine | None = None) -> Result:
        """Run the program to its end. `machine`: reusable CPU with the program loaded; without one a new one is
        built."""
        started = time.perf_counter()
        self.begin(machine)
        try:
            self.execute(int(self.timeout_s * 1_000_000))
        finally:
            self.finish()
        elapsed = time.perf_counter() - started
        if self.error is not None:
            raise self.error
        if self.services.exit_code is None:
            if elapsed < self.timeout_s * STOP_MARGIN:
                raise EmulatorError(f"stopped without exit at {self._location()} ({self._registers()})")
            raise EmulatorTimeout(f"no end after {self.timeout_s:g} s (at {self._location()})")
        return Result(self.services.exit_code, bytes(self.fs.output), elapsed, dict(self.calls))

    # --- helpers -------------------------------------------------------------------------------------------------
    def _registers(self) -> str:
        names = ("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "CS", "DS", "ES", "SS", "FLAGS")
        return " ".join(f"{n}={self.regs.get(n) & 0xFFFF:04X}" for n in names)

    def _location(self, number: int | None = None) -> str:
        """CS:IP of the current instruction; for a software interrupt the `int nn` that raised it."""
        cs, ip = self.regs.get("CS") & 0xFFFF, self.regs.get("IP") & 0xFFFF
        if number is not None and ip >= 2:
            if self.regs.read(cs, ip - 2, 2) == bytes([0xCD, number]):
                ip -= 2
        return f"{cs:04X}:{ip:04X}"

    def _abort(self, text: str, number: int | None = None) -> None:
        self.machine.spent = True  # state unclear: never reuse
        if self.error is None:
            self.error = EmulatorError(f"{text} at {self._location(number)} ({self._registers()})")
        self.mu.emu_stop()

    def _memory_fault(self, access: int, address: int, size: int) -> bool:
        self._abort(f"memory access outside the mapped memory: kind {access}, address {address:#x}, size {size}")
        return False

    def _count(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1

    def _ticks(self) -> int:
        """BIOS ticks since midnight (18.2 per second)."""
        lt = time.localtime()
        seconds = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec + (time.time() % 1)
        return int(seconds * TICKS_PER_SECOND)

    # --- interrupts ----------------------------------------------------------------------------------------------
    def _interrupt(self, number: int) -> None:
        if self.error is not None:
            self.mu.emu_stop()
            return
        try:
            self.mu.mem_write(0x46C, struct.pack("<I", self._ticks()))
            r = self.regs
            vector = struct.unpack("<HH", r.read_linear(4 * number, 4))
            if r.get("CS") & 0xFFFF != STUB_SEG and vector != (4 * number, STUB_SEG):
                self._count(f"{number:02X}/program")
                self._deliver(*vector)
                return
            handler = getattr(self, f"_int{number:02x}", None)
            if handler is None:
                raise Unsupported(f"unsupported interrupt INT {number:02X}h")
            handler()
        except EmulatorError as e:
            self._abort(str(e), number)
        except Exception as e:  # a bug in the emulation: never run on
            self._abort(f"emulation of INT {number:02X}h: {type(e).__name__}: {e}", number)

    def _deliver(self, off: int, seg: int) -> None:
        """Interrupt into the program's handler: push FLAGS, CS, IP and jump to the vector."""
        r = self.regs
        flags = r.get("EFLAGS")
        sp = (r.get("SP") - 6) & 0xFFFF
        r.write(r.get("SS"), sp, struct.pack("<HHH", r.get("IP") & 0xFFFF, r.get("CS") & 0xFFFF, flags & 0xFFFF))
        r.set("SP", sp)
        r.set("EFLAGS", flags & ~INTERRUPT_FLAGS)
        r.set("CS", seg)
        r.set("IP", off)

    def _zero_flag(self, on: bool) -> None:
        flags = self.regs.get("EFLAGS")
        self.regs.set("EFLAGS", (flags | ZERO) if on else (flags & ~ZERO))

    def _int20(self) -> None:
        self._count("20")
        self.fs.close_all()
        self.services.exit_code = 0
        self.mu.emu_stop()

    def _int10(self) -> None:
        r = self.regs
        ax = r.get("AX")
        ah = ax >> 8
        self._count(f"10/{ah:02X}")
        if ah == 0x0E:  # teletype output: the screen is the console output
            self.fs.output.append(ax & 0xFF)
        elif ah == 0x0F:  # video mode 3, 80 columns, page 0
            r.set("AX", 0x5003)
            r.set("BX", r.get("BX") & 0x00FF)
        else:
            raise Unsupported(f"unsupported INT 10h AH={ah:02X}h")

    def _int16(self) -> None:
        ah = self.regs.get("AX") >> 8
        self._count(f"16/{ah:02X}")
        if ah != 0x01:
            raise Unsupported(f"unsupported INT 16h AH={ah:02X}h")
        self._zero_flag(True)  # no key waiting

    def _int1a(self) -> None:
        r = self.regs
        ah = r.get("AX") >> 8
        self._count(f"1A/{ah:02X}")
        if ah != 0x00:
            raise Unsupported(f"unsupported INT 1Ah AH={ah:02X}h")
        ticks = self._ticks()
        r.set("CX", ticks >> 16)
        r.set("DX", ticks & 0xFFFF)
        r.set("AX", r.get("AX") & 0xFF00)  # AL = 0: midnight not passed

    def _int2f(self) -> None:
        ax = self.regs.get("AX")
        self._count(f"2F/{ax:04X}")
        if ax != 0x1686:  # DPMI: CPU mode? No DPMI host: AX stays
            raise Unsupported(f"unsupported INT 2Fh AX={ax:04X}h")

    def _int21(self) -> None:
        ax = self.regs.get("AX")
        ah, al = ax >> 8, ax & 0xFF
        self._count(f"21/{ah:02X}" + (f"{al:02X}" if ah in (0x25, 0x35, 0x44, 0x42, 0x3D, 0x43, 0x57) else ""))
        handler = getattr(self, f"_ah_{ah:02x}", None)
        if handler is not None:
            try:
                handler(al)
            except DosError as e:
                self.services.fail(e.code)
        elif not self.services.call(ah, al):
            raise Unsupported(f"unsupported INT 21h AH={ah:02X}h")
        if self.services.exit_code is not None:
            self.mu.emu_stop()

    # --- INT 21h functions of this host --------------------------------------------------------------------------
    # 25h: set interrupt vector AL to DS:DX
    def _ah_25(self, al: int) -> None:
        r = self.regs
        r.write_linear(4 * al, struct.pack("<HH", r.get("DX"), r.get("DS")))

    # 35h: get interrupt vector AL -> ES:BX
    def _ah_35(self, al: int) -> None:
        off, seg = struct.unpack("<HH", self.regs.read_linear(4 * al, 4))
        self.regs.set("ES", seg)
        self.regs.set("BX", off)

    # 2Fh: get DTA -> ES:BX
    def _ah_2f(self, al: int) -> None:
        seg, off = self.services.dta_far
        self.regs.set("ES", seg)
        self.regs.set("BX", off)

    # 48h: allocate BX paragraphs -> AX segment; on failure BX = largest free block
    def _ah_48(self, al: int) -> None:
        r = self.regs
        segment, largest = self.arena.allocate(r.get("BX"), PSP_SEG)
        if segment is None:
            r.set("BX", largest)
            raise DosError(NOT_ENOUGH_MEMORY)
        r.set("AX", segment)
        r.carry(False)

    # 49h: free the block at ES
    def _ah_49(self, al: int) -> None:
        self.arena.free(self.regs.get("ES"))
        self.regs.carry(False)

    # 4Ah: resize the block at ES to BX paragraphs; on failure BX = largest possible
    def _ah_4a(self, al: int) -> None:
        r = self.regs
        largest = self.arena.resize(r.get("ES"), r.get("BX"))
        if largest is not None:
            r.set("BX", largest)
            raise DosError(NOT_ENOUGH_MEMORY)
        r.carry(False)

    # 62h: PSP segment -> BX
    def _ah_62(self, al: int) -> None:
        self.regs.set("BX", PSP_SEG)


def run_realmode(
    exe: bytes,
    dosfs: DosFs,
    args: str,
    env: list[tuple[str, str]],
    program_path: str,
    timeout_s: float,
    machine: RealModeMachine | None = None,
) -> Result:
    """Run a real-mode MZ or COM program to its end (see `RealModeEmu`)."""
    return RealModeEmu(exe, dosfs, args, env, program_path, timeout_s).run(machine)

