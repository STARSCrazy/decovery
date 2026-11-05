"""Phar Lap 386|DOS-Extender host: runs the flat 32-bit P3 image of a bound Phar Lap program (Watcom WCC386 9.5)
in unicorn, with DOS and the extender's services emulated in Python.

A bound program starts with the extender (real mode); the P3 header follows its MZ stub and describes a flat
image without relocations (load address, entry point and stack in the header). Only the image runs; the extender
itself is never executed, its services (INT 21h in protected mode with 32-bit pointers, AH=25h/30h/4Ah) are
emulated here. Any call the emulation does not know ends the run with an `EmulatorError` naming the interrupt, the
address and the registers; it never continues silently.

Memory (linear = offset, all program segments have base 0):
    0x00001000...       image, BSS, stack (ESP from the header), then the heap (grows with AH=4Ah)
    PSP_LIN / ENV_LIN   PSP (selector 0x24) and environment (0x2C), own bases
    REAL_LIN            first megabyte (selector 0x34; screen 0x1C)
Selectors as Phar Lap (LDT): 0x0C code, 0x14 data, 0x1C screen, 0x24 PSP, 0x2C environment, 0x34 first MB.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from functools import lru_cache

from .dosfs import DosFs
from .errors import EmulatorError, EmulatorTimeout, Unsupported
from .services import DosServices, Regs

P3_HEADER = 0x180
PAGE = 0x1000

SEL_CODE, SEL_DATA, SEL_SCREEN, SEL_PSP, SEL_ENV, SEL_REAL = 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34
GDT_LIN = 0x7F000000
LDT_LIN = GDT_LIN + 0x100
PSP_LIN = GDT_LIN + 0x1000
ENV_LIN = GDT_LIN + 0x2000
ENV_SIZE = 0x1000
REAL_LIN = 0x7E000000
HEAP_MAX = 0x10000000  # program segment at most 256 MiB
MEMORY_LIMIT = 0x01000000  # PSP+0x60: 16 MiB like DOSBox (memsize 16)
BASES = {
    SEL_CODE: 0,
    SEL_DATA: 0,
    SEL_SCREEN: REAL_LIN + 0xB8000,
    SEL_PSP: PSP_LIN,
    SEL_ENV: ENV_LIN,
    SEL_REAL: REAL_LIN,
}
PHAR = 0x50484152  # EBX = 'PHAR' asks AH=30h for the extender
MAX_COMMAND_TAIL = 126


@dataclass(frozen=True)
class P3Image:
    image: bytes
    base: int
    eip: int
    esp: int
    memory: int  # image + BSS (header: memory needed by the loaded image)
    min_extra: int  # pages


def load_p3(data: bytes) -> P3Image:
    """The flat P3 image of a bound Phar Lap program."""
    if data[:2] not in (b"MZ", b"ZM"):
        raise EmulatorError("not an MZ file")
    # bound program: MZ stub of the extender, then P3 (searched from the end of the stub)
    last_page, pages = struct.unpack_from("<HH", data, 2)
    stub = pages * 512 - ((512 - last_page) if last_page else 0)
    p3 = data.find(b"P3", stub & ~0xF)
    while p3 >= 0 and (p3 + 6 > len(data) or struct.unpack_from("<H", data, p3 + 4)[0] != P3_HEADER):
        p3 = data.find(b"P3", p3 + 1)
    if p3 < 0 or p3 + P3_HEADER > len(data):
        raise EmulatorError("no Phar Lap P3 header found")
    header = data[p3 : p3 + P3_HEADER]
    level = struct.unpack_from("<H", header, 2)[0]
    if level != 1:
        raise EmulatorError(f"P3 with level {level} (only flat = 1)")
    if struct.unpack_from("<I", header, 0x18)[0]:
        raise EmulatorError("P3 with relocations is not supported")
    image_off, image_size = struct.unpack_from("<II", header, 0x26)
    min_extra = struct.unpack_from("<I", header, 0x56)[0]
    base, esp = struct.unpack_from("<II", header, 0x5E)
    eip = struct.unpack_from("<I", header, 0x68)[0]
    memory = struct.unpack_from("<I", header, 0x74)[0]
    image = data[p3 + image_off : p3 + image_off + image_size]
    return P3Image(image, base, eip, esp, max(memory, len(image)), min_extra)


@lru_cache(maxsize=4)
def load_p3_file(path: str, size: int, mtime_ns: int) -> P3Image:
    """`load_p3` of a file, cached by path, size and modification time."""
    with open(path, "rb") as f:
        return load_p3(f.read())


@lru_cache(maxsize=None)
def _reg(name: str) -> int:
    from unicorn import x86_const

    return getattr(x86_const, f"UC_X86_REG_{name}")


def _descriptor(base: int, limit: int, kind: int, dpl: int = 0) -> bytes:
    """32-bit segment descriptor, 4 KiB granularity for large limits. kind: 0x9A code, 0x92 data (with P/DPL)."""
    granularity = 0
    if limit > 0xFFFFF:
        limit >>= 12
        granularity = 0x80
    access = kind | (dpl << 5)
    return struct.pack(
        "<HHBBBB",
        limit & 0xFFFF,
        base & 0xFFFF,
        (base >> 16) & 0xFF,
        access,
        granularity | 0x40 | ((limit >> 16) & 0xF),
        (base >> 24) & 0xFF,
    )


@dataclass
class Result:
    exit_code: int
    output: bytes  # everything written to the CON handles
    elapsed_s: float = 0.0
    calls: dict = field(default_factory=dict)  # count per service (diagnosis)


class Machine:
    """unicorn CPU with memory for one P3 program, reusable: `reset()` restores the loaded state. Only the 4 KiB
    pages of the image that changed are written back (a write into code pages drops the translated blocks), the
    heap is unmapped. Not thread-safe: one machine per thread or process."""

    def __init__(self, p3: P3Image):
        from unicorn import UC_ARCH_X86, UC_HOOK_INTR, UC_HOOK_MEM_INVALID, UC_MODE_32, Uc
        from unicorn import x86_const as r

        self.p3 = p3
        self.active: PharLapEmu | None = None
        self.spent = False
        self.runs = 0
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mu = mu
        end = max(p3.base + p3.memory, p3.esp)
        self.floor = (end + 0xFFFF) & ~0xFFFF  # always mapped: image, BSS, stack
        self.top = self.floor
        mu.mem_map(0, self.floor)
        self.original = bytes(p3.base) + p3.image + bytes(self.floor - p3.base - len(p3.image))
        mu.mem_write(0, self.original)
        mu.mem_map(GDT_LIN, 0x10000)
        mu.mem_map(REAL_LIN, 0x110000)
        gdt = bytearray(8 * 4)
        gdt[0x08:0x10] = _descriptor(0, 0xFFFFFFFF, 0x9A)
        gdt[0x10:0x18] = _descriptor(0, 0xFFFFFFFF, 0x92)
        ldt = bytearray(8 * 8)
        for sel, kind, limit in (
            (SEL_CODE, 0x9A, 0xFFFFFFFF),
            (SEL_DATA, 0x92, 0xFFFFFFFF),
            (SEL_SCREEN, 0x92, 0x7FFF),
            (SEL_PSP, 0x92, 0xFF),
            (SEL_ENV, 0x92, ENV_SIZE - 1),
            (SEL_REAL, 0x92, 0xFFFFF),
        ):
            i = sel & ~7
            ldt[i : i + 8] = _descriptor(BASES[sel], limit, kind)
        mu.mem_write(GDT_LIN, bytes(gdt))
        mu.mem_write(LDT_LIN, bytes(ldt))
        mu.reg_write(r.UC_X86_REG_GDTR, (0, GDT_LIN, len(gdt) - 1, 0))
        mu.reg_write(r.UC_X86_REG_LDTR, (0, LDT_LIN, len(ldt) - 1, 0x82))
        for reg, sel in (
            (r.UC_X86_REG_SS, SEL_DATA),
            (r.UC_X86_REG_DS, SEL_DATA),
            (r.UC_X86_REG_ES, SEL_PSP),
            (r.UC_X86_REG_FS, SEL_DATA),
            (r.UC_X86_REG_GS, SEL_DATA),
            (r.UC_X86_REG_CS, SEL_CODE),
        ):
            mu.reg_write(reg, sel)
        mu.reg_write(r.UC_X86_REG_ESP, p3.esp)
        mu.reg_write(r.UC_X86_REG_EIP, p3.eip)
        self.start = mu.context_save()
        mu.hook_add(UC_HOOK_INTR, lambda m, number, _: self.active._interrupt(number))
        mu.hook_add(UC_HOOK_MEM_INVALID, lambda m, access, address, size, value, _: self.active._memory_fault(
            access, address, size))
        self.fresh = True

    def heap(self, size: int) -> int:
        """Grow the program segment to `size` bytes (never shrinks); returns the new end."""
        new = (size + 0xFFFF) & ~0xFFFF
        if new > self.top:
            self.mu.mem_map(self.top, new - self.top)
            self.top = new
        return self.top

    def reset(self, emu: PharLapEmu) -> None:
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
        if self.top > self.floor:
            mu.mem_unmap(self.floor, self.top - self.floor)
            self.top = self.floor
        now = bytes(mu.mem_read(0, self.floor))
        original = self.original
        for a in range(0, self.floor, PAGE):
            if now[a : a + PAGE] != original[a : a + PAGE]:
                mu.mem_write(a, original[a : a + PAGE])
        mu.mem_write(REAL_LIN, bytes(0x110000))
        mu.context_restore(self.start)


class _PharLapRegs(Regs):
    wide = True

    def __init__(self, mu):
        self.mu = mu

    def get(self, name: str) -> int:
        return self.mu.reg_read(_reg(name))

    def set(self, name: str, value: int) -> None:
        self.mu.reg_write(_reg(name), value)

    def linear(self, seg: int, off: int) -> int:
        base = BASES.get(seg & 0xFFFF & ~3)
        if base is None:
            raise EmulatorError(f"unknown selector {seg & 0xFFFF:#x}")
        return (base + off) & 0xFFFFFFFF

    def read_linear(self, address: int, n: int) -> bytes:
        return bytes(self.mu.mem_read(address, n))

    def write_linear(self, address: int, data: bytes) -> None:
        self.mu.mem_write(address, data)


class PharLapEmu:
    """One run of a Phar Lap P3 program on `fs`. `env`: environment in order; `program`: DOS path of the program
    (end of the environment block)."""

    def __init__(
        self,
        p3: P3Image,
        fs: DosFs,
        args: str,
        env: list[tuple[str, str]],
        program: str,
        timeout_s: float = 120.0,
    ):
        self.p3 = p3
        self.fs = fs
        self.args = args
        self.env = env
        self.program = program
        self.timeout_s = timeout_s
        self.vectors_pm: dict[int, tuple[int, int]] = {}
        self.vectors_rm: dict[int, int] = {}
        self.error: EmulatorError | None = None
        self.calls: dict[str, int] = {}
        self.machine: Machine | None = None

    # --- setup ---------------------------------------------------------------------------------------------------
    def _psp(self) -> bytes:
        psp = bytearray(0x100)
        psp[0:2] = b"\xcd\x20"
        tail = self.args.encode("cp437")
        if tail and not tail.startswith(b" "):
            tail = b" " + tail
        if len(tail) > MAX_COMMAND_TAIL:
            raise EmulatorError(f"command line too long for DOS ({len(tail)} characters)")
        psp[0x80] = len(tail)
        psp[0x81 : 0x81 + len(tail)] = tail
        psp[0x81 + len(tail)] = 0x0D
        struct.pack_into("<H", psp, 0x2C, SEL_ENV)
        # Phar Lap extension: +0x60 = memory limit (WCC386 takes it minus the break as its memory budget)
        struct.pack_into("<I", psp, 0x60, MEMORY_LIMIT)
        return bytes(psp)

    def _environment(self) -> bytes:
        block = b"".join(f"{k}={v}".encode("cp437") + b"\0" for k, v in self.env) + b"\0"
        block += struct.pack("<H", 1) + self.program.encode("cp437") + b"\0"
        if len(block) > ENV_SIZE:
            raise EmulatorError("environment too large")
        return block

    def begin(self, machine: Machine | None = None) -> None:
        """Bring the machine to the loaded state and write PSP and environment; then `execute(p3.eip)`."""
        psp, environment = self._psp(), self._environment()
        self.machine = machine or Machine(self.p3)
        if self.machine.p3 is not self.p3 and self.machine.p3 != self.p3:
            raise EmulatorError("machine belongs to another program")
        self.machine.reset(self)
        self.mu = self.machine.mu
        self.regs = _PharLapRegs(self.mu)
        self.services = DosServices(self.fs, self.regs)
        self.mu.mem_write(PSP_LIN, psp)
        self.mu.mem_write(ENV_LIN, environment)

    def execute(self, start: int, timeout_us: int = 0) -> None:
        """Run from EIP `start` until the program ends, a hook stops it or the time (µs, 0 = none) is up. CPU
        faults land in `self.error`."""
        from unicorn import UcError

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

    def run(self, machine: Machine | None = None) -> Result:
        """Run the program to its end. `machine`: reusable CPU with memory (saves unicorn's translation); without
        one a new one is built."""
        started = time.perf_counter()
        self.begin(machine)
        try:
            self.execute(self.p3.eip, int(self.timeout_s * 1_000_000))
        finally:
            self.finish()
        if self.error is not None:
            raise self.error
        if self.services.exit_code is None:
            raise EmulatorTimeout(f"no end after {self.timeout_s:g} s (EIP={self.regs.get('EIP'):#x})")
        return Result(self.services.exit_code, bytes(self.fs.output), time.perf_counter() - started, dict(self.calls))

    # --- helpers -------------------------------------------------------------------------------------------------
    def _registers(self) -> str:
        r = self.regs
        wide = " ".join(f"{n}={r.get(n):08X}" for n in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"))
        return wide + " " + " ".join(f"{n}={r.get(n):04X}" for n in ("CS", "DS", "ES", "SS"))

    def _location(self, number: int | None = None) -> str:
        """CS:EIP of the current instruction; for a software interrupt the `int nn` that raised it."""
        eip = self.regs.get("EIP")
        if number is not None and eip >= 2:
            try:
                if bytes(self.mu.mem_read(eip - 2, 2)) == bytes([0xCD, number]):
                    eip -= 2
            except Exception:
                pass
        return f"{self.regs.get('CS') & 0xFFFF:04X}:{eip:08X}"

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

    # --- interrupts ----------------------------------------------------------------------------------------------
    def _interrupt(self, number: int) -> None:
        if self.error is not None:
            self.mu.emu_stop()
            return
        try:
            self._timer()
            if number == 0x21:
                self._int21()
            elif number == 0x2F:
                self._int2f()
            else:
                raise Unsupported(f"unsupported interrupt INT {number:02X}h")
        except EmulatorError as e:
            self._abort(str(e), number)
        except Exception as e:  # a bug in the emulation: never run on
            self._abort(f"emulation of INT {number:02X}h: {type(e).__name__}: {e}", number)

    def _timer(self) -> None:
        """BIOS tick counter at 0:46C (18.2 per second since midnight), updated on every interrupt."""
        lt = time.localtime()
        seconds = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec + (time.time() % 1)
        self.mu.mem_write(REAL_LIN + 0x46C, struct.pack("<I", int(seconds * 1193180 / 65536) & 0xFFFFFFFF))

    def _int2f(self) -> None:
        ax = self.regs.get("EAX") & 0xFFFF
        self._count(f"2F/{ax:04X}")
        if ax == 0x1686:  # DPMI: CPU mode? No DPMI host (like Phar Lap over VCPI in DOSBox): AX stays
            return
        raise Unsupported(f"unsupported INT 2Fh AX={ax:04X}h")

    def _int21(self) -> None:
        eax = self.regs.get("EAX")
        ah, al = (eax >> 8) & 0xFF, eax & 0xFF
        self._count(f"21/{ah:02X}" + (f"{al:02X}" if ah in (0x25, 0x44, 0x42, 0x3D, 0x43, 0x57) else ""))
        handler = getattr(self, f"_ah_{ah:02x}", None)
        if handler is not None:
            handler(al)
        elif not self.services.call(ah, al):
            raise Unsupported(f"unsupported INT 21h AH={ah:02X}h")
        if self.services.exit_code is not None:
            self.mu.emu_stop()

    # 30h: DOS version; with EBX='PHAR' the extender answers
    def _ah_30(self, al: int) -> None:
        r = self.regs
        if r.get("EBX") == PHAR:
            r.set("EAX", (0x4458 << 16) | 0x0005)  # 'DX', DOS 5.0
            r.set("EBX", 0x00000034 | 0x00003100)  # BL '4' (386|DOS-Extender 4.x), BH '1'
            r.set("ECX", 0)
            r.set("EDX", 0)
        else:
            r.set("EAX", 0x0005)
        r.carry(False)

    # 4Ah: Phar Lap: grow or shrink a segment (ES = selector, EBX = pages)
    def _ah_4a(self, al: int) -> None:
        r = self.regs
        sel = r.get("ES") & 0xFFFF
        pages = r.get("EBX")
        if sel & ~3 not in (SEL_DATA, SEL_CODE):
            raise Unsupported(f"unsupported INT 21h AH=4Ah for selector {sel:#x}")
        size = pages * PAGE
        if size > HEAP_MAX:
            r.set("EBX", HEAP_MAX // PAGE)
            self.services.fail(8)
            return
        self.machine.heap(size)
        r.carry(False)

    # 2Fh: get DTA (ES:EBX)
    def _ah_2f(self, al: int) -> None:
        self.regs.set("ES", SEL_DATA)
        self.regs.set("EBX", self.services.dta)

    # 35h: get interrupt vector
    def _ah_35(self, al: int) -> None:
        self.regs.set("ES", SEL_CODE)
        self.regs.set("EBX", 0)

    # 25h: Phar Lap services (AL = subfunction)
    def _ah_25(self, al: int) -> None:
        r = self.regs
        cl = r.get("ECX") & 0xFF
        if al == 0x02:  # get protected-mode vector -> ES:EBX
            sel, off = self.vectors_pm.get(cl, (SEL_CODE, 0))
            r.set("ES", sel)
            r.set("EBX", off)
        elif al == 0x03:  # get real-mode vector -> EBX = segment:offset
            r.set("EBX", self.vectors_rm.get(cl, 0))
        elif al == 0x04:  # set protected-mode vector (DS:EDX); never raised
            self.vectors_pm[cl] = (r.get("DS") & 0xFFFF, r.get("EDX"))
        elif al == 0x05:  # set real-mode vector (EBX)
            self.vectors_rm[cl] = r.get("EBX")
        elif al == 0x06:  # vector always taken in protected mode (DS:EDX)
            self.vectors_pm[cl] = (r.get("DS") & 0xFFFF, r.get("EDX"))
            self.vectors_rm[cl] = 0
        elif al == 0x07:  # set both: protected mode DS:EDX, real mode EBX
            self.vectors_pm[cl] = (r.get("DS") & 0xFFFF, r.get("EDX"))
            self.vectors_rm[cl] = r.get("EBX")
        elif al == 0x26:  # configuration: DS:EBX buffer (0x100 bytes configuration + 0x100 swapping)
            buffer = bytearray(0x200)
            # +0x108: selector of the first MB (WCC386 reads the BIOS tick counter 0:46C through it)
            struct.pack_into("<H", buffer, 0x108, SEL_REAL)
            r.write(r.get("DS"), r.get("EBX"), bytes(buffer))
        else:
            raise Unsupported(f"unsupported Phar Lap service AX=25{al:02X}h")
        r.carry(False)
