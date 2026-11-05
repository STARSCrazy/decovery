"""INT 21h services shared by the DOS hosts, written against a small register/memory adapter (`Regs`).

The Phar Lap host passes pointers as DS:EDX and counts in ECX; a 16-bit host as DS:DX and CX. `Regs.arg("DX")`
returns whichever the host uses, so the services stay the same. Services a host implements differently (memory,
interrupt vectors, the DTA address as a far pointer, the extender's own calls) stay in the host.
"""

from __future__ import annotations

import struct
import time

from .dosfs import DosFs
from .errors import DosError, Unsupported

CARRY = 0x0001
ZERO = 0x0040
SEARCH_KEY = 0x0D  # DTA offset of the search number (DOS keeps its search state in bytes 0-20)


class Regs:
    """Register and memory access of one host. `wide`: pointers and counts are 32-bit (EDX, ECX)."""

    wide = True

    def get(self, name: str) -> int:
        raise NotImplementedError

    def set(self, name: str, value: int) -> None:
        raise NotImplementedError

    def linear(self, seg: int, off: int) -> int:
        """Linear address of `seg`:`off` (`seg` a selector or a real-mode segment value)."""
        raise NotImplementedError

    def read_linear(self, address: int, n: int) -> bytes:
        raise NotImplementedError

    def write_linear(self, address: int, data: bytes) -> None:
        raise NotImplementedError

    # Derived helpers ---------------------------------------------------------------------------------------------
    def arg(self, name: str) -> int:
        """The 16-bit register `name` ("DX", "CX", "SI", ...) or its 32-bit form on a wide host."""
        value = self.get("E" + name)
        return value if self.wide else value & 0xFFFF

    def read(self, seg: int, off: int, n: int) -> bytes:
        return self.read_linear(self.linear(seg, off), n)

    def write(self, seg: int, off: int, data: bytes) -> None:
        self.write_linear(self.linear(seg, off), data)

    def string(self, seg: int, off: int, max_n: int = 260) -> str:
        """ASCIIZ string at `seg`:`off` (CP437)."""
        address = self.linear(seg, off)
        try:
            raw = self.read_linear(address, max_n)
        except Exception:  # end of a mapped region: byte by byte
            chunk = bytearray()
            while len(chunk) < max_n:
                c = self.read_linear(address + len(chunk), 1)[0]
                if c == 0:
                    break
                chunk.append(c)
            raw = bytes(chunk)
        return raw.split(b"\0", 1)[0].decode("cp437")

    def carry(self, on: bool) -> None:
        flags = self.get("EFLAGS")
        self.set("EFLAGS", (flags | CARRY) if on else (flags & ~CARRY))

    def set_low(self, name: str, value: int) -> None:
        """Set the low byte of an E-register (AL, DL, ...)."""
        self.set(name, (self.get(name) & 0xFFFFFF00) | (value & 0xFF))


class DosServices:
    """INT 21h functions on a `DosFs`. `call(ah, al)` returns False for a function it does not provide."""

    def __init__(self, fs: DosFs, regs: Regs):
        self.fs = fs
        self.regs = regs
        self.dta = 0  # linear address of the disk transfer area
        self.dta_far = (0, 0)  # the DTA as set: (segment or selector, offset)
        self.searches = 0  # number of the last find-first search
        self.exit_code: int | None = None

    def call(self, ah: int, al: int) -> bool:
        handler = getattr(self, f"_ah_{ah:02x}", None)
        if handler is None:
            return False
        try:
            handler(al)
        except DosError as e:
            self.fail(e.code)
        return True

    def ok(self) -> None:
        self.regs.carry(False)

    def fail(self, code: int) -> None:
        r = self.regs
        r.set("EAX", (r.get("EAX") & 0xFFFF0000) | code)
        r.carry(True)

    def _name(self, seg_reg: str = "DS", off_reg: str = "DX") -> str:
        return self.regs.string(self.regs.get(seg_reg), self.regs.arg(off_reg))

    def _handle(self, h: int) -> None:
        self.regs.set("EAX", h)
        self.ok()

    # 02h: character DL to the console
    def _ah_02(self, al: int) -> None:
        self.fs.write(1, bytes([self.regs.get("EDX") & 0xFF]))
        self.regs.set_low("EAX", self.regs.get("EDX") & 0xFF)

    # 06h: direct console I/O: DL = FFh reads (no key: ZF set, AL = 0), any other DL is written
    def _ah_06(self, al: int) -> None:
        r = self.regs
        dl = r.get("EDX") & 0xFF
        if dl == 0xFF:
            r.set_low("EAX", 0)
            r.set("EFLAGS", r.get("EFLAGS") | ZERO)
        else:
            self.fs.write(1, bytes([dl]))
            r.set_low("EAX", dl)

    # 09h: "$"-terminated string at DS:DX to the console
    def _ah_09(self, al: int) -> None:
        r = self.regs
        address = r.linear(r.get("DS"), r.arg("DX"))
        text = bytearray()
        while len(text) < 0x10000:
            chunk = r.read_linear(address + len(text), 64)
            end = chunk.find(b"$")
            if end >= 0:
                text += chunk[:end]
                break
            text += chunk
        else:
            raise Unsupported("INT 21h AH=09h: no '$' within 64 KiB")
        self.fs.write(1, bytes(text))
        r.set_low("EAX", ord("$"))

    # 0Bh: console input status: no key waiting (AL = 0); C runtimes poll it for Ctrl-Break
    def _ah_0b(self, al: int) -> None:
        self.regs.set_low("EAX", 0)

    # 0Eh: select drive (DL); AL = number of drives
    def _ah_0e(self, al: int) -> None:
        self.fs.select_drive(self.regs.get("EDX") & 0xFF)
        self.regs.set_low("EAX", 26)

    # 19h: current drive
    def _ah_19(self, al: int) -> None:
        self.regs.set_low("EAX", ord(self.fs.current) - ord("A"))

    # 1Ah: set DTA (DS:DX)
    def _ah_1a(self, al: int) -> None:
        self.dta_far = (self.regs.get("DS") & 0xFFFF, self.regs.arg("DX"))
        self.dta = self.regs.linear(*self.dta_far)

    # 29h: parse a file name at DS:SI into the FCB at ES:DI. AL bit 0: skip leading separators; bits 1-3: keep
    # drive, name, extension of the FCB when the text has none. AL = 0 (no wildcards), 1 (wildcards), FFh (bad
    # drive); SI points after the name.
    def _ah_29(self, al: int) -> None:
        r = self.regs
        si, di = r.arg("SI"), r.arg("DI")
        text = r.read(r.get("DS"), si, 128) + b"\0"
        fcb = bytearray(r.read(r.get("ES"), di, 12))
        i = 0
        while text[i] in b" \t":
            i += 1
        if al & 1 and text[i] in b":.;,=+":
            i += 1
            while text[i] in b" \t":
                i += 1
        result = 0
        if text[i + 1] == ord(":") and chr(text[i]).isalpha():
            drive = chr(text[i]).upper()
            fcb[0] = ord(drive) - ord("A") + 1
            if drive not in self.fs.drives:
                result = 0xFF
            i += 2
        elif not al & 2:
            fcb[0] = 0

        def field(width: int) -> bytes | None:
            nonlocal i
            out = bytearray()
            while text[i] > 0x20 and text[i] not in b'."/\\[]:|<>+=;,':
                c = text[i]
                if c == ord("*"):
                    out += b"?" * (width - len(out))
                elif len(out) < width:
                    out.append(ord(chr(c).upper()) if c < 0x80 else c)
                i += 1
            return bytes(out.ljust(width, b" ")[:width]) if out else None

        name = field(8)
        if name is not None:
            fcb[1:9] = name
        elif not al & 4:
            fcb[1:9] = b" " * 8
        ext = None
        if text[i] == ord("."):
            i += 1
            ext = field(3)
        if ext is not None:
            fcb[9:12] = ext
        elif not al & 8:
            fcb[9:12] = b" " * 3
        if result == 0 and b"?" in fcb[1:12]:
            result = 1
        r.write(r.get("ES"), di, bytes(fcb))
        end = si + i
        if not r.wide:
            end = (r.get("ESI") & 0xFFFF0000) | (end & 0xFFFF)
        r.set("ESI", end)
        r.set_low("EAX", result)

    # 30h: DOS version 5.0
    def _ah_30(self, al: int) -> None:
        r = self.regs
        r.set("EAX", (r.get("EAX") & 0xFFFF0000) | 0x0005)
        r.set("EBX", r.get("EBX") & 0xFFFF0000)
        r.set("ECX", r.get("ECX") & 0xFFFF0000)

    # 36h: free disk space of drive DL (0 = current): AX sectors per cluster, BX free clusters, CX bytes per
    # sector, DX clusters; AX = FFFFh for a drive that does not exist. Always about 1 GiB free.
    def _ah_36(self, al: int) -> None:
        r = self.regs
        number = r.get("EDX") & 0xFF
        drive = self.fs.current if number == 0 else chr(ord("A") + number - 1)
        if drive not in self.fs.drives:
            r.set("EAX", (r.get("EAX") & 0xFFFF0000) | 0xFFFF)
            return
        for name, value in (("EAX", 64), ("EBX", 0x7FFF), ("ECX", 512), ("EDX", 0xFFF0)):
            r.set(name, (r.get(name) & 0xFFFF0000) | value)

    # 2Ah: date
    def _ah_2a(self, al: int) -> None:
        lt = time.localtime()
        self.regs.set("ECX", lt.tm_year)
        self.regs.set("EDX", (lt.tm_mon << 8) | lt.tm_mday)
        self.regs.set_low("EAX", (lt.tm_wday + 1) % 7)

    # 2Ch: time
    def _ah_2c(self, al: int) -> None:
        t = time.time()
        lt = time.localtime(t)
        self.regs.set("ECX", (lt.tm_hour << 8) | lt.tm_min)
        self.regs.set("EDX", (lt.tm_sec << 8) | int((t % 1) * 100))

    # 33h: Ctrl-Break check
    def _ah_33(self, al: int) -> None:
        if al == 0:
            self.regs.set_low("EDX", 0)
        elif al == 5:
            self.regs.set_low("EDX", 3)  # boot drive C:

    # 37h: switch character
    def _ah_37(self, al: int) -> None:
        if al != 0:
            raise Unsupported(f"unsupported INT 21h AH=37h AL={al:02X}h")
        self.regs.set("EAX", self.regs.get("EAX") & 0xFFFFFF00)
        self.regs.set_low("EDX", ord("/"))

    # 3Ch: create, 5Bh: create new
    def _ah_3c(self, al: int) -> None:
        self._handle(self.fs.create(self._name()))

    def _ah_5b(self, al: int) -> None:
        self._handle(self.fs.create_new(self._name()))

    # 3Dh: open (AL = access mode)
    def _ah_3d(self, al: int) -> None:
        self._handle(self.fs.open(self._name(), al & 7))

    # 3Eh: close
    def _ah_3e(self, al: int) -> None:
        self.fs.close(self.regs.get("EBX"))
        self.ok()

    # 3Fh: read (BX handle, CX count, DS:DX buffer)
    def _ah_3f(self, al: int) -> None:
        r = self.regs
        data = self.fs.read(r.get("EBX"), r.arg("CX"))
        if data:
            r.write(r.get("DS"), r.arg("DX"), data)
        r.set("EAX", len(data))
        self.ok()

    # 40h: write (BX handle, CX count, DS:DX buffer); CX = 0 truncates
    def _ah_40(self, al: int) -> None:
        r = self.regs
        n = r.arg("CX")
        data = r.read(r.get("DS"), r.arg("DX"), n) if n else b""
        r.set("EAX", self.fs.write(r.get("EBX"), data))
        self.ok()

    # 41h: delete
    def _ah_41(self, al: int) -> None:
        self.fs.delete(self._name())
        self.ok()

    # 42h: move file pointer (CX:DX offset, AL origin) -> DX:AX
    def _ah_42(self, al: int) -> None:
        r = self.regs
        offset = ((r.get("ECX") & 0xFFFF) << 16) | (r.get("EDX") & 0xFFFF)
        target = self.fs.seek(r.get("EBX"), offset, al)
        r.set("EAX", target & 0xFFFF)
        r.set("EDX", (target >> 16) & 0xFFFF)
        self.ok()

    # 43h: get (AL=0) or set file attributes
    def _ah_43(self, al: int) -> None:
        attr = self.fs.attributes(self._name())
        if al == 0:
            self.regs.set("ECX", attr)
        self.ok()  # setting attributes has no meaning on the host

    # 44h: IOCTL, only AL=00h (device information)
    def _ah_44(self, al: int) -> None:
        if al != 0:
            raise Unsupported(f"unsupported INT 21h AH=44h AL={al:02X}h")
        r = self.regs
        info = self.fs.ioctl_info(r.get("EBX"))
        r.set("EDX", info)
        r.set("EAX", (r.get("EAX") & 0xFFFF0000) | info)
        self.ok()

    # 45h: duplicate handle BX -> AX (both share the file position)
    def _ah_45(self, al: int) -> None:
        self._handle(self.fs.dup(self.regs.get("EBX")))

    # 46h: make handle CX refer to the file of BX (CX is closed first if open)
    def _ah_46(self, al: int) -> None:
        self.fs.force_dup(self.regs.get("EBX"), self.regs.get("ECX"))
        self.ok()

    # 47h: current directory (DL drive, DS:SI buffer)
    def _ah_47(self, al: int) -> None:
        r = self.regs
        cwd = self.fs.getcwd(r.get("EDX") & 0xFF)
        r.write(r.get("DS"), r.arg("SI"), cwd.encode("cp437") + b"\0")
        self.ok()

    # 4Ch: end the program with exit code AL
    def _ah_4c(self, al: int) -> None:
        self.fs.close_all()
        self.exit_code = al

    # 4Eh: find first (DS:DX pattern, CX attributes), 4Fh: find next; results go to the DTA. As in DOS, the
    # search state lives in the reserved bytes of the DTA (here: a search number), so a program may copy the record
    # elsewhere and continue from the copy (WMAKE does).
    def _ah_4e(self, al: int) -> None:
        self.searches += 1
        entry = self.fs.find_first(self._name(), self.regs.get("ECX") & 0xFF, self.searches)
        self._found(entry, self.searches)

    def _ah_4f(self, al: int) -> None:
        key = struct.unpack("<I", self.regs.read_linear(self.dta + SEARCH_KEY, 4))[0]
        self._found(self.fs.find_next(key), key)

    def _found(self, entry, key: int) -> None:
        record = bytearray(entry.dta())
        struct.pack_into("<I", record, SEARCH_KEY, key)
        self.regs.write_linear(self.dta, bytes(record))
        self.ok()

    # 56h: rename (DS:DX old, ES:DI new)
    def _ah_56(self, al: int) -> None:
        self.fs.rename(self._name(), self._name("ES", "DI"))
        self.ok()

    # 57h: get (AL=0) or set (AL=1) file date and time
    def _ah_57(self, al: int) -> None:
        r = self.regs
        if al == 0:
            date, clock = self.fs.file_time(r.get("EBX"))
            r.set("ECX", clock)
            r.set("EDX", date)
        elif al == 1:
            self.fs.file_time(r.get("EBX"))  # checks the handle; the host keeps its own time
        else:
            raise Unsupported(f"unsupported INT 21h AH=57h AL={al:02X}h")
        self.ok()
