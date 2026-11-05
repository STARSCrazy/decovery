"""DOS file system on host directories: drive letters map to folders, names are matched case-insensitively and
shortened to 8.3 like DOS does. Operations raise `DosError` with the DOS error code the INT 21h service returns.

Handles 0-4 are the devices CON (stdin, stdout, stderr), AUX and PRN; files get the lowest free handle from 5.
Everything written to a CON handle is collected in `output`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import DosError

DEVICES = ("CON", "NUL", "AUX", "PRN")

FILE_NOT_FOUND = 2
PATH_NOT_FOUND = 3
ACCESS_DENIED = 5
INVALID_HANDLE = 6
INVALID_DRIVE = 15
NOT_SAME_DEVICE = 0x11
NO_MORE_FILES = 0x12
SEEK_ERROR = 0x19
FILE_EXISTS = 80

ATTR_READ_ONLY = 0x01
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20


def short_name(name: str) -> str:
    """DOS spelling of one path component: upper case, stem 8, extension 3."""
    name = name.upper()
    if name in (".", ".."):
        return name
    stem, dot, ext = name.partition(".")
    return stem[:8] + (("." + ext[:3]) if dot else "")


def dos_date_time(t: float) -> tuple[int, int]:
    lt = time.localtime(t)
    date = ((max(lt.tm_year, 1980) - 1980) << 9) | (lt.tm_mon << 5) | lt.tm_mday
    clock = (lt.tm_hour << 11) | (lt.tm_min << 5) | (lt.tm_sec // 2)
    return date, clock


def matches(name: str, pattern: str) -> bool:
    """DOS wildcard match of 8.3 names: `?` matches one character, `*` the rest of stem or extension."""

    def split(n: str) -> tuple[str, str]:
        stem, _, ext = n.partition(".")
        return stem.ljust(8)[:8], ext.ljust(3)[:3]

    def same(actual: str, mask: str) -> bool:
        expanded = ""
        for i, c in enumerate(mask):
            if c == "*":
                expanded += "?" * (len(mask) - i)
                break
            expanded += c
        return all(m == "?" or m == a for a, m in zip(actual, expanded.ljust(len(actual))))

    name_stem, name_ext = split(name)
    mask_stem, mask_ext = split(pattern)
    return same(name_stem, mask_stem) and same(name_ext, mask_ext)


class OpenFile:
    __slots__ = ("file", "path", "device", "writable")

    def __init__(self, file: BinaryIO | None, path: Path | None, device: str = "", writable: bool = False):
        self.file, self.path, self.device, self.writable = file, path, device, writable


@dataclass(frozen=True)
class FindEntry:
    name: str
    attr: int
    time: int
    date: int
    size: int

    def dta(self) -> bytes:
        """The 43-byte find record DOS writes to the DTA."""
        record = bytearray(43)
        record[0x15] = self.attr
        record[0x16:0x1E] = (
            self.time.to_bytes(2, "little") + self.date.to_bytes(2, "little") + self.size.to_bytes(4, "little")
        )
        name = self.name.encode("cp437", "replace")[:12]
        record[0x1E : 0x1E + len(name)] = name
        return bytes(record)


class DosFs:
    """Drives of one DOS program run. `drives`: {"C": Path, ...}; `read_only`: drives without write access."""

    def __init__(self, drives: dict[str, Path], read_only: set[str] | frozenset[str] = frozenset(), current: str = "C"):
        self.drives = {k.upper(): Path(v) for k, v in drives.items()}
        self.read_only = {k.upper() for k in read_only}
        self.current = current.upper()
        self.cwd = {k: "" for k in self.drives}  # current directory per drive, without leading backslash
        self.output = bytearray()
        self.handles: dict[int, OpenFile] = {}
        self.searches: dict[int, list[Path]] = {}
        self._devices()

    def _devices(self) -> None:
        self.handles = {
            0: OpenFile(None, None, "CON"),
            1: OpenFile(None, None, "CON", True),
            2: OpenFile(None, None, "CON", True),
            3: OpenFile(None, None, "AUX", True),
            4: OpenFile(None, None, "PRN", True),
        }

    # --- names ---------------------------------------------------------------------------------------------------
    def resolve(self, dos_path: str) -> tuple[str, Path]:
        """DOS path -> (drive, host path). Components are shortened to 8.3; existing entries keep their case."""
        n = dos_path.replace("/", "\\")
        if len(n) >= 2 and n[1] == ":":
            drive, n = n[0].upper(), n[2:]
        else:
            drive = self.current
        if drive not in self.drives:
            raise DosError(PATH_NOT_FOUND)
        if not n.startswith("\\"):
            n = self.cwd[drive] + "\\" + n if self.cwd[drive] else n
        parts: list[str] = []
        for part in n.split("\\"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(short_name(part))
        path = self.drives[drive]
        for part in parts:
            path = self._entry(path, part)
        return drive, path

    def host(self, dos_path: str) -> Path:
        return self.resolve(dos_path)[1]

    @staticmethod
    def _entry(folder: Path, name: str) -> Path:
        candidate = folder / name
        if candidate.exists():
            return candidate
        try:
            for p in folder.iterdir():
                if short_name(p.name) == name:
                    return p
        except OSError:
            pass
        return candidate

    # --- handles -------------------------------------------------------------------------------------------------
    def _new_handle(self, entry: OpenFile) -> int:
        h = 5
        while h in self.handles:
            h += 1
        self.handles[h] = entry
        return h

    def _file(self, h: int) -> OpenFile:
        entry = self.handles.get(h & 0xFFFF)
        if entry is None:
            raise DosError(INVALID_HANDLE)
        return entry

    def open(self, name: str, mode: int) -> int:
        """Open an existing file; `mode` is AL & 7 (0 read, 1 write, 2 read/write)."""
        device = name.upper().rstrip(":")
        if device in DEVICES:
            return self._new_handle(OpenFile(None, None, device, mode != 0))
        drive, path = self.resolve(name)
        if not path.is_file():
            raise DosError(FILE_NOT_FOUND if path.parent.is_dir() else PATH_NOT_FOUND)
        if mode != 0 and drive in self.read_only:
            raise DosError(ACCESS_DENIED)
        f = open(path, "rb" if mode == 0 else "r+b")
        return self._new_handle(OpenFile(f, path, writable=mode != 0))

    def create(self, name: str) -> int:
        return self._create(name, new_only=False)

    def create_new(self, name: str) -> int:
        return self._create(name, new_only=True)

    def _create(self, name: str, new_only: bool) -> int:
        drive, path = self.resolve(name)
        if drive in self.read_only:
            raise DosError(ACCESS_DENIED)
        if new_only and path.exists():
            raise DosError(FILE_EXISTS)
        if not path.parent.is_dir():
            raise DosError(PATH_NOT_FOUND)
        f = open(path, "w+b")
        return self._new_handle(OpenFile(f, path, writable=True))

    def close(self, h: int) -> None:
        entry = self.handles.pop(h & 0xFFFF, None)
        if entry is None:
            raise DosError(INVALID_HANDLE)
        if entry.file is not None:
            entry.file.close()

    def close_all(self) -> None:
        """DOS closes every open file when the program ends."""
        for entry in self.handles.values():
            if entry.file is not None:
                entry.file.close()
        self._devices()

    def read(self, h: int, n: int) -> bytes:
        entry = self._file(h)
        if entry.file is None:
            return b""
        return entry.file.read(n)

    def write(self, h: int, data: bytes) -> int:
        """Write `data`; an empty write truncates a file at its position. Returns the count DOS reports."""
        entry = self._file(h)
        if entry.file is None:
            if entry.device == "CON":
                self.output += data
        else:
            if not entry.writable:
                raise DosError(ACCESS_DENIED)
            if not data:
                entry.file.truncate()
            else:
                entry.file.write(data)
        return len(data)

    def seek(self, h: int, offset: int, whence: int) -> int:
        """`offset` is the unsigned 32-bit CX:DX value; signed for `whence` 1 (current) and 2 (end)."""
        entry = self._file(h)
        if whence == 0:
            target = offset
        else:
            if offset & 0x80000000:
                offset -= 1 << 32
            if entry.file is None:
                target = 0
            elif whence == 1:
                target = entry.file.tell() + offset
            elif whence == 2:
                target = entry.file.seek(0, 2) + offset
            else:
                raise DosError(1)
        if target < 0:
            raise DosError(SEEK_ERROR)
        if entry.file is not None:
            entry.file.seek(target)
        return target

    def ioctl_info(self, h: int) -> int:
        """Device information word of IOCTL AL=00h."""
        entry = self._file(h)
        if entry.file is None:
            return 0x80D3 if entry.device == "CON" else (0x8084 if entry.device == "NUL" else 0x80C0)
        return 0x0002  # a file on drive C:

    def file_time(self, h: int) -> tuple[int, int]:
        """(date, time) of an open file in DOS format; the current time for devices."""
        entry = self._file(h)
        t = entry.path.stat().st_mtime if (entry.file is not None and entry.path is not None) else time.time()
        return dos_date_time(t)

    # --- names on disk -------------------------------------------------------------------------------------------
    def delete(self, name: str) -> None:
        drive, path = self.resolve(name)
        if drive in self.read_only:
            raise DosError(ACCESS_DENIED)
        if not path.is_file():
            raise DosError(FILE_NOT_FOUND)
        path.unlink()

    def rename(self, old: str, new: str) -> None:
        drive_old, path_old = self.resolve(old)
        drive_new, path_new = self.resolve(new)
        if drive_old != drive_new:
            raise DosError(NOT_SAME_DEVICE)
        if drive_old in self.read_only:
            raise DosError(ACCESS_DENIED)
        if not path_old.exists():
            raise DosError(FILE_NOT_FOUND)
        if path_new.exists():
            raise DosError(ACCESS_DENIED)
        path_old.rename(path_new)

    def attributes(self, name: str) -> int:
        drive, path = self.resolve(name)
        if not path.exists():
            raise DosError(FILE_NOT_FOUND)
        if path.is_dir():
            return ATTR_DIRECTORY
        return ATTR_ARCHIVE | (ATTR_READ_ONLY if drive in self.read_only else 0)

    def find_first(self, pattern: str, attr: int, key: int) -> FindEntry:
        """Start a search for `pattern` (wildcards in the last component); `key` identifies it (the DTA address)."""
        n = pattern.replace("/", "\\")
        folder, _, name = n.rpartition("\\")
        if len(n) >= 2 and n[1] == ":" and not folder:
            folder, name = n[:2], n[2:]
        _, host_folder = self.resolve(folder + "\\" if folder else ".")
        if not host_folder.is_dir():
            raise DosError(PATH_NOT_FOUND)
        mask = short_name(name)
        found = []
        for p in sorted(host_folder.iterdir(), key=lambda x: x.name.upper()):
            if p.is_dir() and not attr & ATTR_DIRECTORY:
                continue
            if matches(short_name(p.name), mask):
                found.append(p)
        self.searches[key] = found
        return self.find_next(key)

    def find_next(self, key: int) -> FindEntry:
        found = self.searches.get(key) or []
        if not found:
            raise DosError(NO_MORE_FILES)
        p = found.pop(0)
        st = p.stat()
        date, clock = dos_date_time(st.st_mtime)
        return FindEntry(
            name=short_name(p.name),
            attr=ATTR_DIRECTORY if p.is_dir() else ATTR_ARCHIVE,
            time=clock,
            date=date,
            size=st.st_size if p.is_file() else 0,
        )

    # --- drives --------------------------------------------------------------------------------------------------
    def getcwd(self, drive_number: int) -> str:
        """Current directory (without drive and leading backslash); `drive_number` 0 = current, 1 = A:, ..."""
        drive = self.current if drive_number == 0 else chr(ord("A") + drive_number - 1)
        if drive not in self.drives:
            raise DosError(INVALID_DRIVE)
        return self.cwd[drive]

    def select_drive(self, number: int) -> None:
        """Select drive `number` (0 = A:); an unmounted drive leaves the current one."""
        drive = chr(ord("A") + number)
        if drive in self.drives:
            self.current = drive
