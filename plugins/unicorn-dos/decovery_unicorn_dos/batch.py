"""Turns the command lines of a `runner/run` job into steps, like COMMAND.COM running them as a batch file.

`SET NAME=value` changes the environment of the following lines (an empty value removes the variable), a leading
`@` suppresses the echo of its line, `ECHO OFF`/`ECHO ON` switch the echo, `ECHO text` prints, `REM` does nothing.
Any other line runs a program: with a path as given, otherwise from the current directory and then the `PATH`
directories (the tool drive D:), trying `.COM`, `.EXE` and `.BAT` when no extension is given. A `.BAT` file (on the
build drive C:) is read and its lines run in place, as with `CALL`.

Every program is looked at before anything runs: one that no host of this plugin can run makes the whole call
fail with `RUNNER_UNSUPPORTED`, so the caller can try its next runner.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

from decovery_plugin import RpcError

from .dosfs import DosFs
from .errors import RUNNER_UNSUPPORTED, DosError

HOSTS = frozenset({"pharlap"})  # hosts this plugin provides
INITIAL_ENV = (("COMSPEC", "Z:\\COMMAND.COM"), ("PATH", "Z:\\"))
MAX_BATCH_DEPTH = 8
P3_HEADER = 0x180
MAX_COM_SIZE = 0xFF00

_SET = re.compile(r"^SET\s+([^=\s]+)\s*=(.*)$", re.IGNORECASE)


@dataclass(frozen=True)
class Step:
    """One line of a job. kind: "set", "echo" (prints `text`), "noop", "run" or "missing" (`text` = message)."""

    kind: str
    echo: str | None  # the line as echoed after the prompt; None when echo is off or the line starts with "@"
    text: str | None = None
    env: tuple[tuple[str, str], ...] = ()  # environment the program gets ("run") or after the line ("set")
    program: str | None = None  # host path of the program
    dos_path: str | None = None
    args: str = ""
    host: str | None = None


def _program_kind(data: bytes) -> tuple[str | None, str]:
    """(host or None, description) of an executable."""
    if data[:2] not in (b"MZ", b"ZM"):
        if len(data) > MAX_COM_SIZE:
            return None, "file too large for a COM program"
        return "realmode", "COM program"
    if len(data) < 0x1C:
        return None, "truncated MZ header"
    last_page, pages = struct.unpack_from("<HH", data, 2)
    stub = pages * 512 - ((512 - last_page) if last_page else 0)
    p3 = data.find(b"P3", stub & ~0xF)
    while p3 >= 0 and (p3 + 6 > len(data) or struct.unpack_from("<H", data, p3 + 4)[0] != P3_HEADER):
        p3 = data.find(b"P3", p3 + 1)
    if p3 >= 0 and p3 + P3_HEADER <= len(data):
        level = struct.unpack_from("<H", data, p3 + 2)[0]
        if level != 1:
            return None, f"Phar Lap P3 image with level {level}"
        if struct.unpack_from("<I", data, p3 + 0x18)[0]:
            return None, "Phar Lap P3 image with relocations"
        return "pharlap", "Phar Lap P3 image"
    if len(data) >= 0x40 and struct.unpack_from("<H", data, 0x18)[0] >= 0x40:
        new_header = struct.unpack_from("<I", data, 0x3C)[0]
        signature = data[new_header : new_header + 2]
        if signature in (b"LE", b"LX", b"NE", b"PE"):
            return None, f"{signature.decode()} executable"
    return "realmode", "real-mode MZ program"


def choose_host(data: bytes) -> str | None:
    """"pharlap" for a bound Phar Lap program with a flat P3 image, "realmode" for other MZ and COM programs, None
    for what no host runs (LE/LX/NE/PE, P3 with relocations or segments)."""
    return _program_kind(data)[0]


def _join(folder: str, name: str) -> str:
    return folder.rstrip("\\") + "\\" + name


def _find_program(fs: DosFs, name: str, env: list[tuple[str, str]]) -> tuple[Path, str] | None:
    name = name.replace("/", "\\").upper()
    last = name.rsplit("\\", 1)[-1]
    candidates = [name] if "." in last else [name + ext for ext in (".COM", ".EXE", ".BAT")]
    if "\\" in name or ":" in name:
        folders = [""]
    else:
        path = dict(env).get("PATH", "")
        folders = [f"{fs.current}:\\{fs.cwd[fs.current]}"] + [p for p in path.split(";") if p.strip()]
    for folder in folders:
        for candidate in candidates:
            dos = _join(folder, candidate) if folder else candidate
            if not (len(dos) >= 2 and dos[1] == ":"):
                dos = f"{fs.current}:" + ("" if dos.startswith("\\") else "\\") + dos
            try:
                host = fs.host(dos)
            except DosError:
                continue
            if host.is_file():
                return host, dos[0].upper() + dos[1:].upper()
    return None


def plan(
    commands: list[str],
    drives: dict[str, Path],
    hosts: frozenset[str] = HOSTS,
    current: str = "C",
) -> list[Step]:
    """Steps of one job. Raises `RpcError(RUNNER_UNSUPPORTED)` for a program no host in `hosts` runs."""
    fs = DosFs(drives, set(), current)
    env = list(INITIAL_ENV)
    steps: list[Step] = []
    echo_on = True

    def lines(texts: list[str], depth: int) -> None:
        nonlocal env, echo_on
        for raw in texts:
            line = raw.strip()
            if not line:
                continue
            silent = line.startswith("@")
            body = line[1:].lstrip() if silent else line
            if not body:
                continue
            echo = body if echo_on and not silent else None
            word, _, rest = body.partition(" ")
            word = word.upper()
            if body.upper() in ("ECHO OFF", "ECHO ON"):
                steps.append(Step("noop", echo))
                echo_on = body.upper() == "ECHO ON"
                continue
            if word == "REM":
                steps.append(Step("noop", echo))
                continue
            if word == "ECHO":
                steps.append(Step("echo", echo, text=rest))
                continue
            match = _SET.match(body)
            if match:
                key, value = match[1].upper(), match[2]
                env = [(k, v) for k, v in env if k != key] + ([(key, value)] if value else [])
                steps.append(Step("set", echo, env=tuple(env)))
                continue
            name, _, args = body.partition(" ")
            found = _find_program(fs, name, env)
            if found is None:
                steps.append(Step("missing", echo, text=f"program not found: {name}"))
                continue
            host_path, dos_path = found
            if dos_path.endswith(".BAT"):
                steps.append(Step("noop", echo))
                if depth >= MAX_BATCH_DEPTH:
                    steps.append(Step("missing", None, text=f"{dos_path}: batch files nested too deeply"))
                    continue
                text = host_path.read_bytes().decode("cp437")
                lines(text.replace("\r", "").split("\n"), depth + 1)
                continue
            host, kind = _program_kind(host_path.read_bytes())
            if host is None or host not in hosts:
                raise RpcError(RUNNER_UNSUPPORTED, f"{dos_path}: {kind} cannot be run by unicorn-dos")
            steps.append(
                Step(
                    "run",
                    echo,
                    env=tuple(env),
                    program=str(host_path),
                    dos_path=dos_path,
                    args=args.strip(),
                    host=host,
                )
            )

    lines(list(commands), 0)
    return steps
