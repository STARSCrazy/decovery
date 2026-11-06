"""decovery plugin running original DOS compilers in dosbox-lab (capability `runner` v1). See README.md."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from decovery_plugin import Context, Plugin, RpcError

from .backend import (
    BACKEND_UNAVAILABLE,
    Backend,
    BackendError,
    BatchResult,
    DosboxLabBackend,
    MountSpec,
)

__all__ = ["BACKEND_UNAVAILABLE", "Backend", "BatchResult", "MountSpec", "build_plugin"]

__version__ = "0.1.0"

RUNNER_VERSION = 1
INVALID_PARAMS = -32602
BATCH_NAME = "NB.BAT"

# Commands the shell runs itself: no CALL and no errorlevel check (they leave the errorlevel of the last program).
INTERNAL = frozenset(
    "SET ECHO REM CD CHDIR PATH PAUSE VER VOL DIR MD MKDIR RD RMDIR DEL ERASE COPY REN RENAME TYPE CLS DATE TIME".split()
)
_WORD = re.compile(r"[A-Za-z]+")
_DRIVE = re.compile(r"[A-Za-z]:\s*$")
_MARKER = re.compile(r"DECOVERY-(JOB-(\d+)-END|JOB-(\d+)|EXIT-(\d+)-FAILED)")


def _is_internal(line: str) -> bool:
    text = line.lstrip("@ \t")
    word = _WORD.match(text)
    return bool(_DRIVE.match(text)) or (word is not None and word.group().upper() in INTERNAL)


def build_script(jobs: list[list[str]], current_drive: str) -> str:
    """The batch file for all jobs. Per job: a begin marker, its lines, then `DECOVERY-JOB-<i>-END`. After a
    program line, `IF ERRORLEVEL 1 GOTO F<i>` jumps to a shared ladder that echoes `DECOVERY-EXIT-<code>-FAILED`
    with the exact errorlevel and continues with the next job (`SET DJ=<i>` remembers which one)."""
    out = ["@ECHO OFF"]
    for i, commands in enumerate(jobs):
        out += [f"@ECHO DECOVERY-JOB-{i}", f"{current_drive}:", "CD \\"]
        for line in commands:
            if _is_internal(line):
                out.append(line)
            else:
                out += [f"CALL {line}", f"IF ERRORLEVEL 1 GOTO F{i}"]
        out += [f"@ECHO DECOVERY-JOB-{i}-END", f"GOTO N{i}", f":F{i}", f"SET DJ={i}", "GOTO LADDER", f":N{i}"]
    out.append("GOTO FINISH")
    out.append(":LADDER")
    out += [f"IF ERRORLEVEL {code} GOTO E{code}" for code in range(255, 1, -1)]
    out.append("GOTO E1")
    for code in range(255, 0, -1):
        out += [f":E{code}", f"@ECHO DECOVERY-EXIT-{code}-FAILED", "GOTO N%DJ%"]
    out.append(":FINISH")
    return "\r\n".join(out) + "\r\n"


def parse_output(stdout: str, count: int) -> list[dict[str, Any]]:
    """Per job `{started, exit_code, stdout}`; `exit_code` is None while the job has no end marker."""
    jobs: list[dict[str, Any]] = [{"started": False, "exit_code": None, "stdout": ""} for _ in range(count)]
    current: dict[str, Any] | None = None
    position = 0
    after_marker = False
    for match in _MARKER.finditer(stdout):
        text = stdout[position : match.start()]
        if after_marker and text.startswith("\r\n"):
            text = text[2:]
        if current is not None:
            current["stdout"] += text
        position, after_marker = match.end(), True
        end, begin, failed = match.group(2), match.group(3), match.group(4)
        if begin is not None and int(begin) < count:
            current = jobs[int(begin)]
            current["started"] = True
        elif end is not None and int(end) < count:
            jobs[int(end)]["exit_code"] = 0
            current = None
        elif failed is not None and current is not None:
            current["exit_code"] = int(failed)
            current = None
    tail = stdout[position:]
    if after_marker and tail.startswith("\r\n"):
        tail = tail[2:]
    if current is not None:
        current["stdout"] += tail
    return jobs


def _parse(params: Any) -> tuple[list[MountSpec], str, float, list[list[str]]]:
    try:
        mounts: dict[str, MountSpec] = {}
        for mount in params["mounts"]:
            drive = mount["drive"]
            if not isinstance(drive, str) or len(drive) != 1 or not drive.isalpha():
                raise TypeError("'mounts[].drive'")
            if not isinstance(mount["path"], str) or not isinstance(mount["writable"], bool):
                raise TypeError("'mounts[].path' or 'mounts[].writable'")
            path = Path(mount["path"])
            if not path.is_dir():
                raise TypeError(f"'mounts[].path' (no directory: {path})")
            mounts[drive.upper()] = MountSpec(drive.upper(), path, not mount["writable"])
        current = params.get("current_drive", "C")
        if not isinstance(current, str) or current.upper() not in mounts or mounts[current.upper()].read_only:
            raise TypeError("'current_drive' (must be a writable mount)")
        timeout_s = params["timeout_s"]
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
            raise TypeError("'timeout_s'")
        jobs = []
        for job in params["jobs"]:
            commands = job["commands"]
            if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
                raise TypeError("'jobs[].commands'")
            for command in commands:
                if "\r" in command or "\n" in command:
                    raise TypeError("'jobs[].commands' (line break in a command)")
                try:
                    command.encode("cp437")
                except UnicodeEncodeError:
                    raise TypeError(f"'jobs[].commands' (character outside code page 437: {command!r})") from None
            jobs.append(commands)
    except (KeyError, TypeError, AttributeError) as exc:
        raise RpcError(INVALID_PARAMS, f"invalid runner/run params: missing or malformed {exc}") from exc
    current_mount = mounts.pop(current.upper())
    return [current_mount, *mounts.values()], current.upper(), float(timeout_s), jobs


def _outcomes(jobs: list[dict[str, Any]], batch: BatchResult, timeout_s: float, total_s: float) -> list[dict]:
    results = []
    stopped_in: int | None = None
    for i, job in enumerate(jobs):
        if job["exit_code"] is not None:
            outcome = {"status": "done", "exit_code": job["exit_code"], "message": None}
        elif batch.status == "timeout" and job["started"]:
            stopped_in = i
            outcome = {
                "status": "timeout",
                "exit_code": None,
                "message": f"no end after {timeout_s:g} s per job (batch limit {total_s:g} s)",
            }
        elif job["started"]:
            stopped_in = i
            detail = batch.message or f"batch {batch.status}"
            outcome = {"status": "failed", "exit_code": None, "message": f"job did not end: {detail}"}
        else:
            reason = f"batch stopped in job {stopped_in}" if stopped_in is not None else f"batch {batch.status}"
            outcome = {"status": "failed", "exit_code": None, "message": f"job not run: {reason}"}
        outcome["stdout"] = job["stdout"]
        results.append(outcome)
    return results


def build_plugin(backend_factory: Callable[[], Backend] = DosboxLabBackend) -> Plugin:
    """The dosbox-lab plugin. `backend_factory` is called once per request."""
    plugin = Plugin("dosbox-lab", __version__)

    @plugin.method("runner/run", capability_version=RUNNER_VERSION)
    def run(params: dict, ctx: Context) -> dict:
        mounts, current, timeout_s, commands = _parse(params)
        if not commands:
            return {"jobs": []}
        script = mounts[0].path / BATCH_NAME
        if script.exists():
            raise RpcError(INVALID_PARAMS, f"invalid runner/run params: {script} already exists")
        total_s = timeout_s * len(commands)
        script.write_bytes(build_script(commands, current).encode("cp437"))
        try:
            batch = backend_factory().run_batch(mounts, BATCH_NAME, total_s)
        except BackendError as exc:
            raise RpcError(exc.code, exc.message) from exc
        finally:
            script.unlink(missing_ok=True)
        return {"jobs": _outcomes(parse_output(batch.stdout, len(commands)), batch, timeout_s, total_s)}

    return plugin
