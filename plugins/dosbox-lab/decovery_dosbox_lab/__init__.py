"""decovery plugin running original DOS compilers in dosbox-lab (capability `runner` v1). See README.md.

A request's jobs are split over up to `max_parallel` DOSBox instances that run at the same time (one per core at
most, fewer when the free memory does not hold that many, and no more than the request's `options.jobs`). Larger jobs
(`cost`) go first, each to the instance with the least work so far. Every instance runs its jobs in one batch file
`NB<k>.BAT` with its own TMP directory `C:\\NBT<k>`; the results are merged in job order.

A job's result does not depend on which jobs share its instance: each job starts in the root of the current drive
with errorlevel 0 and gets back the environment variables it changed, and its time limit is its own (`timeout_s`,
measured from its begin marker while the session runs). When a job does not end in time (or DOSBox fails), the
session stops; the jobs it did not reach answer `failed` with "job not run", which the host submits once more.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
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

__all__ = [
    "BACKEND_UNAVAILABLE",
    "MEMORY_PER_INSTANCE_MB",
    "Backend",
    "BatchResult",
    "MountSpec",
    "build_plugin",
    "build_script",
    "max_instances",
    "parse_output",
    "split_jobs",
]

__version__ = "0.1.0"

RUNNER_VERSION = 1
INVALID_PARAMS = -32602
# Memory of one headless DOSBox-X process with the default 16 MB guest (`cycles=max` keeps one core busy).
MEMORY_PER_INSTANCE_MB = 256
# A program that only ends with exit code 0 (MOV AX,4C00h; INT 21h): run before each job, it resets the errorlevel
# the previous job left behind.
ZERO_PROGRAM = bytes.fromhex("B8004CCD21")
ZERO_NAME = "ZERO.COM"
# Added to a session's backstop limit (`timeout_s` x its jobs) for DOSBox to start; the per-job limit is enforced by
# watching the output. The host's call budget is `timeout_s` x jobs + 30 s.
SESSION_SLACK_S = 10
SAVED = "DECOVERY_SAVED"  # prefix of the variables that keep a job's environment to restore after it

# Commands the shell runs itself: no CALL and no errorlevel check (they leave the errorlevel of the last program). A
# program started inside an `IF` or `FOR` line gets no errorlevel check either.
INTERNAL = frozenset(
    "SET ECHO REM CD CHDIR PATH PAUSE VER VOL DIR MD MKDIR RD RMDIR DEL ERASE COPY REN RENAME TYPE CLS DATE TIME "
    "IF FOR".split()
)
# An internal command is a whole word: followed by the end, white space or a delimiter; `.` belongs to a program
# name (TYPE.EXE), digits to a longer name (MD5SUM).
_WORD = re.compile(r"([A-Za-z]+)(?=$|[\s/\\;,=+<>|])")
_DRIVE = re.compile(r"[A-Za-z]:\s*$")
_DOT = re.compile(r"(ECHO|CD|CHDIR)\.", re.IGNORECASE)  # `ECHO.` prints an empty line, `CD..` goes up
# would jump in or out of the generated batch file: a label, or GOTO at the start or inside an IF/FOR line
_FLOW = re.compile(r"(GOTO(?=$|[\s:])|:)", re.IGNORECASE)
_GOTO = re.compile(r"(?<![A-Za-z0-9_])GOTO(?![A-Za-z0-9_])", re.IGNORECASE)
_SET = re.compile(r"SET\s+([^=\s]+)\s*=", re.IGNORECASE)
_MARKER = re.compile(r"DECOVERY-(JOB-(\d+)-END|JOB-(\d+)|EXIT-(\d+)-FAILED)")


def _is_internal(line: str) -> bool:
    text = line.lstrip("@ \t")
    word = _WORD.match(text)
    return (
        bool(_DRIVE.match(text))
        or bool(_DOT.match(text))
        or (word is not None and word.group(1).upper() in INTERNAL)
    )


def _jumps(line: str) -> bool:
    text = line.lstrip("@ \t")
    if _FLOW.match(text):
        return True
    word = _WORD.match(text)
    return word is not None and word.group(1).upper() in ("IF", "FOR") and _GOTO.search(text) is not None


def _set_names(commands: list[str]) -> list[str]:
    """The variables a job's `SET` lines change, upper case, in first-use order."""
    names: list[str] = []
    for line in commands:
        match = _SET.match(line.lstrip("@ \t"))
        if match and match.group(1).upper() not in names:
            names.append(match.group(1).upper())
    return names


def free_memory_mb() -> int | None:
    """Available physical memory in MB, or None when the platform does not tell."""
    if os.name == "nt":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("memory_load", ctypes.c_ulong),
                ("total_phys", ctypes.c_ulonglong),
                ("avail_phys", ctypes.c_ulonglong),
                ("total_page_file", ctypes.c_ulonglong),
                ("avail_page_file", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("avail_virtual", ctypes.c_ulonglong),
                ("avail_extended_virtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(MemoryStatus)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return int(status.avail_phys // (1024 * 1024))
    try:
        return int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // (1024 * 1024))
    except (ValueError, OSError, AttributeError):
        return None


def max_instances() -> int:
    """DOSBox instances that may run at once: one per logical core, as many as the free memory holds."""
    count = os.cpu_count() or 1
    free = free_memory_mb()
    if free is not None:
        count = min(count, free // MEMORY_PER_INSTANCE_MB)
    return max(1, count)


def split_jobs(costs: list[int], instances: int) -> list[list[int]]:
    """Job indices per instance: larger cost first, each job to the instance with the least cost so far (then the
    fewest jobs). Every instance gets at least one job when there are enough."""
    loads = [(0, 0, k) for k in range(max(1, min(instances, len(costs))))]
    split: list[list[int]] = [[] for _ in loads]
    for i in sorted(range(len(costs)), key=lambda i: -costs[i]):
        load, count, k = min(loads)
        split[k].append(i)
        loads[k] = (load + costs[i], count + 1, k)
    return split


def build_script(
    jobs: list[list[str]], current_drive: str, numbers: list[int] | None = None, tmp_dir: str | None = None
) -> str:
    """The batch file for `jobs` (numbered `numbers`, default 0, 1, ...). Per job: a begin marker, the root of the
    current drive, the values of the variables the job sets (and `TMP`) saved, with `tmp_dir` `SET TMP=<current>:\\
    <tmp_dir>` and the errorlevel reset (`<tmp_dir>\\ZERO.COM`), its lines, then `DECOVERY-JOB-<i>-END`. After a
    program line, `IF ERRORLEVEL 1 GOTO F<i>` jumps to a shared ladder that echoes `DECOVERY-EXIT-<code>-FAILED` with
    the exact errorlevel and continues at `:N<i>` (`SET DJ=<i>` remembers which one), where the saved variables are
    restored on both paths."""
    out = ["@ECHO OFF"]
    for i, commands in zip(numbers if numbers is not None else range(len(jobs)), jobs):
        names = _set_names(commands)
        if tmp_dir is not None and "TMP" not in names:
            names.insert(0, "TMP")
        out += [f"@ECHO DECOVERY-JOB-{i}", f"{current_drive}:", "CD \\"]
        out += [f"SET {SAVED}{k}=%{name}%" for k, name in enumerate(names)]
        if tmp_dir is not None:
            out += [f"SET TMP={current_drive}:\\{tmp_dir}", f"{current_drive}:\\{tmp_dir}\\{ZERO_NAME}"]
        for line in commands:
            if _is_internal(line):
                out.append(line)
            else:
                out += [f"CALL {line}", f"IF ERRORLEVEL 1 GOTO F{i}"]
        out += [f"@ECHO DECOVERY-JOB-{i}-END", f"GOTO N{i}", f":F{i}", f"SET DJ={i}", "GOTO LADDER", f":N{i}"]
        for k, name in enumerate(names):
            out += [f"SET {name}=%{SAVED}{k}%", f"SET {SAVED}{k}="]
        out.append("SET DJ=")
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


def _parse(params: Any) -> tuple[list[MountSpec], str, float, list[list[str]], list[int], int | None]:
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
        costs = []
        for job in params["jobs"]:
            commands = job["commands"]
            if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
                raise TypeError("'jobs[].commands'")
            cost = job.get("cost", 0)
            if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
                raise TypeError("'jobs[].cost'")
            costs.append(cost)
            for command in commands:
                if "\r" in command or "\n" in command:
                    raise TypeError("'jobs[].commands' (line break in a command)")
                if _jumps(command):
                    raise TypeError(f"'jobs[].commands' (GOTO and labels are not supported: {command!r})")
                try:
                    command.encode("cp437")
                except UnicodeEncodeError:
                    raise TypeError(f"'jobs[].commands' (character outside code page 437: {command!r})") from None
            jobs.append(commands)
        share = (params.get("options") or {}).get("jobs")
        if share is not None and (isinstance(share, bool) or not isinstance(share, int) or share < 1):
            raise TypeError("'options.jobs'")
    except (KeyError, TypeError, AttributeError) as exc:
        raise RpcError(INVALID_PARAMS, f"invalid runner/run params: missing or malformed {exc}") from exc
    current_mount = mounts.pop(current.upper())
    return [current_mount, *mounts.values()], current.upper(), float(timeout_s), jobs, costs, share


class _Watch:
    """Called by the backend with the session's output so far: notes when each job's begin marker appears and stops
    the session when the running job has run longer than `timeout_s`, or when the request is cancelled."""

    def __init__(self, timeout_s: float, clock: Callable[[], float], ctx: Context):
        self.timeout_s = timeout_s
        self.clock = clock
        self.ctx = ctx
        self.position = 0
        self.running: int | None = None
        self.since = 0.0
        self.ended = 0

    def __call__(self, stdout: str) -> bool:
        now = self.clock()
        complete = stdout.rfind("\n") + 1  # markers are whole lines
        for match in _MARKER.finditer(stdout, self.position, complete):
            if match.group(3) is not None:
                self.running, self.since = int(match.group(3)), now
            else:
                if match.group(2) is not None:
                    # one event per ended job: a hang is told from a slow compile by the events that stop coming
                    self.ended += 1
                    elapsed = now - self.since
                    self.ctx.progress(self.ended, None, f"job {int(match.group(2)) + 1} ended after {elapsed:.1f} s")
                self.running = None
        self.position = max(self.position, complete)
        if self.ctx.cancelled:
            return True
        return self.running is not None and now - self.since > self.timeout_s


def _outcome(job: dict[str, Any], batch: BatchResult, timeout_s: float) -> dict:
    """The outcome of one job of a session; nothing in it depends on the other jobs of the session."""
    if job["exit_code"] is not None:
        outcome = {"status": "done", "exit_code": job["exit_code"], "message": None}
    elif not job["started"]:
        message = f"job not run: its DOSBox session stopped before it ({batch.message or batch.status})"
        outcome = {"status": "failed", "exit_code": None, "message": message}
    elif batch.status == "timeout":
        outcome = {"status": "timeout", "exit_code": None, "message": f"no end after {timeout_s:g} s"}
    else:
        detail = batch.message or f"batch {batch.status}"
        outcome = {"status": "failed", "exit_code": None, "message": f"job did not end: {detail}"}
    outcome["stdout"] = job["stdout"]
    return outcome


class _Instance:
    """One DOSBox instance's share of a request: its batch file, its TMP directory and its jobs."""

    def __init__(self, number: int, mounts: list[MountSpec], current: str, timeout_s: float):
        self.mounts = mounts
        self.current = current
        self.timeout_s = timeout_s
        self.script_name = f"NB{number}.BAT"
        self.tmp_name = f"NBT{number}"
        self.script = mounts[0].path / self.script_name
        self.tmp = mounts[0].path / self.tmp_name

    def claim(self) -> None:
        """Creates the TMP directory with the errorlevel reset program; refuses to touch existing files."""
        for path in (self.script, self.tmp):
            if path.exists():
                raise RpcError(INVALID_PARAMS, f"invalid runner/run params: {path} already exists")
        self.tmp.mkdir()
        (self.tmp / ZERO_NAME).write_bytes(ZERO_PROGRAM)

    def release(self) -> None:
        self.script.unlink(missing_ok=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run(
        self,
        backend_factory: Callable[[], Backend],
        jobs: list[tuple[int, list[str]]],
        clock: Callable[[], float],
        ctx: Context,
    ) -> dict:
        """Outcomes by job number, from one DOSBox session. Each job may run `timeout_s` from its begin marker; the
        session as a whole is bounded by `timeout_s` x its jobs + `SESSION_SLACK_S` (DOSBox start-up), which stays
        within the host's call budget for any number of instances."""
        numbers = [n for n, _ in jobs]
        text = build_script([c for _, c in jobs], self.current, numbers, self.tmp_name)
        self.script.write_bytes(text.encode("cp437"))
        limit = self.timeout_s * len(jobs) + SESSION_SLACK_S
        try:
            watch = _Watch(self.timeout_s, clock, ctx)
            batch = backend_factory().run_batch(self.mounts, self.script_name, limit, watch)
        except BackendError as exc:
            raise RpcError(exc.code, exc.message) from exc
        finally:
            self.script.unlink(missing_ok=True)
        parsed = parse_output(batch.stdout, max(numbers) + 1)
        return {n: _outcome(parsed[n], batch, self.timeout_s) for n in numbers}


def build_plugin(
    backend_factory: Callable[[], Backend] = DosboxLabBackend, clock: Callable[[], float] = time.monotonic
) -> Plugin:
    """The dosbox-lab plugin. `backend_factory` is called once per batch (one DOSBox session); `clock` measures the
    jobs' run time (tests pass the fake backend's clock)."""
    plugin = Plugin("dosbox-lab", __version__)
    instances = max_instances()
    plugin.set_limits("runner", max_parallel=instances, memory_per_instance_mb=MEMORY_PER_INSTANCE_MB)

    @plugin.method("runner/run", capability_version=RUNNER_VERSION)
    def run(params: dict, ctx: Context) -> dict:
        mounts, current, timeout_s, commands, costs, share = _parse(params)
        if not commands:
            return {"jobs": []}
        split = split_jobs(costs, min(instances, share or instances))
        workers = [_Instance(k, mounts, current, timeout_s) for k in range(len(split))]
        claimed: list[_Instance] = []
        try:
            for worker in workers:
                worker.claim()
                claimed.append(worker)
            with ThreadPoolExecutor(len(workers)) as threads:  # each thread waits for its DOSBox process
                futures = [
                    threads.submit(worker.run, backend_factory, [(i, commands[i]) for i in part], clock, ctx)
                    for worker, part in zip(workers, split)
                ]
                merged: dict[int, dict] = {}
                for future in futures:
                    merged.update(future.result())
        finally:
            for worker in claimed:
                worker.release()
        return {"jobs": [merged[i] for i in range(len(commands))]}

    return plugin
