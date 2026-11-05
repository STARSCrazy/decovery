"""Runs jobs: in a pool of worker processes (spawned, default 8, `DECOVERY_UNICORN_PARALLEL`), each keeping one
reused machine per program, or in-process with machines from a factory (tests).

A job is a dict: `drives` {letter: path}, `read_only` [letters], `current` drive, `timeout_s`, `steps` (from
`batch.plan`). Its outcome has the `runner/run` shape: `status`, `exit_code`, `stdout`, `message`.
"""

from __future__ import annotations

import multiprocessing
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from typing import Any, Callable

from .dosfs import DosFs
from .errors import EmulatorError, EmulatorTimeout

PARALLEL = 8
MAX_MACHINES = 4


def parallel() -> int:
    try:
        return max(1, int(os.environ.get("DECOVERY_UNICORN_PARALLEL") or PARALLEL))
    except ValueError:
        return PARALLEL


def _outcome(status: str, exit_code: int | None, stdout: list[str], message: str | None) -> dict:
    return {"status": status, "exit_code": exit_code, "stdout": "".join(stdout), "message": message}


class MachineCache:
    """One reusable machine per program; a machine that is spent (failed or timed-out run) is replaced."""

    def __init__(self, factory: Callable[[Any], Any]):
        self.factory = factory
        self.machines: dict[str, Any] = {}

    def get(self, program: str, p3) -> Any:
        machine = self.machines.get(program)
        if machine is None or machine.spent or machine.p3 != p3:
            if machine is None and len(self.machines) >= MAX_MACHINES:
                self.machines.pop(next(iter(self.machines)))
            machine = self.factory(p3)
            self.machines[program] = machine
        return machine


def execute_job(job: dict, machine_for: Callable[[str, Any], Any]) -> dict:
    """Run the steps of one job in order until the first non-zero exit code."""
    from .pharlap import PharLapEmu, load_p3_file

    timeout_s = float(job["timeout_s"])
    deadline = time.monotonic() + timeout_s
    prompt = f"{job.get('current', 'C')}:\\>"
    stdout: list[str] = []
    exit_code = 0
    for step in job["steps"]:
        if step.echo is not None:
            stdout.append(f"{prompt}{step.echo}\r\n")
        if step.kind == "echo":
            stdout.append(f"{step.text}\r\n")
            continue
        if step.kind == "missing":
            return _outcome("failed", None, stdout, step.text)
        if step.kind != "run":
            continue
        remaining = deadline - time.monotonic()
        timed_out = f"no end after {timeout_s:g} s ({step.dos_path})"
        if remaining <= 0:
            return _outcome("timeout", None, stdout, timed_out)
        fs = DosFs({k: Path(v) for k, v in job["drives"].items()}, set(job["read_only"]), job.get("current", "C"))
        try:
            st = os.stat(step.program)
            p3 = load_p3_file(step.program, st.st_size, st.st_mtime_ns)
            emu = PharLapEmu(p3, fs, step.args, list(step.env), step.dos_path, timeout_s=remaining)
            result = emu.run(machine_for(step.program, p3))
        except EmulatorTimeout:
            stdout.append(bytes(fs.output).decode("cp437"))
            return _outcome("timeout", None, stdout, timed_out)
        except EmulatorError as e:
            stdout.append(bytes(fs.output).decode("cp437"))
            return _outcome("failed", None, stdout, str(e))
        except OSError as e:
            return _outcome("failed", None, stdout, f"{step.dos_path}: {e}")
        stdout.append(result.output.decode("cp437"))
        exit_code = result.exit_code
        if exit_code != 0:
            break
    return _outcome("done", exit_code, stdout, None)


_CACHE: MachineCache | None = None


def run_job(job: dict) -> dict:
    """Worker entry point: one job with this process's machines."""
    global _CACHE
    if _CACHE is None:
        from .pharlap import Machine

        _CACHE = MachineCache(Machine)
    return execute_job(job, _CACHE.get)


class JobPool:
    """Spawn-based process pool, started on first use and kept for later calls."""

    def __init__(self, workers: int | None = None, worker: Callable[[dict], dict] = run_job):
        self.workers = workers or parallel()
        self.worker = worker
        self._pool: ProcessPoolExecutor | None = None
        self._lock = threading.Lock()

    def _get(self) -> ProcessPoolExecutor:
        with self._lock:
            if self._pool is None:
                self._pool = ProcessPoolExecutor(self.workers, mp_context=multiprocessing.get_context("spawn"))
            return self._pool

    def _discard(self, pool: ProcessPoolExecutor) -> None:
        with self._lock:
            if self._pool is pool:
                self._pool = None
        pool.shutdown(wait=False, cancel_futures=True)

    def run(self, jobs: list[dict]) -> list[dict]:
        pool = self._get()
        futures = [pool.submit(self.worker, job) for job in jobs]
        outcomes = []
        broken = False
        for future in futures:
            try:
                outcomes.append(future.result())
            except BrokenProcessPool as e:
                broken = True
                outcomes.append(_outcome("failed", None, [], f"emulator worker process ended unexpectedly: {e}"))
            except Exception as e:  # a bug in the worker must not lose the other jobs
                outcomes.append(_outcome("failed", None, [], f"emulator worker: {type(e).__name__}: {e}"))
        if broken:
            self._discard(pool)
        return outcomes

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
