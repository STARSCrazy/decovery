"""Runs jobs: in a pool of worker processes (spawned, default 8, `DECOVERY_UNICORN_PARALLEL`), each keeping one
reused machine per program, or in-process with machines from a factory (tests).

A job is a dict: `drives` {letter: path}, `read_only` [letters], `current` drive, `timeout_s`, `steps` (from
`batch.plan`). Its outcome has the `runner/run` shape: `status`, `exit_code`, `stdout`, `message`.

A worker process that dies (a crash inside unicorn) breaks the whole pool and with it every job still pending. Those
jobs run once more, each in a fresh process of its own, so only a job that breaks again is reported as failed.
A retried job runs again from its first step, so jobs must be idempotent (compiling and linking are: they
rewrite their outputs).
"""

from __future__ import annotations

import multiprocessing
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
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


def new_machine(image: Any) -> Any:
    """A machine for a loaded program: the exe bytes (real mode) or a `P3Image` (Phar Lap)."""
    if isinstance(image, bytes):
        from .realmode import RealModeMachine

        return RealModeMachine(image)
    from .pharlap import Machine

    return Machine(image)


class MachineCache:
    """One reusable machine per program; a machine that is spent (failed or timed-out run) is replaced."""

    def __init__(self, factory: Callable[[Any], Any] = new_machine):
        self.factory = factory
        self.machines: dict[str, Any] = {}

    def get(self, program: str, image: Any) -> Any:
        machine = self.machines.get(program)
        if machine is None or machine.spent or machine.image != image:
            if machine is None and len(self.machines) >= MAX_MACHINES:
                self.machines.pop(next(iter(self.machines)))
            machine = self.factory(image)
            self.machines[program] = machine
        return machine


def _run_step(step, fs: DosFs, remaining: float, machine_for: Callable[[str, Any], Any]):
    st = os.stat(step.program)
    if step.host == "realmode":
        from .realmode import RealModeEmu, read_exe_file

        exe = read_exe_file(step.program, st.st_size, st.st_mtime_ns)
        emu = RealModeEmu(exe, fs, step.args, list(step.env), step.dos_path, timeout_s=remaining)
        return emu.run(machine_for(step.program, exe))
    from .pharlap import PharLapEmu, load_p3_file

    p3 = load_p3_file(step.program, st.st_size, st.st_mtime_ns)
    emu = PharLapEmu(p3, fs, step.args, list(step.env), step.dos_path, timeout_s=remaining)
    return emu.run(machine_for(step.program, p3))


def execute_job(job: dict, machine_for: Callable[[str, Any], Any]) -> dict:
    """Run the steps of one job in order until the first non-zero exit code."""
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
            result = _run_step(step, fs, remaining, machine_for)
        except EmulatorTimeout:
            stdout.append(bytes(fs.output).decode("cp437"))
            return _outcome("timeout", None, stdout, timed_out)
        except EmulatorError as e:
            stdout.append(bytes(fs.output).decode("cp437"))
            return _outcome("failed", None, stdout, str(e))
        except OSError as e:
            fs.close_all()
            return _outcome("failed", None, stdout, f"{step.dos_path}: {e}")
        except Exception as e:  # a bug in the emulation: the same outcome in a worker and in-process
            fs.close_all()
            stdout.append(bytes(fs.output).decode("cp437"))
            return _outcome("failed", None, stdout, f"emulation error: {type(e).__name__}: {e}")
        stdout.append(result.output.decode("cp437"))
        exit_code = result.exit_code
        if exit_code != 0:
            break
    return _outcome("done", exit_code, stdout, None)


def _worker_failed(e: Exception) -> dict:
    return _outcome("failed", None, [], f"emulator worker: {type(e).__name__}: {e}")


def _worker_died(e: Exception) -> dict:
    return _outcome("failed", None, [], f"emulator worker process ended unexpectedly: {e}")


_CACHE: MachineCache | None = None


def run_job(job: dict) -> dict:
    """Worker entry point: one job with this process's machines."""
    global _CACHE
    if _CACHE is None:
        _CACHE = MachineCache()
    return execute_job(job, _CACHE.get)


def _spawn(workers: int) -> ProcessPoolExecutor:
    return ProcessPoolExecutor(workers, mp_context=multiprocessing.get_context("spawn"))


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
                self._pool = _spawn(self.workers)
            return self._pool

    def _discard(self, pool: ProcessPoolExecutor) -> None:
        with self._lock:
            if self._pool is pool:
                self._pool = None
        pool.shutdown(wait=False, cancel_futures=True)

    def run(self, jobs: list[dict]) -> list[dict]:
        pool = self._get()
        futures = [pool.submit(self.worker, job) for job in jobs]
        outcomes: list[dict | None] = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except BrokenProcessPool:
                outcomes.append(None)  # this job or another one killed the pool
            except Exception as e:  # a bug in the worker must not lose the other jobs
                outcomes.append(_worker_failed(e))
        unfinished = [i for i, outcome in enumerate(outcomes) if outcome is None]
        if unfinished:
            self._discard(pool)
            with ThreadPoolExecutor(min(self.workers, len(unfinished))) as threads:
                for i, outcome in zip(unfinished, threads.map(self._alone, [jobs[i] for i in unfinished])):
                    outcomes[i] = outcome
        return outcomes

    def _alone(self, job: dict) -> dict:
        """Run one job again in a fresh process of its own: if it dies once more, nothing else is lost."""
        pool = _spawn(1)
        try:
            return pool.submit(self.worker, job).result()
        except BrokenProcessPool as e:
            return _worker_died(e)
        except Exception as e:
            return _worker_failed(e)
        finally:
            pool.shutdown(wait=True, cancel_futures=True)

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
