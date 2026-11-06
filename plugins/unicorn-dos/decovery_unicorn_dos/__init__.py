"""decovery plugin running original DOS compilers in the unicorn emulator (capability `runner` v1). See README.md.

Licensed GPL-2.0-only (it uses unicorn); decovery itself only talks to it over the plugin protocol.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable

from decovery_plugin import Context, Plugin, RpcError

from .batch import plan
from .errors import INVALID_PARAMS
from .pool import MEMORY_PER_WORKER_MB, JobPool, MachineCache, execute_job, parallel

__version__ = "0.1.0"

RUNNER_VERSION = 1


def _parse(params: Any) -> tuple[dict[str, Path], set[str], str, float, list[list[str]], list[int], int | None]:
    try:
        drives: dict[str, Path] = {}
        read_only: set[str] = set()
        for mount in params["mounts"]:
            drive = mount["drive"]
            if not isinstance(drive, str) or len(drive) != 1 or not drive.isalpha():
                raise TypeError("'mounts[].drive'")
            if not isinstance(mount["path"], str) or not isinstance(mount["writable"], bool):
                raise TypeError("'mounts[].path' or 'mounts[].writable'")
            path = Path(mount["path"])
            if not path.is_dir():
                raise TypeError(f"'mounts[].path' (no directory: {path})")
            drives[drive.upper()] = path
            if not mount["writable"]:
                read_only.add(drive.upper())
        current = params.get("current_drive", "C")
        if not isinstance(current, str) or current.upper() not in drives:
            raise TypeError("'current_drive'")
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
            jobs.append(commands)
            costs.append(cost)
        share = (params.get("options") or {}).get("jobs")
        if share is not None and (isinstance(share, bool) or not isinstance(share, int) or share < 1):
            raise TypeError("'options.jobs'")
    except (KeyError, TypeError, AttributeError) as exc:
        raise RpcError(INVALID_PARAMS, f"invalid runner/run params: missing or malformed {exc}") from exc
    return drives, read_only, current.upper(), float(timeout_s), jobs, costs, share


def build_plugin(machine_factory: Callable[[Any], Any] | None = None) -> Plugin:
    """The unicorn-dos plugin. Jobs run in worker processes, one pool for the life of the plugin with one worker per
    logical core (declared as `max_parallel`); a request runs at most `options.jobs` of them at once. With
    `machine_factory` (called with a `P3Image` or the exe bytes of a real-mode program, see `pool.new_machine`) they
    run in this process instead, one after another (tests)."""
    plugin = Plugin("unicorn-dos", __version__)
    plugin.set_limits("runner", max_parallel=parallel(), memory_per_instance_mb=MEMORY_PER_WORKER_MB)
    pool = JobPool() if machine_factory is None else None
    machines = MachineCache(machine_factory) if machine_factory is not None else None
    lock = threading.Lock()  # machines are not thread-safe

    @plugin.on_shutdown
    def close_pool() -> None:
        if pool is not None:
            pool.close()

    @plugin.method("runner/run", capability_version=RUNNER_VERSION)
    def run(params: dict, ctx: Context) -> dict:
        drives, read_only, current, timeout_s, commands, costs, share = _parse(params)
        # every program is checked before any job runs (RUNNER_UNSUPPORTED leaves nothing behind)
        steps = [plan(job, drives, current=current) for job in commands]
        jobs = [
            {
                "drives": {k: str(v) for k, v in drives.items()},
                "read_only": sorted(read_only),
                "current": current,
                "timeout_s": timeout_s,
                "steps": job_steps,
                "cost": cost,
            }
            for job_steps, cost in zip(steps, costs)
        ]
        started = time.monotonic()
        finished = 0

        def report(index: int, outcome: dict) -> None:
            # one event per ended job: a hang is told from a slow compile by the events that stop coming
            nonlocal finished
            finished += 1
            ctx.progress(
                finished,
                len(jobs),
                f"job {index + 1} of {len(jobs)} {outcome.get('status')} after {time.monotonic() - started:.1f} s",
            )

        if pool is not None:
            outcomes = pool.run(jobs, parallel=share, on_done=report)
        else:
            with lock:
                outcomes = []
                for index, job in enumerate(jobs):
                    outcomes.append(execute_job(job, machines.get))
                    report(index, outcomes[-1])
        return {"jobs": outcomes}

    return plugin
