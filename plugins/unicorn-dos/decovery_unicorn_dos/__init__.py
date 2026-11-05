"""decovery plugin running original DOS compilers in the unicorn emulator (capability `runner` v1). See README.md.

Licensed GPL-2.0-only (it uses unicorn); decovery itself only talks to it over the plugin protocol.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable

from decovery_plugin import Context, Plugin, RpcError

from .batch import plan
from .errors import INVALID_PARAMS
from .pool import JobPool, MachineCache, execute_job

__version__ = "0.1.0"

RUNNER_VERSION = 1


def _parse(params: Any) -> tuple[dict[str, Path], set[str], str, float, list[list[str]]]:
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
        for job in params["jobs"]:
            commands = job["commands"]
            if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
                raise TypeError("'jobs[].commands'")
            jobs.append(commands)
    except (KeyError, TypeError, AttributeError) as exc:
        raise RpcError(INVALID_PARAMS, f"invalid runner/run params: missing or malformed {exc}") from exc
    return drives, read_only, current.upper(), float(timeout_s), jobs


def build_plugin(machine_factory: Callable[[Any], Any] | None = None) -> Plugin:
    """The unicorn-dos plugin. Jobs run in worker processes; with `machine_factory` (called with a `P3Image`,
    returns a `pharlap.Machine`) they run in this process instead, one after another (tests)."""
    plugin = Plugin("unicorn-dos", __version__)
    pool = JobPool() if machine_factory is None else None
    machines = MachineCache(machine_factory) if machine_factory is not None else None
    lock = threading.Lock()  # machines are not thread-safe

    @plugin.on_shutdown
    def close_pool() -> None:
        if pool is not None:
            pool.close()

    @plugin.method("runner/run", capability_version=RUNNER_VERSION)
    def run(params: dict, ctx: Context) -> dict:
        drives, read_only, current, timeout_s, commands = _parse(params)
        # every program is checked before any job runs (RUNNER_UNSUPPORTED leaves nothing behind)
        steps = [plan(job, drives, current=current) for job in commands]
        jobs = [
            {
                "drives": {k: str(v) for k, v in drives.items()},
                "read_only": sorted(read_only),
                "current": current,
                "timeout_s": timeout_s,
                "steps": job_steps,
            }
            for job_steps in steps
        ]
        if pool is not None:
            outcomes = pool.run(jobs)
        else:
            with lock:
                outcomes = [execute_job(job, machines.get) for job in jobs]
        return {"jobs": outcomes}

    return plugin
