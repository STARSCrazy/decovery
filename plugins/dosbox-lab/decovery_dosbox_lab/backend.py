"""All dosbox-lab access lives behind `Backend`, so the plugin logic can be tested with a fake backend.

`DosboxLabBackend` calls `dosbox_lab.run_batch` (headless DOSBox-X fork, see github.com/STARSCrazy/dosbox-lab).
The package is imported lazily, so this module loads without it; it is exercised against a real emulator only by
`tests/test_local_dosbox.py` (skipped unless `DOSBOX_LAB_PACKAGE` is set).
"""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

BACKEND_UNAVAILABLE = -32010

# `watch(stdout so far)` returns True to stop the session (status `timeout`).
Watch = Callable[[str], bool]


class BackendError(Exception):
    """dosbox-lab is missing or unusable; `code` is the JSON-RPC error code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class MountSpec:
    drive: str  # one upper-case letter
    path: Path
    read_only: bool  # mounted as CD-ROM


@dataclass(frozen=True)
class BatchResult:
    """`status` is dosbox-lab's: done, timeout, shell_exited or crashed. `stdout` is the whole console capture."""

    status: str
    stdout: str
    message: str | None = None


class Backend(ABC):
    @abstractmethod
    def run_batch(
        self, mounts: list[MountSpec], command: str, timeout_s: float, watch: Watch | None = None
    ) -> BatchResult:
        """Runs `command` in one headless DOS session, at most `timeout_s`. The first mount is the current drive.
        While it runs, `watch` gets the console output so far; when it returns True, the session is stopped and the
        result has status `timeout`."""


class DosboxLabBackend(Backend):
    """`dosbox_lab.run_batch` with `watch` (the output while it grows) and `snapshot=False` (the host snapshots its
    files itself). Needs a dosbox-lab whose `run_batch` takes `watch` (see README.md); `stopped` (the watch ended the
    session) is reported as `timeout`."""

    def run_batch(
        self, mounts: list[MountSpec], command: str, timeout_s: float, watch: Watch | None = None
    ) -> BatchResult:
        try:
            import dosbox_lab
        except ImportError as exc:
            raise BackendError(
                BACKEND_UNAVAILABLE,
                f"dosbox-lab is not installed ({exc}); run `decovery setup dosbox-lab --package <dir>`",
            ) from exc
        if "watch" not in inspect.signature(dosbox_lab.run_batch).parameters:
            raise BackendError(
                BACKEND_UNAVAILABLE,
                "dosbox-lab is too old: its run_batch has no `watch` (per-job time limits need it); update the "
                "package and run `decovery setup dosbox-lab --package <dir>`",
            )
        try:
            result = dosbox_lab.run_batch(
                [dosbox_lab.Mount(m.drive, str(m.path), cdrom=m.read_only) for m in mounts],
                command,
                timeout_s=timeout_s,
                watch=watch,
                snapshot=False,
            )
        except dosbox_lab.DmcpError as exc:
            if "emulator not found" in exc.message:
                raise BackendError(BACKEND_UNAVAILABLE, exc.message) from exc
            return BatchResult("crashed", "", f"dosbox-lab: {exc}")
        stdout_path = result.get("stdout")
        if stdout_path and Path(stdout_path).is_file():
            stdout = Path(stdout_path).read_bytes().decode("cp437")
        else:
            stdout = result.get("stdout_text") or ""
        status = "timeout" if result["status"] == "stopped" else result["status"]
        return BatchResult(status, stdout, result.get("error"))
