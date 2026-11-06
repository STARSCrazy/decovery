"""All dosbox-lab access lives behind `Backend`, so the plugin logic can be tested with a fake backend.

`DosboxLabBackend` calls `dosbox_lab.run_batch` (headless DOSBox-X fork, see github.com/STARSCrazy/dosbox-lab).
The package is imported lazily, so this module loads without it; it is exercised against a real emulator only by
`tests/test_local_dosbox.py` (skipped unless `DOSBOX_LAB_PACKAGE` is set).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

BACKEND_UNAVAILABLE = -32010


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
    def run_batch(self, mounts: list[MountSpec], command: str, timeout_s: float) -> BatchResult:
        """Runs `command` in one headless DOS session. The first mount is the current drive."""


class DosboxLabBackend(Backend):
    def run_batch(self, mounts: list[MountSpec], command: str, timeout_s: float) -> BatchResult:
        try:
            import dosbox_lab
        except ImportError as exc:
            raise BackendError(
                BACKEND_UNAVAILABLE,
                f"dosbox-lab is not installed ({exc}); run `decovery setup dosbox-lab --package <dir>`",
            ) from exc
        try:
            result = dosbox_lab.run_batch(
                [dosbox_lab.Mount(m.drive, str(m.path), cdrom=m.read_only) for m in mounts],
                command,
                timeout_s=timeout_s,
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
        return BatchResult(result["status"], stdout, result.get("error"))
