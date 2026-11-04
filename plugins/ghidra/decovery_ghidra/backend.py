"""All Ghidra / pyghidra access lives here, so the plugin logic can be tested with a fake backend.

`GhidraBackend` is a first cut: its pyghidra calls follow the usage of the predecessor project but have not been
run against a real Ghidra from this repository's tests (none is installed on the CI machines).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .mapping import GhidraAddress, MemoryBlockSpec

EXPECTED_GHIDRA_VERSION = "12.1.4"

Progress = Callable[..., None]


class BackendError(Exception):
    """Ghidra is missing or unusable; `code` is the JSON-RPC error code to answer with."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


BACKEND_UNAVAILABLE = -32010


@dataclass(frozen=True)
class GhidraFunction:
    segment: int | None
    offset: int
    name: str
    size: int


@dataclass(frozen=True)
class DecompileResult:
    code: str | None
    error: str | None


def check_ghidra_version(install_dir: Path, warn: Callable[[str], None]) -> None:
    """Warn when the install is not the expected Ghidra version."""
    props = install_dir / "Ghidra" / "application.properties"
    found = None
    try:
        for line in props.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "application.version":
                found = value.strip()
    except OSError:
        pass
    if found != EXPECTED_GHIDRA_VERSION:
        warn(f"Ghidra version {found or 'unknown'} found, {EXPECTED_GHIDRA_VERSION} expected")


def _warn_stderr(message: str) -> None:
    print(f"decovery-ghidra: warning: {message}", file=sys.stderr, flush=True)


class GhidraBackend:
    def __init__(self) -> None:
        self._pyghidra = None
        self._project_cm = None
        self._program = None
        self._consumer = None
        self._decompiler = None

    # -- startup ---------------------------------------------------------------------------------------------

    def _start(self):
        install = os.environ.get("GHIDRA_INSTALL_DIR")
        if not install:
            raise BackendError(BACKEND_UNAVAILABLE, "GHIDRA_INSTALL_DIR is not set; point it to a Ghidra installation")
        install_dir = Path(install)
        if not install_dir.is_dir():
            raise BackendError(BACKEND_UNAVAILABLE, f"GHIDRA_INSTALL_DIR does not exist: {install_dir}")
        try:
            import pyghidra
        except ImportError as exc:
            raise BackendError(BACKEND_UNAVAILABLE, f"pyghidra is not installed ({exc})") from exc
        check_ghidra_version(install_dir, _warn_stderr)
        if not pyghidra.started():
            pyghidra.start(install_dir=install_dir)
            # Java would otherwise write to fd 1, which carries the protocol.
            from java.lang import System  # type: ignore[import-not-found]

            System.setOut(System.err)
        return pyghidra

    # -- backend interface -----------------------------------------------------------------------------------

    def open_program(
        self,
        language_id: str,
        blocks: list[MemoryBlockSpec],
        entry_points: list[GhidraAddress],
        project_dir: str,
        progress: Progress,
    ) -> int:
        """Build a program from memory blocks, disassemble from the entry points, analyze; returns the
        function count."""
        pyghidra = self._start()
        self._pyghidra = pyghidra
        self.close()
        import java.lang  # type: ignore[import-not-found]
        from ghidra.app.decompiler import DecompileOptions, DecompInterface  # type: ignore[import-not-found]
        from ghidra.program.database import ProgramDB  # type: ignore[import-not-found]
        from ghidra.program.model.lang import LanguageID  # type: ignore[import-not-found]
        from ghidra.program.util import DefaultLanguageService  # type: ignore[import-not-found]
        from java.io import ByteArrayInputStream  # type: ignore[import-not-found]

        total = 4
        progress(0, total, "creating program")
        Path(project_dir).mkdir(parents=True, exist_ok=True)
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(language_id))
        owner = java.lang.Object()
        program = ProgramDB("target", language, language.getDefaultCompilerSpec(), owner)
        monitor = pyghidra.task_monitor()
        factory = program.getAddressFactory()
        tx = program.startTransaction("memory")
        try:
            memory = program.getMemory()
            for spec in blocks:
                start = factory.getAddress(spec.start.text())
                block = memory.createInitializedBlock(
                    spec.name, start, ByteArrayInputStream(spec.data), spec.size, monitor, False
                )
                block.setRead(spec.read)
                block.setWrite(spec.write)
                block.setExecute(spec.execute)
            progress(1, total, "memory created")
            for entry in entry_points:
                address = factory.getAddress(entry.text())
                program.getSymbolTable().addExternalEntryPoint(address)
        finally:
            program.endTransaction(tx, True)
        progress(2, total, "analyzing")
        pyghidra.analyze(program, pyghidra.task_monitor())
        progress(3, total, "analysis finished")
        decompiler = DecompInterface()
        decompiler.setOptions(DecompileOptions())
        decompiler.openProgram(program)
        self._program, self._decompiler, self._consumer = program, decompiler, owner
        count = int(program.getFunctionManager().getFunctionCount())
        progress(4, total, "ready")
        return count

    def functions(self) -> list[GhidraFunction]:
        program = self._require_program()
        result = []
        for function in program.getFunctionManager().getFunctions(True):
            result.append(
                GhidraFunction(
                    segment=self._segment(function.getEntryPoint()),
                    offset=int(function.getEntryPoint().getOffset()),
                    name=str(function.getName()),
                    size=int(function.getBody().getNumAddresses()),
                )
            )
        return result

    def decompile(self, address: GhidraAddress) -> DecompileResult:
        program = self._require_program()
        target = program.getAddressFactory().getAddress(address.text())
        function = program.getFunctionManager().getFunctionAt(target)
        if function is None:
            return DecompileResult(None, f"no function at {address.text()}")
        outcome = self._decompiler.decompileFunction(function, 60, self._pyghidra.task_monitor())
        if not outcome.decompileCompleted():
            return DecompileResult(None, str(outcome.getErrorMessage()))
        return DecompileResult(str(outcome.getDecompiledFunction().getC()), None)

    def close(self) -> None:
        if self._decompiler is not None:
            self._decompiler.dispose()
        if self._program is not None and self._consumer is not None:
            self._program.release(self._consumer)
        self._program = self._decompiler = self._consumer = None

    # -- helpers ---------------------------------------------------------------------------------------------

    def _require_program(self):
        if self._program is None:
            raise BackendError(BACKEND_UNAVAILABLE, "no program is open")
        return self._program

    @staticmethod
    def _segment(address) -> int | None:
        getter = getattr(address, "getSegment", None)
        return int(getter()) if getter is not None else None
