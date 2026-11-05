"""All Ghidra / pyghidra access lives behind `Backend`, so the plugin logic can be tested with a fake backend.

`GhidraBackend` is ported from Decomp's Ghidra engine (`oeffnen`/`_oeffnen`, `_importieren`, `_programm_bauen`,
`_aufrufart_einrichten`, `_g`/`_a`, `funktionen`, `dekompilieren`, `schliessen`; apply and export in `apply.py`
and `export.py`). Ghidra is imported lazily, so this module loads without it. It is exercised against a real
Ghidra only by `tests/test_local_ghidra.py` (skipped unless `GHIDRA_INSTALL_DIR` is set).
"""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .mapping import GhidraAddress, MemoryBlockSpec

EXPECTED_GHIDRA_VERSION = "12.1.4"
BACKEND_UNAVAILABLE = -32010
INVALID_PARAMS = -32602
DECOMPILE_TIMEOUT_SECONDS = 60
PROGRAM_PATH = "/target"

Progress = Callable[..., None]


class BackendError(Exception):
    """Ghidra is missing or unusable, or the request cannot be served; `code` is the JSON-RPC error code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


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
    disassembly: list[tuple[GhidraAddress, str]] = field(default_factory=list)  # filled when decompiling failed


@dataclass(frozen=True)
class OpenOutcome:
    functions: int
    reused: bool


# Watcom register calling convention as a Ghidra prototype (compiler spec extension). EBX/ECX/EDX are left out of
# <unaffected> on purpose: as parameter registers they would otherwise read unaff_EDX instead of param_2. An EDX:EAX
# return is left out on purpose: Ghidra would take every read of EDX after a call for a 64-bit return.
WATCALL_NAME = "__watcall"
WATCALL_XML = """<prototype name="__watcall" extrapop="unknown" stackshift="4">
  <input>
    <pentry minsize="1" maxsize="4"><register name="EAX"/></pentry>
    <pentry minsize="1" maxsize="4"><register name="EDX"/></pentry>
    <pentry minsize="1" maxsize="4"><register name="EBX"/></pentry>
    <pentry minsize="1" maxsize="4"><register name="ECX"/></pentry>
    <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack"/></pentry>
  </input>
  <output>
    <pentry minsize="4" maxsize="10" metatype="float"><register name="ST0"/></pentry>
    <pentry minsize="1" maxsize="4"><register name="EAX"/></pentry>
  </output>
  <unaffected>
    <register name="ESI"/>
    <register name="EDI"/>
    <register name="EBP"/>
    <register name="ESP"/>
  </unaffected>
</prototype>
"""


class Backend(ABC):
    """What the plugin needs from Ghidra. Addresses are `GhidraAddress` values; the plugin maps them."""

    @abstractmethod
    def ghidra_version(self) -> str:
        """Version of the Ghidra in use (starts it if needed)."""

    @abstractmethod
    def open_program(
        self,
        language_id: str,
        blocks: list[MemoryBlockSpec],
        entry_points: list[GhidraAddress],
        location: str,
        options: dict,
        reuse: bool,
        progress: Progress,
    ) -> OpenOutcome:
        """Open the Ghidra project in `location`. With `reuse` and a saved program there, open that without
        analysis; otherwise build the program from the blocks, analyze and save it. `options`:
        `calling_convention` (str or None)."""

    @abstractmethod
    def functions(self) -> list[GhidraFunction]: ...

    @abstractmethod
    def apply(self, symbols, types_h: str, references, calling_convention: str | None) -> tuple[int, list[str]]:
        """Apply knowledge (see `apply.py`); returns (items applied, warnings)."""

    @abstractmethod
    def export_data(self):
        """An `export.ExportData` of the open program."""

    @abstractmethod
    def decompile(self, address: GhidraAddress) -> DecompileResult: ...

    @abstractmethod
    def close(self) -> None: ...


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


def _is_locked(exc: Exception) -> bool:
    """Ghidra's LockException: another process holds the project open."""
    text = f"{type(exc).__name__} {exc}"
    return "LockException" in text or "Unable to lock project" in text


class GhidraBackend(Backend):
    def __init__(self) -> None:
        self._pyghidra = None
        self._project_cm = None
        self._project = None
        self._program = None
        self._consumer = None
        self._decompiler = None
        self._location: Path | None = None

    # -- startup ---------------------------------------------------------------------------------------------

    def _start(self):
        if self._pyghidra is not None:
            return self._pyghidra
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
        self._pyghidra = pyghidra
        return pyghidra

    def ghidra_version(self) -> str:
        self._start()
        from ghidra.framework import Application  # type: ignore[import-not-found]

        return str(Application.getApplicationVersion())

    # -- addresses -------------------------------------------------------------------------------------------

    def _to_g(self, address: GhidraAddress, program=None):
        space = (program or self._program).getAddressFactory().getDefaultAddressSpace()
        if address.segment is None:
            return space.getAddress(address.offset)
        from jpype import JInt  # type: ignore[import-not-found]  # else ambiguous with getAddress(long, boolean)

        return space.getAddress(JInt(address.segment), JInt(address.offset))

    @staticmethod
    def _to_spec(g) -> GhidraAddress | None:
        from ghidra.program.model.address import SegmentedAddress  # type: ignore[import-not-found]

        if g is None or not g.isMemoryAddress():
            return None
        if isinstance(g, SegmentedAddress):
            return GhidraAddress(int(g.getSegment()), int(g.getSegmentOffset()))
        return GhidraAddress(None, int(g.getOffset()))

    # -- open ------------------------------------------------------------------------------------------------

    def open_program(self, language_id, blocks, entry_points, location, options, reuse, progress) -> OpenOutcome:
        pyghidra = self._start()
        self.close()
        from .project import PROJECT_NAME

        folder = Path(location)
        folder.mkdir(parents=True, exist_ok=True)
        try:
            self._project_cm = pyghidra.open_project(str(folder), PROJECT_NAME, create=True)
            self._project = self._project_cm.__enter__()
            reused = reuse and self._project.getProjectData().getFile(PROGRAM_PATH) is not None
            if not reused:
                self._import(language_id, blocks, entry_points, options.get("calling_convention"), progress)
            self._program, self._consumer = pyghidra.consume_program(self._project, PROGRAM_PATH)
            from ghidra.app.decompiler import DecompileOptions, DecompInterface  # type: ignore[import-not-found]

            self._decompiler = DecompInterface()
            self._decompiler.setOptions(DecompileOptions())
            self._decompiler.openProgram(self._program)
        except BackendError:
            self._close_quietly()
            raise
        except Exception as exc:
            self._close_quietly()
            if _is_locked(exc):
                raise BackendError(
                    BACKEND_UNAVAILABLE, f"the Ghidra project in {folder} is open in another process"
                ) from exc
            raise
        self._location = folder
        return OpenOutcome(int(self._program.getFunctionManager().getFunctionCount()), reused)

    def _import(self, language_id, blocks, entry_points, calling_convention, progress) -> None:
        """Build the program from the memory blocks into the project, then analyze and save it."""
        import java.lang  # type: ignore[import-not-found]
        from ghidra.program.database import ProgramDB  # type: ignore[import-not-found]
        from ghidra.program.model.lang import LanguageID  # type: ignore[import-not-found]
        from ghidra.program.util import DefaultLanguageService  # type: ignore[import-not-found]
        from java.io import ByteArrayInputStream  # type: ignore[import-not-found]

        pyghidra = self._pyghidra
        total = 4
        progress(0, total, "creating program")
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(language_id))
        owner = java.lang.Object()
        program = ProgramDB("target", language, language.getDefaultCompilerSpec(), owner)
        monitor = pyghidra.task_monitor()
        tx = program.startTransaction("memory")
        try:
            memory = program.getMemory()
            for spec in blocks:
                block = memory.createInitializedBlock(
                    spec.name, self._to_g(spec.start, program), ByteArrayInputStream(spec.data), spec.size, monitor,
                    False,
                )
                block.setRead(spec.read)
                block.setWrite(spec.write)
                block.setExecute(spec.execute)
            for entry in entry_points:
                program.getSymbolTable().addExternalEntryPoint(self._to_g(entry, program))
        finally:
            program.endTransaction(tx, True)
        self._project.getProjectData().getRootFolder().createFile("target", program, monitor)
        program.release(owner)
        progress(1, total, "program created")
        program, consumer = pyghidra.consume_program(self._project, PROGRAM_PATH)
        try:
            if calling_convention:
                self._install_calling_convention(program, calling_convention)
            if program.getDefaultPointerSize() == 4:
                with pyghidra.transaction(program, "analysis options"):
                    program.getOptions("Analyzers").setBoolean("Aggressive Instruction Finder", True)
            progress(2, total, "analyzing")
            pyghidra.analyze(program, pyghidra.task_monitor())  # cancels its monitor at the end
            progress(3, total, "saving")
            program.save("import and analysis", pyghidra.task_monitor())
        finally:
            program.release(consumer)
        progress(4, total, "ready")

    def _install_calling_convention(self, program, name: str) -> None:
        from ghidra.program.database import SpecExtension  # type: ignore[import-not-found]

        if name != WATCALL_NAME:
            if program.getCompilerSpec().getCallingConvention(name) is None:
                raise BackendError(
                    INVALID_PARAMS,
                    f"unknown calling convention {name!r} (known: {WATCALL_NAME} and those of the compiler spec, "
                    "e.g. __cdecl)",
                )
            return
        try:
            with self._pyghidra.transaction(program, "calling convention"):
                SpecExtension(program).addReplaceCompilerSpecExtension(WATCALL_XML, self._pyghidra.task_monitor())
        except Exception as exc:
            raise BackendError(BACKEND_UNAVAILABLE, f"calling convention {name} could not be installed: {exc}") from exc

    # -- queries ---------------------------------------------------------------------------------------------

    def functions(self) -> list[GhidraFunction]:
        program = self._require_program()
        result = []
        for function in program.getFunctionManager().getFunctions(True):
            start = self._to_spec(function.getEntryPoint())
            if start is None or function.isExternal():
                continue
            result.append(
                GhidraFunction(start.segment, start.offset, str(function.getName()),
                               int(function.getBody().getNumAddresses()))
            )
        return result

    def apply(self, symbols, types_h, references, calling_convention) -> tuple[int, list[str]]:
        from .apply import GhidraApplier

        program = self._require_program()
        applier = GhidraApplier(self._pyghidra, program, self._location, self._to_g, self._to_spec)
        result = applier.apply(symbols, types_h, references, calling_convention)
        self._decompiler.flushCache()
        return result

    def export_data(self):
        from .export import read_program

        return read_program(self._require_program(), self._to_spec)

    def decompile(self, address: GhidraAddress) -> DecompileResult:
        program = self._require_program()
        function = program.getFunctionManager().getFunctionAt(self._to_g(address))
        if function is None:
            return DecompileResult(None, f"no function at {address.text()}")
        outcome = self._decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, self._pyghidra.task_monitor())
        decompiled = outcome.getDecompiledFunction() if outcome.decompileCompleted() else None
        if decompiled is not None:
            return DecompileResult(str(decompiled.getC()), None)
        error = str(outcome.getErrorMessage() or "").strip() or "decompilation did not complete"
        disassembly = []
        for ins in program.getListing().getInstructions(function.getBody(), True):
            if (at := self._to_spec(ins.getAddress())) is not None:
                disassembly.append((at, str(ins)))
        return DecompileResult(None, error, disassembly)

    # -- shutdown --------------------------------------------------------------------------------------------

    def close(self) -> None:
        decompiler, program, consumer, cm = self._decompiler, self._program, self._consumer, self._project_cm
        self._decompiler = self._program = self._consumer = self._project = self._project_cm = None
        self._location = None
        try:
            if decompiler is not None:
                decompiler.dispose()
        finally:
            try:
                if program is not None:
                    program.release(consumer)
            finally:
                if cm is not None:
                    cm.__exit__(None, None, None)

    def _close_quietly(self) -> None:
        """Clean up after an error; a follow-up error must not hide the first."""
        try:
            self.close()
        except Exception:
            pass

    def _require_program(self):
        if self._program is None:
            raise BackendError(BACKEND_UNAVAILABLE, "no program is open")
        return self._program
