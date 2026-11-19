"""All Ghidra / pyghidra access lives behind `Backend`, so the plugin logic can be tested with a fake backend.

`GhidraBackend` is ported from Decomp's Ghidra engine (`oeffnen`/`_oeffnen`, `_importieren`, `_programm_bauen`,
`_aufrufart_einrichten`, `_g`/`_a`, `funktionen`, `dekompilieren`, `schliessen`; apply and export in `apply.py`
and `export.py`). Ghidra is imported lazily, so this module loads without it. It is exercised against a real
Ghidra only by `tests/test_local_ghidra.py` (skipped unless `GHIDRA_INSTALL_DIR` is set).
"""

from __future__ import annotations

import json
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import aztec
from .mapping import GhidraAddress, MemoryBlockSpec, overlay_address

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
class DecompileLine:
    line: int  # 1-based line of getC(), including blank lines
    ranges: list[tuple[GhidraAddress, GhidraAddress]]  # inclusive token bounds


@dataclass(frozen=True)
class DecompileVariable:
    name: str | None = None
    data_type: str | None = None
    storage: str | None = None
    first_use: GhidraAddress | None = None


@dataclass(frozen=True)
class DecompileSignature:
    calling_convention: str | None = None
    return_type: str | None = None
    parameters: list[DecompileVariable] | None = None


@dataclass(frozen=True)
class DecompileResult:
    code: str | None
    error: str | None
    disassembly: list[tuple[GhidraAddress, str]] = field(default_factory=list)  # filled when decompiling failed
    lines: list[DecompileLine] | None = None
    signature: DecompileSignature | None = None
    variables: list[DecompileVariable] | None = None


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


# Aztec C86 helpers as call fixups (aztec.py). `$csav` leaves BP pointing at the pushed BP, 2 below the caller's
# SP before the call, and SP below the frame (AX = -frame size) and the saved SI, DI; the rest of the function then
# reads parameters at BP+4. The decompiler already counts the call's return address (SP is 2 lower in the fixup),
# so BP is SP here. The switch helper jumps to a case target; the decompiler gets the targets as a jump-table
# override at the call.
CSAV_FIXUP = "decovery_aztec_csav"
CSAV_FIXUP_XML = f"""<callfixup name="{CSAV_FIXUP}">
  <pcode>
    <body><![CDATA[
      local slot:4 = segment(SS, SP);
      *[ram]:2 slot = BP;
      BP = SP;
      SP = SP - 4 + AX;
    ]]></body>
  </pcode>
</callfixup>
"""
SWITCH_FIXUP = "decovery_aztec_switch"
SWITCH_FIXUP_XML = f"""<callfixup name="{SWITCH_FIXUP}">
  <pcode>
    <body><![CDATA[
      SP = SP + 2;
      goto [AX];
    ]]></body>
  </pcode>
</callfixup>
"""


# Per switch call: {"cases": [...], "targets": [address offsets, default last]}; read back when decompiling.
SWITCH_PROPERTY = "decovery.aztec.switch"
# Per run-time helper entry: its role; such functions decompile to a stub (aztec.stub) and carry LIBRARY_TAG.
HELPER_PROPERTY = "decovery.aztec.helper"
LIBRARY_TAG = "LIBRARY"


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
        `calling_convention` (str or None), `aggressive_instruction_finder` (bool, the plugin sets it for
        x86-flat-32 only), `decompiler_parameter_id` (bool, for x86-real-16 only)."""

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


def _pre_comment(program, address, text: str) -> None:
    listing = program.getListing()
    try:
        from ghidra.program.model.listing import CommentType  # type: ignore[import-not-found]

        listing.setComment(address, CommentType.PRE, text)
    except ImportError:
        from ghidra.program.model.listing import CodeUnit  # type: ignore[import-not-found]

        listing.setComment(address, CodeUnit.PRE_COMMENT, text)


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
        self._overlay_blocks: list[MemoryBlockSpec] = []
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
            from java.lang import System, Thread  # type: ignore[import-not-found]

            System.setOut(System.err)
            # The SDK runs requests on worker threads, so this is usually one. The thread that creates the JVM is
            # its non-daemon "main" thread; if it ends still attached, DestroyJavaVM at interpreter exit waits for
            # it forever. Detach it; JPype re-attaches it as a daemon on its next Java call.
            Thread.detach()
        self._pyghidra = pyghidra
        return pyghidra

    def ghidra_version(self) -> str:
        self._start()
        from ghidra.framework import Application  # type: ignore[import-not-found]

        return str(Application.getApplicationVersion())

    # -- addresses -------------------------------------------------------------------------------------------

    def _to_g(self, address: GhidraAddress, program=None):
        factory = (program or self._program).getAddressFactory()
        space = factory.getDefaultAddressSpace()
        if address.segment is None:
            base = space.getAddress(address.offset)
        else:
            from jpype import JInt  # type: ignore[import-not-found]  # else ambiguous with getAddress(long, boolean)

            base = space.getAddress(JInt(address.segment), JInt(address.offset))
        if address.space is None:
            return base
        # ADR 0011: the same processor address in the overlay's own address space
        overlay = factory.getAddressSpace(address.space)
        if overlay is None or not overlay.isOverlaySpace():
            raise BackendError(INVALID_PARAMS, f"overlay {address.space} has no address space in the program")
        return overlay.getAddressInThisSpaceOnly(base.getOffset())

    def _to_spec(self, g) -> GhidraAddress | None:
        from ghidra.program.model.address import SegmentedAddress  # type: ignore[import-not-found]

        if g is None or not g.isMemoryAddress():
            return None
        space = g.getAddressSpace()
        if space.isOverlaySpace():
            return overlay_address(self._overlay_blocks, str(space.getName()), int(g.getOffset()))
        if isinstance(g, SegmentedAddress):
            return GhidraAddress(int(g.getSegment()), int(g.getSegmentOffset()))
        return GhidraAddress(None, int(g.getOffset()))

    # -- open ------------------------------------------------------------------------------------------------

    def open_program(self, language_id, blocks, entry_points, location, options, reuse, progress) -> OpenOutcome:
        pyghidra = self._start()
        self.close()
        from .project import PROJECT_NAME

        self._overlay_blocks = [b for b in blocks if b.overlay]

        folder = Path(location)
        folder.mkdir(parents=True, exist_ok=True)
        try:
            self._project_cm = pyghidra.open_project(str(folder), PROJECT_NAME, create=True)
            self._project = self._project_cm.__enter__()
            reused = reuse and self._project.getProjectData().getFile(PROGRAM_PATH) is not None
            if not reused:
                self._import(language_id, blocks, entry_points, options, progress)
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

    def _import(self, language_id, blocks, entry_points, options, progress) -> None:
        """Build the program from the memory blocks into the project, then analyze and save it."""
        import java.lang  # type: ignore[import-not-found]
        from ghidra.program.database import ProgramDB  # type: ignore[import-not-found]
        from ghidra.program.model.lang import LanguageID  # type: ignore[import-not-found]
        from ghidra.program.util import DefaultLanguageService  # type: ignore[import-not-found]
        from java.io import ByteArrayInputStream  # type: ignore[import-not-found]

        pyghidra = self._pyghidra
        calling_convention = options.get("calling_convention")
        total = 4
        progress(0, total, "creating program")
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(language_id))
        owner = java.lang.Object()
        program = ProgramDB("target", language, language.getDefaultCompilerSpec(), owner)
        monitor = pyghidra.task_monitor()
        tx = program.startTransaction("memory")
        try:
            memory = program.getMemory()
            for name in dict.fromkeys(spec.overlay for spec in blocks if spec.overlay):
                program.createOverlaySpace(name, program.getAddressFactory().getDefaultAddressSpace())
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
            self._set_data_segment(program, blocks)
        finally:
            program.endTransaction(tx, True)
        self._project.getProjectData().getRootFolder().createFile("target", program, monitor)
        program.release(owner)
        progress(1, total, "program created")
        program, consumer = pyghidra.consume_program(self._project, PROGRAM_PATH)
        try:
            if calling_convention:
                self._install_calling_convention(program, calling_convention)
            if options.get("aggressive_instruction_finder"):
                with pyghidra.transaction(program, "analysis options"):
                    program.getOptions("Analyzers").setBoolean("Aggressive Instruction Finder", True)
            with pyghidra.transaction(program, "Aztec helpers"):
                sites = self._prepare_aztec(program, blocks)
                if options.get("decompiler_parameter_id"):
                    program.getOptions("Analyzers").setBoolean("Decompiler Parameter ID", True)
            progress(2, total, "analyzing")
            pyghidra.analyze(program, pyghidra.task_monitor())  # cancels its monitor at the end
            with pyghidra.transaction(program, "Aztec switch tables and data labels"):
                self._finish_aztec(program, blocks, sites, bool(options.get("decompiler_parameter_id")))
            progress(3, total, "saving")
            program.save("import and analysis", pyghidra.task_monitor())
        finally:
            program.release(consumer)
        progress(4, total, "ready")

    # -- Aztec C86 run-time helpers (see aztec.py) ----------------------------------------------------------

    def _set_data_segment(self, program, blocks) -> None:
        """DS of all code is the data segment of the overlay data blocks, when they name one. The part of that
        segment no block covers (the main program's uninitialized data) becomes an uninitialized block."""
        from java.math import BigInteger  # type: ignore[import-not-found]

        segment = aztec.data_segment(blocks)
        register = program.getLanguage().getRegister("DS")
        if segment is None or register is None:
            return
        context = program.getProgramContext()
        for spec in blocks:
            if spec.execute:
                start = self._to_g(spec.start, program)
                context.setValue(register, start, start.add(spec.size - 1), BigInteger.valueOf(segment))
        for offset, size in aztec.uncovered(blocks, segment):
            block = program.getMemory().createUninitializedBlock(
                f"DS.bss.{offset:04X}", self._to_g(GhidraAddress(segment, offset), program), size, False)
            block.setRead(True)
            block.setWrite(True)
            block.setExecute(False)

    def _prepare_aztec(self, program, blocks) -> list:
        """Before analysis: give `$csav` and the switch helper call fixups (the switch helper never returns), mark
        the inline switch tables as data and disassemble their targets. Returns the switch sites as
        (call address, [target addresses])."""
        from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore[import-not-found]
        from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore[import-not-found]
        from ghidra.program.model.address import AddressSet  # type: ignore[import-not-found]
        from ghidra.program.model.data import WordDataType  # type: ignore[import-not-found]
        from ghidra.program.model.symbol import RefType, SourceType  # type: ignore[import-not-found]

        def at(spec, offset):
            return self._to_g(GhidraAddress(spec.start.segment, offset, spec.start.space), program)

        code = [spec for spec in blocks if spec.execute and spec.start.segment is not None]
        helpers, switch = [], {}
        for spec in code:
            for found in aztec.find_helpers(spec.data, spec.start.offset):
                helpers.append((at(spec, found.offset), found))
                if found.kind == "switch":
                    switch.setdefault((spec.start.space, spec.start.segment), []).append(found.offset)
        dense = {id(spec): aztec.dense_switch_sites(spec.data, spec.start.offset) for spec in code}
        if not helpers and not any(dense.values()):
            return []
        self._install_fixups(program)
        functions = program.getFunctionManager()
        roles = program.getUsrPropertyManager().createStringPropertyMap(HELPER_PROPERTY)
        for address, found in helpers:
            DisassembleCommand(address, None, True).applyTo(program)
            CreateFunctionCmd(address).applyTo(program)
            function = functions.getFunctionAt(address)
            if function is None:
                continue
            roles.add(address, found.role)
            function.addTag(LIBRARY_TAG)
            if found.kind == "long":
                self._long_signature(program, function)
            else:
                function.setCallFixup(CSAV_FIXUP if found.kind == "csav" else SWITCH_FIXUP)
                function.setNoReturn(found.kind == "switch")
        sites = []
        listing, references = program.getListing(), program.getReferenceManager()
        for spec in code:
            own = switch.get((spec.start.space, spec.start.segment), [])
            shared = switch.get((None, spec.start.segment), []) if spec.start.space else []
            for site in aztec.switch_sites(spec.data, spec.start.offset, own + shared) + dense[id(spec)]:
                call = at(spec, site.call)
                for word in range(0, site.size, 2):
                    listing.createData(at(spec, site.table + word), WordDataType.dataType, 2)
                targets = [at(spec, target) for target in site.targets]
                for target in targets:
                    references.addMemoryReference(call, target, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0)
                found = AddressSet()
                for target in targets:
                    found.add(target)
                DisassembleCommand(found, None, True).applyTo(program)
                sites.append((call, targets, site))
        return sites

    @staticmethod
    def _long_signature(program, function) -> None:
        """`long f(long a, long b)` with a in DX:AX, b in BX:CX and the result in DX:AX (aztec.py)."""
        from ghidra.program.model.data import LongDataType  # type: ignore[import-not-found]
        from ghidra.program.model.listing import (  # type: ignore[import-not-found]
            Function, ParameterImpl, ReturnParameterImpl, VariableStorage)
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]
        from java.util import ArrayList  # type: ignore[import-not-found]

        def pair(high, low):
            return VariableStorage(program, program.getRegister(high), program.getRegister(low))

        long_type = LongDataType.dataType
        result = ReturnParameterImpl(long_type, pair("DX", "AX"), program)
        parameters = ArrayList()
        parameters.add(ParameterImpl("a", long_type, pair("DX", "AX"), program))
        parameters.add(ParameterImpl("b", long_type, pair("BX", "CX"), program))
        function.updateFunction(None, result, parameters, Function.FunctionUpdateType.CUSTOM_STORAGE, True,
                                SourceType.IMPORTED)

    def _finish_aztec(self, program, blocks, sites, parameter_id: bool) -> None:
        """After analysis: switch tables as decompiler jump-table overrides (with the case values as a comment), the
        case targets in the function body, and DS-relative labels for unnamed data in the data segment. With
        `parameter_id`, the prototypes of the functions with a switch are derived again: during analysis the
        decompiler took the switch value for an unrecovered jump target."""
        import java.util  # type: ignore[import-not-found]
        from ghidra.app.cmd.function import CreateFunctionCmd, DecompilerParameterIdCmd  # type: ignore
        from ghidra.program.model.address import AddressSet  # type: ignore[import-not-found]
        from ghidra.program.model.pcode import JumpTable  # type: ignore[import-not-found]
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

        functions = program.getFunctionManager()
        monitor = self._pyghidra.task_monitor()
        entries = AddressSet()
        cases = program.getUsrPropertyManager().createStringPropertyMap(SWITCH_PROPERTY)
        for call, targets, site in sites:
            function = functions.getFunctionContaining(call)
            if function is None:
                continue
            CreateFunctionCmd.fixupFunctionBody(program, function, monitor)
            JumpTable(call, java.util.ArrayList(targets), True, 0).writeOverride(function)
            _pre_comment(program, call, site.comment())
            cases.add(call, json.dumps({"cases": site.cases, "targets": [int(t.getOffset()) for t in targets]}))
            entries.add(function.getEntryPoint())
        if parameter_id and not entries.isEmpty():
            DecompilerParameterIdCmd("switch tables", entries, SourceType.ANALYSIS, False, False,
                                     DECOMPILE_TIMEOUT_SECONDS).applyTo(program, monitor)
        if program.getUsrPropertyManager().getStringPropertyMap(HELPER_PROPERTY) is not None:
            self._take_dead_returns(program)
        segment = aztec.data_segment(blocks)
        if segment is not None:
            self._label_data_segment(program, blocks, segment)

    def _take_dead_returns(self, program) -> None:
        """Aztec C86 ends a function whose last statement is an endless loop with an unreachable `ret`; Ghidra
        leaves the byte undefined and the function ends one byte early. A lone `ret` right behind a body that ends
        in an unconditional jump joins that body."""
        from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore[import-not-found]

        listing, memory, functions = program.getListing(), program.getMemory(), program.getFunctionManager()
        for function in list(functions.getFunctions(True)):
            if function.isExternal() or function.isThunk():
                continue
            body = function.getBody()
            last = listing.getInstructionContaining(body.getMaxAddress())
            flow = None if last is None else last.getFlowType()
            if flow is None or not flow.isJump() or flow.isConditional() or flow.hasFallthrough():
                continue
            try:
                after = last.getMaxAddress().add(1)
            except Exception:
                continue
            if (not memory.contains(after) or memory.getByte(after) & 0xFF != 0xC3
                    or not listing.isUndefined(after, after) or functions.getFunctionContaining(after) is not None
                    or program.getReferenceManager().hasReferencesTo(after)):
                continue
            DisassembleCommand(after, None, False).applyTo(program)
            if listing.getInstructionAt(after) is not None:
                function.setBody(body.union(program.getAddressFactory().getAddressSet(after, after)))

    def _label_data_segment(self, program, blocks, segment: int) -> None:
        """Ghidra names data by linear (overlay) or normalized (`1000:8262` for DS:8302) addresses; name unnamed
        data in DS by its DS offset instead."""
        from ghidra.program.model.address import AddressSet  # type: ignore[import-not-found]
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

        symbols, listing, references = program.getSymbolTable(), program.getListing(), program.getReferenceManager()
        base = segment * 16
        for space in [None, *dict.fromkeys(b.overlay for b in blocks if b.overlay)]:
            low = self._to_g(GhidraAddress(segment, 0, space), program)
            window = AddressSet(low, low.add(0xFFFF))
            for address in references.getReferenceDestinationIterator(window, True):
                symbol = symbols.getPrimarySymbol(address)
                if symbol is not None and not symbol.isDynamic():
                    continue
                if listing.getInstructionAt(address) is not None:
                    continue
                if not any(ref.getReferenceType().isData() for ref in references.getReferencesTo(address)):
                    continue
                name = aztec.data_label(GhidraAddress(segment, int(address.getOffset()) - base, space))
                symbols.createLabel(address, name, SourceType.ANALYSIS)

    def _install_fixups(self, program) -> None:
        from ghidra.program.database import SpecExtension  # type: ignore[import-not-found]

        extension = SpecExtension(program)
        for xml in (CSAV_FIXUP_XML, SWITCH_FIXUP_XML):
            extension.addReplaceCompilerSpecExtension(xml, self._pyghidra.task_monitor())

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
        roles = program.getUsrPropertyManager().getStringPropertyMap(HELPER_PROPERTY)
        if roles is not None and (role := roles.getString(function.getEntryPoint())) is not None:
            return DecompileResult(aztec.stub(str(role), str(function.getPrototypeString(False, False))), None)
        outcome = self._decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, self._pyghidra.task_monitor())
        decompiled = outcome.getDecompiledFunction() if outcome.decompileCompleted() else None
        if decompiled is not None:
            code, lines = self._printed(function, outcome.getCCodeMarkup(), str(decompiled.getC()))
            signature, variables = self._high_metadata(outcome.getHighFunction())
            return DecompileResult(code, None, lines=lines, signature=signature, variables=variables)
        error = str(outcome.getErrorMessage() or "").strip() or "decompilation did not complete"
        disassembly = []
        for ins in program.getListing().getInstructions(function.getBody(), True):
            if (at := self._to_spec(ins.getAddress())) is not None:
                disassembly.append((at, str(ins)))
        return DecompileResult(None, error, disassembly)

    def _label_switch_cases(self, function, markup) -> bool:
        """Aztec switch tables (aztec.py): the decompiler labels the cases of an overridden jump table by target
        address; relabel them with the table's values. Its override carries no label values, so the case tokens
        are rewritten (line structure unchanged). True when a token changed."""
        import java.util  # type: ignore[import-not-found]
        from ghidra.app.decompiler import ClangCaseToken, ClangToken  # type: ignore[import-not-found]

        sites = self._switch_calls(function)
        text = ClangToken.class_.getDeclaredField("text")
        text.setAccessible(True)
        nodes = java.util.ArrayList()
        markup.flatten(nodes)
        tokens = list(nodes)
        changed = False
        for index, token in enumerate(tokens):
            if not isinstance(token, ClangCaseToken) or (switch := token.getSwitchOp()) is None:
                continue
            site = sites.get(int(switch.getSeqnum().getTarget().getOffset()))
            if site is None:
                continue
            labels = aztec.case_labels(site["cases"], site["targets"])
            try:  # getValue() is the magnitude of a negative label; the text carries the sign
                value = int(str(token.getText()), 0)
            except ValueError:
                value = int(token.getValue())
            label = labels.get(value) or next(
                (labels[t] for t in labels if (t & 0xFFFF) == (value & 0xFFFF)), None)
            if label is None:
                continue
            text.set(token, label)
            if label.startswith("default"):  # drop the `case ` before it
                back = index - 1
                while back >= 0 and str(tokens[back].getText()).strip() in ("", "case"):
                    keyword = str(tokens[back].getText()).strip() == "case"
                    text.set(tokens[back], "")
                    back -= 1
                    if keyword:
                        break
            changed = True
        return changed

    def _printed(self, function, markup, code: str) -> tuple[str, list[DecompileLine] | None]:
        """C text and line records from the markup, with Aztec switch cases relabelled and expected warnings left
        out. Without markup, the decompiler's own text."""
        if markup is None:
            return code, None
        from ghidra.app.decompiler import PrettyPrinter  # type: ignore[import-not-found]

        calls = self._switch_calls(function)
        relabelled = bool(calls) and self._label_switch_cases(function, markup)
        # getDecompiledFunction().getC() is this printer's text. Enumerating its lines preserves blank lines
        # and avoids matching text (identical C statements may have different instruction origins).
        printed = list(PrettyPrinter(function, markup, None).getLines())
        texts = [str(PrettyPrinter.getText(line)) for line in printed]
        drop = aztec.expected_warnings(texts, set(calls))
        kept = [(line, text) for index, (line, text) in enumerate(zip(printed, texts)) if index not in drop]
        result = []
        for number, (line, _) in enumerate(kept, 1):
            ranges = []
            for token in line.getAllTokens():
                start = self._to_spec(token.getMinAddress())
                end = self._to_spec(token.getMaxAddress())
                if start is not None and end is not None:
                    ranges.append((start, end))
            result.append(DecompileLine(number, ranges))
        if relabelled or drop:
            from ghidra.util import StringUtilities  # type: ignore[import-not-found]

            code = "".join(text + str(StringUtilities.LINE_SEPARATOR) for _, text in kept)
        return code, result

    def _switch_calls(self, function) -> dict:
        """Aztec switch calls in `function`: {address offset: {"cases", "targets"}} (see SWITCH_PROPERTY)."""
        cases = self._require_program().getUsrPropertyManager().getStringPropertyMap(SWITCH_PROPERTY)
        if cases is None:
            return {}
        found = {}
        for address in cases.getPropertyIterator(function.getBody()):
            found[int(address.getOffset())] = json.loads(str(cases.getString(address)))
        return found

    @staticmethod
    def _storage(storage) -> str | None:
        if storage is None or storage.isBadStorage() or storage.isUnassignedStorage() or storage.isVoidStorage():
            return None
        if storage.isRegisterStorage():
            registers = [str(register.getName()) for register in storage.getRegisters()]
            return "register:" + ":".join(registers) if registers else None
        if storage.isStackStorage():
            return f"stack:{int(storage.getStackOffset()):+d}"
        # Ghidra's own readable representation retains compound, memory and unique storage locations.
        return str(storage) or None

    @staticmethod
    def _data_type(data_type) -> str | None:
        return str(data_type.getDisplayName()) if data_type is not None else None

    def _variable(self, symbol, first_use: bool = False) -> DecompileVariable:
        name = symbol.getName()
        return DecompileVariable(
            str(name) if name else None,
            self._data_type(symbol.getDataType()),
            self._storage(symbol.getStorage()),
            self._to_spec(symbol.getPCAddress()) if first_use else None,
        )

    def _high_metadata(self, high) -> tuple[DecompileSignature | None, list[DecompileVariable] | None]:
        if high is None:
            return None, None
        prototype = high.getFunctionPrototype()
        signature = None
        if prototype is not None:
            convention = prototype.getModelName()
            parameters = [prototype.getParam(index) for index in range(prototype.getNumParams())]
            signature = DecompileSignature(
                str(convention) if convention else None,
                self._data_type(prototype.getReturnType()),
                [self._variable(symbol) for symbol in parameters if symbol is not None],
            )
        symbols = high.getLocalSymbolMap()
        variables = None if symbols is None else [
            self._variable(symbol, first_use=True) for symbol in symbols.getSymbols() if not symbol.isGlobal()
        ]
        return signature, variables

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
