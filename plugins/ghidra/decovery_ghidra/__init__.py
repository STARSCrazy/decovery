"""decovery plugin exposing Ghidra analysis and decompilation. See README.md.

This module holds the protocol handlers (validation, project persistence, progress, cancellation, error codes)
and stays free of Ghidra imports; everything Ghidra-facing sits behind `backend.Backend`.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable

from decovery_plugin import Context, Plugin, RpcError, decode_blob

from . import apply, export, mapping, project
from .backend import Backend, BackendError, GhidraBackend

__version__ = "0.2.0"

ANALYZER_VERSION = 2
DECOMPILER_VERSION = 2

INVALID_PARAMS = -32602
NOT_OPENED = -32011
IO_FAILED = -32012


def _backend_error(exc: BackendError) -> RpcError:
    return RpcError(exc.code, exc.message)


def _io_error(exc: OSError) -> RpcError:
    return RpcError(IO_FAILED, f"project or file I/O failed: {exc}")


def build_plugin(backend_factory: Callable[[], Backend] = GhidraBackend) -> Plugin:
    """The Ghidra plugin; `backend_factory` is called once per `analyzer/open` (tests inject a fake)."""
    plugin = Plugin("ghidra", __version__)
    session: dict[str, Any] = {"backend": None, "arch": None, "calling_convention": None}
    # The SDK runs requests on worker threads; one Ghidra program is used by one request at a time.
    lock = threading.RLock()

    @plugin.on_shutdown
    def close_session() -> None:
        """Release the program, the decompiler and the project lock when the session ends."""
        with lock:
            backend, session["backend"] = session["backend"], None
            if backend is not None:
                backend.close()

    def opened() -> tuple[Backend, str]:
        if session["backend"] is None:
            raise RpcError(NOT_OPENED, "no program is open; call analyzer/open first")
        return session["backend"], session["arch"]

    @plugin.method("analyzer/open", capability_version=ANALYZER_VERSION)
    def open_program(params: dict, ctx: Context) -> dict:
        try:
            program = params["program"]
            project_dir = params["project_dir"]
            program_hash = params["program_hash"]
            if not isinstance(project_dir, str) or not project_dir:
                raise TypeError("'project_dir'")
            if not isinstance(program_hash, str) or not program_hash:
                raise TypeError("'program_hash'")
            options = params.get("options") or {}
            if not isinstance(options, dict):
                raise TypeError("'options'")
            calling_convention = options.get("calling_convention")
            if calling_convention is not None and not isinstance(calling_convention, str):
                raise TypeError("'options.calling_convention'")
            regions = program["regions"]
            arch = mapping.common_arch(regions)
            language_id = mapping.language_for(arch)
            blocks = [mapping.block_for(r, arch, decode_blob(r["blob"])) for r in regions]
            entries = [mapping.to_ghidra_address(a, arch) for a in program.get("entry_points", [])]
        except (KeyError, TypeError, AttributeError) as exc:
            raise RpcError(INVALID_PARAMS, f"invalid analyzer/open params: missing or malformed {exc}") from exc
        except mapping.MappingError as exc:
            raise RpcError(INVALID_PARAMS, str(exc)) from exc
        with lock:
            if session["backend"] is not None:
                session["backend"].close()
                session["backend"] = None
            backend = backend_factory()
            try:
                location = project.project_location(project_dir)
                key = project.project_key(program_hash, backend.ghidra_version(), calling_convention)
                reuse = project.stored_key_matches(location, key)
                if not reuse:
                    project.reset_project(location)
                outcome = backend.open_program(
                    language_id,
                    blocks,
                    entries,
                    str(location),
                    {
                        "calling_convention": calling_convention,
                        # Decomp enabled it for flat 32-bit formats only, never for real mode
                        "aggressive_instruction_finder": arch == "x86-flat-32",
                    },
                    reuse,
                    ctx.progress,
                )
                project.save_key(location, key)
            except BackendError as exc:
                raise _backend_error(exc) from exc
            except OSError as exc:
                raise _io_error(exc) from exc
            session.update(backend=backend, arch=arch, calling_convention=calling_convention)
        return {"functions": outcome.functions, "reused": outcome.reused}

    @plugin.method("analyzer/functions", capability_version=ANALYZER_VERSION)
    def functions(params: dict, ctx: Context) -> list[dict]:
        with lock:
            backend, arch = opened()
            try:
                found = backend.functions()
            except BackendError as exc:
                raise _backend_error(exc) from exc
        found = sorted(found, key=lambda f: (f.segment or 0, f.offset))
        return [
            {
                "address": mapping.from_ghidra_address(mapping.GhidraAddress(f.segment, f.offset), arch),
                "name": f.name,
                "size": f.size,
            }
            for f in found
        ]

    @plugin.method("analyzer/apply", capability_version=ANALYZER_VERSION)
    def apply_knowledge(params: dict, ctx: Context) -> dict:
        with lock:
            backend, arch = opened()
            try:
                symbols, types_h, references, warnings = apply.parse_apply_params(params, arch)
            except apply.ParamsError as exc:
                raise RpcError(INVALID_PARAMS, f"invalid analyzer/apply params: {exc}") from exc
            try:
                applied, more = backend.apply(symbols, types_h, references, session["calling_convention"])
            except BackendError as exc:
                raise _backend_error(exc) from exc
            except OSError as exc:
                raise _io_error(exc) from exc
        return {"applied": applied, "warnings": warnings + list(more)}

    @plugin.method("analyzer/export", capability_version=ANALYZER_VERSION)
    def export_analysis(params: dict, ctx: Context) -> dict:
        with lock:
            backend, arch = opened()
            out_path = params.get("out_path")
            if not isinstance(out_path, str) or not out_path:
                raise RpcError(INVALID_PARAMS, "analyzer/export needs 'out_path': string")
            try:
                data = backend.export_data()
            except BackendError as exc:
                raise _backend_error(exc) from exc
        try:
            return export.write_export(data, arch, out_path)
        except OSError as exc:
            raise _io_error(exc) from exc

    @plugin.method("decompiler/decompile", capability_version=DECOMPILER_VERSION)
    def decompile(params: dict, ctx: Context) -> list[dict]:
        with lock:
            backend, arch = opened()
        addresses = params.get("addresses")
        out_dir = params.get("out_dir")
        if not isinstance(addresses, list):
            raise RpcError(INVALID_PARAMS, "decompiler/decompile needs 'addresses': [..]")
        if not isinstance(out_dir, str) or not out_dir:
            raise RpcError(INVALID_PARAMS, "decompiler/decompile needs 'out_dir': string")
        results = []
        for index, text in enumerate(addresses):
            ctx.check_cancelled()
            ctx.progress(index, len(addresses))
            entry: dict[str, Any] = {"address": text}
            try:
                address = mapping.to_ghidra_address(text, arch)
                with lock:
                    outcome = backend.decompile(address)
            except mapping.MappingError as exc:
                entry["error"] = str(exc)
            except BackendError as exc:
                entry["error"] = exc.message
            except Exception as exc:  # one failing function must not lose the batch
                entry["error"] = f"{type(exc).__name__}: {exc}"
            else:
                if outcome.code is not None:
                    path = Path(out_dir) / f"{mapping.file_stem(text)}.c"
                    code = outcome.code.replace("\r\n", "\n")
                    try:
                        export.write_atomic(path, code.encode("utf-8", "replace"))
                    except OSError as exc:  # out_dir unusable: no later function would fare better
                        raise _io_error(exc) from exc
                    entry["path"] = str(path)
                else:
                    entry["error"] = outcome.error or "decompilation failed"
                    disassembly = []
                    for at, line in outcome.disassembly:
                        try:
                            disassembly.append([mapping.from_ghidra_address(at, arch), line])
                        except mapping.MappingError:
                            continue
                    if disassembly:
                        entry["disassembly"] = disassembly
            results.append(entry)
        ctx.progress(len(addresses), len(addresses))
        return results

    return plugin
