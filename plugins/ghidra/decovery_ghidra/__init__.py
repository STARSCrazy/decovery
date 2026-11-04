"""decovery plugin exposing Ghidra analysis and decompilation. See README.md."""

from __future__ import annotations

from typing import Any, Callable

from decovery_plugin import Context, Plugin, RpcError, decode_blob

from . import mapping
from .backend import BackendError, GhidraBackend

__version__ = "0.1.0"

INVALID_PARAMS = -32602
NOT_OPENED = -32011


def build_plugin(backend_factory: Callable[[], Any] = GhidraBackend) -> Plugin:
    """The Ghidra plugin; `backend_factory` is called once per `analyzer/open` (tests inject a fake)."""
    plugin = Plugin("ghidra", __version__)
    session: dict[str, Any] = {"backend": None, "arch": None}

    def backend_and_arch() -> tuple[Any, str]:
        if session["backend"] is None:
            raise RpcError(NOT_OPENED, "no program is open; call analyzer/open first")
        return session["backend"], session["arch"]

    @plugin.method("analyzer/open", capability_version=1)
    def open_program(params: dict, ctx: Context) -> dict:
        try:
            program = params["program"]
            project_dir = params["project_dir"]
            regions = program["regions"]
            arch = mapping.common_arch(regions)
            language_id = mapping.language_for(arch)
            blocks = [mapping.block_for(r, arch, decode_blob(r["blob"])) for r in regions]
            entries = [mapping.to_ghidra_address(a, arch) for a in program.get("entry_points", [])]
        except (KeyError, TypeError) as exc:
            raise RpcError(INVALID_PARAMS, f"invalid analyzer/open params: missing or malformed {exc}") from exc
        except mapping.MappingError as exc:
            raise RpcError(INVALID_PARAMS, str(exc)) from exc
        if session["backend"] is not None and hasattr(session["backend"], "close"):
            session["backend"].close()
        backend = backend_factory()
        try:
            count = backend.open_program(language_id, blocks, entries, project_dir, ctx.progress)
        except BackendError as exc:
            raise RpcError(exc.code, exc.message) from exc
        session["backend"], session["arch"] = backend, arch
        return {"functions": count}

    @plugin.method("analyzer/functions", capability_version=1)
    def functions(params: dict, ctx: Context) -> list[dict]:
        backend, arch = backend_and_arch()
        try:
            found = backend.functions()
        except BackendError as exc:
            raise RpcError(exc.code, exc.message) from exc
        found = sorted(found, key=lambda f: (f.segment or 0, f.offset))
        return [
            {
                "address": mapping.from_ghidra_address(mapping.GhidraAddress(f.segment, f.offset), arch),
                "name": f.name,
                "size": f.size,
            }
            for f in found
        ]

    @plugin.method("decompiler/decompile", capability_version=1)
    def decompile(params: dict, ctx: Context) -> list[dict]:
        backend, arch = backend_and_arch()
        addresses = params.get("addresses")
        if not isinstance(addresses, list):
            raise RpcError(INVALID_PARAMS, "decompiler/decompile needs 'addresses': [..]")
        results = []
        for index, text in enumerate(addresses):
            ctx.check_cancelled()
            ctx.progress(index, len(addresses))
            entry: dict[str, Any] = {"address": text}
            try:
                outcome = backend.decompile(mapping.to_ghidra_address(text, arch))
            except mapping.MappingError as exc:
                entry["error"] = str(exc)
            except BackendError as exc:
                entry["error"] = exc.message
            except Exception as exc:  # one failing function must not lose the batch
                entry["error"] = f"{type(exc).__name__}: {exc}"
            else:
                if outcome.error is not None:
                    entry["error"] = outcome.error
                else:
                    entry["code"] = outcome.code
            results.append(entry)
        return results

    return plugin
