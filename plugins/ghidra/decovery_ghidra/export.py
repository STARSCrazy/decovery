"""`analyzer/export`: read functions, calls, strings and data accesses from Ghidra and write them as one JSON file.

`read_program` is the only Ghidra-facing part (imports are local to it); the records and the writer are pure
Python so the plugin logic is tested with a fake backend. Ported from Decomp's Ghidra engine (`funktionen`,
`aufrufe`, `strings`, `globale_zugriffe`).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import mapping
from .hashing import blake3_hex
from .mapping import GhidraAddress


@dataclass(frozen=True)
class FunctionRecord:
    start: GhidraAddress
    end: GhidraAddress  # inclusive
    body_size: int
    name: str | None  # None: Ghidra has only a default name


@dataclass(frozen=True)
class CallRecord:
    site: GhidraAddress
    caller: GhidraAddress
    callee: GhidraAddress


@dataclass(frozen=True)
class StringRecord:
    address: GhidraAddress
    text: str
    users: tuple[GhidraAddress, ...]


@dataclass(frozen=True)
class AccessRecord:
    function: GhidraAddress
    address: GhidraAddress
    kind: str  # "read" | "write"


@dataclass(frozen=True)
class ExportData:
    functions: list[FunctionRecord]
    calls: list[CallRecord]
    strings: list[StringRecord]
    accesses: list[AccessRecord]


def write_atomic(path: Path, data: bytes) -> None:
    """Write `<path>.tmp`, then rename over `path`."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _clean_text(text: str) -> str:
    """Strings read from Java may hold lone surrogates, which UTF-8 cannot carry."""
    return text.encode("utf-8", "replace").decode("utf-8")


def export_document(data: ExportData, arch: str) -> dict:
    """The export file content: decovery address strings, deterministic order, records whose addresses do not
    fit the arch dropped."""

    def text(address: GhidraAddress) -> str | None:
        try:
            return mapping.from_ghidra_address(address, arch)
        except mapping.MappingError:
            return None

    functions = []
    for f in data.functions:
        start, end = text(f.start), text(f.end)
        if start and end:
            functions.append({"start": start, "end": end, "body_size": int(f.body_size), "name": f.name})
    functions.sort(key=lambda f: f["start"])

    calls = set()
    for c in data.calls:
        site, caller, callee = text(c.site), text(c.caller), text(c.callee)
        if site and caller and callee:
            calls.add((caller, site, callee))

    strings = []
    for s in data.strings:
        address = text(s.address)
        if address:
            users = sorted({u for u in map(text, s.users) if u})
            strings.append({"address": address, "text": _clean_text(s.text), "users": users})
    strings.sort(key=lambda s: s["address"])

    accesses = set()
    for a in data.accesses:
        function, address = text(a.function), text(a.address)
        if function and address and a.kind in ("read", "write"):
            accesses.add((function, address, a.kind))

    return {
        "schema": 1,
        "functions": functions,
        "calls": [{"site": s, "caller": c, "callee": e} for c, s, e in sorted(calls)],
        "strings": strings,
        "data_accesses": [{"function": f, "address": a, "kind": k} for f, a, k in sorted(accesses)],
    }


def write_export(data: ExportData, arch: str, out_path: str) -> dict:
    """Write the export file atomically; returns `{path, blake3}`."""
    document = export_document(data, arch)
    raw = (json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    write_atomic(Path(out_path), raw)
    return {"path": str(out_path), "blake3": blake3_hex(raw)}


# -- Ghidra ----------------------------------------------------------------------------------------------------


def read_program(program, to_spec: Callable[[object], GhidraAddress | None]) -> ExportData:
    """Everything `analyzer/export` reports, read from an open Ghidra program. `to_spec` maps a Ghidra address to
    a `GhidraAddress` (None when it is not a memory address)."""
    from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]
    from ghidra.program.util import DefinedStringIterator  # type: ignore[import-not-found]

    fm, listing, rm, mem = (
        program.getFunctionManager(),
        program.getListing(),
        program.getReferenceManager(),
        program.getMemory(),
    )

    functions = []
    for f in fm.getFunctions(True):
        if f.isExternal():
            continue
        start, end = to_spec(f.getEntryPoint()), to_spec(f.getBody().getMaxAddress())
        if start is None or end is None:
            continue
        name = str(f.getName())
        if name == mapping.default_name(start) or f.getSymbol().getSource() == SourceType.DEFAULT:
            name = None
        functions.append(FunctionRecord(start, end, int(f.getBody().getNumAddresses()), name))

    calls = []
    for f in fm.getFunctions(True):
        caller = to_spec(f.getEntryPoint())
        if caller is None:
            continue
        for ins in listing.getInstructions(f.getBody(), True):
            if not ins.getFlowType().isCall():
                continue
            for ref in ins.getReferencesFrom():
                if not ref.getReferenceType().isCall():
                    continue
                target = fm.getFunctionAt(ref.getToAddress())
                callee = to_spec(target.getEntryPoint()) if target is not None else None
                site = to_spec(ins.getAddress())
                if callee is not None and site is not None:
                    calls.append(CallRecord(site, caller, callee))

    strings = []
    for d in DefinedStringIterator.forProgram(program):
        address = to_spec(d.getAddress())
        if address is None:
            continue
        users = set()
        for r in rm.getReferencesTo(d.getAddress()):
            f = fm.getFunctionContaining(r.getFromAddress())
            if f is not None and (entry := to_spec(f.getEntryPoint())) is not None:
                users.add(entry)
        strings.append(StringRecord(address, str(d.getValue()), tuple(users)))

    # Reads/writes of memory outside the function. Pure DATA references (immediates, address taken) count only
    # when they point into a non-executable block.
    accesses = set()
    for f in fm.getFunctions(True):
        function = to_spec(f.getEntryPoint())
        if function is None:
            continue
        for ins in listing.getInstructions(f.getBody(), True):
            for ref in ins.getReferencesFrom():
                rt, target = ref.getReferenceType(), ref.getToAddress()
                if (
                    ref.isStackReference()
                    or not rt.isData()
                    or not target.isMemoryAddress()
                    or not mem.contains(target)
                    or f.getBody().contains(target)
                ):
                    continue
                if fm.getFunctionAt(target) is not None:
                    continue
                data = listing.getDataAt(target)
                if data is not None and data.hasStringValue():
                    continue
                kinds = [k for k, yes in (("read", rt.isRead()), ("write", rt.isWrite())) if yes]
                if not kinds:
                    block = mem.getBlock(target)
                    if block is None or block.isExecute():
                        continue  # an immediate that happens to point into code
                    kinds = ["read"]
                if (address := to_spec(target)) is not None:
                    accesses.update(AccessRecord(function, address, k) for k in kinds)

    return ExportData(functions, calls, strings, list(accesses))
