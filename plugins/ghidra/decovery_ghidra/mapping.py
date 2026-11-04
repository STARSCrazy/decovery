"""Maps decovery's program description to Ghidra vocabulary and Ghidra addresses back.

Pure Python, no Ghidra imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

LANGUAGES = {
    "x86-flat-32": "x86:LE:32:default",
    "x86-real-16": "x86:LE:16:Real Mode",
}

# decovery address kind used by each architecture
ADDRESS_KIND = {
    "x86-flat-32": "flat",
    "x86-real-16": "seg",
}


class MappingError(ValueError):
    """The program description cannot be mapped to Ghidra."""


@dataclass(frozen=True)
class GhidraAddress:
    """An address in Ghidra's space: flat offset, or segment:offset in real mode."""

    segment: int | None
    offset: int

    def text(self) -> str:
        """Text form Ghidra's address factory parses."""
        if self.segment is None:
            return f"{self.offset:08X}"
        return f"{self.segment:04X}:{self.offset:04X}"


@dataclass(frozen=True)
class MemoryBlockSpec:
    name: str
    start: GhidraAddress
    size: int
    read: bool
    write: bool
    execute: bool
    data: bytes


_FLAT = re.compile(r"flat:([0-9A-F]{8})")
_SEG = re.compile(r"seg:([0-9A-F]{4}):([0-9A-F]{4})")


def language_for(arch: str) -> str:
    try:
        return LANGUAGES[arch]
    except KeyError:
        raise MappingError(f"unsupported arch {arch!r}; supported: {', '.join(sorted(LANGUAGES))}") from None


def to_ghidra_address(text: str, arch: str) -> GhidraAddress:
    """Parse a decovery address string for a program of the given architecture."""
    kind = ADDRESS_KIND.get(arch)
    if kind is None:
        raise MappingError(f"unsupported arch {arch!r}")
    if not isinstance(text, str):
        raise MappingError(f"address must be a string, got {type(text).__name__}")
    flat = _FLAT.fullmatch(text)
    seg = _SEG.fullmatch(text)
    if kind == "flat" and flat:
        return GhidraAddress(None, int(flat.group(1), 16))
    if kind == "seg" and seg:
        return GhidraAddress(int(seg.group(1), 16), int(seg.group(2), 16))
    raise MappingError(f"address {text!r} is not a {kind}: address (arch {arch})")


def from_ghidra_address(address: GhidraAddress, arch: str) -> str:
    """Canonical decovery text of a Ghidra address."""
    kind = ADDRESS_KIND.get(arch)
    if kind == "flat" and address.segment is None:
        return f"flat:{address.offset:08X}"
    if kind == "seg" and address.segment is not None:
        return f"seg:{address.segment:04X}:{address.offset:04X}"
    raise MappingError(f"address {address} does not fit arch {arch!r}")


def permissions(text: str) -> tuple[bool, bool, bool]:
    if not isinstance(text, str) or set(text) - set("rwx-"):
        raise MappingError(f"permissions must be made of r, w, x, -: {text!r}")
    return "r" in text, "w" in text, "x" in text


def common_arch(regions: list[dict]) -> str:
    if not regions:
        raise MappingError("program has no regions")
    archs = {r.get("arch") for r in regions}
    if len(archs) != 1:
        raise MappingError(f"all regions must share one arch, got {sorted(map(str, archs))}")
    return archs.pop()


def block_for(region: dict, arch: str, data: bytes) -> MemoryBlockSpec:
    """Memory block for a decovery region whose blob has been decoded to `data`."""
    size = region.get("size")
    if not isinstance(size, int) or size <= 0:
        raise MappingError(f"region {region.get('name')!r}: size must be a positive integer")
    if len(data) > size:
        raise MappingError(f"region {region.get('name')!r}: blob ({len(data)} bytes) larger than size {size}")
    read, write, execute = permissions(region.get("permissions", "r--"))
    return MemoryBlockSpec(
        name=str(region.get("name") or "region"),
        start=to_ghidra_address(region.get("start"), arch),
        size=size,
        read=read,
        write=write,
        execute=execute,
        data=data.ljust(size, b"\0"),
    )
