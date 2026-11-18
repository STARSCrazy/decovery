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
    """An address in Ghidra's space: flat offset, or segment:offset in real mode. `space` names the overlay
    address space of an overlay (ADR 0011: one Ghidra overlay space per overlay); None = the default space."""

    segment: int | None
    offset: int
    space: str | None = None

    def text(self) -> str:
        """Text form Ghidra's address factory parses (`NAME::SSSS:OOOO` in an overlay space)."""
        inner = f"{self.offset:08X}" if self.segment is None else f"{self.segment:04X}:{self.offset:04X}"
        return f"{self.space}::{inner}" if self.space else inner

    @staticmethod
    def parse(text: str) -> "GhidraAddress":
        """Inverse of `text()`."""
        space, sep, inner = text.rpartition("::")
        if not sep:
            space, inner = None, text
        segment, sep, offset = inner.partition(":")
        if sep:
            return GhidraAddress(int(segment, 16), int(offset, 16), space or None)
        return GhidraAddress(None, int(inner, 16), space or None)


@dataclass(frozen=True)
class MemoryBlockSpec:
    name: str
    start: GhidraAddress
    size: int
    read: bool
    write: bool
    execute: bool
    data: bytes

    @property
    def overlay(self) -> str | None:
        """Name of the overlay address space the block belongs to (None = default space)."""
        return self.start.space


_FLAT = re.compile(r"flat:([0-9A-F]{8})")
_SEG = re.compile(r"seg:([0-9A-F]{4}):([0-9A-F]{4})")
_OVL = re.compile(r"ovl:([A-Z0-9_]{1,16}):([0-9A-F]{4}):([0-9A-F]{4})")


_OVL_NAME = re.compile(r"[A-Z0-9_]{1,16}")


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
    ovl = _OVL.fullmatch(text)
    if kind == "flat" and flat:
        return GhidraAddress(None, int(flat.group(1), 16))
    if kind == "seg" and seg:
        return GhidraAddress(int(seg.group(1), 16), int(seg.group(2), 16))
    if kind == "seg" and ovl:
        return GhidraAddress(int(ovl.group(2), 16), int(ovl.group(3), 16), ovl.group(1))
    raise MappingError(f"address {text!r} is not a {kind}: address (arch {arch})")


def from_ghidra_address(address: GhidraAddress, arch: str) -> str:
    """Canonical decovery text of a Ghidra address."""
    kind = ADDRESS_KIND.get(arch)
    if address.space is not None:
        if kind == "seg" and address.segment is not None and _OVL_NAME.fullmatch(address.space):
            return f"ovl:{address.space}:{address.segment:04X}:{address.offset:04X}"
        raise MappingError(f"address {address} does not fit arch {arch!r}")
    if kind == "flat" and address.segment is None:
        return f"flat:{address.offset:08X}"
    if kind == "seg" and address.segment is not None:
        return f"seg:{address.segment:04X}:{address.offset:04X}"
    raise MappingError(f"address {address} does not fit arch {arch!r}")


def default_name(address: GhidraAddress) -> str:
    """decovery's default function name (`fun_0001A2B0`, `fun_1000_0010`, `fun_VINIT_0000_505E`); functions without a knowledge name
    carry it in Ghidra, so decompiled callers read the same names as decovery's output."""
    return "fun_" + address.text().replace("::", "_").replace(":", "_")


def merged_ranges(ranges: list[tuple[GhidraAddress, GhidraAddress]], arch: str) -> list[dict]:
    """Canonical inclusive ranges; merge overlaps/adjacency only within the same segment.

    Never bridge a gap or combine segmented aliases: each endpoint keeps the decompiler's segment.
    """
    valid = []
    for start, end in ranges:
        if start.segment != end.segment or start.space != end.space or start.offset > end.offset:
            continue
        try:
            from_ghidra_address(start, arch)
            from_ghidra_address(end, arch)
        except MappingError:
            continue
        valid.append((start, end))
    valid.sort(key=lambda pair: (pair[0].space or "", pair[0].segment or 0, pair[0].offset, pair[1].offset))
    merged: list[tuple[GhidraAddress, GhidraAddress]] = []
    for start, end in valid:
        if (merged and merged[-1][1].segment == start.segment and merged[-1][1].space == start.space
                and start.offset <= merged[-1][1].offset + 1):
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, GhidraAddress(end.segment, max(previous_end.offset, end.offset), end.space))
        else:
            merged.append((start, end))
    return [{"start": from_ghidra_address(start, arch), "end": from_ghidra_address(end, arch)}
            for start, end in merged]


def file_stem(text: str) -> str:
    """Output file name of a decovery address: `:` replaced by `_`."""
    return text.replace(":", "_")


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


def overlay_address(blocks: list[MemoryBlockSpec], space: str, linear: int) -> GhidraAddress | None:
    """A Ghidra overlay-space address back as segment:offset in that overlay: Ghidra keeps only the linear offset,
    the segment comes from the overlay block that holds it. None outside every block of the overlay."""
    for b in blocks:
        if b.overlay != space or b.start.segment is None:
            continue
        base = b.start.segment * 16
        if base + b.start.offset <= linear < base + b.start.offset + b.size:
            return GhidraAddress(b.start.segment, linear - base, space)
    return None
