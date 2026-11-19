"""Aztec C86 run-time patterns Ghidra does not understand on its own. Pure Python, no Ghidra imports.

- `$csav` (frame helper): functions start with `mov ax,-frame; call $csav`. The helper pops its return address,
  sets up `BP` and the frame, saves `SI`/`DI` and calls the rest of the function, so that rest runs with `BP` as
  frame pointer. Ghidra sees an ordinary call and loses `BP` (`unaff_BP`).
- the switch helper: `mov cx,n; call $swt` followed by an inline table of n-1 case values, n-1 targets and the
  default target. The helper never returns to the call; Ghidra decodes the table as code.
- the data segment: overlay data blocks sit in the program's data segment (`DS`), which Ghidra otherwise assumes
  to be 0, so `[0x9202]` lands in the code segment.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .mapping import GhidraAddress, MemoryBlockSpec

# pop bx; push bp; mov bp,sp; add sp,ax
CSAV_PREFIX = bytes.fromhex("5B 55 8B EC 03 E0")
# pop bx; push di; push es; mov di,cs; mov es,di; mov di,bx; mov bx,cx; shl bx,1; cld; repne scasw
SWITCH_PREFIX = bytes.fromhex("5B 57 06 8C CF 8E C7 8B FB 8B D9 D1 E3 FC F2 AF")
MAX_CASES = 1024


@dataclass(frozen=True)
class SwitchSite:
    call: int  # offset of the `call` to the helper
    table: int  # offset of the inline table (right after the call)
    size: int  # table size in bytes
    cases: list[int]  # case values (compared with AX)
    targets: list[int]  # case targets in table order, the default last

    def comment(self) -> str:
        """What the table says, for a comment at the call: the decompiler labels the cases by target address."""
        pairs = ", ".join(f"{case:#x} -> {target:04X}" for case, target in zip(self.cases, self.targets))
        return f"switch (AX): {pairs}; default -> {self.targets[-1]:04X}"


def _find_all(data: bytes, pattern: bytes) -> list[int]:
    found, at = [], data.find(pattern)
    while at >= 0:
        found.append(at)
        at = data.find(pattern, at + 1)
    return found


def find_csav(data: bytes) -> list[int]:
    """Offsets (into `data`) of `$csav`-like frame helpers."""
    return _find_all(data, CSAV_PREFIX)


def find_switch_helpers(data: bytes) -> list[int]:
    """Offsets (into `data`) of the table-driven switch helper."""
    return _find_all(data, SWITCH_PREFIX)


def switch_sites(data: bytes, base: int, helpers: list[int]) -> list[SwitchSite]:
    """`mov cx,n; call <helper>` sites in `data` (which starts at segment offset `base`); `helpers` are segment
    offsets. Tables that leave `data` or have an implausible count are skipped."""
    wanted = set(helpers)
    sites = []
    for at in range(len(data) - 5):
        if data[at] != 0xB9 or data[at + 3] != 0xE8:
            continue
        count = struct.unpack_from("<H", data, at + 1)[0]
        call = base + at + 3
        target = (call + 3 + struct.unpack_from("<H", data, at + 4)[0]) & 0xFFFF
        if target not in wanted or not 1 <= count <= MAX_CASES:
            continue
        table = call + 3
        size = 2 * (2 * count - 1)
        start = table - base
        if start + size > len(data):
            continue
        words = struct.unpack_from(f"<{2 * count - 1}H", data, start)
        sites.append(SwitchSite(call, table, size, list(words[:count - 1]), list(words[count - 1:])))
    return sites


def data_segment(blocks: list[MemoryBlockSpec]) -> int | None:
    """The data segment shared by all non-executable overlay blocks; None without such blocks or when they
    disagree."""
    segments = {b.start.segment for b in blocks if b.overlay and not b.execute}
    if len(segments) != 1 or None in segments:
        return None
    return segments.pop()


def uncovered(blocks: list[MemoryBlockSpec], segment: int) -> list[tuple[int, int]]:
    """(offset, size) runs of the 64 KiB data segment that no default-space block covers."""
    base = segment * 16
    covered = sorted(
        (b.start.segment * 16 + b.start.offset, b.start.segment * 16 + b.start.offset + b.size)
        for b in blocks if b.overlay is None and b.start.segment is not None
    )
    runs, at, end = [], base, base + 0x10000
    for low, high in covered:
        if high <= at or low >= end:
            continue
        if low > at:
            runs.append((at - base, low - at))
        at = max(at, high)
    if at < end:
        runs.append((at - base, end - at))
    return runs


def data_label(address: GhidraAddress) -> str:
    """Name for unnamed data in the data segment: Ghidra's segmented `DAT_ssss_oooo` with the `DS` offset (Ghidra
    itself names by the linear or a normalized address), in an overlay space with the overlay name."""
    prefix = f"DAT_{address.space}_" if address.space else "DAT_"
    return f"{prefix}{address.segment:04x}_{address.offset:04x}"
