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

import re
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


def _case_value(value: int) -> str:
    """16-bit case value, negative ones signed as the decompiler prints them."""
    return f"-{0x10000 - value:#x}" if value >= 0x8000 else f"{value:#x}"


def case_labels(cases: list[int], targets: list[int]) -> dict[int, str]:
    """Label text for each switch target (`targets` in table order, the default last), in the form the decompiler
    prints after `case `: `0x52`, `0x52: case 0x53`, `default`, `0x7: default`. The decompiler only knows the
    targets of an overridden jump table and labels each case by its address."""
    values: dict[int, list[int]] = {}
    for case, target in zip(cases, targets):
        values.setdefault(target, []).append(case)
    labels = {target: ": case ".join(_case_value(v) for v in found) for target, found in values.items()}
    default = targets[-1]
    labels[default] = f"{labels[default]}: default" if default in labels else "default"
    return labels


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


# cmp ax,n; jae +8; xchg ax,bx; shl bx,1; jmp cs:[bx+table]  -- the dense switch, table of n targets in front
DENSE_TAIL = bytes.fromhex("73 08 93 D1 E3 2E FF A7")


def dense_switch_sites(data: bytes, base: int) -> list[SwitchSite]:
    """Dense switches in `data` (at segment offset `base`): `[sub ax,k;] cmp ax,n; jae default; xchg ax,bx;
    shl bx,1; jmp cs:[bx+table]` with the n-word table right in front of the `sub`/`cmp`. Case i is value i+k;
    the default is the instruction after the jump. `call` is the jump's offset."""
    sites = []
    for tail in _find_all(data, DENSE_TAIL):
        cmp = tail - 3
        if cmp < 0 or data[cmp] != 0x3D or tail + 10 > len(data):
            continue
        count = struct.unpack_from("<H", data, cmp + 1)[0]
        bias, start = 0, cmp
        if cmp >= 3 and data[cmp - 3] == 0x2D:
            bias, start = struct.unpack_from("<H", data, cmp - 2)[0], cmp - 3
        table = struct.unpack_from("<H", data, tail + 8)[0]
        if not 1 <= count <= MAX_CASES or table != base + start - 2 * count or table < base:
            continue
        words = struct.unpack_from(f"<{count}H", data, table - base)
        jump = base + tail + 5
        cases = [(i + bias) & 0xFFFF for i in range(count)]
        sites.append(SwitchSite(jump, table, 2 * count, cases, [*words, jump + 5]))
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


_WARNING = re.compile(r"/\* WARNING( \(jumptable\))?: (.*) \*/")
_UNREACHABLE = re.compile(r"Removing unreachable block \([^,]*,0x([0-9a-fA-F]+)\)")


def expected_warnings(lines: list[str], switch_calls: set[int]) -> set[int]:
    """Indices of decompiler warning lines to leave out in a function with Aztec switch calls (`switch_calls`:
    address offsets of the calls): the override notice and the unreachable call block are what the switch model
    does; the notice that a helper call is replaced by its fixup is how the helpers are modelled; a
    `WARNING (jumptable)` repeats the same warning from the jump-table pass; exact repeats go too."""
    drop, seen = set(), set()
    plain = {m.group(2) for line in lines if (m := _WARNING.fullmatch(line.strip())) and not m.group(1)}
    for index, line in enumerate(lines):
        match = _WARNING.fullmatch(line.strip())
        if match is None:
            continue
        message = match.group(2)
        unreachable = _UNREACHABLE.fullmatch(message)
        if (
            _INJECTION.fullmatch(message)
            or (switch_calls and message == "Switch is manually overridden")
            or (unreachable and int(unreachable.group(1), 16) in switch_calls)
            or (match.group(1) and message in plain)
            or line.strip() in seen
        ):
            drop.add(index)
        seen.add(line.strip())
    return drop


# Long arithmetic helpers: operands in DX:AX and BX:CX, result in DX:AX. `$ldv` (signed divide) and the signed
# remainder fix the signs and call the unsigned divider, which leaves the quotient in DX:AX and the remainder in
# BX:CX; the unsigned remainder entry calls it and moves BX:CX to DX:AX.
# push di; sub di,di; test dx,dx; jns; neg dx; neg ax; sbb dx,0; inc di; test bx,bx; jns; neg bx; neg cx; sbb bx,0;
# xor di,1; call
LONG_DIVIDE_PREFIX = bytes.fromhex("57 2B FF 85 D2 79 08 F7 DA F7 D8 83 DA 00 47 85 DB 79 0B F7 DB F7 D9 83 DB 00 81"
                                   " F7 01 00 E8")
# push di; mov di,0; the same sign fixes without the xor; call
LONG_REMAINDER_PREFIX = bytes.fromhex("57 BF 00 00 85 D2 79 08 F7 DA F7 D8 83 DA 00 47 85 DB 79 07 F7 DB F7 D9 83 DB"
                                      " 00 E8")
# call +5 (the unsigned divider); mov ax,cx; mov dx,bx; ret
UNSIGNED_REMAINDER = bytes.fromhex("E8 05 00 8B C1 8B D3 C3")


@dataclass(frozen=True)
class Helper:
    offset: int  # segment offset of the entry
    kind: str  # "csav" | "switch" | "long"
    role: str  # what it does, for the comment in place of its pseudo-C


def _call_target(data: bytes, base: int, at: int) -> int:
    return (base + at + 3 + struct.unpack_from("<H", data, at + 1)[0]) & 0xFFFF


def find_helpers(data: bytes, base: int) -> list[Helper]:
    """The run-time helpers this module models, in `data` at segment offset `base`, by entry offset."""
    found = [Helper(base + i, "csav", "$csav: function prologue (frame, SI/DI saved)") for i in find_csav(data)]
    found += [Helper(base + i, "switch", "$swt/$cswt: switch on AX through the inline table after the call")
              for i in find_switch_helpers(data)]
    dividers = set()
    for prefix, role in ((LONG_DIVIDE_PREFIX, "$ldv: signed long division"),
                         (LONG_REMAINDER_PREFIX, "signed long remainder")):
        for at in _find_all(data, prefix):
            found.append(Helper(base + at, "long", f"{role}, DX:AX by BX:CX into DX:AX"))
            call = at + len(prefix) - 1
            if call + 3 <= len(data):
                dividers.add(_call_target(data, base, call))
    for at in _find_all(data, UNSIGNED_REMAINDER):
        if _call_target(data, base, at) in dividers:
            found.append(Helper(base + at, "long", "unsigned long remainder, DX:AX by BX:CX into DX:AX"))
    for divider in sorted(dividers):
        if base <= divider < base + len(data):
            found.append(Helper(divider, "long", "unsigned long division, DX:AX by BX:CX into DX:AX "
                                                 "(remainder in BX:CX)"))
    return sorted(set(found), key=lambda h: h.offset)


def stub(role: str, prototype: str) -> str:
    """Pseudo-C in place of a run-time helper's body: its role and prototype (calls to it are modelled)."""
    return f"/* Aztec C86 run-time helper: {role} */\n\n{prototype};\n"


_INJECTION = re.compile(r"Function: .* replaced with injection: decovery_aztec_\w+")
