# ADR 0011: Overlay addresses

Status: accepted · 2026-11-18 (owner approved the `ovl:` form at gate A)

## Context

The third target is a small-model DOS program (MZ) plus overlay files that the main program loads at run time into
a fixed window of its own code and data segments (Aztec C86 `ovloader`). Every overlay occupies the same CS:IP range
as the others; `seg:SSSS:OOOO` cannot tell them apart, and an overlay has no fixed linear address because it shares
the window with the other overlays. Decomp addresses such code as `ovl:NAME:SSSS:OOOO`.

## Decision

- New `Address::Ovl { overlay: OverlayName, seg: u16, off: u16 }` with the canonical text `ovl:NAME:SSSS:OOOO`
  (seg/off four upper-case hex digits, as `seg:`). `seg` is the segment relative to the main program's load segment,
  the same base as `seg:` addresses of the main program.
- `OverlayName` holds `[A-Za-z0-9_]{1,16}`, stored and printed upper case (the overlay's file stem, as DOS sees it).
  It is a fixed 16-byte array so `Address` stays `Copy`. Parsing accepts lower case and normalises it.
- `linear()` is `None`: two overlays share linear addresses. `offset_by` moves `off` only. `address_key` gives
  `ovl_NAME_SSSS_OOOO` (the generic rule: canonical text with `:` replaced by `_`).
- Ordering: `Address` derives `Ord`; `Ovl` sorts after the other kinds, then by name, segment, offset.
- Two `ovl:` addresses compare positionally (ranges, segments, line maps) only within the same overlay; an `ovl:`
  address never falls into a main-program segment and vice versa.
- Workspace: overlays are `[[overlay]]` entries in `decovery.toml` (`name`, `file`, `sha256`, `format`, optional
  `file_offset`/`size` of the overlay inside the file), managed by `decovery overlay add|list|remove`. Their memory
  segments are ordinary `[[target.segment]]` entries whose `start` is an `ovl:` address, so the memory map, file
  offsets and `in_segment` work unchanged. A user-typed `ovl:` address whose name is not configured is an error that
  names the known overlays.
- Ghidra: one overlay address space per overlay (Ghidra's overlay blocks), named after the overlay, as Decomp's
  Ghidra project does.

## Why not `seg:` with a different segment

A synthetic segment per overlay (e.g. `seg:F001:…`) would give every overlay a linear address, but a false one: the
code runs at the main program's CS, so decoded near calls and jumps, data references through DS and the runtime
addresses of a trace would all disagree with the stored address. Keeping the real CS:IP plus the overlay name keeps
the bytes and the addresses consistent.

## Migration

Decomp's `ovl:NAME:SSSS:OOOO` maps 1:1 (Decomp's `rel:` → `seg:` is unchanged). Decomp's 32-bit form
`ovl:NAME:XXXXXXXX` has no target yet and is rejected with a syntax error until one needs it.

## Consequences

- Text forms and keys of the existing kinds are unchanged; stores and attempt shards need no schema bump (they hold
  addresses as text).
- Code that matches on `Address` gets an `Ovl` arm; positional comparisons that used `linear()` treat `ovl:` like
  `sel:` (same space only).
