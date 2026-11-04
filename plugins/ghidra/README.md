# decovery-ghidra

decovery plugin that drives Ghidra through pyghidra. Run as `python -m decovery_ghidra` (stdio, protocol in
`docs/plugin-protocol.md`). Needs the `decovery-plugin` SDK; pyghidra is imported only when a program is opened.

Status: skeleton. The logic (mapping, dispatch, errors) is tested with a fake backend; the real `GhidraBackend`
has not been run against Ghidra yet.

## Setup

- `GHIDRA_INSTALL_DIR` points to a Ghidra installation. Expected version `12.1.4`; another version logs a warning
  to stderr.
- `pip install pyghidra` (extra `ghidra`), JDK 21 for Ghidra.

## Capabilities

`{"analyzer": 1, "decompiler": 1}`

| Method | Params | Result |
|---|---|---|
| `analyzer/open` | `{program: {format, entry_points: [addr], regions: [{name, start, size, arch, permissions, blob}]}, project_dir}` | `{functions: int}`, with `$/progress` during analysis |
| `analyzer/functions` | `{}` | `[{address, name, size}]` |
| `decompiler/decompile` | `{addresses: [addr]}` | `[{address, code?, error?}]` (per-function errors do not fail the batch) |

Addresses are decovery strings (`flat:0001A2B0`, `seg:1234:0010`). Architectures: `x86-flat-32` maps to
`x86:LE:32:default`, `x86-real-16` to `x86:LE:16:Real Mode`; all regions of a program share one arch.
`permissions` is a string over `r`, `w`, `x`, `-`; `blob` is a protocol blob (inline below 64 KiB, else path and
blake3).

## Plugin-specific error codes

| Code | Meaning |
|---|---|
| `-32602` | invalid params or unmappable program description |
| `-32010` | Ghidra unavailable (`GHIDRA_INSTALL_DIR` unset or wrong, pyghidra missing) |
| `-32011` | no program open (`analyzer/open` not called yet) |

Tests: `python -m unittest discover -s tests` (finds the SDK in `../decovery-plugin-sdk` when it is not installed).
