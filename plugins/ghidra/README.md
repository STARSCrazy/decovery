# decovery-ghidra

decovery plugin that drives Ghidra through pyghidra. Run as `python -m decovery_ghidra` (stdio, protocol in
`docs/plugin-protocol.md`). Needs the `decovery-plugin` SDK; pyghidra is imported only when a program is opened.

The Ghidra calls are ported from the predecessor project's Ghidra engine. The plugin logic (validation, project
persistence, export format, decompile batches) is tested with a fake backend; `tests/test_local_ghidra.py` runs a
tiny program through a real Ghidra and is skipped unless `GHIDRA_INSTALL_DIR` is set and pyghidra is installed.

## Setup

- `GHIDRA_INSTALL_DIR` points to a Ghidra installation. Expected version `12.1.4`; another version logs a warning
  to stderr.
- `pip install pyghidra` (extra `ghidra`, which also brings `blake3`), JDK 21 for Ghidra. Without the `blake3`
  package the export hash is computed by a slow pure-Python fallback.

## Capabilities

`{"analyzer": 2, "decompiler": 2}`; full shapes in `docs/plugin-protocol.md`.

| Method | Params | Result |
|---|---|---|
| `analyzer/open` | `{program, project_dir, program_hash, options?: {calling_convention?}}` | `{functions, reused}` |
| `analyzer/functions` | `{}` | `[{address, name, size}]` |
| `analyzer/apply` | `{symbols, types_h, references}` | `{applied, warnings}` |
| `analyzer/export` | `{out_path}` | `{path, blake3}`; the file holds functions, calls, strings, data accesses |
| `decompiler/decompile` | `{addresses, out_dir}` | `[{address, path?, error?, disassembly?, lines?, signature?, variables?}]` |

Addresses are decovery strings (`flat:0001A2B0`, `seg:1234:0010`). Architectures: `x86-flat-32` maps to
`x86:LE:32:default`, `x86-real-16` to `x86:LE:16:Real Mode`; all regions of a program share one arch.

### Decompiler v2 metadata

The response stays a list, one entry per requested address. Successful entries retain `address` and `path`;
the `.c` file holds the same pseudo-C text as before (there is no inline `c` response field). Available metadata
is added to that entry:

```json
[
  {
    "address": "seg:1000:0010",
    "path": "out/seg_1000_0010.c",
    "lines": [
      {"line": 1, "ranges": []},
      {"line": 4, "ranges": [{"start": "seg:1000:0010", "end": "seg:1000:0015"}]}
    ],
    "signature": {
      "calling_convention": "__cdecl",
      "return_type": "int",
      "parameters": [{"name": "count", "type": "int", "storage": "register:AX"}]
    },
    "variables": [
      {"name": "count", "type": "int", "storage": "register:AX"},
      {"name": "saved", "type": "int", "storage": "stack:-4", "first_use": "seg:1000:0014"}
    ]
  }
]
```

`lines` enumerates every printer line, including blank and unaddressed lines, with 1-based numbers into the
written `.c` text. Ranges have **inclusive** endpoints from Clang tokens; overlapping and adjacent ranges in
the same segment are merged. Gaps and distinct segments stay separate; no instruction coverage is fabricated.
Flat programs use `flat:XXXXXXXX` endpoints instead. The example above abbreviates the line list.

Signature parameters are in prototype order; `variables` contains the HighFunction's locals and parameters.
Types use Ghidra's display names. Simple storage is `register:AX` or a signed decimal stack offset such as
`stack:+4`; other storage uses Ghidra's readable representation. `first_use` is the symbol's storage-validity
PC address, when supplied by Ghidra, rather than a guessed function entry. Missing metadata, including individual
name/type/storage/signature fields, is omitted. Known empty lists remain `[]`. Failed entries retain the v1
`error` and optional `disassembly` shape without metadata.

The opt-in `test_second_target_line_coverage_five_functions` additionally needs `DECOVERY_TARGET_MZ` (private
second-target executable) and `DECOVERY_GOLDEN_DIR` (private report directory). It records coverage of instruction
starts for five real-mode functions to `ghidra-v2-line-coverage.json`; mapping holes are reported and allowed.
Neither private inputs nor report data belong in this repository.

## Project persistence

`project_dir` holds the Ghidra project (`decovery.gpr`, `decovery.rep/`), `project.json` (program hash, Ghidra
version, calling convention the project was built with) and `applied.json` (what the last apply set, so the next
one can take back what the knowledge dropped). A matching `project.json` reopens the saved program without
re-analysis. A `project_dir` with a leading-dot path component moves to
`%LOCALAPPDATA%/decovery/ghidra/<blake3 of the path>` (Ghidra rejects such paths).

## Layout

| Module | Role |
|---|---|
| `__init__.py` | protocol handlers: validation, progress, cancellation, error codes (no Ghidra imports) |
| `backend.py` | `Backend` interface and `GhidraBackend` (open, import, analyze, decompile) |
| `apply.py` | knowledge parsing and `GhidraApplier` |
| `export.py` | export records, deterministic writer, `read_program` |
| `project.py` | project location and reuse key |
| `mapping.py` | decovery program description and addresses to Ghidra and back |
| `hashing.py` | BLAKE3 (package if installed, else pure Python) |

## Plugin-specific error codes

| Code | Meaning |
|---|---|
| `-32602` | invalid params, unmappable program description, unknown calling convention |
| `-32010` | Ghidra unavailable (`GHIDRA_INSTALL_DIR` unset or wrong, pyghidra missing, project locked) |
| `-32011` | no program open (`analyzer/open` not called yet) |
| `-32012` | project or file I/O failed (project folder, export file, `out_dir`) |

Tests: `python -m unittest discover -s tests` (finds the SDK in `../decovery-plugin-sdk` when it is not installed).
