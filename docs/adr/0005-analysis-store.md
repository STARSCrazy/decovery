# ADR 0005: Analysis store

Status: accepted · 2026-11-05

## Context

`status`, `find` and `show` must answer without a running Ghidra (design 5.11 item 8): function boundaries, call
graph, strings, data accesses and the provider's pseudo-C have to be readable from disk. `cache/` is gitignored, so
anything kept there does not reach CI or a second machine, and a fresh clone would have to re-run the provider.

## Decision

1. Analysis results are workspace data, committed with the workspace, in `knowledge/analysis/`:
   - `analysis.json`: one file with `schema`, provider name and version, `target_sha256`, `knowledge_hash`,
     creation date, functions, call edges, strings and data accesses (`schemas/analysis.schema.json`).
   - `decompiled/<address>.c`: pseudo-C per function as the provider printed it; the address has `:` replaced by
     `_` (`flat_00010010.c`).
2. They are replaced as a whole by `analyze` or `migrate`, never edited by hand. Hand-written facts belong in
   `knowledge/symbols.toml` and stay there.
3. `target_sha256` must equal `decovery.toml` `target.sha256`; an analysis of another target is rejected instead of
   shown. `knowledge_hash` (blake3 over `symbols.toml`, `types.h`, `references.toml`, each with name and length
   prefix) records the knowledge the analysis was made with, so staleness can be reported.
4. Writes follow the workspace rules: atomic, deterministic (sorted, LF, UTF-8, pretty JSON plus a trailing
   newline) and only while holding the workspace lock.

## Consequences

- The directory grows with the program (one `.c` per function); users who do not want it in version control can
  ignore it and re-run `analyze`.
- Readers need no provider: `decovery-core` loads the JSON and builds an in-memory index (function containing an
  address, callers, callees, strings, accesses).
- A provider with a different data model maps into this schema; fields it cannot fill stay empty rather than
  extending the schema ad hoc (new fields need a schema bump).
