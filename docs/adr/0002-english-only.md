# ADR 0002: English only

Status: accepted · 2026-11-04

## Decision
Identifiers, CLI verbs and flags, MCP tool and parameter names, file names, TOML keys, enum values, messages and
documentation are English. Workspaces of the predecessor tool Decomp (German schema) are converted once with
`decovery migrate`.

## Consequences
decovery does not read Decomp's files directly; parity checks run on migrated copies.
