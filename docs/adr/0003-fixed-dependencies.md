# ADR 0003: Fixed dependencies are the exception

Status: accepted · 2026-11-04

## Decision
Linked into the binary are only `iced-x86` (x86 decoding on every hot path) and general-purpose crates:
`serde`, `serde_json`, `toml`, `clap`, `thiserror`, `blake3`, `tracing`, `rayon`, `rmcp`, `sha2`
(general-purpose hashing: archive checksums of third-party downloads). Everything else —
Ghidra, IDA, Binary Ninja, rizin, dosbox-lab, decomp-permuter, m2c, objdiff-core, wibo, wine, unicorn, original
compilers — is reached through a capability contract as a plugin, an external process or an optional cargo
feature. No GPL code is linked. Adding a fixed dependency requires a new ADR.

Amendment (Task 12): `tokio` (features `rt`, `sync`) — rmcp's stdio server runs on a tokio runtime, which
`decovery-mcp` must build; rmcp re-exports `schemars`, so it is not a direct dependency.

## Consequences
The default build works without any optional provider and reports a missing capability instead of failing.
