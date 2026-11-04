# Guide for AI agents working on decovery

- Read `docs/design/0001-decovery-design.md` before changing interfaces; architectural changes need an ADR in
  `docs/adr/`.
- **English only**: identifiers, CLI verbs and flags, MCP tool and parameter names, file names, TOML keys, enum
  values, messages and docs.
- **No proprietary material** in the repository or in test fixtures (no game binaries, commercial compilers,
  decompiled game code, golden data derived from them). Tests that need private data are
  `#[ignore = "local: …"]` and read paths from `DECOVERY_LOCAL_WORKSPACE` (a private Decomp workspace) / `DECOVERY_GOLDEN_DIR`.
- **Fixed dependencies** are limited to `iced-x86` and general-purpose crates listed in ADR 0003. Third-party
  tools are reached through capability contracts (plugins, external processes, optional features). No GPL code is
  linked.
- Library code never panics on input data; malformed input returns an error naming the byte offset.
- Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` before committing.
  Stage files explicitly.
