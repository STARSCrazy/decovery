# de·covery

Recover source code from old executables — with AI agents doing the work and tools doing the checking.

decovery is a facade that coordinates the tools a decompilation project needs — an analysis/decompiler backend
(Ghidra first), a runtime lab (dosbox-lab), the original compiler, an object-level differ and a source mutator —
and exposes them to AI agents through a small set of task-level commands (CLI and MCP). Its focus is
**matching decompilation**: rebuilding functions so that the original compiler produces byte-identical code.
Only decovery decides whether something matches; agents propose, the tool verifies.

DOS programs (COM, MZ, LE) built with Watcom are the first target; the interfaces are designed for Windows
programs (NE, PE), other compilers (Borland, Microsoft, GCC) and other languages.

## Status

Phase 0 — not usable yet. See [the design](docs/design/0001-decovery-design.md) and
[the phase-0 plan](docs/plans/2026-11-04-phase-0.md).

## Building

```sh
cargo build --release
cargo test
```

Rust stable (see `rust-toolchain.toml`). Python plugins live in `plugins/` and need Python 3.12 or newer.

## No proprietary material

This repository must never contain game executables, commercial compilers or libraries, code decompiled from
proprietary programs, or data derived from them. Tests use bytes built inside the tests. Work on real targets
happens in separate, private workspaces; third-party tools live outside the repository.

## Licence

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option.
Contributions are accepted under the same terms.
