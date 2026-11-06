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

Phase 1 — the facade works on migrated Decomp workspaces: knowledge, generated output, `status`, `find`, `show`,
`annotate`, `analyze` and an MCP server. The Ghidra path is not yet verified end to end. See
[the design](docs/design/0001-decovery-design.md) and [the phase-1 plan](docs/plans/2026-11-05-phase-1.md).

## Usage

```sh
decovery migrate <decomp-workspace> <dir>          # convert a Decomp workspace
cd <dir>
decovery status                                    # counts and the next thing to do
decovery show <name|address>                       # header and pseudo-C of a function
decovery annotate <name|address> --name <new>      # record a name, --comment, --signature, --refute …
decovery analyze                                   # re-run the analyzer plugin (needs `decovery setup ghidra`)
decovery mcp                                       # the same commands as MCP tools over stdio
```

Every command takes `--workspace <dir>` (default: the current directory), `--json` and `--jobs <n>` (most compile
jobs in flight at once over all runners; default: the number of logical cores).

## Building

```sh
cargo build --release
cargo test
```

Rust stable (see `rust-toolchain.toml`). Python plugins live in `plugins/` and need Python 3.12 or newer.

## Setting up Ghidra

`decovery setup ghidra` installs Ghidra 12.1.4, a JDK 21 (Eclipse Temurin) and a pyghidra venv into `extern/`
and registers the `ghidra` analyzer plugin in the user config, which `decovery analyze` reads. **It downloads
about 500 MB** (checksums are pinned; windows-x64 and linux-x64 only). Run it inside the repository, or pass
`--plugins-dir`. `--extern <dir>` picks the install directory; `--ghidra-zip` / `--jdk-zip` take files you
downloaded yourself. `DECOVERY_PYTHON` selects the Python that creates the venv. A second run keeps what is
installed.

`decovery analyze` runs the `command` of the `[plugins.<name>]` entry in a workspace's `decovery.toml` (and in the
user config) as a program on your machine. Only analyze workspaces you trust.

## No proprietary material

This repository must never contain game executables, commercial compilers or libraries, code decompiled from
proprietary programs, or data derived from them. Tests use bytes built inside the tests. Work on real targets
happens in separate, private workspaces; third-party tools live outside the repository.

## Licence

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option.
Contributions are accepted under the same terms.
