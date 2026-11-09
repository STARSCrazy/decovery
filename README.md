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

Phase 2 — decovery rebuilds functions and whole programs with the original DOS compilers: `build` compiles the
rebuild sources, compares every function with the original and records the verdicts; `link` links the whole program
with the original linker and compares it with the original file; `diagnose` explains why a function differs. The
compilers run in the `unicorn-dos` emulator plugin (or in DOSBox through `dosbox-lab`). On the two reference
targets (a Watcom 9.5 LE game and a Turbo C 2.0 MZ tool) the build verdicts equal Decomp's, the MZ tool links
byte-identical, and the LE game links with identical code and data pages (see
[the phase-2 parity report](docs/parity/phase-2.md)). Assembler sources are not built yet. See
[the design](docs/design/0001-decovery-design.md) and [the phase-2 plan](docs/plans/2026-11-05-phase-2.md).

## Usage

```sh
decovery migrate <decomp-workspace> <dir>          # convert a Decomp workspace
cd <dir>
decovery status                                    # counts and the next thing to do
decovery show <name|address>                       # header and pseudo-C of a function
decovery annotate <name|address> --name <new>      # record a name, --comment, --signature, --refute …
decovery analyze                                   # re-run the analyzer plugin (needs `decovery setup ghidra`)
decovery build                                     # compile src/, compare every function, record the verdicts
decovery build ai.c                                # only these source files
decovery build --function <name> --variant a.c --variant b.c
                                                   # rank candidate sources for one function (nothing recorded)
decovery build --function <name> --function-source f.c
                                                   # candidate definition of the function alone
decovery diagnose <name|address>                   # why a rebuilt function differs and what to try
decovery link                                      # link the whole program and compare it with the original
decovery mcp                                       # the same commands as MCP tools over stdio
```

Every command takes `--workspace <dir>` (default: the current directory), `--json` and `--jobs <n>` (most compile
jobs in flight at once over all runners; default: the number of logical cores).

`build` exits 0 when every built function is identical, 1 when one differs or a file failed, 2 on errors; `link`
exits 0 when the program is identical, 1 when it differs, 2 when the link failed. Only decovery sets verdicts:
`identical` means the bytes match and every reference was checked against the original. `link` writes
`cache/rebuild/REBUILD.EXE` and `knowledge/rebuild-program.toml`. MZ programs are compiled and linked from all
rebuild sources; LE programs get their identical rebuilt functions inserted into the original image, which is then
linked as one module. After an identical MZ link, the public symbols the knowledge base lacks are recorded from the
linker map (`source = link`).

The MCP server offers the same tools: `build` (with `files`, `function`, `variants`), `link` and `diagnose`, next
to `status`, `find`, `show`, `annotate`, `analyze` and `detail`.

The rebuild is configured in the workspace's `decovery.toml`:

```toml
[rebuild]
compiler = "watcom-9.5"            # profile id, see profiles/
flags = "-ox -ot -oa -4s"
# tool_dir = "<compiler dir>"      # overrides the user config's [toolchains] entry

[rebuild.link]
profile = "watcom-9.5"             # linker profile; MZ: libraries, flags, startup (e.g. "C0S")
```

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

## Setting up the compilers

The original DOS compilers are not part of decovery; you need your own copies. Register each compiler directory
once:

```sh
decovery setup toolchain watcom-9.5 <dir>          # WCC386, WLINK and their libraries
decovery setup toolchain turbo-c-2.0 <dir>         # TCC.EXE, TLINK.EXE, LIB/, INCLUDE/
```

This writes `[toolchains]` into the user config; `[rebuild] tool_dir` in a workspace overrides it. The profiles in
`profiles/` (`watcom-9.5`, `watcom-10.6`, `turbo-c-2.0`) describe how each compiler and linker is called.

The compilers run in an emulator plugin:

- `decovery setup unicorn-dos` creates a venv with the `unicorn-dos` plugin and the unicorn emulator (installed by pip)
  and registers it in the user config. It runs 32-bit Phar Lap tools (Watcom) and 16-bit real-mode tools
  (Turbo C) without DOSBox, several jobs in parallel. `--python <exe>` (or `DECOVERY_PYTHON`) picks the Python
  3.12+ that creates the venv; `--extern <dir>` the install directory.
- `decovery setup dosbox-lab --package <dir>` registers the `dosbox-lab` runner, which runs the tools in DOSBox
  instances. The DOSBox executable is not installed.

A profile lists its runners in order; `[rebuild] runners` in a workspace overrides the list.

## No proprietary material

This repository must never contain game executables, commercial compilers or libraries, code decompiled from
proprietary programs, or data derived from them. Tests use bytes built inside the tests. Work on real targets
happens in separate, private workspaces; third-party tools live outside the repository.

## Licence

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option.
Contributions are accepted under the same terms.
