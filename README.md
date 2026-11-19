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
targets (a Watcom 9.5 LE game and a Turbo C 2.0 MZ tool) the build verdicts equal Decomp's except one listed
deviation where decovery's stricter reference check is right, the MZ tool links byte-identical, and the LE game links with identical code and data pages (see
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
decovery diagnose <name> --deep registers          # plus Decomp's model: context, structure, registers, slots, joint
decovery diagnose --deep <name>                    # --deep without a mode runs joint (structure and registers)
decovery search <name> --strategy chain --minutes 20
                                                   # Decomp's search; decovery builds the candidate (--apply writes it)
decovery verify <name> --check equivalence         # Decomp's evidence (equivalence, behavior --run <name>)
decovery link                                      # link the whole program and compare it with the original
decovery mcp                                       # the same commands as MCP tools over stdio
```

Every command takes `--workspace <dir>` (default: the current directory), `--json` and `--jobs <n>` (most compile
jobs in flight at once over all runners; default: the number of logical cores). With `--json`, stdout holds the
JSON response alone and `build`, `link` and `analyze` print no progress lines.

`build` exits 0 when every built function is identical, 1 when one differs or a file failed, 2 on errors; `link`
exits 0 when the program is identical, 1 when it differs, 2 when the link failed. Only decovery sets verdicts:
`identical` means the bytes match and every reference was checked against the original. `link` writes
`cache/rebuild/REBUILD.EXE` and `knowledge/rebuild-program.toml`. MZ programs are compiled and linked from all
rebuild sources; LE programs get their identical rebuilt functions inserted into the original image, which is then
linked as one module. After an identical MZ link, the public symbols the knowledge base lacks are recorded from the
linker map (`source = link`).

The MCP server offers the same tools: `build` (with `files`, `function`, `variants`), `link`, `diagnose` (with
`deep`), `search` and `verify`, next to `status`, `find`, `show`, `annotate`, `analyze` and `detail`.

The rebuild is configured in the workspace's `decovery.toml`:

```toml
[rebuild]
compiler = "watcom-9.5"            # profile id, see profiles/
flags = "-ox -ot -oa -4s"
# tool_dir = "<compiler dir>"      # overrides the user config's [toolchains] entry

[rebuild.link]
profile = "watcom-9.5"             # linker profile; MZ: libraries, flags, startup (e.g. "C0S")
```

Flags for single source files replace the `flags` above for that file. Either list them in the config:

```toml
[rebuild.file_flags]
"npc.c" = "+b +c"
```

or put a comment in the first ten lines of the source itself, which survives renames and does not collide in merges
(ADR 0014):

```c
/* decovery: flags = +b +c */
```

When both are present and differ, the build warns and the source comment wins. A `[rebuild.file_flags]` entry that
names no file in `src/` is warned about. `build` takes a file name in `src/` or a path to it (relative to the
workspace or to `src/`, or absolute inside `src/`); `find --limit <n|all>` lifts the 100-row default.

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

An existing Ghidra and JDK are registered without any download: `decovery setup ghidra --ghidra-dir <ghidra install>
--jdk-dir <jdk>` (the Ghidra directory holds `support/`, the JDK `bin/java`; Ghidra 12.1 needs JDK 21 or newer). Only
the pyghidra venv is created. Setting `PYTHONPATH` to the plugin is not enough: `analyze` needs the `[plugins.ghidra]`
entry with a `command` (in the workspace's `decovery.toml` or the user config, `%APPDATA%\decovery\config.toml` on
Windows, `~/.config/decovery/config.toml` elsewhere), and its error names both files when the entry is missing. A
hand-written entry looks like this:

```toml
[plugins.ghidra]
command = ["<venv>/Scripts/python.exe", "-m", "decovery_ghidra"]
env = { GHIDRA_INSTALL_DIR = "<ghidra install>", JAVA_HOME = "<jdk>" }
```

`decovery analyze` runs the `command` of the `[plugins.<name>]` entry in a workspace's `decovery.toml` (and in the
user config) as a program on your machine. Only analyze workspaces you trust.

## Setting up the compilers

The original DOS compilers are not part of decovery; you need your own copies. Register each compiler directory
once:

```sh
decovery setup toolchain watcom-9.5 <dir>          # WCC386, WLINK and their libraries
decovery setup toolchain turbo-c-2.0 <dir>         # TCC.EXE, TLINK.EXE, LIB/, INCLUDE/
decovery setup toolchain aztec-c86-4.2b <dir>      # BIN/CC.EXE and its passes, LIB/, INCLUDE/
```

This writes `[toolchains]` into the user config; `[rebuild] tool_dir` in a workspace overrides it. The profiles in
`profiles/` (`watcom-9.5`, `watcom-10.6`, `turbo-c-2.0`, `aztec-c86-3.4b`, `aztec-c86-4.2b`, `aztec-c86-5.2a`)
describe how each compiler and linker is called. Aztec C86 has no linker step: its objects are compared against the
original image with the relocated fields as gaps, and a module of an overlay is compared as a whole (code, data, BSS).
Assembler sources (`.asm`) of an Aztec C86 4.2b workspace are assembled by its AS (`BIN/AS.EXE` in the same
directory, called as `AS X.ASM`); a function there runs from a public label to the next one, local labels stay inside
it (ADR 0015). Without the toolchain, the built-in assembler takes byte-listing sources.

## Overlays

A program that loads overlay files (Aztec C86 `.OVR`) registers them in the workspace:

```sh
decovery overlay add VINIT.OVR VBASE.OVR [--format aztec-c86] [--ds SSSS]   # checks the header, adds segments
decovery overlay list
decovery overlay remove VINIT
```

Functions in an overlay have addresses of the form `ovl:NAME:SSSS:OOOO` (ADR 0011). `migrate` takes Decomp's
overlay list over unchanged.

`diagnose` and `compare --function` take an overlay function by address, by its knowledge name (`VPCVW_ovmain`) or by
its C name when that is unique; a C name used in several overlays (`ovmain`) is an error that lists the candidates.
`diagnose --deep` is not available for overlay functions (the `decomp-legacy` plugin takes `flat:` and `seg:` only).

An overlay module too large for the compiler in one piece is split into several source files and listed in link
order (ADR 0013); building any of them builds the others too and compares the whole module:

```toml
[[rebuild.module]]
overlay = "NPC"
files = ["npc.c", "npc_b.c"]
```

Source files keep DOS 8.3 names (`[a-z0-9_-]{1,8}.(c|h|s|asm)`): the compilers run under DOS and see at most eight
characters before the extension, so split files are named like `npc_b.c`, not `npc_part2.c`; the build refuses
longer names. The build warns when the code of one file does not end where the functions of the next begin. Uninitialised globals
the files share (Aztec common symbols) are placed in the module's BSS in order of first appearance and count into its
size. Aztec cuts identifiers to 31 characters (profile key `name_length`); the build matches a cut name with the longer
knowledge name, and `annotate --name` warns about a longer name. The memory DOS allocates behind an MZ image
(`minalloc`: uninitialised data, stack) belongs to the memory map, so globals there can be named.

The compilers run in an emulator plugin:

- `decovery setup unicorn-dos` creates a venv with the `unicorn-dos` plugin and the unicorn emulator (installed by pip)
  and registers it in the user config. It runs 32-bit Phar Lap tools (Watcom) and 16-bit real-mode tools
  (Turbo C) without DOSBox, several jobs in parallel. `--python <exe>` (or `DECOVERY_PYTHON`) picks the Python
  3.12+ that creates the venv; `--extern <dir>` the install directory.
- `decovery setup dosbox-lab --package <dir>` registers the `dosbox-lab` runner, which runs the tools in DOSBox
  instances. The DOSBox executable is not installed.

A profile lists its runners in order; `[rebuild] runners` in a workspace overrides the list.

## Decomp legacy bridge

Until decovery has its own Watcom register and stack-slot models, search chain and behavioural checks, `diagnose
--deep`, `search` and `verify` run them in [Decomp](docs/adr/0007-decomp-legacy-bridge.md) through the
`decomp-legacy` plugin, on a shadow of the workspace in `cache/legacy/decomp/` (the Decomp workspace itself is never
written). It needs two things:

```sh
decovery migrate <decomp-workspace> <dir>          # writes [legacy] decomp_workspace into decovery.toml
decovery setup decomp-legacy --decomp <Decomp checkout>
                                                   # registers [plugins.decomp-legacy] with the checkout's venv Python
```

Decomp's reports pass through unchanged and are German (`report`, `report_language = "de"`). Verdicts stay
decovery's: a candidate from `search` is built by decovery as a function-level attempt next to the current source,
and `--apply` writes it into `src/` only when decovery's verdict is better (identical, or fewer differing
instructions). `verify` reports Decomp's result as evidence (`source = "decomp"`) and records nothing. The MCP
server keeps the plugin, and with it Decomp's server and Ghidra project, running between calls.

## Memory, jobs, exemplars and the benchmark

- `decovery history <name>` lists what was tried on a function (builds, variants, search candidates) with decovery's
  verdict, the best attempt and the attempt budget; `--archive` shows one archived definition. Attempts are JSON Lines
  shards in `cache/attempts/`. `decovery migrate-attempts` imports Decomp's attempt memory and archive (safe to repeat).
- `decovery job` lists, shows and cancels jobs: long commands (`build`, `link`, `analyze`, `diagnose --deep`,
  `search`, `verify`) can run in the background; the job store is persistent.
- `decovery show <name>` and `decovery find similar <name>` list similar identical functions (exemplars) of the
  workspace; they appear in the response, never in the generated `output/` files.
- Every MCP tool call is logged in `cache/calls/<yyyy-mm>.jsonl` (tool, seconds, outcome, actor).
- `decovery bench run|report|compare` measures how well an agent recovers solved functions from solution-free copies
  (ADR 0009). A run needs a suite file naming workspaces and functions and a driver from the user config
  (`[bench.drivers.<name>]`). The reference driver `tools/bench-drivers/claude_code.py` runs Claude Code on your
  subscription and needs a one-time login into its own profile (`CLAUDE_CONFIG_DIR`, by default
  `%LOCALAPPDATA%\decovery\claude-bench`); see [tools/bench-drivers/README.md](tools/bench-drivers/README.md). Results
  and open points: [the phase-3 parity report](docs/parity/phase-3.md).

## No proprietary material

This repository must never contain game executables, commercial compilers or libraries, code decompiled from
proprietary programs, or data derived from them. Tests use bytes built inside the tests. Work on real targets
happens in separate, private workspaces; third-party tools live outside the repository.

## Licence

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option.
Contributions are accepted under the same terms.
