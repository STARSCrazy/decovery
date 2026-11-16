# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Decomp legacy bridge (ADR 0007), Rust side: `diagnose --deep <context|structure|registers|slots|joint>`, the new
  tools `search` (`chain`, `permute`, `beam`, `forms`; `--apply`) and `verify` (`equivalence`, `behavior`) in the CLI
  and the MCP server, run through the `decomp-legacy` plugin (capability `legacy` v1). Decomp's reports pass through
  as `report` with `report_language = "de"`; a search candidate is built by decovery next to the current source and
  written into `src/` only with `--apply` and a better verdict; Decomp's equivalence result is evidence with
  `source = "decomp"`, never a verdict. The MCP server keeps the plugin running between calls.
- `[legacy] decomp_workspace` in `decovery.toml`; `migrate` writes it.
- `decovery setup decomp-legacy --decomp <checkout>` registers `[plugins.decomp-legacy]` with the checkout's venv
  Python and a `PYTHONPATH` of the checkout's `src/`, `plugins/decomp-legacy` and the SDK.
- Plugin errors carry `error.data` to the host (`PluginError::Remote { data }`).
- Compiler profiles name their string-literal sections (`[literals]`); the fill between Watcom's literals is not
  compared (ADR 0006 item 12).
- Sources in direct subdirectories of `src/`; assembler files marked `decovery: build only` are left out.

### Fixed
- Assembler sources: jump tables in a segment of their own, label offsets in another code segment and functions
  the analysis split are compared correctly (ADR 0006 item 13); `data_` default names resolve like `DAT_`.
- Phase-2 parity refresh: 603 of Decomp's 618 identical functions confirmed, 15 listed deviations
  (`docs/parity/phase-2.md`).

## [0.2.0] - 2026-11-09

Phases 1 and 2: knowledge, analysis and the facade tools; toolchain, `build`, `link` and the second target.

### Added
- Knowledge write-back: `symbols.toml` and `types.h` are written atomically and byte-stable; typed rebuild and
  reference records; a workspace lock serializes writers ("workspace is locked by pid N" after 10 s).
- Analysis store in `knowledge/analysis` (ADR 0005): functions, call edges, strings, data accesses and
  pseudo-C per function, tied to the target by its sha256.
- `migrate` imports Decomp's generated analysis (function ranges, calls, strings, globals and bodies).
- Output generation: one `output/functions/<segment>/<address>_<name>.c` per function with an English header,
  plus `output/index.md`, `status.json` and `calls.json`; a rename moves the file and regenerates callers and
  callees.
- `decovery status`, `find`, `show`, `annotate`, `analyze` and `detail`, with a common response envelope and
  handles for results over budget.
- `analyze` runs analyzer plugins; the Ghidra plugin keeps its project, applies the knowledge, exports the
  analysis and decompiles in batches.
- `decovery setup ghidra` installs Ghidra, a JDK and a pyghidra venv with pinned checksums and registers the
  plugin in the user config.
- `decovery mcp`: MCP server over stdio with the tools `status`, `find`, `show`, `annotate`, `analyze` and
  `detail`.
- Phase-1 parity check of `show` against Decomp (`docs/parity/phase-1.md`).
- MZ and COM loader; OMF frames and groups; module comparison with 16-bit reference anchors (ADR 0006), with
  DGROUP frame bases taken from the program's startup code and unanchored data references kept unchecked.
- Compiler profiles (`watcom-9.5`, `watcom-10.6`, `turbo-c-2.0`), tool directories (`decovery setup toolchain`,
  `[rebuild] tool_dir`), source staging and an inline-assembly check.
- Runner contract with plugin and native runners; the `unicorn-dos` emulator plugin (Phar Lap host for 32-bit
  Watcom tools, real-mode host for 16-bit tools) and the `dosbox-lab` runner plugin; `decovery setup unicorn-dos`
  and `decovery setup dosbox-lab`. Plugins declare their limits and keep reusable worker pools.
- `decovery build`: compile the rebuild sources, compare every function with the original and record verdicts and
  blockers (`data-layout` for items the module's layout moved); an object cache skips unchanged sources. Variants
  (`--variant`, `--function-source`) are ranked in one call, function-level attempts compile in shrunk files and
  are confirmed on the full file.
- `decovery diagnose` with generic diagnosis rules.
- `decovery link`: MZ programs are compiled and linked with the original linker and compared with the original;
  LE programs get their identical rebuilt functions inserted into the original image and linked as one module. An
  identical MZ link records the public symbols the knowledge base lacks from the linker map.
- MCP tools `build`, `link` and `diagnose`.
- Phase-2 parity check of `build` and `link` against Decomp (`docs/parity/phase-2.md`).
- Built-in assembler for byte-listing assembler sources (`db`, `dd name`, `call name`, `jmp near ptr name`); the
  profile's assembler runs only for lines outside that subset.
- A data section with a single vote is anchored when its whole content occurs exactly once in the original at the
  voted position (ADR 0006 item 4); default names `DAT_`/`FUN_` plus eight hex digits resolve to their address on
  flat targets (ADR 0006 item 11).

## [0.1.0] - 2026-11-05

Phase 0: scaffold, loaders, comparison, plugin protocol.

### Added
- Workspace scaffold, CI and governance files.
- Design document, phase-0 plan and ADRs 0001–0004.
- Typed address model and program model.
- LE loader.
- OMF object reader with section model and function view.
- Function comparison with a decovery verdict and Decomp-compatible metrics.
- Workspace configuration and `migrate` from Decomp (`decomp.toml`, symbols).
- `migrate` carries the whole Decomp workspace into the English layout and reports generated output and
  caches as skipped.
- Versioned JSON-RPC plugin protocol with plugin host and Python SDK.
- Ghidra plugin skeleton.
- `decovery compare`: one rebuilt function against the original in a workspace, with verdict, blockers and
  metrics as text or JSON.
- Phase-0 parity check against Decomp (`docs/parity/phase-0.md`).
