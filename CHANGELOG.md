# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
