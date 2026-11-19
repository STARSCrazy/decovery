# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Phase-4 acceptance (`docs/parity/phase-4.md`): on the third target (MZ program with 13 overlays, Aztec C86 4.2b)
  `build` on the migrated workspace gives 322 identical functions and 7 identical overlay modules; 1144 of 1144
  verdicts equal Decomp's frozen baseline, no deviations.
- Aztec C86 profiles `aztec-c86-3.4b`, `aztec-c86-4.2b`, `aztec-c86-5.2a` (runners `unicorn-dos`, `dosbox-lab`), an
  Aztec object and library reader (ADR 0012), object-against-image verdicts with link gaps, and whole overlay module
  comparison (code, data, BSS).
- Overlay addresses `ovl:NAME:SSSS:OOOO` (ADR 0011), `[[overlay]]` in `decovery.toml`, `decovery overlay
  add|list|remove`, overlay loading and an Aztec prologue search with placeholders.
- `migrate` takes Decomp's overlays and overlay attempts over and writes the compiler rules for the workspace's
  compiler (Decomp's `compilerwissen/`) to `knowledge/compiler-rules.toml`.
- Phase-3 acceptance: benchmark of 30 tasks, two runs of the reference driver, 19 of 30 solved each
  (`docs/parity/phase-3.md`).
- Attempt memory: `history`, `migrate-attempts` (66 299 attempts and 4 049 archive entries of the first target
  migrated), persistent `job`s, exemplars in `show` and `find similar` (parity with Decomp 18/20 top 1, 20/20 top 3),
  the tool-call log `cache/calls/`, and `bench run|report|compare` with the reference Claude Code driver.
- Phase-3 extra runs (`docs/parity/phase-3.md`): one `core+legacy` task (copy 60 MB, 75 MB after the first bridge call,
  first bridge call 45 s, no leak), cost extrapolation of the full acceptance, and 4 previously unsolved probe tasks
  with line mapping (2 of 4 solved now). Open in phase 3: the exemplar effect on the bench (no switch hides
  exemplars), bridge use in a task that really searches, and the full probe re-run for line mapping.
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
- `[linker] le_system`: the LE response file names a system of the linker's system file (`system dos4g`); the
  `watcom-10.6` profile uses it, so its LE links carry the preload flag like the original. The first target now links
  identical with WLINK 10.6 in DOSBox (`dosbox-lab`).

### Fixed
- `build --function <f> --function-source` on an Aztec C86 overlay function judges the variant like `build` (against
  the image, relocated fields as link gaps) instead of reporting "the original bytes … are not in the program"; the
  function may be given by its knowledge name (`VPCVW_ovmain`) when its rebuild record holds the C name. `find
  similar` reads overlay functions (they have no linear address). A function source for a function that the current
  file does not define yet says so: the function must be in the file already, or the whole file is passed.
- `build` per function: blockers are counted per kind (`blocker_counts` in JSON, `wrong-relative-ref ×20` in the
  text, kinds separated by `, `), and after a code size change of an overlay module the differing functions behind
  its first real difference carry `consequence: true` and `(follow-on)` in the text.
- The build summary names an overlay module's first real difference as address, function and offset
  (`first real difference at ovl:VPCVW:0000:5344 in cvw_show_message +0x2D`), not only the size finding; the module
  JSON adds `code.first_difference_address`, `code.first_difference_function` and
  `code.first_difference_function_offset` next to the module offset `code.first_difference`.
- Overlay module JSON: after a code size change the `ambiguous` list is left empty (nearly every later external
  reference disagrees, 1378 entries on a shifted module); `ambiguous_count` gives the number and
  `ambiguous_omitted` says the list was dropped. Changed meaning: `ambiguous` is no longer complete after a size
  change.
- Aztec C86 `build` no longer warns that frame `DATA` or section `DATA` has no anchor: those warnings came from the
  module comparison of linked targets, whose verdicts an Aztec build discards (functions are compared with link
  gaps, overlay data and BSS by the module comparison). The module JSON says what it checked: `data.state`
  (`equal`, `differs`, or `unchecked` when every rebuilt data byte is a link gap) and `data.gaps`; `bss.state` and
  `bss.checked = "size"` (BSS has no bytes, only its size and references into it are checked). Changed meaning:
  `data.equal` is now `false` for data that was not compared (it was `true`).
- `build` reports a function by its knowledge name: a source that still defines it under its default name
  (`fun_VPCVW_0000_6096`) no longer hides the name given with `annotate`; the rebuild record takes the knowledge's
  name, the source's name is the fallback, and `build --function` also accepts the default name.
- Overlay module findings and the `diagnose --deep` refusal for overlay functions no longer carry a run of spaces
  in the middle of the text (a continued string literal kept its indentation).
- `diagnose --deep` works without a mode (`joint`, structure and registers together); `diagnose --deep NAME` takes
  NAME as the function, `--deep registers` etc. still select a mode.
- Overlay `diagnose` (Aztec C86) agreed with `build` only when no relocated field changed a branch: relocated fields
  of the function now take the original's bytes (link gaps, as in `build`), and the module's functions take the
  analysis' names at their placed addresses, so short jumps and calls inside the module compare by where they lead.
- Overlay module comparison: relocated code fields are judged only as references, so `first_difference` is the first
  real byte difference; `instructions_differing` is computed for modules and link-gap comparisons (it stayed 0); a
  new `findings` list names a code size that differs from the original (a partial module with its covered range, or
  a longer module whose later differences are likely consequences), and the build summary shows the first one.
- `diagnose` and `compare --function` on overlay functions: the original bytes are read from the overlay, `compare`
  finds overlay functions by address, knowledge name or default name (Aztec objects compared as `build` does), an
  exact name wins over overlay-qualified ones and an ambiguous name lists its candidates; `diagnose --deep` refuses
  overlay functions with a clear message.
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
