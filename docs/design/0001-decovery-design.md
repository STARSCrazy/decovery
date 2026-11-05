# decovery — design

Status: draft for review · 2026-11-04

## 1. Intent

decovery recovers source code from old executables. It is the common facade through which AI agents drive the
tools that do the actual work — a decompiler/analysis backend (Ghidra first), a runtime lab (dosbox-lab), the
original compiler/assembler/linker, an object-level differ, and a source mutator (decomp-permuter transforms) —
and it is optimised so that agents get more functions understood and rebuilt **byte-identically**.

It is the successor of the private Python tool *Decomp* (≈51k LOC), which proved
the approach on a DOS game from 1993 (Watcom C/C++32 9.5, DOS/4GW LE) and a few other DOS targets. Decomp is
DOS-/Watcom-centric, German throughout, exposes 83 MCP tools, and needs Python + JDK 21 + Ghidra installed.
decovery generalises what worked, fixes the agent ergonomics, and is meant to be published on GitHub and shared.

### Why

- No existing project combines static analysis, runtime evidence and a compiler-in-the-loop matching cycle,
  and none of them handles DOS-era formats/compilers (LE, OMF, Watcom/Borland) end-to-end
  (survey 2026-11-04: rea, re-mcp, GhidraMCP, ida-pro-mcp, decomp.me/cromper, objdiff, m2c, decomp-permuter,
  retrokit, Exhume).
- Agent-driven matching projects report two dominant failure modes: the agent *claims* a match that is not one,
  and it loops on random permutation far from the target. decovery attacks both structurally.

## 2. Goals, non-goals, anti-goals

Goals
- G1 One facade (CLI + MCP + JSON) over interchangeable backends, with a small task-level tool set for agents.
- G2 A generic matching cycle that works for any compiler given only a declarative **profile**; compiler-family
  **extensions** (register-allocation model, stack-slot model, diagnosis rules, directed rewrites, prototype
  syntax) raise the hit rate but are optional.
- G3 Language-neutral core; C is the first source language, others (C++, Turbo Pascal, assembler) plug in via
  the same frontend contract.
- G4 Platform-neutral program model: DOS (COM, MZ, LE/LX, NE) first, Windows (NE, PE) later.
- G5 Fast and compact: one statically linked binary for the core; heavy third-party tools are optional plugins.
- G6 Publishable: clean GitHub repository, permissive licence, CI, docs, contribution guide, no proprietary bits.
- G7 Shareable pieces go upstream (OMF for objdiff, Watcom 9.5/LE for decomp.me, a rea provider / re-mcp
  backend).

Non-goals
- Writing a new decompiler. Ghidra (and later IDA/Binary Ninja/rizin) do the decompiling.
- Writing a new DOS emulator. dosbox-lab and unicorn do the executing.
- A GUI. Agents and terminals are the users; editors get files.
- Bit-compatibility with Decomp's on-disk formats (replaced by an English schema plus a one-time `migrate`).

Anti-goals (would make it a failure even if it works)
- The agent, not the tool, decides that something matches.
- A tool list so large or so verbose that agents burn context finding their way (Decomp's 83 tools).
- Proprietary material (game executables, commercial compilers, decompiled game code, Ghidra caches) in the
  public repo or its test fixtures.
- Any German identifier, parameter, file key or message left in code or formats.
- Silent nondeterminism: the same inputs and seed must give the same attempts and verdicts.

## 3. Constraints (decided)

- **Language:** core in **Rust** (stable, edition 2024, toolchain installed via rustup on the dev machine).
  Plugins in Rust (in-process) or **Python ≥ 3.12** (out-of-process). Reasons: objdiff-core and iced-x86 are Rust
  crates; unicorn, tree-sitter and the MCP SDK (`rmcp`) have Rust bindings; the matching-decomp community works
  in Rust and Python.
- **English everywhere:** identifiers, CLI verbs and flags, MCP tool and parameter names, file names, TOML keys,
  enum values, messages, docs.
- **Name:** `decovery` (repo, crates `decovery-*`, CLI binary `decovery`). Typography "de·covery" only in
  README/logo.
- **Repository layout on disk:** third-party components that must not be committed live outside the repository
  in a sibling directory `extern/` (Ghidra, compilers, dosbox-lab build, private target workspaces, build output),
  referenced by configured paths.
- **Licence:** `Apache-2.0 OR MIT`. GPL tools (m2c GPL-3, dosbox-lab GPL-2) are only ever used as separate
  processes, never linked.
- **Platforms:** Windows x64 first (dosbox-lab is Windows-only today); code must stay portable to Linux/macOS
  (no Windows-only APIs in core crates; paths via `camino`/`std::path`).
- **No system-wide installs** required at runtime beyond what a user opts into; backends are located by config.
- **Loose coupling to third-party projects.** Foreign projects are reached through capability contracts and are
  replaceable. They are linked into the binary only as a listed exception (section 5.7); everything else runs as
  an out-of-process plugin or an optional cargo feature. The default build must work with none of the optional
  providers present (it then reports the missing capability instead of failing).
- **Not DOS- or Watcom-shaped.** Every contract must be able to describe Windows programs (NE, PE; imports,
  exports, resources, sections) and other compilers/languages (MSVC, Borland, GCC, C++ with name mangling) and
  architectures without a contract change (section 5.8). DOS/Watcom is the first instance, not the model.
- **No `examples/` directory.** Documentation shows usage inline; tests use fixtures only.
- **Porting Decomp is allowed.** Decomp is the author's own code; its modules may be translated to English and
  published under `Apache-2.0 OR MIT`. Compiler rules (`rules/<family>.toml`) are published with **neutralised
  evidence**: compiler behaviour and patterns only; references to proprietary programs (function names, addresses,
  code) are removed and replaced by evidence on project-built Open Watcom fixtures where possible. The original
  evidence stays in the private workspaces.
- **Priority: replace Decomp for the author's own work first.** Within each phase, parity on the first target leads;
  public fixtures, docs and the Open Watcom path come along but second.
- **Ghidra is the standard analysis/decompiler provider** and expected for good results: its pseudo-C is the
  starting point of every rebuild, plus types, data flow and xrefs. `decovery setup ghidra` installs the pinned
  version (and a JDK) into `extern/`. The core's minimal analyzer only keeps `status/find/build/diff` working
  without a running Ghidra (night runs, CI); IDA/Binary Ninja/rizin are alternatives, not peers in priority.
- **Ghidra version:** the Ghidra plugin pins 12.1.4 by default (matches Decomp's cached project); the version is
  configurable. *(builder's call)*

## 4. Concepts

| Concept | Meaning |
|---|---|
| Workspace | One target program under study: `decovery.toml` + `knowledge/` + `src/` + generated `output/` + `cache/`. Lives in its own (usually private) git repo. |
| Program | The loaded image: format, architecture + mode per region, sections/segments/objects, address spaces, relocations/fixups, entry points, imports/exports, resources, debug info if present. |
| Address | Typed: `flat:XXXXXXXX` (32-bit linear/VA), `flat64:…` (64-bit VA, reserved), `seg:SSSS:OOOO` (real mode, relative to load segment), `sel:SSSS:OOOO` (protected-mode segment, e.g. NE), `file:0x…` (file offset). One canonical text form each. |
| Function | Address range + name + prototype + module assignment + status. |
| Claim | Any piece of knowledge (name, type, comment, prototype, boundary) with `confidence` = `confirmed` \| `assumed` \| `refuted`, `source` (`human`, `signature`, `runtime`, `similarity`, `analysis`, `agent`) and `evidence` text. Precedence `human` > `confirmed` > `assumed`; refuted claims are kept with history. |
| Profile | Declarative description of a compiler (or assembler/linker) version: invocation, flag space, naming, object format, calling conventions, prologue patterns. |
| Family extension | Optional code for a compiler family (e.g. Watcom) implementing extension traits. |
| Attempt | One build of one source variant for one or more functions: inputs (content hashes), profile, flags, outputs, diff, verdict. Immutable, recorded in the logbook. |
| Verdict | Set **only** by decovery. `identical`: all non-relocated bytes equal **and** every relocated field refers to the same target as the original (resolved symbol/address + addend + fixup kind/width; a merely masked field is not enough). `equivalent`: not identical, with an evidence level — `static` (difference proven harmless by analysis, e.g. register renaming only) or `tested` (behaviour equal on N recorded runtime cases + M generated cases, counts and coverage stored). `differs`: with metrics. `unchecked`: never built. Progress reports count `identical` and `equivalent` separately; only `identical` counts as matched. *(builder's call)* |
| Job | A long-running operation (search, night run, bulk decompile) with a handle, progress and partial results. |

## 5. Architecture

```
 Agent facade      MCP (stdio + streamable HTTP) · CLI · JSON output
                   ~15 task tools · summaries + handles · budgets · next-step hints · jobs
 ──────────────────────────────────────────────────────────────────────────────────────
 Core              workspace · program model · knowledge/claims · attempts + logbook
                   content-addressed cache · scheduler (parallel, cancellable) · config
 ──────────────────────────────────────────────────────────────────────────────────────
 Capabilities      contract (trait)            providers  (F = fixed exception, O = optional feature, P = plugin)
   Loader          load image                  own: mz, com, le/lx; later ne, pe                      (core)
   Analyzer        functions, xrefs, strings   ghidra P (standard); own minimal analyzer (core); later ida P, binja P, rizin P
   Decompiler      pseudo-C per function       ghidra P (standard); later others P
   Arch            decode/describe insns       x86 via iced-x86 F; other archs as further Arch impls
   ObjectReader    symbols/sections/relocs     own: omf, coff, a.out; elf via `object` O
   Toolchain       compile/assemble/link       profile + Runner (no code per compiler)
   Runner          execute a tool command      native, unicorn-host P (DOS/extender, later Win32 console), dosbox-lab P, wibo/wine (process)
   Differ          object vs original bytes    own instruction differ (core); objdiff-core O
   Debugger, Tracer, MemoryImage,             dosbox-lab P; later Windows debuggers, tracers,  (see 5.9, 5.10)
   TestEnvironment, OsState                   minidumps P
   Emulator        run a function on cases     unicorn P (GPL-2, separate binary); icicle-emu O under evaluation
   SourceFrontend  parse/rewrite/print/check   C (own parser, tree-sitter-c O for error-tolerant editing)
   Mutator         source variants             own rewrites; decomp-permuter transforms P
   Search          strategy over variants      hill-climb, beam, family-directed               (core)
 ──────────────────────────────────────────────────────────────────────────────────────
 Profiles + family extensions   profiles/*.toml · watcom (RegisterModel, StackSlotModel, Rules, Rewrites,
                                PrototypeSyntax) · turbo-c · gcc-djgpp · msc …
```

### 5.1 Plugin model

Two kinds, one contract per capability:

1. **In-process (Rust):** a crate implementing the capability trait, compiled in behind a cargo feature. Used for
   everything on hot paths (diff, disassembly, mutation, scoring, emulation, loaders, object readers, and family
   models once ported).
2. **Out-of-process:** any executable speaking the **decovery plugin protocol**: JSON-RPC 2.0, newline-delimited,
   over stdio. Handshake `initialize` returns `{name, version, protocol, capabilities[]}`. Plugins are long-lived
   (a warm Ghidra JVM stays open), may be pooled, support `$/cancel` and per-request timeouts. Large data never
   travels inline: requests and responses carry paths into the workspace cache plus content hashes. Python plugins
   use a small SDK package (`decovery-plugin`) that implements the framing and capability dispatch.

Performance rule: plugin calls are coarse-grained (batch: "decompile these 200 functions", "score these 500
variants"). Estimated per-call overhead is µs–sub-ms versus ms–s for a compile or decompile (estimate, to be
measured in phase 0).

Plugins are discovered from `decovery.toml` / user config (`[plugins.<name>] command = [...]`), not from a global
registry. `analyze` executes the `command` a workspace's `decovery.toml` names, so only analyze workspaces you trust.

### 5.2 Compiler profiles

Declarative TOML, ids aligned with decomp.me where a counterpart exists. Sketch:

```toml
id = "watcom-9.5"
family = "watcom"
language = "c"
version = "9.5"
bits = 32
object_format = "omf"
runner = "unicorn-dos"            # default; overridable per workspace
command = "BINW\\WCC386.EXE {flags} -fo={output} {input}"
symbol_decoration = { function = "{name}_", data = "_{name}" }
calling_conventions = ["watcall", "cdecl"]
prologue_patterns = []
[flags]
space = [["-ox", "-os", "-ot"], ["-3s", "-4s", "-5s", "-3r", "-4r", "-5r"], ["-oa", ""]]
[linker]
profile = "watcom-10.6-wlink"
[assembler]
profile = "watcom-10.6-wasm"
```

The tool directory (`BINW` root) comes from user config or workspace config, never from the profile.

### 5.3 Family extension traits

| Trait | Purpose | Watcom source in Decomp |
|---|---|---|
| `RegisterModel` | predict/explain register allocation for a variant without compiling; read the real allocator's trace | `registerwahl.py`, `vergabe*.py`, `vorhersage.py` |
| `StackSlotModel` | explain/predict local stack slot order | `plaetze.py` |
| `DiagnosisRules` | pattern in instruction diff → cause + suggested rewrite (data-driven, `rules/<family>.toml`) | `regelwerk.py`, `compilerwissen/` |
| `DirectedRewrites` | rewrites that apply a rule's suggestion automatically | `umformungen.py`, `formen.py`, `vergabe_umsetzen.py` |
| `PrototypeSyntax` | family-specific declarations (`#pragma aux`, `__watcall`, `__far`) for the frontend and the decompiler | `watcall.py`, permuter lexer extension |

All traits are optional. A compiler with only a profile still gets: build, diff, generic diagnosis, permutation,
beam search, logbook.

### 5.4 Agent facade

Target tool set (names final in phase 1; ≤ 16 tools):

| Tool | Does |
|---|---|
| `status` | workspace overview: progress, open work, running jobs, suggested next step |
| `find` | search functions/strings/symbols/xrefs with filters and sorting |
| `show` | one function: header (callers, callees, globals, runtime evidence, match status), pseudo-C or rebuild source, diff summary |
| `annotate` | add/refute claims (name, type, prototype, comment, boundary) with confidence + evidence |
| `analyze` | (re)run analysis/decompilation for the whole program or a selection |
| `build` | compile a source file or variant, diff, return verdict per function |
| `diagnose` | explain the remaining differences (rules, register/stack models), ranked suggestions with expected effect |
| `try` | build several explicit variants in one call and rank them |
| `search` | start a search job (strategy, budget, seed); returns a job handle |
| `job` | poll/cancel a job, fetch partial results |
| `verify` | behavioural equivalence for a non-identical rebuild (recorded runtime cases + generated cases) |
| `runtime` | sessions, recordings, imports, replay, inspection, interaction via the runtime contract (5.9) |
| `link` | link the whole program and compare with the original |
| `history` | logbook queries: what was tried for a function, what failed, best known state |
| `detail` | fetch a full report by handle (diffs, traces, allocation logs) |

Output conventions: every response has a short `summary`, structured `data` bounded by a default budget, and
`handles` for anything larger. Responses state verdicts as tool findings; the facade never echoes an agent's
claim as a verdict. `search` is only offered by `status`/`diagnose` as next step when the diff is small (threshold
configurable, default ≥ 95 % instruction match) — below that, `diagnose` comes first.

The CLI mirrors the tools 1:1 (`decovery show <fn>`, `decovery build src/map.c`), with `--json` for machine output.
A remote mode lets the CLI talk to a running MCP server so the warm backends are shared (as Decomp's
`fernzugang.py` does).

### 5.5 Workspace layout (English schema)

```
<workspace>/
  decovery.toml            target file + hash, format, segments, detected facts, profile, runners, plugins
  knowledge/
    symbols.toml           functions, globals, labels with claims
    types.h                C types (parsed by the C frontend)
    notes.md               free text
    runs.toml, runs/       runtime runs (coverage etc.)
    rebuild.toml           per-function build results (versioned, shown in output)
    analysis/              analysis.json + decompiled/ (provider results, generated by analyze/migrate)
    style.md               program-specific coding style
  src/                     rebuild sources (C, headers, asm)
  output/                  generated, never hand-edited: one .c per function with header, indices
  cache/                   gitignored: backend projects, objects, attempts, logbook
```

Shared, program-independent knowledge lives in the decovery repo: `rules/<family>.toml` (diagnosis rules with
evidence), `profiles/`, signatures built from *free* libraries only (Open Watcom), interrupt tables.
Signatures from commercial libraries are built locally into `extern/` and never committed.

### 5.6 Interop

- `objdiff.json` export per workspace; objdiff-core as an optional differ provider.
- decomp.me compiler ids/flag names in profiles; later a scratch export.
- permuter directory export (`base.c`, `target.o`, `compile.sh`, `settings.toml`) for users who run the original.
- `decomp-symbols/1` symbol file for dosbox-lab (existing contract, kept as is; it is already English).
- `decovery migrate <decomp-workspace>`: one-time, lossless conversion of a Decomp workspace (knowledge, rules,
  logbook, attempt archive, rebuild results) into the English schema; reports anything it could not map.

### 5.7 Fixed third-party dependencies (the exceptions)

Linked into the binary, because they sit on hot paths, are small and stable, and have permissive licences:

| Dependency | Why fixed | Licence |
|---|---|---|
| `iced-x86` | x86-16/32/64 decode/encode/format on every diff, analysis and search step | MIT |
| general-purpose Rust crates | `serde`, `toml`, `serde_json`, `clap`, `rmcp`, `tracing`, `rayon`, `blake3`, `thiserror` | MIT/Apache |

**Not fixed: unicorn.** Unicorn 2 is GPL-2; linking it would make the binary GPL. The `Emulator` and the
unicorn tool host therefore live in a separate GPL-2 provider, the Python plugin `plugins/unicorn-dos`
(`unicorn==2.1.1` wheel, ADR 0004 amendment), spoken to over the plugin protocol. Calls are coarse (one per
compile, one per batch of cases), so the process boundary costs little. Phase 0 also evaluates `icicle-emu`
(Rust, permissive, SLEIGH-based) as an in-process alternative; switching would be an ADR.

Everything else — Ghidra, IDA, Binary Ninja, rizin, dosbox-lab, decomp-permuter, m2c, objdiff-core, wibo, wine,
original compilers — is reached through a contract as a plugin, an external process, or an optional feature.
Adding a fixed dependency requires an ADR.

### 5.8 Extensibility axes (Windows programs, other compilers, other languages)

The contracts are shaped for these axes from the start; DOS/Watcom is only the first point on each:

| Axis | First instance | Later instances the contract must already admit |
|---|---|---|
| Executable format | COM, MZ, LE | LX, NE (Win16), PE/PE32+ (Win32/Win64); imports by name/ordinal, exports, resources, TLS, sections with flags |
| Architecture / mode | x86-16 real, x86-32 flat | x86-16 protected (NE selectors), x86-64; non-x86 via further `Arch` impls (the core never matches on x86 opcodes) |
| Object format | OMF | COFF (MSVC, DJGPP), ELF, a.out; archives/import libraries (`.lib` OMF and COFF) |
| Debug info | none | Watcom debug, CodeView, PDB (read when present, become `confirmed` claims) |
| Compiler | Watcom 9.5 | Watcom 10.x/OW2, Borland/Turbo C/C++, MSC/MSVC, GCC/DJGPP/MinGW, Delphi/Turbo Pascal |
| Calling convention | watcall, cdecl | stdcall, fastcall (MS/Borland), thiscall, pascal, far/near variants; described as data (register/stack assignment, cleanup, decoration) |
| Symbol decoration | C (`name_`, `_name`) | C++ mangling schemes (MSVC, Borland, Watcom, Itanium) via a `Demangler` contract |
| Language | C | C++, Pascal, assembler — each a `SourceFrontend` |
| Tool host | unicorn DOS/extender, DOSBox | native Windows, Win32 console host in unicorn, wibo/wine on Linux |
| Runtime evidence | dosbox-lab | Windows debugger/tracer providers delivering the same records (coverage, calls, snapshots) |
| Linked program compare | LE | NE, PE (section/relocation/import-table aware) |

Rule for contributors: a new format/compiler/language must be addable by implementing contracts and writing a
profile; if it needs a change to a core type, that change is an ADR.

### 5.9 Runtime interfaces (by role; dosbox-lab is the first provider)

dosbox-lab (DOSBox-X fork, GPL-2, Python API `dosbox_lab.api.Dosbox`, ~70 MCP tools, formats
documented in the dosbox-lab repository) is the first runtime provider. Its capabilities are reached through five
role-based interfaces. The records are defined in decovery's core, so that other providers (Windows debuggers,
tracers, minidumps, the unicorn provider) deliver the same data. A provider may implement any subset and declares
it in `initialize`; dosbox-lab implements all five.

| Interface | Operations | dosbox-lab mapping | Later providers |
|---|---|---|---|
| `Debugger` | pause, step, step over, run until; breakpoints on code, system calls (INT 21h, later Win32 API) and memory (watchpoints with write log); registers (per `Arch`), descriptors/paging; memory read/write/search; disassemble at address; evaluate | `emu_*`, `break_add`, `break_int_add`, `watch_add`, `watch_log`, `cpu_*`, `mem_*`, `cpu_disassemble`, `emu_eval` | Windows debugger, gdb |
| `Tracer` | coverage (per instruction, optional basic-block counters), indirect flow edges, call log (entry registers/flags/stack, return registers), event stream (process start/exit, system calls with filters), file accesses | `coverage_*`, `flow_*`, `calls_*`, `events_*`, `dos_files` | Frida, unicorn, hardware tracing |
| `MemoryImage` | capture an image at a trigger, enumerate images, load image ranges, module map (bases of objects/segments), map runtime ↔ workspace addresses, export symbols to the provider | `snapshot`, `modules_set_segments`, `symbols_load` (`decomp-symbols/1`), `symbol_lookup` | Windows minidumps, unicorn |
| `TestEnvironment` | sessions (instances with mounts, run folders, parallel), batch commands (exit code, console, produced files), machine-state save/load (opaque blob), **replay** a function from a captured state with modified inputs (result in the same shape as the `Emulator`), input and screen (keys, text, mouse, screenshot, screen text, scripted scenarios) | `dosbox_start`, `run_batch`, `state_save`, `state_load`, `func_run`, `key`, `type_text`, `mouse_*`, `screenshot`, `screen_text`, `scenario.py` | unicorn, Windows sandbox |
| `OsState` | loaded programs, memory arenas, open files, current target; typed payload per OS | `dos_programs`, `dos_mcb`, `dos_files`, `dos_target` | Win16, Win32 |

The batch part of `TestEnvironment` is the same contract as the toolchain `Runner`, so the original compilers can
run in dosbox-lab, in the unicorn host or natively without the toolchain knowing which.

Two ways of use, both supported:
1. **decovery drives dosbox-lab** through the plugin (`plugins/dosbox-lab`, using the Python API): batch compiles,
   recordings, memory images and replay for `verify`.
2. **The agent drives dosbox-lab directly** through its own MCP server (interactive play to reach code), and
   decovery imports the run folder afterwards (`runtime import`). Formats are recognised by content, not file name.

Provider-specific operations that are not abstracted stay reachable through `runtime` with
`provider_call {name, args}`, clearly marked non-portable in the response.

In the facade, `runtime` is one tool with actions (`start`, `record`, `capture`, `stop`, `import`, `replay`,
`inspect`, `interact`, `export-symbols`, `provider-call`) to keep the tool count ≤ 16.

### 5.10 Memory images

Exact memory images are first-class data, not provider files.

- **Capture with a trigger.** An image is captured at an event, normally a function entry breakpoint, and linked
  to the `CallRecord` of that call (registers, flags, stack). The inputs of that call are then known exactly. A
  second image at return, or the watchpoint write log of the call, gives its effect.
- **Model.** `MemoryImage { id, provider, trigger (breakpoint | call | label | time), call_record?, regions:
  [{runtime_base, length, blocks[]}], module_map: [{module, object/segment, runtime_base}], cpu_state,
  machine_state? (opaque provider blob for exact replay), provenance }`.
- **Mapping.** Runtime addresses map to workspace addresses (`flat:`, `seg:`, `sel:`) through the module map. If a
  provider cannot report bases, they are recovered by byte search of known object contents (as Decomp's
  `momentaufnahme.py` does) and stored as `assumed` with evidence.
- **Storage.** Content-addressed in `cache/` in 64 KiB blocks (blake3); images of the same program share
  unchanged blocks, so hundreds of images cost little. Images are workspace data and can be imported from runs.
- **Consumers.**
  1. `verify`: original and rebuild run from the same real image — replay in the provider (`func_run`) or the
     image loaded into the emulator with the recorded registers. Compared: return value, registers, flags, and
     the set of memory writes.
  2. Knowledge: real values of globals, tables and pointer targets become claims with `source = runtime`, used for
     type and structure recovery.
  3. Image diff (before/after a call, or between two triggers) lists the side effects of a function.
  4. Packed, self-modifying or overlay code is analysed from the image after unpacking/loading.
  5. Agents: search values, check a structure layout against real data, read strings at runtime.

### 5.11 Decisions from the interface review (2026-11-04)

Senior-judgment review of all interfaces before implementation; these override earlier sections where they differ.

1. **Verdict is decovery's rule, not Decomp's.** Decomp checks only self-relative references by name, treats
   absolute fixups as gaps and lets unnamed references pass. decovery checks every relocated field against the
   original's relocation target (LE fixups via `Program.relocations`), requires zero differing instructions, and
   reports `blockers` (unchecked reference, wrong absolute reference, wrong relative reference, instruction
   difference, inline assembly/cheat) next to the verdict. Decomp's numbers are kept as `metrics` for parity;
   where the verdicts differ, the case goes into the parity deviation list. On disk: `verdict`, `blockers[]`,
   `metrics`.
2. **Every on-disk file carries `schema = 1`** (`decovery.toml`, `symbols.toml`, `rebuild.toml`, logbook records).
   Refuted claims are structured (`refuted = [{name, source, confidence, evidence, date}]`), not free text.
3. **Addresses:** `sel:SSSS:OOOOOOOO` is the *static* segment number from the file (NE segment table index) plus
   offset; runtime selectors appear only in runtime records and are mapped through the module map. `file:0x…` is
   an input form converted at the CLI/MCP boundary, not a program address. `flat64:` is a reserved text form;
   its variant is added with the first 64-bit loader.
4. **Plugin protocol:** `initialize` returns capabilities with versions (`{"analyzer": {"version": 1}}`);
   notification `$/progress {id, done, total?, message?}`; on timeout the host sends `$/cancel` and discards a late
   response by id; requests flow host → plugin only; blobs below 64 KiB inline, above by path + blake3. The host
   has one reader thread and routes responses by id, so calls can overlap and be cancelled.
5. **Plugins get decovery's program description, not backend vocabulary:** `analyzer/open {program: {format,
   entry_points, regions: [{name, start, size, arch, permissions, blob}]}, project_dir}`; the Ghidra plugin maps
   it to a Ghidra language/loader itself.
6. **Object model:** sections (kind, bitness, data, relocations with typed targets: symbol, section+offset,
   unknown) and symbols; the "function = public in a code section" split is a derived view, not the model. Gaps
   are derived from relocations.
7. **One path each:** one `Runner` contract (native, unicorn host, dosbox-lab batch); one `FunctionExec` contract
   ("run this function from this state with these inputs") served by the unicorn provider and dosbox-lab's
   `func_run`; `TestEnvironment` keeps sessions, machine state and interaction only.
8. **No own analyzer for now:** Ghidra's results are stored in the workspace as claims (`source = analysis`,
   provider recorded); night runs and CI read those. An own analyzer comes only when a real case needs it.
9. **Facade:** `try` folds into `build {variants[]}`; `detail` fetches any handle including job results; `job`
   only polls and cancels.
10. **Runtime roles** (`Debugger`, `Tracer`, `MemoryImage`, `TestEnvironment`, `OsState`) stay the target design;
    their schemas (`MemoryImage`, `CallRecord`, …) are fixed in phase 5, not earlier. Until then agents reach
    dosbox-lab's extra functions through its own MCP server and `provider_call`.
11. **Type hygiene:** public enums/structs `#[non_exhaustive]`; serialized enum values are stable string ids
    (`"x86-32"`, `"absolute"`); relocation = kind (`absolute`, `relative`, `selector`, `far-pointer`) + width;
    enum variants are added together with the code that produces them.

## 6. Repository layout

```
decovery/
  README.md  AGENTS.md  CONTRIBUTING.md  CODE_OF_CONDUCT.md  SECURITY.md  CHANGELOG.md
  LICENSE-APACHE  LICENSE-MIT  Cargo.toml  rust-toolchain.toml  .gitignore  .gitattributes  .editorconfig
  .github/ workflows/ (ci.yml, release.yml), ISSUE_TEMPLATE/, pull_request_template.md, dependabot.yml
  crates/
    decovery-core/        address model, program model, claims, workspace, attempts, logbook, cache
    decovery-loaders/     mz, com, le/lx (ne, pe later)
    decovery-objects/     omf, coff, a.out (elf via `object`)
    decovery-x86/         iced wrapper, CFG, data flow, calling-convention detection
    decovery-toolchain/   profiles, runners, build orchestration
    decovery-diff/        objdiff-core adapter, instruction alignment, metrics
    decovery-runtime/     runtime/emulator contracts + generic records (coverage, calls, snapshots, cases)
    decovery-source-c/    C frontend
    decovery-search/      mutators, strategies, scheduler integration
    decovery-plugin/      plugin protocol types + out-of-process host
    decovery-mcp/         agent facade (rmcp)
    decovery-cli/         binary `decovery`
    decovery-family-watcom/  (phase 4) Rust port of the Watcom models
  plugins/                out-of-process providers, each separately licensed/packaged
    unicorn-dos/          Python, GPL-2.0: unicorn tool host (Phar Lap, real-mode DOS); later Emulator, Win32 console
    decovery-plugin-sdk/  Python: framing + dispatch for Python plugins
    ghidra/               Analyzer + Decompiler via pyghidra
    dosbox-lab/           Runtime + Runner via dosbox-lab
    watcom-legacy/        Decomp's Watcom models, translated to English, until ported to Rust
  profiles/  rules/  schemas/  skills/  docs/ (design/, adr/, guides/)  tests/fixtures/
```

Fixtures are built by the project from source with a free compiler (Open Watcom 2) or hand-written assembler;
the original commercial compilers are only exercised in local, opt-in tests (`--features local-toolchains`,
paths from `extern/`).

## 7. Phases and acceptance

Each phase ends with a parity check against Decomp on a migrated copy of the first target's workspace (private,
local), plus public tests on fixtures. *(builder's call)* The baseline is frozen per phase: a tagged Decomp commit
plus a snapshot of that workspace, recorded in `docs/parity/<phase>.md`. Where decovery is right and
Decomp is wrong, decovery does not reproduce the bug; the case goes into that file's deviation list with
evidence.

Without a running Ghidra, `status/find/show/build` work from the analysis results stored in the workspace
(section 5.11, item 8).

| # | Scope | Done when |
|---|---|---|
| 0 | Repo scaffold (all GitHub files, CI), this design + ADRs, core address/program model, LE + OMF readers, own instruction differ (objdiff-core as optional feature), plugin protocol + Python SDK + Ghidra plugin skeleton, `migrate` for `decomp.toml`/`symbols`; licence check unicorn vs. icicle-emu | `cargo test` green in CI; for 20 functions of the first target the diff of decovery equals Decomp's instruction diff; Ghidra plugin answers `initialize` + `functions` |
| 1 | Workspace + knowledge/claims, analysis via Ghidra plugin, facade tools `status/find/show/annotate/analyze/detail`, output generation | `show` on the first target equals Decomp's `zeige` content (modulo English), knowledge round-trips |
| 2 | Toolchain: profiles (watcom-9.5, watcom-10.6, turbo-c-2.0, gcc-djgpp), runners (unicorn-dos port of `emu_dos.py`, dosbox-lab, native), `build/try/link`, generic diagnosis; MZ loader + 16-bit path for the second target | `build` verdicts equal Decomp for all identical functions of the first target **and** for all identical functions of a second target (Turbo C 2.0, MZ, 16-bit real mode) using only its profile, no family extension. The second target's binary and Turbo C 2.0 live in `extern/` |
| 3 | C frontend, mutators (permuter transforms ported), search strategies, logbook, jobs, `search/job/history` | night run via `search` jobs reproduces Decomp's decisions on a sample |
| 4 | Watcom family: legacy Python plugin first, then hot paths (register prediction) ported to `decovery-family-watcom` | `diagnose` reports equal Decomp's `vergabe`/`plaetze` on the sample |
| 5 | `verify` (unicorn cases + dosbox-lab `func_run`), `runtime` import | `verify` without Ghidra's emulator agrees with Decomp's `gleichwertig` |
| 6 | Upstream contributions and adapters (objdiff OMF PR, decomp.me Watcom 9.5/LE, rea/re-mcp adapter) | PRs opened |

## 8. Decided here vs. left to the builder

Decided: name, Rust core + Python plugins, English everywhere, licence, repo location and `extern/` split,
capability list, two plugin kinds and protocol style (JSON-RPC 2.0 NDJSON over stdio, blobs by path+hash),
profile/extension split, verdict ownership, ≤ 16 facade tools and their responsibilities, workspace schema
shape, phase order, parity-by-migration.

Left to the builder: crate-internal design, exact trait signatures, TOML field names beyond the sketches, MCP
tool parameter names (English, consistent), error types, logging/tracing setup, CI matrix details, which
tree-sitter vs. hand-written parser parts the C frontend uses, cache layout, test organisation.

## 9. Resolved questions

- Second target early: yes, a Turbo C 2.0 program (MZ, 16-bit) from phase 2, profile only.
- Ghidra pinning: 12.1.4 default, configurable (builder's call).
- Decomp code may be ported; rule evidence neutralised; Decomp replacement has priority.
- Verdict definitions, parity baseline freezing, minimal own analyzer: builder's calls (sections 4, 7).
