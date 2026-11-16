# ADR 0007: Decomp legacy bridge

Status: accepted · 2026-11-16

## Context

Phases 0–2 reached parity with Decomp for `show`, `build` and `link`. What makes Decomp productive on the first
target today lies in phases 3–6: the Watcom register and stack-slot models (`vergabe`, `plaetze`, `gemeinsam`,
mutation), the search chain (`kette`: structure, slots, registers, form catalogue, permuter, beam search) with its
logbook, and behavioural checks (`gleichwertig`, `verhalten`). Porting them is months of work; until then the author
has to switch back to Decomp for every hard function.

The design already plans "legacy Python plugin first" for the Watcom family (section 7, phase 5). This ADR pulls
that step forward and widens it to the search and verify paths, so that the planned facade tools exist now with
Decomp as their backend, and later Rust ports replace the backend behind an unchanged tool surface.

A spike on 2026-11-16 showed that Decomp runs unchanged on a *shadow workspace* (a copy of `decomp.toml`,
`wissen/`, `nachbau/` and the Ghidra project, with the runtime recordings linked): `nachbau vergabe` on a 368-byte
function took 37 s with `DECOMP_WATCOM_EMU=1`.

## Decision

1. **Plugin `decomp-legacy`** (`plugins/decomp-legacy`, Python, capability `legacy` v1). It runs under the Python of
   a Decomp checkout (its venv) and drives Decomp's CLI as subprocesses. It never writes into the Decomp workspace
   it was migrated from.
2. **Shadow workspace** in `<decovery workspace>/cache/legacy/decomp/`:
   - copied from the source Decomp workspace: `decomp.toml`, `wissen/`, `cache/ghidra/` (once; again only when the
     source's `cache/ghidra/meta.json` changes);
   - linked (directory junction on Windows, symlink elsewhere): `cache/laufzeit/` (read-only recordings, large);
   - mirrored from decovery before every call: `src/` → `nachbau/` (copy changed files, remove files that vanished;
     only `*.c`, `*.h`, `*.asm`, `*.s`, `*.inc`);
   - names: decovery's function and global names are written into the shadow's `wissen/symbole.toml` (through
     Decomp's own `decomp.wissen` API, so the format stays Decomp's), so rebuild sources that use decovery names
     resolve in Decomp's comparison;
   - own: `cache/nachbau/` (Decomp's run caches and logbook for this shadow).
3. **One Decomp server per shadow.** On the first call the plugin starts
   `python -m decomp --bereich <shadow> mcp --nur-fernzugang --eltern <plugin pid>` (Decomp tool 40), waits for
   `cache/fernzugang.json`, and every later CLI call is forwarded to it, so Ghidra opens once. `shutdown` stops it
   (`FernDienst.server_beenden()` request, then kill after a grace period).
4. **Fixed command map** (English operation → Decomp command); nothing else can be run through the bridge:

   | operation | Decomp command | main result |
   |---|---|---|
   | `context` | `nachbau kontext F` | report text |
   | `structure` | `nachbau struktur F` | report text |
   | `registers` | `nachbau vergabe F --json J` | report text + JSON |
   | `slots` | `nachbau plaetze F` | report text |
   | `joint` | `nachbau gemeinsam F --json` | report text + JSON |
   | `chain` | `nachbau kette F --minuten M` | `cache/nachbau/kette/<f>/ergebnis.txt`, `beste.c` |
   | `permute` | `nachbau permutieren F --minuten M` | report text, best version |
   | `beam` | `nachbau strahl F --minuten M` | report text, best version |
   | `forms` | `nachbau formen F` | report text, best version |
   | `equivalence` | `nachbau gleichwertig F --json` | JSON |
   | `behavior` | `nachbau verhalten F [--lauf N]` | report text |

   `F` is the function's address in Decomp form (`flat:0001A2B0` → `va:0001A2B0`, `seg:SSSS:OOOO` →
   `rel:SSSS:OOOO`). Options are a closed set per operation (minutes, rounds, `--datei` from a candidate source,
   run name); unknown options are rejected.
5. **Verdicts stay decovery's.** A candidate source the bridge finds (`chain`, `permute`, `beam`, `forms`) is only a
   proposal: the facade builds it with decovery's own `build` (function-level attempt) and reports decovery's
   verdict next to Decomp's report. Decomp's `equivalence` result is reported as evidence with `source = "decomp"`,
   never as a decovery verdict.
6. **Facade surface** (counts towards the ≤ 16 tools of the design): `diagnose` gains `--deep <operation>` for
   `context`, `structure`, `registers`, `slots`, `joint`; new tool `search` (`chain`, `permute`, `beam`, `forms`);
   new tool `verify` (`equivalence`, `behavior`). When a Rust implementation of an operation lands, it replaces the
   bridge for that operation; the tool shape does not change.
7. **Language.** Decomp's reports are German. The bridge passes them through unchanged as `report` with
   `report_language = "de"`; every structured field decovery adds is English. This is the one sanctioned exception
   to ADR 0002 and ends with the port of each operation.
8. **Configuration.** `migrate` records `[legacy] decomp_workspace = "<absolute path of the source workspace>"`.
   `decovery setup decomp-legacy --decomp <Decomp checkout>` registers `[plugins.decomp-legacy]` in the user config
   with that checkout's venv Python. Without either, the operations fail with a message naming the missing step.

## Protocol: capability `legacy` v1

`initialize` announces `{"legacy": {"version": 1, "limits": {"max_parallel": 2, "memory_per_instance_mb": 3000}}}`.

### `legacy/run`

Params:

```json
{"decomp_workspace": "D:/.../syndicate-1993", "shadow_dir": "<ws>/cache/legacy/decomp",
 "sources_dir": "<ws>/src", "symbols": [{"address": "flat:0001A2B0", "kind": "function", "name": "ai_tick"}],
 "operation": "registers", "function": "flat:00016E40", "options": {"minutes": 10}, "timeout_s": 900}
```

Options (all optional, closed set; anything else is `-32602`):

| option | type | operations | Decomp flag |
|---|---|---|---|
| `minutes` | number | `chain`, `permute`, `beam`, `forms`, `slots`, `equivalence` | `--minuten` |
| `rounds` | integer | `chain`, `permute`, `beam`, `forms` | `--runden` |
| `source` | path | `registers`, `slots`, `joint`, `structure`, `permute` | `--datei` (a candidate source of the function) |
| `all` | bool | `registers` | `--alle` |
| `run` | string | `behavior` | `--lauf` |

The plugin refreshes the shadow (decision 2; the Ghidra copy only when needed), makes sure the Decomp server runs
(decision 3), runs the command with `DECOMP_WATCOM_EMU=1` unless the caller's environment sets it, and sends a
`$/progress` heartbeat at least every 10 s (`message` = Decomp's last stderr line).

Result:

```json
{"exit_code": 0, "report": "<Decomp stdout>", "report_language": "de", "json": {"...": "..."},
 "candidate": {"path": "<shadow>/cache/nachbau/kette/<f>/beste.c", "kind": "module"},
 "artifacts": ["<paths of report files>"], "shadow": {"refreshed": true, "ghidra_copied": false}, "seconds": 37.5}
```

`json` is null for operations without JSON output; `candidate` is null when the operation found nothing better or
has no candidate. `kind` is `module` (a whole rebuild source file) or `function` (one function's definition).

Errors: `-32602` bad params or option; `-32020` Decomp unavailable (`import decomp` fails, server does not start
within 300 s); `-32021` source workspace missing or not a Decomp workspace; `-32022` Decomp command failed
(`error.data = {exit_code, stderr_tail}`); `-32002` cancelled (the Decomp subprocess is killed).

## Consequences

- Decomp's strongest tools are usable from decovery now, on decovery's sources and names, without touching the
  Decomp workspace.
- The bridge depends on a local Decomp checkout and its venv; it is optional and absent from CI except for tests
  with a fake `decomp` module.
- The shadow costs disk space (the first target's Ghidra project is about 825 MB) and a first-call copy.
- Each ported operation removes one row of the command map; the bridge disappears when the map is empty.
