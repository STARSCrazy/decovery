# decovery-decomp-legacy

decovery plugin that drives a local [Decomp](../../docs/adr/0007-decomp-legacy-bridge.md) checkout, the
predecessor of decovery, for the operations decovery has not ported yet: Watcom register and stack-slot models,
the search chain and its steps, and the behavioural checks. Run as `python -m decovery_decomp_legacy` (stdio,
protocol in `docs/plugin-protocol.md`). Capability `{"legacy": 1}`; the contract is ADR 0007.

## Setup

The plugin runs under the Python of the Decomp checkout's venv (it imports `decomp` and starts `python -m decomp`
with the same interpreter). `decovery setup decomp-legacy --decomp <checkout>` registers it with that Python and
this package and the SDK on its path; by hand: `<checkout>/.venv/Scripts/python.exe -m pip install
plugins/decovery-plugin-sdk plugins/decomp-legacy`. Without an importable `decomp`, `legacy/run` answers `-32020`.

## `legacy/run`

Params `{decomp_workspace, shadow_dir, sources_dir, symbols, operation, function, options?, timeout_s?}`; result
`{exit_code, report, report_language: "de", json, candidate, artifacts, shadow: {refreshed, ghidra_copied},
seconds}`. Operations and the Decomp command each one runs:

| operation | Decomp command | `json` | `candidate` |
|---|---|---|---|
| `context` | `nachbau kontext F` | null | null |
| `structure` | `nachbau struktur F` | null | null |
| `registers` | `nachbau vergabe F --json J` | J (raw register run) | null |
| `slots` | `nachbau plaetze F` | null | null (`beste.c` is an artifact) |
| `joint` | `nachbau gemeinsam F --json` | stdout | null |
| `chain` | `nachbau kette F` | `kette/<f>/ergebnis.json` | `kette/<f>/beste.c` |
| `permute` | `nachbau permutieren F` | null | `permutieren/<f>/beste.c` |
| `beam` | `nachbau strahl F` | null | `strahl/<f>/beste.c` |
| `forms` | `nachbau formen F` | null | `formen/<f>/beste.c` |
| `equivalence` | `nachbau gleichwertig F --json` | stdout | null |
| `behavior` | `nachbau verhalten F` | null | null |

`F` is the function's address in Decomp form (`flat:0001A2B0` -> `va:0001A2B0`, `seg:SSSS:OOOO` ->
`rel:SSSS:OOOO`). Result paths are below `<shadow>/cache/nachbau/`; `<f>` is the name Decomp gives the function
there (its `wissen/nachbau.toml` entry, else its knowledge name, else `fun_<address>`). A candidate is always a whole
module file (`kind: "module"`) and is reported only when the run wrote it: Decomp writes `beste.c` only when it
found something better than the source. `report` is Decomp's German report (`ergebnis.txt` for `joint`, the
`bericht` field for `equivalence`, otherwise stdout); `artifacts` lists the result files this run wrote.

Options (closed set; anything else is `-32602`): `minutes` (`chain`, `permute`, `beam`, `slots`, `equivalence`),
`rounds` (`chain`, `permute`, `beam`, `forms`), `source` (`registers`, `slots`, `structure`, `permute`; a candidate
file in Decomp's `probieren --datei` format, absolute or relative to `sources_dir`), `all` (`registers`), `run`
(`behavior`).

## How a request runs

1. **Shadow refresh** (serialized with server starts by one lock). Into `shadow_dir`: `decomp.toml` (relative
   `datei` paths made absolute), `wissen/` (each file copied when its source size or time changed; copies of
   vanished files removed; state in `cache/legacy-shadow.json`), Decomp's Ghidra project (only when the source's
   `meta.json` differs from the shadow's; lock files left out; while a Decomp server holds the shadow's project,
   the plugin waits for the other runs and stops the server first), `cache/laufzeit` as a junction (Windows) or
   symlink to the source's recordings, and `nachbau/` mirrored from `sources_dir` by content (`.c`, `.h`, `.asm`,
   `.s`, `.inc`; other files Decomp makes there stay). Where a path component starts with a dot, the Ghidra
   project lives under `%LOCALAPPDATA%/decomp/ghidra/<hash>` as Decomp keeps it.
2. **Names.** `symbols` go into the shadow's `wissen/symbole.toml` and the function names of `wissen/nachbau.toml`
   through Decomp's `decomp.wissen` / `decomp.nachbau.ergebnis` API (only when the symbols or those files changed).
   decovery's name wins: entries are replaced directly with `quelle = "import"` (Decomp's precedence check would
   keep a stronger `mensch` name), and another address holding the same name loses it.
3. **Server.** One `python -m decomp --bereich <shadow> mcp --nur-fernzugang --eltern <plugin pid>` per shadow
   (Decomp tool 40, log in `cache/legacy-server.log`), started on the first call and checked with a ping before each
   one; a server another process already runs on the shadow is used and left running. It ends with the plugin
   (`beenden` request at shutdown, killed after 60 s; `--eltern` ends it if the plugin dies).
4. **Command.** `python -m decomp --bereich <shadow> nachbau ...` with `DECOMP_WATCOM_EMU=1` unless the
   environment sets it; the CLI forwards to the server, so Ghidra opens once. A `$/progress` heartbeat every 5 s
   carries the CLI's last stderr line, else the server log's.

Up to two runs at once (`max_parallel` 2, about 3 GB each). `$/cancel` and `timeout_s` kill the CLI process tree;
the command it forwarded would go on inside the server, so the server is killed as soon as no other run uses it
and the next run starts a fresh one.

Errors: `-32602` bad params or option, `-32020` Decomp unavailable (import fails, server does not start within
300 s or exits), `-32021` `decomp_workspace` has no `decomp.toml`, `-32022` the command failed (`data = {exit_code,
stderr_tail}`; a timeout has `exit_code: null, timed_out: true`), `-32002` cancelled.

## Tests

`python -m unittest discover -s tests` runs against the fake Decomp in `tests/fake/` (CLI, server protocol and the
knowledge API; no Decomp checkout and no proprietary data needed). `tests/test_local_decomp.py` runs one real
operation through the plugin protocol and is skipped unless `DECOVERY_DECOMP_WORKSPACE` (a Decomp workspace, only
read) and `DECOVERY_DECOMP_PYTHON` (the Decomp venv's Python) are set; see its docstring for the optional variables.
