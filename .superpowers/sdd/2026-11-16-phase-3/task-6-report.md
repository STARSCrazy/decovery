# Task 6 report: driver contract, limits and the bench run

Status: DONE_WITH_CONCERNS. Built on Codex's WIP commit 796e193 (driver, run, MCP limits, user config, tests).

## Completed beyond the WIP

- Fixed the three failing tests in `crates/decovery-cli/tests/bench_run_synthetic.rs`:
  - `run_record_matches_schema`: `schemas/bench-run.schema.json` was truncated (invalid JSON). Rewritten in full
    (required keys, types, `state` and P17 `exit` enums).
  - `solving_driver_is_solved_by_decovery_verdict`, `quota_pauses_and_resume_continues`: the fake runner's
    `FAKE_OMF_REQUIRED_TEXT` mode (added by the WIP) still looked up `V001.OBJ` for variant jobs, so every variant
    failed to compile. It now serves the stem's object when the staged source holds the text (variants too), else
    `FALLBACK.OBJ`; documented in the fixture's docstring. Test fixture only, no test weakened.
- `call-limit` exit (P17): a task whose driver ended `ok` after the endpoint refused a call while a limit was spent
  is recorded `exit = "call-limit"`. Tests first: assertions added to `tool_calls_beyond_limit_are_refused`,
  `variants_count_as_builds` (and `exit = "ok"` for the idle driver).
- CLI `decovery bench run <suite.toml> --driver <name> [--parallel N] [--seed S] [--repeat R] [--only ID…]
  [--max-total-tokens N] [--max-total-cost-usd X] [--resume RUN] [--keep] [--json]` with drivers from
  `[bench.drivers.<name>]`; passes `current_exe()` as `decovery_exe` (B/T6 ruling). Exit 0 done, 1 paused /
  stopped-at-limit, 2 errors. New test `cli_bench_run_uses_the_configured_driver` (user config via `APPDATA` /
  `XDG_CONFIG_HOME`, unknown driver → exit 2).
- ADR `docs/adr/0009-bench-driver-contract.md`.
- Clippy fixes in `run.rs` (collapsed `if let` chain; the splice is only written when it changes `src/`).

## Rulings

- Run tests live in `decovery-cli/tests/bench_run_synthetic.rs` (preflight B/T6), not `decovery-bench/tests`.
- `call-limit` = driver exit ok + a refused non-harness call in the call log + usage at a limit
  (`max_searches = 0` does not count as spent).
- Run token limit sums input + output + cache writes (preflight B/T8), cache reads separately.
- Bench actor: driver env `DECOVERY_ACTOR=bench:<run-id>`, harness builds `bench-harness` (excluded from usage
  and own budget, per the Task 3 fix ruling; budget rule in core already counts `bench:*`).
- A quota result replaced on resume is kept in the run record under `previous_attempts` (extra key) and counted
  in totals.

## Concerns

- RED for the new `call-limit` assertions and the CLI test was not captured in a log (implementation followed
  directly).
- P19 (background builds vs per-call counting, `job poll` cost) is left to Task 11.
- `config_hash` includes the suite's absolute paths, so `--resume` from a moved suite directory is refused.
- No model tokens spent; only the synthetic `fake_driver.py`.

## Verification

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` clean;
`cargo test --workspace` (without `DECOVERY_PYTHON`): 642 passed, 0 failed, 17 ignored. No Python plugin
directory touched (only the facade test fixture `omf_runner.py`).
