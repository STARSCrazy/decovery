# Review: Tasks 6 and 7 (73f5ddc..f0368e4, f0368e4..bbe8118)

Reviewer: Claude (Opus), 2026-11-17. No model tokens spent.

## Critical
- None.

## Important (fixed)
- I1 `run.rs` `build()`: the harness build ignored the CLI's exit status and always read `knowledge/rebuild.toml`.
  When the final build failed before writing (lock timeout, config error, crash: exit 2 or killed), the verdict came
  from an older record, possibly the agent's own build, so `solved` could come from something other than decovery's
  verdict on the final copy. Fix: only exit 0 (identical) / 1 (built, not identical) read the record; otherwise
  `unchecked`, no distance. Test first: `run::tests::failed_harness_build_does_not_reuse_a_stale_verdict` (RED:
  `left: "identical"`), GREEN after the fix.

## Minor (listed only)
- M1 A splice failure in the evaluation (`splice_function` error, e.g. the definition no longer found) aborts the
  task as `driver-error` and skips the final build, although the plan says evaluate after any exit; better a warning
  and build anyway.
- M2 `compare`, paired: sparse metrics (`best_distance_unsolved`, tokens, cost) pair only tasks with values on both
  sides; with no such pair the interval is (0, 0, 0) and reads as consistent, while `mean_a`/`mean_b`/`n_*` use all
  values. Paired best distance compares only tasks unsolved in both runs.
- M3 `hanging_driver_is_killed_and_evaluated` uses `wall_minutes = 0` and a driver without children, so tree killing
  of a grandchild (the MCP server) is not exercised; `quota_pauses_and_resume_continues` does not assert that
  finished results of the first run are kept unchanged.
- M4 Wilson 37/50 reference was computed (python), not taken from a published table (report says so).
- M5 A timed-out driver usually leaves no result file, so its tokens/cost are not counted toward the run limit.
- M6 An admitted call in flight when the MCP server dies is charged in memory only; the restart reloads usage from
  the call log without it (one call of slack).
- M7 Carried from the task report: `config_hash` includes absolute suite paths (resume after moving the suite is
  refused); P19 left to Task 11; RED of the `call-limit` assertions not logged.

## Checked, no finding
Limits (tool calls counted incl. refusals, variants as builds, refused calls zeroed in the log, harness actor
excluded, admission atomic under the lock), core tool set, wall kill (`taskkill /T /F`), quota pause/resume and
`previous_attempts`, run token/cost limit, schema vs record fields and exit enum, Wilson, Newcombe hybrid score,
bootstrap percentiles and B minus A direction, `not-run`/`quota` exclusion, no panics on record input, English,
no new dependencies.

## Gates
`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo test --workspace`
(no `DECOVERY_PYTHON`): 654 passed, 0 failed, 17 ignored.
