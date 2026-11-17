# Task 7 report: bench report and compare

Status: DONE_WITH_CONCERNS (minor).

## Built
- `crates/decovery-bench/src/stats.rs`: `wilson`, `newcombe_difference`, `bootstrap_mean_difference`,
  `bootstrap_paired_difference` (extra, see rulings), splitmix64, median/mean helpers.
- `crates/decovery-bench/src/report.rs`: `GroupBy`, `Report`/`GroupReport`/`MetricSummary`, `report`,
  `RunComparison`/`MetricComparison`, `compare`, text renderers `to_text()` (all `#[non_exhaustive]`, serde).
- CLI `decovery bench report <run.json> [--group-by workspace|profile|tag] [--json]` and
  `decovery bench compare <a.json> <b.json> [--json]` (exit 0, 2 on errors; `--json` is the global flag).
- Tests: `crates/decovery-bench/tests/stats.rs` (10), `crates/decovery-cli/tests/bench_report.rs` (1).

## Rulings
- P16: `Report` and `RunComparison` defined here. Preflight B/T7: `wilson(_, 0)` = (0, 1), successes capped at n;
  Newcombe with an empty sample uses the full Wilson range and never divides by zero.
- Direction: `wilson`/`newcombe`/`bootstrap_*` give first minus second as in the plan; `compare` calls them with B
  first, so every difference in a comparison is B minus A (stated in the text output).
- Pairing: both runs hold the same non-empty set of (task id, repeat) among included tasks. Paired: bootstrap over
  per-task differences (also for `solved`, as Newcombe assumes independence); unpaired: Newcombe for `solved`,
  unpaired bootstrap for the rest. Added `bootstrap_paired_difference` for this (plan listed one bootstrap fn).
- A metric with no values in either run (e.g. cost with no driver cost) is skipped; best distance only counts unsolved
  tasks. `not-run` and `quota` tasks are left out everywhere and counted in `Report.not_run`/`quota`.
- Tag grouping counts a task in every tag; untagged tasks in `(untagged)`; groups sorted by name.
- Warnings: tools, driver, model, suite differ; unpaired.
- Reference values: Wilson 37/50 = 0.6045 / 0.8413 computed independently (python), Newcombe 56/70 vs 48/80 =
  0.2 [0.0524, 0.3339] matches the published table.

## TDD
RED: `cargo test -p decovery-bench --test stats` failed to compile (`no wilson in the root`, `no report in the root`,
`no newcombe_difference`). GREEN: after implementation 9/10, the one failure was an arithmetic slip in my test
(expected mean difference 4.0 - 4.0; real 4.0 - 4.25 = -0.25), corrected the expectation; then 10/10.
No test weakened.

## Gates
`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo test --workspace`
without `DECOVERY_PYTHON`: all pass, 0 failed. No Python touched. No model tokens.

## Concerns
- Percentile bootstrap with 2000 resamples on very small paired samples is coarse (CI can collapse to a point when
  all differences are equal: identical runs give [0, 0], which counts as containing 0).
- Report cost/token cells show median/mean only; no per-tool call stats beyond the summed table.
