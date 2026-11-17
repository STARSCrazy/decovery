# Task 3 review

Range: `505dd60..e1ae436`. Reviewed against the Task 3 brief, plan, binding preflight rows P1, P2, P4, P5, P8-P12, P24, B/T3 and C6-C9, and reviewer-rules.md.

## Spec compliance

Issues found. Recording, archive content metadata, search attribution, history, CLI/MCP routing, call counters and tool-count updates are present. The implementation report explicitly says tests were written after production code; its retrospective RED run does not meet the plan's test-first requirement. That history cannot be repaired retroactively; all follow-up regression tests must be written and observed failing first.

## Strengths

- `tools/history.rs:52` supplies explicit internal search attribution; `tools/legacy.rs:766` skips the current candidate and carries the report artifact.
- `tools/history.rs:317` builds content-only archive metadata including `file`; unchanged builds are deduplicated by input key.
- `decovery-mcp/src/lib.rs:606` logs successful, failed and refused calls before returning, with counters and actor; stdio coverage includes handler refusals.
- The synthetic tests check archives, function-level attempts, apply-once attribution, history handles and preserved rebuild state.

## Critical

None.

## Important

1. `crates/decovery-facade/src/tools/history.rs:300` (reviewed head): `.ok()` and the discarded warnings suppress unreadable or malformed attempt history during recording. A successful build hides damaged history. Preserve file/line warnings and report I/O failures through the build's existing warnings.
2. `crates/decovery-facade/src/tools/find.rs:205` (reviewed head): `Err(_) => false` and discarded warnings make `find --filter parked` silently incomplete. Propagate I/O failures and surface malformed-line warnings.
3. Named cross-cutting risk: history and search now consume the shared distance helper. Focused inspection of `crates/decovery-core/src/attempts.rs:271` showed `distance_of(Differs, Some(Differs), Some(0)) == Some(0)`. `tools/history.rs:382` therefore reports "best identical" even when reference blockers remain, and budget parking is disabled. Reserve zero distance for an identical result.
4. Named cross-cutting risk: automated search now records attempts. Focused inspection of `crates/decovery-core/src/attempts.rs:325` showed non-own attempts are skipped before an identical search result can clear parking. A successfully solved function remains in `find --filter parked`. A judged identical search must clear parking without charging an own attempt.

## Minor / carried forward

- The carried bench-actor note is resolved in the core handoff: whole-file variants attributed to `bench:<run-id>` count as agent attempts; harness attempts remain excluded.
- Deduplication reads the full shard and occurs separately from the append lock; concurrent equal builds may append duplicate input keys. No lines are lost, but avoiding duplicate volume under that race remains an optimization.
- First builds archive each compared function, including a module copy per function; later unchanged builds are deduplicated.
- rmcp refusal classification depends on an error-message prefix. A future dependency update should retain the stdio characterization test.
- No separate call-log JSON schema was specified or added; records carry `schema = 1`.

## Fix evidence

For findings 1-2, added three regression tests before the implementation change:

- `cargo test -p decovery-facade --test history_synthetic reports_malformed_attempt_lines`: RED, both tests fail (`warnings = []` / missing warnings).
- `cargo test -p decovery-facade --test history_synthetic parked_filter_does_not_hide_unreadable_attempt_shards`: RED, `unwrap_err` receives a successful empty response.
- Preserve recording warnings and propagate parked-filter errors; `cargo test -p decovery-facade --test history_synthetic`: GREEN, 11 passed, 0 failed.

The concurrent core writer handed over findings 3-4 and the carried bench-actor fix, then stopped editing. Read `task-3-fix-red.log`: `cargo test -p decovery-core --test attempts` had 10 passes and three expected failures before production changes (`bench_agent_whole_file_variants_count_toward_budget`, `zero_differing_instructions_with_blockers_is_not_identical`, `identical_search_unparks_without_spending_own_budget`). Read `task-3-core-green.log`: the same test binary, built under the separate validation target, passed 13/13. The history summary retains the raw instruction count even when the ranking distance is floored to one for a non-identical result.

## Assessment

Needs fixes at the reviewed head; all four Important findings now have fixes and RED-to-GREEN coverage. No whole-branch review was performed.

Final consolidated checks: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` pass. The final serial `cargo test --workspace --no-fail-fast` reports 613 passed, 1 failed, 17 ignored; the sole failure is the unchanged `decovery-plugin::host_python::shutdown_of_a_hung_plugin_kills_its_workers`. `tasklist` and `taskkill /T /F /PID <owned worker>` both report Access denied in this environment. No test was disabled or weakened. Earlier doctest artifact errors from overlapping Cargo invocations disappeared in the final serial run. Evidence: `final-workspace-tests.log` and its `.exit` (101).

Commit blocked: even after the coordinator added the common Git directory as a writable root, explicit staging failed with `Unable to create D:/Entwicklung/decovery/.git/worktrees/phase-3-build/index.lock: Permission denied`. No index change or commit occurred. This review and its fixes are ready for external validation and a follow-up commit once both environment blockers are removed.
