# Task 4 report — attempt-memory migration

Status: implementation ready; completion and commit blocked by environment validation and Git metadata permissions. No commit created. Task 5 has not started.

## Implementation

- `decovery-core::migrate_attempts` imports Decomp attempt JSONL into address shards; preserves unknown data and source-line hashes; reruns add only new lines, including duplicate detection within an import.
- Native verdicts remain unset for imported findings. Raw Decomp results are retained as evidence and cannot become zero-distance native matches through history or parking.
- Hand attempts and builds map to the appropriate origins; automatic transformations and older automatic-label heuristics do not spend own budget. Binding P2's exact `eigene_fassung` rule takes precedence for nonempty `bauen` (automatic).
- Source hash algorithms and the text-v2 version are retained in algorithm prefixes. Naive times use the machine's current UTC offset at migration; original time and offset remain in extras. The UTC helper handles date rollover, leap years, malformed UTF-8/ASCII input and invalid calendar dates without panicking.
- Archive conversion verifies the original SHA-256 id, manifest shape, declared files, paths, directory spelling, sizes and content hashes. Links are rejected. Multiple objects retain names under `objects/`; a sole object can use `object.obj`. Predecessors are remapped, and unknown metadata is retained under `decomp`. Invalid neighbors are reported without dropping valid attempt records.
- Imports refuse to write into their source and refuse the destination's own bridge shadow as a source. The normal workspace migration checks source isolation before writing any files.
- Added `decovery migrate-attempts [--from PATH]`, defaulting to `[legacy] decomp_workspace`, plus normal-migration integration. Both report imported attempts, new archive entries, already-present attempts, skipped lines/archives and reasons.
- Updated the obsolete layout assertion: the empty legacy attempt file is now processed by the attempt importer, rather than listed as a deliberately skipped cache. The test still checks every other skipped artifact and now checks the versioned empty import report.

## TDD evidence

- `cargo test -p decovery-core --test migrate_attempts`: RED, only the missing import API after correcting a SHA-256 formatting error in the test helper. First implementation: 7 passed, 1 failed because imported identical evidence still had zero native distance. Adding the evidence guard made all 8 initial tests pass.
- `cargo test -p decovery-core --lib migrate::attempts::tests`: RED, missing `to_utc`; GREEN after the timestamp converter, with literal UTC expectations across New Year and leap day.
- `cargo test -p decovery-cli --test migrate_attempts_local normal_migration_imports_attempts_and_dedicated_command_can_rerun`: RED, normal migration's `attempt_memory` was absent. GREEN after normal-migration/CLI wiring, including default and explicit source reruns.
- `umformung_maps_origin`: RED (`Build` instead of the binding P2 `Variant` for `bauen`); GREEN after using the exact legacy own-attempt rule.
- `migration_refuses_to_write_inside_the_source`: RED (destination was created before refusal); GREEN after moving isolation validation before any write.
- Skip-count assertions: RED, missing report fields; GREEN with distinct skipped-line/archive counters and separate retained-record warnings.
- `shadow_attempts_are_not_imported`: RED, shadow import succeeded; GREEN with the explicit shadow guard.
- `archive_directory_spellings_must_not_collide`: RED, missing path-spelling validator; GREEN after checking every directory prefix as well as full file paths.

## Final checks

- `cargo test -p decovery-core`: 112 passed, no failures; private tests remain ignored. Evidence: `task-4-core-tests.log`.
- `cargo test -p decovery-cli --test migrate_attempts_local`: 1 passed, 1 ignored (`local: first target`). `DECOVERY_LOCAL_WORKSPACE` is unset, so private parity was not run.
- `cargo fmt --all --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- Final **serial** `cargo test --workspace --no-fail-fast`: **613 passed, 1 failed, 17 ignored**, exit 101. The sole failure is the existing Windows worker-cleanup test; both process enumeration (`tasklist`) and tree termination (`taskkill /T /F`) are denied by the environment. All doctests pass in this serial run. No tests were disabled, weakened or filtered from the full run. Evidence: `final-workspace-tests.log`.
- No Python production code was changed; no Python package test run is required. No model driver, proprietary fixture, push, merge, remote change or private-source write occurred.
- Explicit staging failed before changing the index: common Git metadata `index.lock` creation is denied. Owner/coordinator notification is pending; a clean committed tree cannot be produced from this environment yet.

## Files

New: `crates/decovery-core/src/migrate/attempts.rs`, `crates/decovery-core/tests/migrate_attempts.rs`, `crates/decovery-cli/tests/migrate_attempts_local.rs`.

Modified: core `Cargo.toml`, workspace `Cargo.lock`, core `src/{analysis,archive,attempts,lib,migrate}.rs`, `src/migrate/layout.rs`, CLI `src/main.rs`, `schemas/attempt.schema.json`. Shared helper visibility changes are crate-private; `sha2` is already permitted by ADR 0003. No new dependency kind or architectural decision was introduced.

## Concerns / continuation

- Restore effective common-Git-directory write access and Windows process-query/termination access, then rerun the full checks before marking either task complete.
- Stage Task 3 separately first. `task-3-core-fixes.patch` contains its core hunks without Task 4's imported-evidence guard; the other four Task 3 code files and `task-3-review.md` are listed in that report. Then append its SHA/concerns to progress and commit the log separately. Repeat for Task 4.
- Run the ignored private migration parity when the environment paths are supplied; no local counts or performance are claimed here.
- Historical DST conversion uses the current migration offset by the accepted ruling; the raw timestamp remains available.
- The plan places record conversion, archive verification and UTC conversion in one file; it is now roughly 700 lines. No unrelated refactor or unplanned file split was made.
- Later tasks must retain the archive's accepted `format = "decovery-attempt-archive/1"` schema-marker exception in Task 15 documentation.
