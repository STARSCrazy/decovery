# Task 3 report: recording attempts, `history`, tool-call log

Status: DONE_WITH_CONCERNS (minor, see the end)

## What was implemented

- **core `calls.rs`** (new, `pub mod calls` in `lib.rs`): `CALLS_DIR = "cache/calls"`, `#[non_exhaustive] CallRecord {schema,
  time, tool, operation, target, seconds, outcome, actor, builds, searches, extra(flatten)}` (P8: `builds`/`searches`
  per call), `CallRecord::new(tool)`, `append_call(root, &record)` → `cache/calls/<yyyy-mm>.jsonl` (month from the record
  time; malformed time → `unknown.jsonl`), one `write_all` under `cache/calls/.lock`. Two unit tests.
- **core `attempts.rs`**: the lock loop is now `pub(crate) fn lock_dir(dir)` (shared with the call log);
  `AttemptRecord::same_attempt(&other)` = Decomp's `Versuch.schluessel` (address, body_hash, context_hash, profile,
  flags, original_hash), read from `Decomp/src/decomp/nachbau/versuche.py` (read only).
- **schemas/attempt.schema.json**: `result` and `verdict` enums gain `other` (T1 note).
- **facade `tools/history.rs`** (new):
  - actor: `set_actor(&str)` (CLI sets `cli`, MCP sets `mcp` once at start), `actor()` = `DECOVERY_ACTOR` (when set,
    non-empty) > set value > `library`; every produced attempt and call record sets it.
  - `RecordAs { origin, label, skip_labels, extra }` (crate-private field `BuildRequest.record`); used only by
    `judge_candidate`.
  - `AttemptSource` (file, LF text, profile, flags, staged header hashes, tool fingerprint; definitions parsed once per
    source): builds an `AttemptRecord` with `body_hash = blake3:<hex>` of the definition (whole text when not defined
    exactly once), `context_hash` = blake3 over the rest of the file + headers + profile + flags + fingerprint,
    `original_hash`, file, profile, flags, actor; and the archive files `function.c`, `module.<ext>`,
    `objects/<name>.obj`, `comparison.txt` (content only, no time), `messages/1.txt`.
  - `mark_archived`: per function, identical attempts plus the best compared non-identical attempt of the call.
  - `record_attempts`: skips an attempt whose key equals its function's last record (shard's last line, or the previous
    one in this batch) — so an unchanged full build appends and archives nothing (C8/volume); archives the marked ones
    with `meta = {address, name, file, profile, flags, body_hash, context_hash, original_hash}` (`meta.file` always set);
    appends the rest in one `append_attempts`. Write failures become build warnings (the rebuild records are already
    saved). Runs after the comparison, outside the workspace lock.
  - `history(root, target, limit, budget)`: summary `"<name>: <n> attempts, best <identical|N instructions differ|none
    compared>, <parked|not parked>"`; data `function`, `attempts` (newest first, ≤ limit and ≤ budget, each `{time,
    origin, label, actor, verdict, result, instructions_differing, bytes_differing, blockers, archive}`),
    `attempts_total`, `best {distance, time, archive}`, `attempt_budget {own, since_progress, limit, parked}` (C14 rename),
    `failures` ([{message: first line, count}]), `warnings`; a `history-attempts` handle with all attempts when not all are
    listed. Bench-harness records are left out (P4). `parked` is false without attempts (T1 note: limit 0).
  - `history_archive(root, target, id, budget)`: `function_c`, `comparison`, `meta`, `files`; refuses an entry of
    another function. (Separate function because the brief fixes `history`'s signature.)
  - Budget limit: `cfg.attempt_budget.unwrap_or(DEFAULT_ATTEMPT_BUDGET)`.
- **build.rs**: full/file build records one attempt per new rebuild record (compared ones and error records of failed
  files, with `extra.message`), origin `build`; staged header hashes and original bytes (from the placements) are kept for
  the hashes; `object_name` helper; asm sources keep their LF text too.
- **variants.rs**: one attempt per variant (origin `variant` for `source`, `function` for `function_source`, label = the
  variant's label), unless `record.skip_labels` names it; result/verdict mapped from the ranking (unchecked/error →
  `error` + `unchecked`); object of the group the variant was judged on (the full file when confirmed). No rebuild record,
  kept object or output is written (still).
- **legacy.rs**: `search` passes `RecordAs { origin: search, label: "search:<strategy>", skip_labels: ["current"], extra:
  {decomp_report: <ergebnis.txt artifact, else the first artifact>} }` to `judge_candidate`. With `--apply` the follow-up
  normal build of the spliced file has the same key as the candidate attempt and appends nothing for the function
  (recorded once; its other functions are recorded as `build`). `function_of`/`Function` became `pub(super)`.
- **find.rs**: `FunctionFilter::Parked` (id `parked`): has attempts and `attempt_budget(..).parked()`.
- **MCP** (`decovery-mcp/src/lib.rs`): twelfth tool `history {target, limit?, archive?}`; filter `parked`; own
  `call_tool` wraps the router and appends one `CallRecord` per call (target from `target`/`function`, operation from
  `deep`/`strategy`/`check`, `builds` = max(1, variants) for build, `searches` = 1 for search, both 0 when refused).
  Outcome: `refused` for router errors, for rmcp's own argument rejection (tool error starting with rmcp's
  `failed to deserialize parameters:`) and for the handlers' parameter checks (marked via a `_meta` key that is removed
  before the answer goes out); `error` for other tool errors; `ok` otherwise. `cancelled` has no producer yet (T10).
  Instructions/doc say twelve tools.
- **CLI**: `decovery history <function> [--limit N] [--archive ID] [--json]`; `--filter parked`; `set_actor("cli")`;
  every workspace command (all but `migrate`, `mcp`, `setup`) appends a `CallRecord` with `actor = cli` (exit 2 →
  `error`), only when the directory holds `decovery.toml`; dispatch moved into `run(cli)`.
- **Test fixture** `fake_legacy.py`: an answer may name `artifacts`.

## Tests

New `crates/decovery-facade/tests/history_synthetic.rs` (8): `build_records_one_attempt_per_function` (also: unchanged
rebuild appends/archives nothing, changed body appends), `variants_record_each_variant_with_label`,
`search_records_only_the_candidate` (with `apply`), `identical_attempt_is_archived_with_function_source` (also best
non-identical archived, worse not), `history_lists_newest_first_with_best_and_budget` (also failures grouped, handle with
a smaller limit), `history_archive_returns_function_source` (also foreign entry refused), `parked_filter_finds_spent_functions`,
`variants_still_write_no_rebuild_record`.
`crates/decovery-cli/tests/mcp_stdio.rs`: `lists_eleven_tools` → `lists_twelve_tools`; new `every_mcp_call_is_logged`
(ok, error, history ok, refused by argument check, refused by the build handler's check; marker not leaked; builds 0 when
refused). `crates/decovery-cli/tests/cli.rs`: new `history_runs_and_commands_are_logged`. `calls.rs` unit tests (2).

### TDD evidence

Tests were written after a first implementation pass; RED was then shown by stashing the implementation
(`git stash push --include-untracked -- crates/*/src schemas fake_legacy.py`) and running the new tests:

- `cargo test -p decovery-facade --test history_synthetic` →
  `error[E0432]: unresolved imports decovery_facade::history, decovery_facade::history_archive` and
  `error[E0599]: no variant ... named Parked found for enum FunctionFilter` (expected: the API does not exist yet).
- `cargo test -p decovery-cli --test mcp_stdio` → `lists_twelve_tools ... FAILED`, `every_mcp_call_is_logged ... FAILED`
  (expected: eleven tools, no call log).

GREEN after `git stash pop`:
- `cargo test -p decovery-facade --test history_synthetic` → `test result: ok. 8 passed; 0 failed`
- `cargo test -p decovery-cli --test mcp_stdio` → `test result: ok. 11 passed; 0 failed`

### Gates

- `cargo fmt --all --check` → clean
- `cargo clippy --workspace --all-targets -- -D warnings` → clean
- `cargo test --workspace` (without `DECOVERY_PYTHON`) → 595 passed, 0 failed
- Python: no Python package directory was touched (only the test fixture `crates/decovery-facade/tests/fixtures/
  fake_legacy.py`, which has no unittest suite); nothing to run.

## Files changed

- Created: `crates/decovery-core/src/calls.rs`, `crates/decovery-facade/src/tools/history.rs`,
  `crates/decovery-facade/tests/history_synthetic.rs`
- Modified: `crates/decovery-core/src/{attempts.rs,lib.rs}`, `crates/decovery-facade/src/{lib.rs,tools/mod.rs,
  tools/build.rs,tools/variants.rs,tools/legacy.rs,tools/find.rs}`, `crates/decovery-facade/tests/fixtures/fake_legacy.py`,
  `crates/decovery-mcp/src/lib.rs`, `crates/decovery-cli/src/main.rs`, `crates/decovery-cli/tests/{mcp_stdio.rs,cli.rs}`,
  `schemas/attempt.schema.json`

## Self-review findings / concerns

1. **Archive volume of a first full build**: every compared function of a build is "the best attempt of its function in
   this call", so the first full build archives one entry per compared function (each with its file's `module.c`). Later
   unchanged builds add nothing (key dedup), so growth is bounded by real changes, but the first build of ~618 functions
   writes ~618 entries. If the intended reading of "best non-identical attempt of each call" is one per call (not per
   function), `mark_archived` is the one place to change.
2. **Apply records once by key dedup**, not by an explicit switch: the follow-up build's attempt for the function has the
   same key as the candidate's (same spliced text, headers, flags, profile, fingerprint, original), so it is skipped.
   Covered by `search_records_only_the_candidate`; a future change to the context hash that differs between the variant
   path and the build path would break it (the test would catch it).
3. **Default actor `library`** when neither `DECOVERY_ACTOR` nor `set_actor` is set (library callers, facade tests).
   With T1's rule, `variant` attempts count toward the budget only for actors `cli`/`mcp`; so a bench agent running under
   `DECOVERY_ACTOR=bench:<run-id>` does not get its variants counted. That is T1's rule, not changed here; flagging it
   for Task 6.
4. Refusal detection for rmcp's argument errors matches rmcp's documented prefix `failed to deserialize parameters:`
   (rmcp turns its own `INVALID_PARAMS` into a tool error with it); a rmcp upgrade that rewords it would log `error`.
5. The dedup check reads each function's whole shard to find its last line (one read per function per build). Fine for
   now; a long history makes full builds read more.
6. No JSON schema for `CallRecord` was added (none listed in the brief); `schema = 1` is written.
