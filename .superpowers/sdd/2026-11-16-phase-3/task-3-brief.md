### Task 3: Recording attempts, the `history` tool and the tool-call log

**Files:**
- Create: `crates/decovery-facade/src/tools/history.rs`, `crates/decovery-facade/tests/history_synthetic.rs`,
  `crates/decovery-core/src/calls.rs`
- Modify: `crates/decovery-facade/src/tools/{build.rs,variants.rs,legacy.rs,mod.rs,find.rs}`,
  `crates/decovery-facade/src/lib.rs`, `crates/decovery-mcp/src/lib.rs`, `crates/decovery-cli/src/main.rs`

**Interfaces:**
- Consumes: Task 1 (`append_attempts`, `read_attempts`, `attempt_budget`, `attempt_distance`), Task 2
  (`archive_save`, `archive_load`).
- Produces:
  ```rust
  pub fn history(root: &Path, target: &str, limit: usize, budget: Budget) -> Result<Response, FacadeError>;
  // FunctionFilter gains Parked (id "parked"): functions whose attempt budget is spent without reaching identical
  // core: tool-call log
  pub const CALLS_DIR: &str = "cache/calls";
  #[non_exhaustive] pub struct CallRecord { pub schema: u32, pub time: String, pub tool: String,
      pub operation: Option<String> /* deep op, strategy, check */, pub target: Option<String>,
      pub seconds: f64, pub outcome: String /* ok | error | refused | cancelled */, pub actor: Option<String>,
      #[serde(flatten)] pub extra: serde_json::Map<String, serde_json::Value> }
  pub fn append_call(root: &Path, record: &CallRecord) -> Result<(), WorkspaceError>;   // cache/calls/<yyyy-mm>.jsonl
  ```
- Recording: every function compared by a full or file `build` gets one record with origin `build`; every variant
  of `build {variants}` gets one record per variant with origin `variant` (whole-file source) or `function`
  (`function_source`), label = the variant label. The bridge's `search` judges its candidate through `build
  {variants}` with the labels `current` and `candidate` (`legacy.rs` `judge_candidate`): only the candidate is
  recorded, with origin `search`, label `search:<strategy>` and `extra.decomp_report` = the report's artifact path
  in the shadow. `actor` is `cli`, `mcp` or the value of `DECOVERY_ACTOR` (bench sets `bench:<run-id>`). Identical
  attempts and the best non-identical attempt of each call are archived (Task 2 files); others are recorded without
  archive. Records are appended after the comparison, outside the workspace lock; `build {variants}` still writes
  nothing else.
- `history` response: `summary` "<name>: <n> attempts, best <distance or identical>, <parked?>"; `data`:
  `attempts` (newest first, at most `limit`, default 20; each `{time, origin, label, actor, verdict, result,
  instructions_differing, bytes_differing, blockers, archive}`), `best {distance, time, archive}`, `budget {own,
  since_progress, limit, parked}`, `failures` (errors grouped by the first line of the message, with counts), and a
  handle with all attempts when they exceed the budget. Archive entries are not handles: `history {target,
  archive}` returns that entry's `function.c` and `comparison.txt`.
- Tool-call log: the MCP server appends one `CallRecord` per tool call (also refused and failed ones); the CLI
  does the same for its commands with `actor = "cli"`. It is never read by tools the agent sees; Task 6 derives
  bench usage from it and the parity documents count bridge use from it (ADR 0008 step 3).
- CLI `decovery history <function> [--limit N] [--archive ID] [--json]`; MCP tool `history {target, limit?,
  archive?}` (twelfth tool).

- [ ] **Step 1:** Tests (fake runner, the bridge's fake `decomp` module): `build_records_one_attempt_per_function`,
  `variants_record_each_variant_with_label`, `search_records_only_the_candidate`,
  `identical_attempt_is_archived_with_function_source`, `history_lists_newest_first_with_best_and_budget`,
  `history_archive_returns_function_source`, `parked_filter_finds_spent_functions`,
  `variants_still_write_no_rebuild_record`, `every_mcp_call_is_logged` (also a refused one).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS; gates.
- [ ] **Step 5:** Commit `feat(history): record attempts, query them, log tool calls`.

