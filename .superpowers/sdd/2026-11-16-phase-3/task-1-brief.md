### Task 1: Attempt records (core)

**Files:**
- Create: `crates/decovery-core/src/attempts.rs`, `crates/decovery-core/tests/attempts.rs`,
  `schemas/attempt.schema.json`
- Modify: `crates/decovery-core/src/lib.rs`, `crates/decovery-core/src/analysis.rs` (`now_utc` next to `today`),
  `crates/decovery-core/src/workspace.rs` (`RebuildConfig::attempt_budget`), `crates/decovery-core/src/address.rs`
  (`address_key`)

**Interfaces:**
- Produces:
  ```rust
  pub const ATTEMPTS_DIR: &str = "cache/attempts";
  pub fn now_utc() -> String;                         // RFC 3339 UTC, seconds
  pub fn address_key(address: Address) -> String;     // file-name-safe key of any address kind
  #[non_exhaustive] pub enum AttemptOrigin { Build, Variant, Function, Search, Bench, Migrate }   // kebab-case ids
  #[non_exhaustive] pub struct AttemptRecord {
      pub schema: u32, pub time: String, pub address: Address, pub name: String, pub file: Option<String>,
      pub origin: AttemptOrigin, pub label: Option<String>, pub actor: Option<String>,   // cli | mcp | bench:<run-id> | migrate
      pub profile: String, pub flags: String,
      pub body_hash: String,     // blake3 hex of the function's definition text, LF line ends
      pub context_hash: String,  // blake3 hex over the rest of the file, the headers and the tool fingerprint
      pub original_hash: String, // blake3 hex of the original function bytes
      pub result: RebuildResult, pub verdict: Option<VerdictId>,
      pub instructions_differing: Option<u32>, pub bytes_differing: Option<u32>,
      pub blockers: Vec<String>, pub diagnosis: Vec<String>, pub archive: Option<String>,
      #[serde(flatten)] pub extra: serde_json::Map<String, serde_json::Value> }
  pub fn append_attempts(root: &Path, records: &[AttemptRecord]) -> Result<(), WorkspaceError>;
  pub fn read_attempts(root: &Path, address: Address) -> Result<(Vec<AttemptRecord>, Vec<String> /*warnings*/), WorkspaceError>;
  pub fn attempt_distance(r: &AttemptRecord) -> Option<u64>;   // 0 identical; instructions_differing; None for error
  #[non_exhaustive] pub struct AttemptBudget { pub own: u32, pub since_progress: u32, pub best: Option<u64>, pub limit: u32 }
  impl AttemptBudget { pub fn parked(&self) -> bool }           // best != Some(0) && since_progress >= limit
  pub fn attempt_budget(records: &[AttemptRecord], limit: u32) -> AttemptBudget;
  pub const DEFAULT_ATTEMPT_BUDGET: u32 = 30;
  ```
- Shard name: `address_key(address)` plus `.jsonl`: the canonical address text with every character outside
  `[A-Za-z0-9_-]` replaced by `_` (`flat_00012340.jsonl`, `seg_0000_01FA.jsonl`); a test covers every
  `Address` variant, so a later overlay address kind gets a key without a change here. Appends take the OS lock on
  `cache/attempts/.lock` (same mechanism as `Workspace::lock`, wait 10 s) and write each shard's new lines in one
  `write_all`. Records are read oldest first.
- Budget rule (port of `versuche.budget`): counted are records with origin `build`, `variant`, `function` or
  `search`, result not `error`, each `body_hash` once, oldest to newest; a new best distance resets
  `since_progress` to 0, otherwise it grows by 1. `limit` comes from `[rebuild] attempt_budget` (default 30).

- [ ] **Step 1:** Tests: `append_then_read_round_trips_unknown_keys`, `shards_are_per_function`,
  `address_key_covers_every_address_kind`, `concurrent_appends_keep_every_line` (8 threads × 50 records, two
  `append_attempts` callers), `torn_last_line_is_skipped` (warning names file and line), `distance_of_error_is_none`,
  `budget_counts_each_body_once`, `budget_parks_after_limit_without_progress` (31 attempts, best 4 after attempt 1
  → parked; one identical → not parked), `now_utc_has_rfc3339_shape`.
- [ ] **Step 2:** Run `cargo test -p decovery-core --test attempts` → FAIL (module missing).
- [ ] **Step 3:** Implement; add `attempt_budget: Option<u32>` to `RebuildConfig`; write `schemas/attempt.schema.json`.
- [ ] **Step 4:** Run → PASS; workspace gates.
- [ ] **Step 5:** Commit `feat(core): attempt records with a budget rule`.

