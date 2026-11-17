### Task 2: Attempt archive (core)

**Files:**
- Create: `crates/decovery-core/src/archive.rs`, `crates/decovery-core/tests/archive.rs`
- Modify: `crates/decovery-core/src/lib.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const ARCHIVE_DIR: &str = "cache/archive";
  pub const ARCHIVE_FORMAT: &str = "decovery-attempt-archive/1";
  pub fn archive_save(root: &Path, meta: &serde_json::Value, files: &BTreeMap<String, Vec<u8>>) -> Result<String /*id*/, WorkspaceError>;
  pub fn archive_load(root: &Path, id: &str) -> Result<ArchiveEntry, WorkspaceError>;
  pub fn archive_ids_for(root: &Path, address: Address) -> Result<Vec<String>, WorkspaceError>;   // meta.address equal
  pub fn archive_remove(root: &Path, id: &str) -> Result<(), WorkspaceError>;   // only for bench copies
  #[non_exhaustive] pub struct ArchiveEntry { pub id: String, pub meta: serde_json::Value, pub files: BTreeMap<String, Vec<u8>> }
  ```
- Port of `versuchsarchiv.py`: manifest `{"format", "meta", "files": {name: {"blake3", "size"}}}` as canonical JSON
  (sorted keys, no spaces, UTF-8); id = blake3 hex (64) of the manifest bytes; entry dir `cache/archive/<id>/`
  with `manifest.json` and `files/<relative posix path>`. Built in `cache/archive/.tmp-<random>/` and renamed onto
  the id dir (20 tries, sleep 50 ms × n on Windows sharing errors); an existing id is verified and kept (idempotent).
  Path rules as Decomp: relative POSIX, no `\`, no empty/`.`/`..` segments, no trailing `.` or space, no reserved DOS
  names (`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`), no control characters or `<>:"|?*`, no
  case-insensitive collisions. `archive_load` verifies id, manifest hash, file set, sizes and hashes.
- Files an attempt stores (Task 3): `function.c` (the definition), `module.c` (the whole compiled file text),
  `object.obj`, `comparison.txt`.

- [ ] **Step 1:** Tests: `same_content_same_id`, `load_verifies_hashes` (a flipped byte → error naming the file),
  `bad_paths_are_rejected` (each rule), `case_collision_is_rejected`, `ids_for_address`, `tmp_dirs_are_ignored`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS; gates.
- [ ] **Step 5:** Commit `feat(core): content-addressed attempt archive`.

