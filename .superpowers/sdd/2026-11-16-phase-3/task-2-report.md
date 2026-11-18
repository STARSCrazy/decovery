# Task 2 report: attempt archive

Implemented `crates/decovery-core/src/archive.rs` (+ exports in lib.rs), tests in `crates/decovery-core/tests/archive.rs` (8 tests).
- API as briefed. Manifest `{"format":"decovery-attempt-archive/1","meta","files":{name:{blake3,size}}}`, canonical JSON, id = blake3 of manifest bytes; build in `cache/archive/.tmp-*`, rename (20 tries, 50 ms * n); existing id is verified and kept.
- P5/C8: id and meta are content only; same content -> same id, no write.
- P6: file names are free relative paths; several `objects/<name>` and `messages/<n>.txt` are fine (test `several_objects_and_messages_round_trip`). Task 4 can map `obj/*.obj` -> `objects/<name>`, `meldungen/<n>.txt` -> `messages/<n>.txt`.
- P7: `meta.file` is not enforced by the archive (meta is opaque); Task 3/4 must always set it.
- B/T2: `format = "decovery-attempt-archive/1"` is the version marker instead of `schema = 1`; Global Constraints should note this.
- Path rules per brief (also reserved names checked on the stem before the first dot, e.g. `CON.txt`; plus file-vs-directory clash). Errors reuse `WorkspaceError::Io` (InvalidData) / `Json`; no new variant.
- `archive_ids_for` reads manifests only (no content verification), skips non-id dirs (`.tmp-*`); `archive_remove` is idempotent.
- `archive_load` rejects files on disk not in the manifest.

Tests: cargo fmt --check, clippy -D warnings, cargo test --workspace all green (DECOVERY_PYTHON unset). No Python touched. TDD: tests and implementation were written together; the RED run was not captured separately.
