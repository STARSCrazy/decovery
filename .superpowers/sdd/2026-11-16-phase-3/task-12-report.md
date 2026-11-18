# Task 12 report: similarity algorithms (diff)

Status: DONE. Commit `feat(diff): similarity algorithms (task 12)`.

## Built
- `crates/decovery-diff/src/similar.rs`: `instruction_forms`, `coarse_forms`, `WINDOW/HASHES/BANDS/PRESELECT`,
  `minhash`, `lsh_keys`, `coverage`, `indel_similarity`, `shared_stretches`, `Stretch`, `Ranked`, `rank`
  (port of Decomp `nachbau/vorbilder.py`), re-exported from `lib.rs`.
- `crates/decovery-diff/Cargo.toml`: `blake3` (workspace dependency, ADR 0003).
- `crates/decovery-diff/tests/similar_synthetic.rs`: 11 tests on hand-built bytes/sequences.

## Rulings applied (preflight row 12, binding)
- (a) coverage rounded to 3 decimals before the score (like similarity).
- (b) final sort is stable on score; ties keep the preselection order (coverage desc, length difference asc,
  index asc). Test `rank_orders_by_score_then_index` became `rank_orders_by_score_then_preselection` plus
  `rank_tie_keeps_preselection_order`.
- (c) the three longest stretches are returned sorted by position. Test `stretches_longest_first` became
  `stretches_top_three_longest_sorted_by_position`.
- Text comes from `decovery_x86::decode_detailed` (`Decoded.text`, Intel; `Decoded.shape` for coarse forms),
  padding via `is_padding()`. Number recognition covers `0x…`, decimal and iced's `…h` hex (`0Ch`, `0FFFFh`),
  with a leading `-` absorbed as in Decomp's regex. Hand-written word tokenizer (no regex crate).

## Decisions of my own
- `Stretch` positions are inclusive instruction indices into the padding-free sequences (Decomp: byte offsets);
  Task 13 maps them if it wants offsets.
- splitmix64 hash = `mix(x + gamma)`; seeds = standard splitmix64 generator from `0x6465636f76657279`.
- LSH band key = first 8 bytes of blake3 over band index (u32 LE) and its 4 rows (u64 LE), so equal rows in
  different bands give different keys.
- Empty target: `coverage` 0, `shared_stretches` empty, `rank` empty (Decomp returns []).
- Decoding uses `DecodeOptions::default()` (no byte padding, no gaps); Task 13 may want the analysed function's
  options for parity with Decomp's `fuellung`.

## Not done
- Tasks 8-11 not needed by Task 12. Task 13 (index, `find similar`) and the local parity check (R4) are Task 13.
