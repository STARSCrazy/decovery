# Task 12 + 13 review

Range: Task 12 = 9b204a1..b63f920, Task 13 = b63f920..03925ee. Checked against the plan (Global Constraints,
Review Focus, Tasks 12/13), preflight rows 12, 13, P15, P20, P23, the reports, and Decomp
`src/decomp/nachbau/vorbilder.py` with its caller `dienst.py::_vorbilder` and `nachbau/ergebnis.py` (read-only).

## Parity with Decomp (Task 12)

Checked and matching: `form` (number regex incl. absorbed `-`, register groups; iced `…h` hex added per ruling),
`_abdeckung`, `_strecken` (greedy, longest continuation, top 3 sorted by position, ruling c), Indel similarity
(`2·LCS/(|a|+|b|)` = rapidfuzz `normalized_similarity`), preselection `(coverage, −len diff)` stable descending,
`max(PRESELECT, top)`, both measures rounded to 3 decimals before the score (ruling a), stable final sort (ruling b),
twin = coarse sequences equal, empty target → empty. Padding: Decomp's `_vorbilder` calls `zerlege` without
`fuellung` (default `False`), so `DecodeOptions::default()` (no byte padding) is the parity setting; the Task 13
report's concern about `fuellung` does not apply. No-op padding behind unconditional instructions is dropped by
`is_padding()` in both.

## Findings

### Critical
None.

### Important (fixed)
1. **Index stale on a changed analysed range** (`exemplars.rs`): entries were only compared by membership, so a
   re-analysis that moved a member's end kept forms decoded from the old range (the report admitted it). Fix: each
   entry records `end` (the range's last address); an entry whose range differs, or an older entry without `end`,
   is decoded again. Test `changed_range_redecodes_entry` (red: 6 forms kept, green: 2).
2. **`show` put the source text outside the budget** (`show.rs`): `data.source.text` was added in full whatever the
   budget. Fix: the definition shares the budget with the shown pseudo-C; beyond it, `text` is null and the
   definition is a `source-text` handle (`source.handle`). Test `show_budget_covers_source_text`.
3. **R4 parity test could never pass** (`exemplars_local.rs`): it read Decomp's identical set as
   `ergebnis = "bytegleich"`; Decomp writes `identisch` (`ergebnis.py`), so the set was empty, every function was
   "open" and decovery's candidates were filtered to nothing. It also ignored Decomp's other candidate rules. Fix:
   `identisch`, `befehle_abweichend` missing or 0, file not `.asm`/`.s` (as `_vorbilder`). Non-ignored test
   `decomp_identical_follows_decomp_member_rule`.

### Minor (listed only)
1. `round3` rounds half away from zero on `x*1000`; Python's `round` is round-half-even on the exact binary value.
   Can flip a third decimal on exact halves (rare tie differences in R4).
2. Candidate tie order: decovery's members are sorted by address; Decomp's follow `nachbau.toml` order. Ties in
   the preselection may order differently.
3. Decomp does not exclude library-classified functions; decovery does (plan demands it). A known R4 reason.
4. Bits change (rebuild profile) does not rebuild the index; only target sha, schema, damage and range do.
5. `find similar` uses `pattern` for the target (plan text: `target`), like `xrefs`; documented in the tool text.
6. The tiny-budget part of `find_similar_returns_source_and_reason` asserts the handle but not that
   `items[0].source` is null.
7. `exemplar_index` is written by `show`/`find` without the workspace lock (atomic write, cache data only).
8. A member whose bytes cannot be read is retried (program loaded) on every refresh.
9. The local test's Decomp address argument (`0x<linear>`) and output parsing are still unverified against real
   data (env not set here).

## Changed assertion in `find_similar_returns_source_and_reason`
Legitimate. add and sub are six instructions each and differ in one (`add` vs `sub`), so with `n = 6` they share
no window: coverage 0 and no stretch, exactly what Decomp's `_abdeckung`/`_strecken` give. Asserting a stretch
there would assert wrong behaviour. Stretch formatting stays covered by the unit test
`reason_names_twin_and_stretches`; an end-to-end stretch in `find` is not covered (no fixture with ≥ 6 shared
instructions), noted, not a defect.

## Other checks
- Solution leakage into bench copies: `cache/` is not copied (P15); the copy's rebuild record of the function is
  gone, so its refreshed index lacks it; `current_source` finds no definition in the copy. OK.
- Panics on input: no `unwrap`/indexing on input in library code (`members[&addr]` only after `retain` on
  `contains_key`; `positions[r.candidate]` from `rank`'s own indices). Damaged index (bad JSON, schema, ids out of
  table, sketch length) → full rebuild. OK.
- Deps: `blake3` in decovery-diff is ADR 0003. English only, no proprietary material. OK.
- Perf test per ruling row 13 (candidate set asserted; wall time `#[ignore = "perf"]`). OK.
- Step 6 (probe re-run) correctly left as owner gate (P20).
