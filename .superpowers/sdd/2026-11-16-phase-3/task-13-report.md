# Task 13 report: exemplar index, `find similar`, exemplars and source in `show`

Status: DONE_WITH_CONCERNS (step 5 written but not run: local env vars unset; step 6 owner gate, not run).

## Built
- `crates/decovery-facade/src/exemplars.rs`: `EXEMPLARS_FILE` (`cache/exemplars/index.json`), `LSH_ALL` (2 000),
  `exemplar_index(session)` (load, refresh against rebuild records, save only when changed; full rebuild on changed
  `target_sha256`, wrong schema or a damaged/inconsistent file), `ExemplarIndex` (`similar`, `candidates`,
  `rank_forms`, `len`, `contains`, `from_sequences` for measurements), `Exemplar` with `reason()`.
  Members: `identical` (effective result) with `instructions_differing == 0`, file not `.asm`/`.s`, not
  library-classified (signature source or `library` set, same rule as `link`), with an analysed range.
  Index file `{schema, target_sha256, forms, entries:[{address,name,file,flags,forms,coarse,minhash}]}` plus
  preserved unknown keys. Only new members are decoded (program loaded only then).
- `find {what: "similar", target (= pattern, like xrefs), limit (default 3)}`: items with source, flags, scores,
  twin, reason ("similarity 0.91, coverage 0.88, twin; shared stretches 0-24↔3-27", instruction indices);
  sources beyond the budget become null and the full result a `find-results` handle; empty index -> hint
  "no solved functions to compare with".
- `show`: data gains `exemplars` (top 3, no source) and `source` `{file, text}`; summary adds
  "; exemplars: a (0.91), …" (score). Failure to compute exemplars is a `warnings` entry, not an error. Output
  files unchanged.
- `build` refreshes the index after recording (failure -> build warning).
- MCP `find` gains `similar`; CLI `find similar <target>` (`--limit` now optional; default 100 / 3).
- Design 5.12 item 2 amended (decision 3).
- `crates/decovery-cli/tests/exemplars_local.rs` (step 5, `#[ignore = "local: first target + Decomp"]`).

## Rulings applied
- P15: no `remove_exemplar`, no copy.rs change; `bench_copy_has_no_exemplar_entry_of_the_function` (in
  `decovery-bench/tests/copy_synthetic.rs`, since the facade cannot depend on the bench) asserts no
  `cache/exemplars/` in the copy and that the refreshed index there lacks the function.
- Row 13: `lookup_of_10000_members_is_fast` asserts the LSH candidate set (<= 100 of 10 000, contains the
  near-duplicate, top 1 correct); the wall-time check is `lookup_of_10000_members_is_fast_in_wall_time`,
  `#[ignore = "perf"]` (passes in release). The local parity test runs Decomp only on a temp copy of the
  workspace and migrates from that copy.
- P20: step 6 (probe re-run) is an owner gate, not run.

## Deviations / own decisions
- `similar` returns `Result<Vec<Exemplar>, FacadeError>` (plan: `Vec`): a missing range or unreadable target is
  an error, not a silent empty list.
- Bits from the rebuild profile, else by target format (LE/flat32 32, else 16). Forms use
  `DecodeOptions::default()` (Task 12), so zero-run padding is not tolerated as Decomp's `fuellung` would; may
  matter for R4.
- Extra tests: `removed_member_leaves_the_index`, `show_without_exemplars_has_no_summary_suffix`, unit
  `reason_names_twin_and_stretches`.
- The synthetic add/sub pair (6 instructions each) has coverage 0, so `find_similar_returns_source_and_reason`
  asserts no stretches there; stretch formatting is covered by the unit test.
- Entries whose analysed range changed under the same target are not re-decoded (only membership is compared).
- Tasks 8-11 not needed: refresh runs synchronously in `build`, no job.

## TDD evidence
- RED: `cargo test -p decovery-facade --test exemplars_synthetic` -> E0432 unresolved `EXEMPLARS_FILE`,
  `ExemplarIndex`, `exemplar_index`; E0599 no `FindWhat::Similar`.
- First run after implementation: 4 failures (fixture had no memory map -> `OutsideMap`; fixed in the test
  helper by adding a segment), then 1 (stretch expectation, see above).
- GREEN: exemplars_synthetic 11 passed / 1 ignored (perf; passes with `--release -- --ignored`); facade lib 34;
  bench copy test passes; workspace `cargo test --workspace` 678 passed, 0 failed, 18 ignored; fmt and clippy clean.

## Open
- Step 5 (R4 parity) not run: `DECOVERY_DECOMP_WORKSPACE`/`DECOVERY_LOCAL_WORKSPACE`, `DECOVERY_DECOMP_PYTHON`,
  `DECOVERY_GOLDEN_DIR` unset here. The test's Decomp invocation (`-m decomp --bereich <copy> nachbau vorbilder
  0x<linear> --anzahl 3`) and `nachbau.toml` parsing (`ergebnis = "bytegleich"`) are unverified against real data.
- Step 6 (probe re-run, `docs/parity/phase-3.md`): owner gate.
