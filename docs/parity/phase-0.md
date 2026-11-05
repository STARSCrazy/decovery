# Phase-0 parity against Decomp

Checked on 2026-11-05 by `crates/decovery-cli/tests/parity_local.rs` (`#[ignore]`, needs the private workspace).

- **Baseline:** Decomp commit `7ca886ed6b4c39f2ac6a4487692c6998f47d5dcf`, private workspace of the first target
  (Watcom C/C++32 9.5, LE), migrated with `decovery migrate` (no unmapped keys).
- **Sample:** the first 20 functions Decomp records as identical and the first 5 it records as differing,
  each compared through `decovery compare --json` against the rebuilt object from `cache/rebuild/obj/`.
  The original function length comes from Decomp's analysis output, as Decomp used it.

## Result

| | count |
|---|---|
| functions compared | 25 |
| metrics equal to Decomp (`bytes`, `equal`, `gaps`, `differing`, `refs_ok`, `refs_wrong`, `instructions_differing`) | 25 |
| verdicts agree (identical vs. not identical) | 25 |

## Verdict differences

None in this sample. All 5 functions Decomp records as differing also differ in bytes and instructions in
decovery. 4 of them carry additional reference blockers in decovery (`wrong_absolute_ref`, `wrong_relative_ref`,
`unchecked_ref`; decovery checks every relocation's target, design 5.11 item 1). Because the bytes already
differ, these blockers do not change the verdict here.

## Deviation list

Empty: no case where decovery is right and Decomp's record is wrong.

The detailed list with function names and addresses is kept privately (`$DECOVERY_GOLDEN_DIR/parity-phase-0.md`).
