# Phase-1 parity against Decomp

Checked on 2026-11-05 by `crates/decovery-cli/tests/show_parity_local.rs` (`#[ignore]`, needs a private
workspace).

- **Baseline:** Decomp commit `7ca886ed6b4c39f2ac6a4487692c6998f47d5dcf`. Each private workspace is migrated
  with `decovery migrate` into a temporary directory.
- **`show_equals_zeige_for_all_functions`:** for every file below Decomp's `ausgabe/funktionen/`, the test runs
  the real binary, `decovery show <start address> --workspace <migrated>` (one process per function, eight in
  parallel), and compares its output byte for byte, body included, with Decomp's file. Before comparing,
  Decomp's file is normalized from CRLF to LF and its header is translated with a fixed German-to-English
  mapping (header keys, value phrases, `va:`/`rel:` → `flat:`/`seg:` in the address-bearing keys only, and
  claim, diagnosis and equivalence ids taken from `migrate`'s own tables). The mapping lives in
  `crates/decovery-facade/tests/support/decomp_mapping.rs` and is shared with the facade's `output_local`
  test. An unknown header key fails the test.
- **`knowledge_round_trips`:** on a migrated copy, `decovery annotate --source human` sets a name, a comment and
  a signature on three functions and refutes the name of a fourth. After re-opening, the four records hold
  exactly the requested state, all other records are unchanged, a second `save_symbols` writes identical
  bytes, and `show` prints the new name.

## Result

| Workspace | Format | Functions | `show` equal | Round trip |
|---|---|---|---|---|
| first target (acceptance) | LE, flat | 675 | 675 | pass |
| second target | LE, flat | 2119 | 2119 | pass |
| third target | MZ, real mode | 140 | 140 | pass |
| fourth target | MZ, real mode | 857 | 831 | pass |

The acceptance target passes both tests. The 26 differences in the fourth target are listed below.

## Excluded header keys

`@laufzeit` (execution coverage) and `@beobachtet` (observed calls) are dropped from Decomp's header before the
comparison. Both report runtime results; decovery's runtime schemas arrive in phase 6, so phase 1 does not
generate these lines.

## Deviation list

One class, 26 functions, all in the fourth target: the `@address` line. Decomp's file states the size as
`(N Bytes, …)` while decovery prints `(M bytes span, N in body, …)` because the function's own end address
gives a span longer than its body. Decomp's current code prints the same span clause; these files were written
by an older Decomp version before that clause existed and were not regenerated. This is stale oracle data, not
a decovery error.

No other differences; no fix to decovery was needed.

## Analysis with Ghidra

`analyze_local::ghidra_bodies_match_decomp` on the first target, with Ghidra 12.1.4 installed by
`decovery setup ghidra`: `analyze` analysed and decompiled all 675 functions, none failed (99 s). Function
ranges and caller/callee sets equal Decomp's analysis; the first 50 pseudo-C bodies and body sizes are
identical. Real-mode (16-bit) targets have not been run through Ghidra yet.

The detailed list with function names and addresses is kept privately (`$DECOVERY_GOLDEN_DIR/parity-phase-1.md`).
