# Task 1 report
Implemented attempts.rs (AttemptRecord/Origin, append_attempts under cache/attempts/.lock with 10 s wait, one write_all per shard, torn-line repair, read_attempts with warnings, distance_of/attempt_distance, AttemptBudget), address_key, now_utc, RebuildConfig::attempt_budget (+decovery schema), schemas/attempt.schema.json.
Preflight rulings applied: body_hash is `<algo>:<hex>` (P2a); budget counts build/function, variant only for actor cli/mcp, never search/bench/migrate or actor bench-harness (P2b, P4); test migrated_automatic_variants_do_not_count; one distance function: legacy.rs better() now uses core distance_of (section C item 6).
Tests: 10/10 in tests/attempts.rs; fmt, clippy -D warnings, cargo test --workspace all green. No Python touched.
Concerns: facade's better() semantics kept (verdict-based); AttemptRecord::new helper added beyond the brief (non_exhaustive construction from tests/other crates).
