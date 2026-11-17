use std::path::Path;

use decovery_core::{
    ATTEMPTS_DIR, Address, AttemptOrigin, AttemptRecord, RebuildResult, VerdictId, address_key,
    append_attempts, attempt_budget, attempt_distance, now_utc, read_attempts,
};

fn record(
    address: Address,
    hash: &str,
    result: RebuildResult,
    differing: Option<u32>,
) -> AttemptRecord {
    let mut r = AttemptRecord::new(address, "f", AttemptOrigin::Build, result);
    r.body_hash = hash.to_string();
    r.actor = Some("cli".to_string());
    r.instructions_differing = differing;
    r
}

fn flat(a: u32) -> Address {
    Address::Flat(a)
}

#[test]
fn append_then_read_round_trips_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut r = record(flat(0x12340), "blake3:aa", RebuildResult::Differs, Some(3));
    r.extra
        .insert("future".into(), serde_json::json!({"k": [1, 2]}));
    r.label = Some("first".into());
    r.blockers = vec!["inline-assembly".into()];
    append_attempts(dir.path(), std::slice::from_ref(&r)).unwrap();
    let (back, warnings) = read_attempts(dir.path(), flat(0x12340)).unwrap();
    assert!(warnings.is_empty());
    assert_eq!(back, vec![r]);
    assert!(
        dir.path()
            .join(ATTEMPTS_DIR)
            .join("flat_00012340.jsonl")
            .is_file()
    );
    // A missing shard is empty.
    assert!(read_attempts(dir.path(), flat(1)).unwrap().0.is_empty());
}

#[test]
fn shards_are_per_function() {
    let dir = tempfile::tempdir().unwrap();
    let a = record(flat(1), "blake3:a", RebuildResult::Differs, Some(1));
    let b = record(
        Address::Seg { seg: 0, off: 0x1FA },
        "blake3:b",
        RebuildResult::Differs,
        Some(1),
    );
    append_attempts(dir.path(), &[a.clone(), b.clone()]).unwrap();
    assert_eq!(read_attempts(dir.path(), flat(1)).unwrap().0, vec![a]);
    assert_eq!(read_attempts(dir.path(), b.address).unwrap().0, vec![b]);
    assert!(
        dir.path()
            .join(ATTEMPTS_DIR)
            .join("seg_0000_01FA.jsonl")
            .is_file()
    );
}

// The exhaustive per-variant check lives in `address.rs` (an in-crate `match` without a wildcard).
#[test]
fn address_key_covers_every_address_kind() {
    assert_eq!(address_key(flat(0x12340)), "flat_00012340");
    assert_eq!(
        address_key(Address::Seg { seg: 0, off: 0x1FA }),
        "seg_0000_01FA"
    );
    assert_eq!(
        address_key(Address::Sel {
            segment: 7,
            off: 0x1234
        }),
        "sel_0007_00001234"
    );
}

#[test]
fn concurrent_appends_keep_every_line() {
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    std::thread::scope(|scope| {
        for t in 0..8u32 {
            scope.spawn(move || {
                for i in 0..50u32 {
                    let hash = format!("blake3:{t}-{i}");
                    let a = record(flat(1), &hash, RebuildResult::Differs, Some(1));
                    if t % 2 == 0 {
                        append_attempts(root, &[a]).unwrap();
                    } else {
                        let b = record(flat(2), &hash, RebuildResult::Differs, Some(1));
                        append_attempts(root, &[a, b]).unwrap();
                    }
                }
            });
        }
    });
    let (one, w1) = read_attempts(root, flat(1)).unwrap();
    let (two, w2) = read_attempts(root, flat(2)).unwrap();
    assert!(w1.is_empty() && w2.is_empty());
    assert_eq!(one.len(), 8 * 50);
    assert_eq!(two.len(), 4 * 50);
}

#[test]
fn torn_last_line_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let r = record(flat(5), "blake3:a", RebuildResult::Differs, Some(2));
    append_attempts(dir.path(), std::slice::from_ref(&r)).unwrap();
    let path = dir.path().join(ATTEMPTS_DIR).join("flat_00000005.jsonl");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("{\"schema\":1,\"time\":\"2026-");
    std::fs::write(&path, text).unwrap();
    let (records, warnings) = read_attempts(dir.path(), flat(5)).unwrap();
    assert_eq!(records, vec![r.clone()]);
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].contains("flat_00000005.jsonl:2"),
        "{}",
        warnings[0]
    );
    // The next append starts on its own line.
    let r2 = record(flat(5), "blake3:b", RebuildResult::Differs, Some(1));
    append_attempts(dir.path(), std::slice::from_ref(&r2)).unwrap();
    let (records, warnings) = read_attempts(dir.path(), flat(5)).unwrap();
    assert_eq!(records, vec![r, r2]);
    assert_eq!(warnings.len(), 1);
}

#[test]
fn distance_of_error_is_none() {
    let a = flat(1);
    let error = record(a, "h", RebuildResult::Error, None);
    assert_eq!(attempt_distance(&error), None);
    let identical = record(a, "h", RebuildResult::Identical, None);
    assert_eq!(attempt_distance(&identical), Some(0));
    let differs = record(a, "h", RebuildResult::Differs, Some(4));
    assert_eq!(attempt_distance(&differs), Some(4));
    let mut unchecked = differs.clone();
    unchecked.verdict = Some(VerdictId::Unchecked);
    assert_eq!(attempt_distance(&unchecked), None);
    let mut verdict_identical = differs;
    verdict_identical.verdict = Some(VerdictId::Identical);
    assert_eq!(attempt_distance(&verdict_identical), Some(0));
}

#[test]
fn budget_counts_each_body_once() {
    let a = flat(1);
    let records = vec![
        record(a, "blake3:x", RebuildResult::Differs, Some(5)),
        record(a, "blake3:x", RebuildResult::Differs, Some(5)),
        record(a, "blake3:y", RebuildResult::Error, None),
        record(a, "blake3:z", RebuildResult::Differs, Some(6)),
    ];
    let b = attempt_budget(&records, 30);
    assert_eq!((b.own, b.since_progress, b.best), (2, 1, Some(5)));
}

#[test]
fn budget_parks_after_limit_without_progress() {
    let a = flat(1);
    let mut records = vec![record(a, "blake3:0", RebuildResult::Differs, Some(4))];
    for i in 1..31 {
        let hash = format!("blake3:{i}");
        records.push(record(a, &hash, RebuildResult::Differs, Some(9)));
    }
    let b = attempt_budget(&records, 30);
    assert_eq!((b.own, b.since_progress, b.best), (31, 30, Some(4)));
    assert!(b.parked());
    records.push(record(a, "blake3:win", RebuildResult::Identical, None));
    let b = attempt_budget(&records, 30);
    assert_eq!((b.since_progress, b.best), (0, Some(0)));
    assert!(!b.parked());
}

#[test]
fn migrated_automatic_variants_do_not_count() {
    let a = flat(1);
    let mut records = Vec::new();
    for i in 0..40 {
        let hash = format!("decomp-sha256:{i}");
        let mut r = record(a, &hash, RebuildResult::Differs, Some(9));
        r.origin = AttemptOrigin::Variant;
        r.actor = Some("migrate".into());
        records.push(r);
    }
    // Searches and the bench harness's own builds do not count either; a caller's variant does.
    let mut search = record(a, "blake3:s", RebuildResult::Differs, Some(9));
    search.origin = AttemptOrigin::Search;
    let mut harness = record(a, "blake3:h", RebuildResult::Differs, Some(9));
    harness.actor = Some("bench-harness".into());
    let mut agent_variant = record(a, "blake3:v", RebuildResult::Differs, Some(9));
    agent_variant.origin = AttemptOrigin::Variant;
    agent_variant.actor = Some("mcp".into());
    records.extend([search, harness, agent_variant]);
    let b = attempt_budget(&records, 30);
    assert_eq!((b.own, b.best, b.parked()), (1, Some(9), false));
}

#[test]
fn now_utc_has_rfc3339_shape() {
    let t = now_utc();
    let b = t.as_bytes();
    assert_eq!(b.len(), 20, "{t}");
    for (i, c) in b.iter().enumerate() {
        match i {
            4 | 7 => assert_eq!(*c, b'-'),
            10 => assert_eq!(*c, b'T'),
            13 | 16 => assert_eq!(*c, b':'),
            19 => assert_eq!(*c, b'Z'),
            _ => assert!(c.is_ascii_digit(), "{t}"),
        }
    }
}

#[test]
fn bench_agent_whole_file_variants_count_toward_budget() {
    let mut r = record(flat(1), "blake3:a", RebuildResult::Differs, Some(2));
    r.origin = AttemptOrigin::Variant;
    r.actor = Some("bench:run-1".into());
    assert_eq!(attempt_budget(&[r], 30).own, 1);
}

#[test]
fn zero_differing_instructions_with_blockers_is_not_identical() {
    let mut r = record(flat(1), "blake3:a", RebuildResult::Differs, Some(0));
    r.verdict = Some(VerdictId::Differs);
    r.blockers.push("unchecked-ref".into());
    assert_ne!(
        attempt_distance(&r),
        Some(0),
        "zero is reserved for identical"
    );
}

#[test]
fn identical_search_unparks_without_spending_own_budget() {
    let mut records = vec![
        record(flat(1), "blake3:a", RebuildResult::Differs, Some(4)),
        record(flat(1), "blake3:b", RebuildResult::Differs, Some(4)),
    ];
    assert!(attempt_budget(&records, 1).parked());
    let mut solved = record(flat(1), "blake3:c", RebuildResult::Identical, Some(0));
    solved.verdict = Some(VerdictId::Identical);
    solved.origin = AttemptOrigin::Search;
    records.push(solved);
    let budget = attempt_budget(&records, 1);
    assert_eq!(budget.own, 2);
    assert!(!budget.parked());
}
