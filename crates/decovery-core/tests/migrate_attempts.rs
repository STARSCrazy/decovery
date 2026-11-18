//! Synthetic migration inputs only; no private workspace data.
use std::collections::BTreeMap;
use std::path::Path;

use decovery_core::migrate::migrate_attempts;
use decovery_core::{
    Address, AttemptOrigin, RebuildResult, archive_load, attempt_budget, read_attempts,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn line(address: &str, transform: &str, label: &str) -> Value {
    json!({
        "adresse": address, "name": "choose", "rumpf_hash": format!("sha256-text-v2-{}", "a".repeat(64)),
        "kontext_hash": "b".repeat(16), "original_hash": "c".repeat(16), "profil": "synthetic",
        "optionen": "-O", "ergebnis": "abweichend", "befehle_abweichend": 3,
        "bytes_abweichend": 2, "diagnose": ["operanden-tausch"], "beschriftung": label,
        "zeit": "2026-11-17T12:00:00", "umformung": transform, "future": {"kept": true}
    })
}

fn lines(root: &Path, records: &[Value]) {
    let path = root.join("cache/nachbau/versuche.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        records.iter().map(|r| format!("{r}\n")).collect::<String>(),
    )
    .unwrap();
}

fn archive(root: &Path, meta: Value, files: &[(&str, &[u8])]) -> String {
    let descriptors: BTreeMap<_, _> = files
        .iter()
        .map(|(name, bytes)| {
            (
                *name,
                json!({
                    "sha256": sha256(bytes), "groesse": bytes.len()
                }),
            )
        })
        .collect();
    let bytes = serde_json::to_vec(
        &json!({"format": "decomp-versuchsarchiv/1", "meta": meta, "dateien": descriptors}),
    )
    .unwrap();
    let id = sha256(&bytes);
    let dir = root.join("cache/nachbau/archiv").join(&id);
    std::fs::create_dir_all(dir.join("dateien")).unwrap();
    for (name, contents) in files {
        let path = dir.join("dateien").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    std::fs::write(dir.join("manifest.json"), bytes).unwrap();
    id
}

#[test]
fn versuche_lines_become_shards() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    let mut identical = line("va:00001010", "hand", "manual");
    identical["ergebnis"] = json!("identisch");
    identical["befehle_abweichend"] = json!(0);
    lines(
        from.path(),
        &[identical, line("rel:0001:0020", "", "build")],
    );
    let report = migrate_attempts(from.path(), to.path()).unwrap();
    assert_eq!(report.attempts, 2);
    assert!(report.skipped.is_empty(), "{report:?}");
    let (flat, _) = read_attempts(to.path(), Address::Flat(0x1010)).unwrap();
    assert_eq!(flat.len(), 1);
    let r = &flat[0];
    assert_eq!(r.schema, 1);
    assert_eq!(r.result, RebuildResult::Identical);
    assert_eq!(
        r.verdict, None,
        "Decomp's finding is evidence, never a decovery verdict"
    );
    assert_ne!(
        decovery_core::attempt_distance(r),
        Some(0),
        "history must not claim a native match"
    );
    assert_eq!(r.extra["decomp_result"], "identisch");
    assert_eq!(r.extra["decomp"]["future"]["kept"], true);
    assert_eq!(
        r.body_hash,
        format!("decomp-sha256-text-v2:{}", "a".repeat(64))
    );
    assert_eq!(r.diagnosis, ["operand-swap"]);
    assert_eq!(r.actor.as_deref(), Some("migrate"));
    assert_eq!(r.extra["decomp_time"], "2026-11-17T12:00:00");
    assert!(r.time.ends_with('Z'));
    assert_eq!(r.extra["decomp_line"].as_str().unwrap().len(), 64);
    let (seg, _) = read_attempts(to.path(), Address::Seg { seg: 1, off: 0x20 }).unwrap();
    assert_eq!(seg.len(), 1);
}

#[test]
fn umformung_maps_origin() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    let cases = [
        ("hand", "manual", AttemptOrigin::Function),
        ("", "build", AttemptOrigin::Build),
        ("bauen", "build", AttemptOrigin::Variant),
        ("permuter", "automatic", AttemptOrigin::Variant),
        ("", "aktuell", AttemptOrigin::Variant),
        ("", "Reihenfolge a", AttemptOrigin::Variant),
        ("", "x (Zeile 4)", AttemptOrigin::Variant),
        ("", "a statt b", AttemptOrigin::Variant),
    ];
    let records: Vec<_> = cases
        .iter()
        .enumerate()
        .map(|(i, (transform, label, _))| line(&format!("va:{:08X}", i + 1), transform, label))
        .collect();
    lines(from.path(), &records);
    migrate_attempts(from.path(), to.path()).unwrap();
    for (i, (_, _, origin)) in cases.iter().enumerate() {
        let (records, _) = read_attempts(to.path(), Address::Flat((i + 1) as u32)).unwrap();
        assert_eq!(records[0].origin, *origin);
    }
}

#[test]
fn migrated_automatic_variants_do_not_count() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    lines(
        from.path(),
        &[
            line("va:00001010", "permuter", "auto"),
            line("va:00001010", "", "aktuell"),
        ],
    );
    migrate_attempts(from.path(), to.path()).unwrap();
    let (records, _) = read_attempts(to.path(), Address::Flat(0x1010)).unwrap();
    assert_eq!(attempt_budget(&records, 1).own, 0);
    assert!(!attempt_budget(&records, 1).parked());
}

#[test]
fn archive_entry_converts_and_relinks_predecessor() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    let predecessor = archive(
        from.path(),
        json!({"adresse": "va:00001010", "funktion": "choose", "datei": "choose.c"}),
        &[("funktion.c", b"int choose(void) { return 1; }\n")],
    );
    let child = archive(
        from.path(),
        json!({"adresse": "va:00001010", "funktion": "choose", "datei": "choose.c", "vorgaenger": predecessor, "future": 7}),
        &[
            ("funktion.c", b"int choose(void) { return 2; }\n"),
            ("modul.c", b"/* neutral module */\n"),
            ("obj/a-1.obj", b"object one"),
            ("obj/a-2.obj", b"object two"),
            ("eingabe/types.h", b"typedef int item;\n"),
            ("meldungen/1.txt", b"ok\n"),
            ("vergleich.txt", b"differs\n"),
        ],
    );
    let mut record = line("va:00001010", "hand", "manual");
    record["archiv_id"] = json!(child);
    lines(from.path(), &[record]);
    let report = migrate_attempts(from.path(), to.path()).unwrap();
    assert_eq!(report.archive_entries, 2, "{report:?}");
    assert!(report.skipped.is_empty(), "{report:?}");
    let (records, _) = read_attempts(to.path(), Address::Flat(0x1010)).unwrap();
    let entry = archive_load(to.path(), records[0].archive.as_deref().unwrap()).unwrap();
    assert_eq!(entry.meta["address"], "flat:00001010");
    assert_eq!(entry.meta["file"], "choose.c");
    assert_eq!(entry.meta["decomp"]["future"], 7);
    assert_eq!(entry.files["objects/a-1.obj"], b"object one");
    assert_eq!(entry.files["objects/a-2.obj"], b"object two");
    assert!(!entry.files.contains_key("object.obj"));
    assert_eq!(entry.files["input/types.h"], b"typedef int item;\n");
    let previous = archive_load(to.path(), entry.meta["predecessor"].as_str().unwrap()).unwrap();
    assert_ne!(previous.id, predecessor);
    assert_eq!(
        previous.files["function.c"],
        b"int choose(void) { return 1; }\n"
    );
    assert_eq!(
        migrate_attempts(from.path(), to.path())
            .unwrap()
            .archive_entries,
        0
    );
}

#[test]
fn broken_archive_entry_is_reported() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    let id = archive(
        from.path(),
        json!({"adresse": "va:00001010"}),
        &[("funktion.c", b"source")],
    );
    std::fs::write(
        from.path()
            .join("cache/nachbau/archiv")
            .join(&id)
            .join("dateien/funktion.c"),
        b"broken",
    )
    .unwrap();
    let mut record = line("va:00001010", "hand", "manual");
    record["archiv_id"] = json!(id);
    lines(from.path(), &[record]);
    let report = migrate_attempts(from.path(), to.path()).unwrap();
    assert_eq!(report.attempts, 1);
    assert_eq!(report.archive_entries, 0);
    assert_eq!(report.skipped_archives, 1);
    assert!(
        report.skipped.iter().any(|r| r.contains("funktion.c")),
        "{report:?}"
    );
    assert!(
        read_attempts(to.path(), Address::Flat(0x1010)).unwrap().0[0]
            .archive
            .is_none()
    );
}

#[test]
fn malformed_line_is_counted() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    lines(
        from.path(),
        &[json!({}), line("va:00001010", "hand", "valid")],
    );
    let path = from.path().join("cache/nachbau/versuche.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{text}{{torn")).unwrap();
    let report = migrate_attempts(from.path(), to.path()).unwrap();
    assert_eq!(report.attempts, 1);
    assert_eq!(report.skipped.len(), 2);
    assert_eq!(report.skipped_lines, 2);
    assert!(report.skipped[0].contains("versuche.jsonl:1"));
    assert!(report.skipped[1].contains("versuche.jsonl:3"));
}

#[test]
fn second_import_adds_only_new_lines() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    let first = line("va:00001010", "hand", "first");
    lines(from.path(), std::slice::from_ref(&first));
    assert_eq!(
        migrate_attempts(from.path(), to.path()).unwrap().attempts,
        1
    );
    let second = migrate_attempts(from.path(), to.path()).unwrap();
    assert_eq!((second.attempts, second.already_present), (0, 1));
    lines(from.path(), &[first, line("va:00001010", "hand", "second")]);
    let third = migrate_attempts(from.path(), to.path()).unwrap();
    assert_eq!((third.attempts, third.already_present), (1, 1));
    assert_eq!(
        read_attempts(to.path(), Address::Flat(0x1010))
            .unwrap()
            .0
            .len(),
        2
    );
}

#[test]
fn overlay_addresses_are_skipped_with_reason() {
    let from = tempfile::tempdir().unwrap();
    let to = tempfile::tempdir().unwrap();
    lines(from.path(), &[line("ovl:0001:0020", "hand", "unsupported")]);
    let report = migrate_attempts(from.path(), to.path()).unwrap();
    assert_eq!(report.attempts, 0);
    assert_eq!(report.skipped_lines, 1);
    assert!(report.skipped[0].contains("ovl:"));
}

#[test]
fn migration_refuses_to_write_inside_the_source() {
    let from = tempfile::tempdir().unwrap();
    std::fs::write(from.path().join("decomp.toml"), "[ziel]\ndatei = \"spiel/PROGRAM.EXE\"\nsha256 = \"ab12\"\nformat = \"le\"\nprozessor = \"x86:LE:32:default\"\n").unwrap();
    let to = from.path().join("destination");
    assert!(decovery_core::migrate_decomp(from.path(), &to).is_err());
    assert!(
        !to.exists(),
        "refusal must happen before writing any source-workspace files"
    );
}

#[test]
fn shadow_attempts_are_not_imported() {
    let to = tempfile::tempdir().unwrap();
    let shadow = to.path().join("cache/legacy/decomp");
    lines(&shadow, &[line("va:00001010", "hand", "internal")]);
    assert!(migrate_attempts(&shadow, to.path()).is_err());
    assert!(!to.path().join("cache/attempts").exists());
}
