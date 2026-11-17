//! CLI integration on synthetic inputs; private parity is opt-in and reads only environment paths.
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;

fn run(arguments: &[&std::ffi::OsStr]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("--json")
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn source(root: &Path) {
    std::fs::write(root.join("decomp.toml"), "[ziel]\ndatei = \"spiel/PROGRAM.EXE\"\nsha256 = \"ab12\"\nformat = \"le\"\nprozessor = \"x86:LE:32:default\"\n").unwrap();
    let path = root.join("cache/nachbau/versuche.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let record = json!({"adresse": "va:00001010", "name": "choose", "rumpf_hash": "a".repeat(64),
        "kontext_hash": "b".repeat(16), "profil": "synthetic", "optionen": "-O", "original_hash": "c".repeat(16),
        "ergebnis": "abweichend", "befehle_abweichend": 3, "zeit": "2026-11-17T12:00:00", "umformung": "hand"});
    std::fs::write(path, format!("{record}\n")).unwrap();
}

#[test]
fn normal_migration_imports_attempts_and_dedicated_command_can_rerun() {
    let from = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let to = parent.path().join("workspace");
    source(from.path());
    let report = run(&["migrate".as_ref(), from.path().as_os_str(), to.as_os_str()]);
    assert_eq!(report["attempt_memory"]["attempts"], 1, "{report}");
    let again = run(&[
        "--workspace".as_ref(),
        to.as_os_str(),
        "migrate-attempts".as_ref(),
    ]);
    assert_eq!(again["attempts"], 0, "{again}");
    assert_eq!(again["already_present"], 1);
    let explicit = run(&[
        "--workspace".as_ref(),
        to.as_os_str(),
        "migrate-attempts".as_ref(),
        "--from".as_ref(),
        from.path().as_os_str(),
    ]);
    assert_eq!(explicit["already_present"], 1);
    assert_eq!(
        std::fs::read_to_string(to.join("cache/attempts/flat_00001010.jsonl"))
            .unwrap()
            .lines()
            .count(),
        1
    );
}

#[test]
#[ignore = "local: first target"]
fn private_attempt_migration_is_repeatable() {
    let from = std::env::var_os("DECOVERY_LOCAL_WORKSPACE")
        .expect("DECOVERY_LOCAL_WORKSPACE must name a private Decomp workspace");
    let destination = tempfile::tempdir().unwrap();
    let to = destination.path().join("workspace");
    let started = std::time::Instant::now();
    let first = run(&["migrate".as_ref(), &from, to.as_os_str()]);
    let again = run(&[
        "--workspace".as_ref(),
        to.as_os_str(),
        "migrate-attempts".as_ref(),
    ]);
    assert_eq!(again["attempts"], 0);
    assert_eq!(again["archive_entries"], 0);
    assert_eq!(
        again["already_present"],
        first["attempt_memory"]["attempts"]
    );
    eprintln!(
        "attempts={}, archive entries={}, elapsed={:?}",
        first["attempt_memory"]["attempts"],
        first["attempt_memory"]["archive_entries"],
        started.elapsed()
    );
}
