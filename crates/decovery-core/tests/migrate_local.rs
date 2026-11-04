//! Local test against the private Decomp workspaces. Run with `cargo test -- --ignored`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use decovery_core::{Workspace, migrate_decomp};

#[test]
#[ignore = "local: private Decomp workspace"]
fn migrates_without_loss() {
    let from = PathBuf::from(
        std::env::var_os("DECOVERY_LOCAL_WORKSPACE").expect("DECOVERY_LOCAL_WORKSPACE is not set"),
    );
    let to = tempfile::tempdir().unwrap();

    let source = std::fs::read_to_string(from.join("wissen").join("symbole.toml")).unwrap();
    let expected = source.matches("[[symbol]]").count();

    let report = migrate_decomp(&from, to.path()).unwrap();
    let ws = Workspace::open(to.path()).unwrap();
    assert_eq!(ws.symbols.len(), expected);

    let allowlist_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("parity")
        .join("phase-0-unmapped.txt");
    let allowlist: BTreeSet<String> = std::fs::read_to_string(&allowlist_path)
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_once('\t').map_or(l, |(k, _)| k).trim().to_string())
        .collect();
    let unexpected: Vec<_> = report
        .unmapped
        .iter()
        .filter(|k| !allowlist.iter().any(|entry| matches(entry, k)))
        .collect();
    assert!(unexpected.is_empty(), "not in allowlist: {unexpected:?}");
    assert!(to.path().join(".gitignore").is_file(), "missing .gitignore");
    // Workspaces differ in what they contain: an output is required exactly when its source exists.
    let wissen = from.join("wissen");
    let has_reports = std::fs::read_dir(&wissen).unwrap().any(|e| {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        name.ends_with(".md") && name != "notizen.md" && name != "programmierstil.md"
    });
    for (source_exists, rel) in [
        (from.join("nachbau").is_dir(), "src"),
        (
            wissen.join("nachbau.toml").is_file(),
            "knowledge/rebuild.toml",
        ),
        (
            wissen.join("nachbau-programm.toml").is_file(),
            "knowledge/rebuild-program.toml",
        ),
        (
            wissen.join("laufzeit.toml").is_file(),
            "knowledge/runs.toml",
        ),
        (
            wissen.join("verweise.toml").is_file(),
            "knowledge/references.toml",
        ),
        (
            wissen.join("programmierstil.md").is_file(),
            "knowledge/style.md",
        ),
        (has_reports, "knowledge/reports"),
        (wissen.join("laufzeit").is_dir(), "knowledge/runs"),
        (
            from.join("cache").join("nachbau").join("obj").is_dir(),
            "cache/rebuild/obj",
        ),
    ] {
        assert_eq!(
            to.path().join(rel).exists(),
            source_exists,
            "{rel}: source exists = {source_exists}"
        );
    }
    if from.join("spiel").is_dir() {
        assert!(ws.config.target.file.starts_with("target/"));
        assert!(to.path().join(&ws.config.target.file).is_file());
    }
    if from.join("ausgabe").is_dir() || from.join("cache").is_dir() {
        assert!(!report.skipped.is_empty());
    }
    eprintln!(
        "symbols: {}, unmapped: {:?}",
        ws.symbols.len(),
        report.unmapped
    );
}

/// An allowlist entry matches a key literally or, with one `*`, by prefix and suffix.
fn matches(entry: &str, key: &str) -> bool {
    match entry.split_once('*') {
        Some((prefix, suffix)) => {
            key.len() >= prefix.len() + suffix.len()
                && key.starts_with(prefix)
                && key.ends_with(suffix)
        }
        None => entry == key,
    }
}
