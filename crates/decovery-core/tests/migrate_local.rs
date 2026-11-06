//! Local test against the private Decomp workspaces. Run with `cargo test -- --ignored`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use decovery_core::{Address, Analysis, Workspace, migrate_decomp};

// Decomp's on-disk names (its workspace is German).
const DECOMP_KNOWLEDGE_DIR: &str = "wissen";
const DECOMP_REBUILD_DIR: &str = "nachbau";
const DECOMP_GAME_DIR: &str = "spiel";
const DECOMP_OUTPUT_DIR: &str = "ausgabe";
const DECOMP_FUNCTIONS_DIR: &str = "funktionen";
const DECOMP_RUNS_DIR: &str = "laufzeit";
const DECOMP_SYMBOLS_FILE: &str = "symbole.toml";
const DECOMP_NOTES_FILE: &str = "notizen.md";
const DECOMP_STYLE_FILE: &str = "programmierstil.md";
const DECOMP_REBUILD_RECORDS_FILE: &str = "nachbau.toml";
const DECOMP_REBUILD_PROGRAM_FILE: &str = "nachbau-programm.toml";
const DECOMP_RUN_RECORDS_FILE: &str = "laufzeit.toml";
const DECOMP_REFERENCES_FILE: &str = "verweise.toml";
const DECOMP_ADDRESS_TAG: &str = "@adresse";
const DECOMP_DECOMPILE_ERROR_PREFIX: &str = "/* Dekompilieren fehlgeschlagen: ";

#[test]
#[ignore = "local: private Decomp workspace"]
fn migrates_without_loss() {
    let from = PathBuf::from(
        std::env::var_os("DECOVERY_LOCAL_WORKSPACE").expect("DECOVERY_LOCAL_WORKSPACE is not set"),
    );
    let to = tempfile::tempdir().unwrap();

    let source =
        std::fs::read_to_string(from.join(DECOMP_KNOWLEDGE_DIR).join(DECOMP_SYMBOLS_FILE)).unwrap();
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
    let knowledge_dir = from.join(DECOMP_KNOWLEDGE_DIR);
    let has_reports = std::fs::read_dir(&knowledge_dir).unwrap().any(|e| {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        name.ends_with(".md") && name != DECOMP_NOTES_FILE && name != DECOMP_STYLE_FILE
    });
    for (source_exists, rel) in [
        (from.join(DECOMP_REBUILD_DIR).is_dir(), "src"),
        (
            knowledge_dir.join(DECOMP_REBUILD_RECORDS_FILE).is_file(),
            "knowledge/rebuild.toml",
        ),
        (
            knowledge_dir.join(DECOMP_REBUILD_PROGRAM_FILE).is_file(),
            "knowledge/rebuild-program.toml",
        ),
        (
            knowledge_dir.join(DECOMP_RUN_RECORDS_FILE).is_file(),
            "knowledge/runs.toml",
        ),
        (
            knowledge_dir.join(DECOMP_REFERENCES_FILE).is_file(),
            "knowledge/references.toml",
        ),
        (
            knowledge_dir.join(DECOMP_STYLE_FILE).is_file(),
            "knowledge/style.md",
        ),
        (has_reports, "knowledge/reports"),
        (
            knowledge_dir.join(DECOMP_RUNS_DIR).is_dir(),
            "knowledge/runs",
        ),
        (
            from.join("cache")
                .join(DECOMP_REBUILD_DIR)
                .join("obj")
                .is_dir(),
            "cache/rebuild/obj",
        ),
    ] {
        assert_eq!(
            to.path().join(rel).exists(),
            source_exists,
            "{rel}: source exists = {source_exists}"
        );
    }
    if from.join(DECOMP_GAME_DIR).is_dir() {
        assert!(ws.config.target.file.starts_with("target/"));
        assert!(to.path().join(&ws.config.target.file).is_file());
    }
    if from.join(DECOMP_OUTPUT_DIR).is_dir() || from.join("cache").is_dir() {
        assert!(!report.skipped.is_empty());
    }
    let functions_dir = from.join(DECOMP_OUTPUT_DIR).join(DECOMP_FUNCTIONS_DIR);
    if functions_dir.is_dir() {
        assert_analysis_matches(&functions_dir, to.path(), report.analysis_functions);
    } else {
        assert_eq!(report.analysis_functions, 0);
        assert!(Analysis::load(to.path()).unwrap().is_none());
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

fn c_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            c_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "c") {
            out.push(path);
        }
    }
}

fn flat_address(text: &str) -> Address {
    match text.strip_prefix("va:") {
        Some(hex) => Address::Flat(u32::from_str_radix(hex, 16).unwrap()),
        None => {
            let (seg, off) = text.strip_prefix("rel:").unwrap().split_once(':').unwrap();
            Address::Seg {
                seg: u16::from_str_radix(seg, 16).unwrap(),
                off: u16::from_str_radix(off, 16).unwrap(),
            }
        }
    }
}

/// The analysis has one function per `*.c` file and `header + stored body` reproduces every file byte for byte.
fn assert_analysis_matches(functions_dir: &Path, to: &Path, imported: u32) {
    let analysis = Analysis::load(to).unwrap().expect("analysis.json");
    let mut files = Vec::new();
    c_files(functions_dir, &mut files);
    assert_eq!(analysis.functions.len(), files.len());
    assert_eq!(imported as usize, files.len());
    assert_eq!(analysis.provider.name, "decomp-import");
    let mut with_error = 0;
    for file in &files {
        // decovery stores LF only: compare against the Decomp file after CRLF -> LF.
        let text = std::fs::read_to_string(file).unwrap().replace("\r\n", "\n");
        // Decomp's `kopf` ends with " */\n" (CRLF after a git autocrlf checkout); the pseudo-C follows directly.
        let end = text.find("\n */").expect("header end") + "\n */".len();
        let header_len = end
            + if text[end..].starts_with("\r\n") {
                2
            } else {
                1
            };
        assert!(text[end..header_len].ends_with('\n'));
        let (header, body) = text.split_at(header_len);
        let first = header.lines().next().unwrap();
        let start_text = first
            .strip_prefix(&format!("/* {DECOMP_ADDRESS_TAG}"))
            .unwrap()
            .trim_start()
            .split(' ')
            .next()
            .unwrap();
        let start = flat_address(start_text);
        let stored = Analysis::decompiled(to, start)
            .unwrap()
            .unwrap_or_else(|| panic!("no body for {}", file.display()));
        assert_eq!(stored, body, "{}", file.display());
        assert_eq!(format!("{header}{stored}"), text, "{}", file.display());
        let function = analysis
            .functions
            .iter()
            .find(|f| f.start == start)
            .unwrap_or_else(|| panic!("no function for {}", file.display()));
        assert_eq!(
            function.decompile_error.is_some(),
            body.starts_with(DECOMP_DECOMPILE_ERROR_PREFIX)
        );
        with_error += usize::from(function.decompile_error.is_some());
    }
    let bodies = std::fs::read_dir(to.join("knowledge/analysis/decompiled"))
        .unwrap()
        .count();
    assert_eq!(bodies, files.len());
    eprintln!(
        "analysis: {} functions ({with_error} with decompile error), {} calls, {} strings, {} accesses",
        analysis.functions.len(),
        analysis.calls.len(),
        analysis.strings.len(),
        analysis.data_accesses.len()
    );
}
