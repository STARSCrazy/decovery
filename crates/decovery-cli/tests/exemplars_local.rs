//! Exemplar parity (risk R4) of decovery's `find similar` against Decomp's `nachbau vorbilder` on the first target.
//! Run with `DECOVERY_DECOMP_WORKSPACE=<Decomp workspace> DECOVERY_DECOMP_PYTHON=<Decomp's Python>
//! DECOVERY_GOLDEN_DIR=<private dir> cargo test -p decovery-cli --test exemplars_local -- --ignored`
//! (`DECOVERY_LOCAL_WORKSPACE` stands in for the Decomp workspace when that is unset).
//!
//! The source workspace is never written: Decomp runs on a throw-away copy in a temporary directory (preflight
//! row 13; Decomp opens its project, takes its lock and writes `cache/` there), decovery on a workspace migrated
//! from the source. Twenty functions Decomp does not record as identical, spread over the size classes, are
//! compared. decovery's candidates are restricted to the functions Decomp's `wissen/nachbau.toml` records as
//! identical. Criteria: top 1 equal in at least 17 of 20, top-3 sets sharing at least 2 members in at least 17 of
//! 20. Every case with its lists goes to `$DECOVERY_GOLDEN_DIR/exemplars-phase-3.json` (names functions, stays
//! private).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use decovery_core::Address;
use decovery_facade::{Session, exemplar_index};
use serde_json::json;

const CASES: usize = 20;
const NEEDED: usize = 17;

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn decomp_workspace() -> PathBuf {
    std::env::var_os("DECOVERY_DECOMP_WORKSPACE")
        .or_else(|| std::env::var_os("DECOVERY_LOCAL_WORKSPACE"))
        .map(PathBuf::from)
        .expect("DECOVERY_DECOMP_WORKSPACE (or DECOVERY_LOCAL_WORKSPACE) is not set")
}

/// Copies `from` to `to` (files and directories; links are not followed).
fn copy_tree(from: &Path, to: &Path) {
    copy_filtered(from, to, true);
}

/// Copies a Decomp workspace; of its top-level `cache/` only `cache/nachbau/` (what `migrate` reads) is copied,
/// because the rest (Ghidra project, scratch files) is large and neither tool needs it here.
fn copy_filtered(from: &Path, to: &Path, top: bool) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let target = to.join(entry.file_name());
        if kind.is_dir() && top && entry.file_name() == "cache" {
            let nachbau = entry.path().join("nachbau");
            if nachbau.is_dir() {
                copy_filtered(&nachbau, &target.join("nachbau"), false);
            }
        } else if kind.is_dir() {
            copy_filtered(&entry.path(), &target, false);
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Names of the functions Decomp's `_vorbilder` takes as candidates from `wissen/nachbau.toml`: `ergebnis =
/// "identisch"`, no differing instructions (`befehle_abweichend` missing or 0), source not `.asm`/`.s`.
fn decomp_identical(workspace: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(workspace.join("wissen/nachbau.toml")).unwrap();
    let table: toml::Table = text.parse().unwrap();
    let mut names = BTreeSet::new();
    for (_, value) in table {
        for item in value.as_array().into_iter().flatten() {
            let identical = item.get("ergebnis").and_then(|v| v.as_str()) == Some("identisch")
                && item
                    .get("befehle_abweichend")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0)
                    == 0
                && !item
                    .get("datei")
                    .and_then(|v| v.as_str())
                    .map(str::to_ascii_lowercase)
                    .is_some_and(|d| d.ends_with(".asm") || d.ends_with(".s"));
            if let (true, Some(name)) = (identical, item.get("name").and_then(|v| v.as_str())) {
                names.insert(name.to_string());
            }
        }
    }
    names
}

/// The names in Decomp's answer, in rank order: lines `<n>. <name> (<address>, nachbau/<file>): …`.
fn decomp_vorbilder(python: &Path, copy: &Path, at: Address) -> (Vec<String>, String) {
    // Decomp's normal form for a flat address is `va:XXXXXXXX`; it rejects `0x…`.
    let address = format!("va:{:08X}", at.linear().unwrap_or(0));
    let out = Command::new(python)
        .args(["-m", "decomp", "--bereich"])
        .arg(copy)
        .args(["nachbau", "vorbilder", &address, "--anzahl", "3"])
        .output()
        .expect("run Decomp");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let names = text
        .lines()
        .filter_map(|line| {
            let (number, rest) = line.split_once(". ")?;
            number.trim().parse::<usize>().ok()?;
            Some(rest.split_once(" (")?.0.to_string())
        })
        .collect();
    (names, text)
}

#[test]
#[ignore = "local: first target + Decomp"]
fn exemplars_match_decomp_vorbilder() {
    let source = decomp_workspace();
    let python = env_path("DECOVERY_DECOMP_PYTHON");
    let golden = env_path("DECOVERY_GOLDEN_DIR");
    let scratch = tempfile::tempdir().unwrap();
    let copy = scratch.path().join("decomp");
    copy_tree(&source, &copy);
    let migrated = scratch.path().join("decovery");
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("migrate")
        .arg(&copy)
        .arg(&migrated)
        .output()
        .expect("run decovery migrate");
    assert!(
        out.status.success(),
        "migrate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let identical = decomp_identical(&source);
    let session = Session::open(&migrated).unwrap();
    let index = exemplar_index(&session).unwrap();
    let mut open: Vec<(u32, Address, String)> = session
        .analysis
        .functions
        .iter()
        .map(|f| (f.body_size, f.start, session.name_of(f.start).name))
        .filter(|(_, _, name)| !identical.contains(name))
        .collect();
    open.sort();
    assert!(open.len() >= CASES, "only {} open functions", open.len());
    let picks: Vec<&(u32, Address, String)> = (0..CASES)
        .map(|k| &open[k * (open.len() - 1) / (CASES - 1)])
        .collect();

    let mut cases = Vec::new();
    let (mut top1, mut top3) = (0usize, 0usize);
    for (size, at, name) in picks {
        let (theirs, text) = decomp_vorbilder(&python, &copy, *at);
        let ours: Vec<String> = index
            .similar(&session, *at, index.len())
            .unwrap_or_default()
            .into_iter()
            .filter(|e| identical.contains(&e.name))
            .take(3)
            .map(|e| e.name)
            .collect();
        let first = !theirs.is_empty() && ours.first() == theirs.first();
        let shared = ours.iter().filter(|n| theirs.contains(n)).count();
        let shares = shared >= 2.min(theirs.len());
        top1 += usize::from(first || (theirs.is_empty() && ours.is_empty()));
        top3 += usize::from(shares);
        cases.push(json!({
            "function": name, "address": at.to_string(), "size": size,
            "decomp": theirs, "decovery": ours, "top1_equal": first, "shared": shared,
            "decomp_text": text,
            "reason": if first && shares { "" } else { "to be explained (show the differing forms)" },
        }));
    }
    let report = json!({ "schema": 1, "cases": cases, "top1_equal": top1, "top3_shared": top3 });
    std::fs::create_dir_all(&golden).unwrap();
    std::fs::write(
        golden.join("exemplars-phase-3.json"),
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
    assert!(
        top1 >= NEEDED && top3 >= NEEDED,
        "top 1 equal {top1}/{CASES}, top 3 sharing {top3}/{CASES}"
    );
}

#[test]
fn decomp_identical_follows_decomp_member_rule() {
    // Decomp's `_vorbilder`: `ergebnis == "identisch"`, no differing instructions, not from assembler
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("wissen")).unwrap();
    std::fs::write(
        dir.path().join("wissen/nachbau.toml"),
        r#"[[funktion]]
adresse = "0x10"
name = "same"
datei = "a.c"
ergebnis = "identisch"
befehle_abweichend = 0

[[funktion]]
adresse = "0x20"
name = "old_entry"
datei = "a.c"
ergebnis = "identisch"

[[funktion]]
adresse = "0x30"
name = "longer_original"
datei = "a.c"
ergebnis = "identisch"
befehle_abweichend = 2

[[funktion]]
adresse = "0x40"
name = "assembler"
datei = "b.ASM"
ergebnis = "identisch"

[[funktion]]
adresse = "0x50"
name = "differs"
datei = "a.c"
ergebnis = "abweichend"
"#,
    )
    .unwrap();
    let names: Vec<String> = decomp_identical(dir.path()).into_iter().collect();
    assert_eq!(names, ["old_entry", "same"]);
}
