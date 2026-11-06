//! Phase-0 parity of `decovery compare` against Decomp on a private Decomp workspace. Run with
//! `DECOVERY_LOCAL_WORKSPACE=<Decomp workspace> DECOVERY_GOLDEN_DIR=<private dir> cargo test -p decovery-cli -- --ignored`.
//!
//! Migrates the workspace, then compares the first 20 functions Decomp records as identical and the first 5 it
//! records as differing through the CLI. Metrics must equal Decomp's; verdict differences are collected (with
//! their blockers) into `$DECOVERY_GOLDEN_DIR/parity-phase-0.md`, which names functions and stays private.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

// Decomp's on-disk names (its workspace is German).
const DECOMP_KNOWLEDGE_DIR: &str = "wissen";
const DECOMP_OUTPUT_DIR: &str = "ausgabe";
const DECOMP_FUNCTIONS_DIR: &str = "funktionen";
const DECOMP_REBUILD_RECORDS_FILE: &str = "nachbau.toml";
const DECOMP_RECORD_TABLE: &str = "funktion";
const DECOMP_ADDRESS_TAG: &str = "@adresse";
const DECOMP_KEY_ADDRESS: &str = "adresse";
const DECOMP_KEY_FILE: &str = "datei";
const DECOMP_KEY_RESULT: &str = "ergebnis";
const DECOMP_RESULT_IDENTICAL: &str = "identisch";
const DECOMP_RESULT_DIFFERS: &str = "abweichend";

/// Decomp's metric key and decovery's field name.
const METRICS: [(&str, &str); 7] = [
    ("bytes", "bytes"),
    ("gleich", "equal"),
    ("luecken", "gaps"),
    ("abweichend", "differing"),
    ("verweise_passend", "refs_ok"),
    ("verweise_falsch", "refs_wrong"),
    ("befehle_abweichend", "instructions_differing"),
];

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn va(text: &str) -> Option<u32> {
    u32::from_str_radix(text.strip_prefix("va:")?, 16).ok()
}

/// Function spans from the `@adresse    va:X .. va:Y (N Bytes` in Decomp's generated output (taken from Ghidra).
fn spans(dir: &Path) -> BTreeMap<u32, u32> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Some(line) = text.lines().find(|l| l.contains(DECOMP_ADDRESS_TAG)) else {
                continue;
            };
            let words: Vec<&str> = line.split_whitespace().collect();
            let Some(i) = words.iter().position(|w| *w == DECOMP_ADDRESS_TAG) else {
                continue;
            };
            if let (Some(start), Some(end)) = (
                words.get(i + 1).and_then(|w| va(w)),
                words.get(i + 3).and_then(|w| va(w)),
            ) {
                out.insert(start, end - start + 1);
            }
        }
    }
    out
}

fn num(e: &toml::Table, key: &str) -> u64 {
    e.get(key).and_then(|v| v.as_integer()).unwrap_or(0) as u64
}

struct Row {
    name: String,
    address: u32,
    recorded: String,
    verdict: String,
    blockers: Vec<String>,
    metric_mismatch: Option<String>,
}

#[test]
#[ignore = "local: private Decomp workspace"]
fn first_20_identical_and_5_differing() {
    let from = env_path("DECOVERY_LOCAL_WORKSPACE");
    let golden = env_path("DECOVERY_GOLDEN_DIR");
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    decovery_core_migrate(&from, &ws);

    let recorded: toml::Table = std::fs::read_to_string(
        from.join(DECOMP_KNOWLEDGE_DIR)
            .join(DECOMP_REBUILD_RECORDS_FILE),
    )
    .unwrap()
    .parse()
    .unwrap();
    let entries: Vec<&toml::Table> = recorded[DECOMP_RECORD_TABLE]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_table().unwrap())
        .collect();
    let with = |result: &str, n: usize| -> Vec<&toml::Table> {
        entries
            .iter()
            .copied()
            .filter(|e| e.get(DECOMP_KEY_RESULT).and_then(|v| v.as_str()) == Some(result))
            .take(n)
            .collect()
    };
    let sample: Vec<&toml::Table> = with(DECOMP_RESULT_IDENTICAL, 20)
        .into_iter()
        .chain(with(DECOMP_RESULT_DIFFERS, 5))
        .collect();
    assert_eq!(
        sample.len(),
        25,
        "workspace has fewer than 20 + 5 recorded functions"
    );
    let spans = spans(&from.join(DECOMP_OUTPUT_DIR).join(DECOMP_FUNCTIONS_DIR));

    let mut rows = Vec::new();
    for e in &sample {
        let name = e["name"].as_str().unwrap();
        let address = va(e[DECOMP_KEY_ADDRESS].as_str().unwrap()).unwrap();
        let stem = e[DECOMP_KEY_FILE].as_str().unwrap().trim_end_matches(".c");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_decovery"));
        cmd.args(["compare", "--json", "--workspace"])
            .arg(&ws)
            .arg("--object")
            .arg(format!("cache/rebuild/obj/{stem}.obj"))
            .args(["--function", name]);
        if let Some(len) = spans.get(&address) {
            cmd.args(["--length", &len.to_string()]);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.code() != Some(2),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        let ours: Vec<u64> = METRICS
            .iter()
            .map(|(_, k)| v["metrics"][k].as_u64().unwrap())
            .collect();
        let theirs: Vec<u64> = METRICS.iter().map(|(k, _)| num(e, k)).collect();
        rows.push(Row {
            name: name.to_string(),
            address,
            recorded: e[DECOMP_KEY_RESULT].as_str().unwrap().to_string(),
            verdict: v["verdict"].as_str().unwrap().to_string(),
            blockers: v["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b["kind"].as_str().unwrap().to_string())
                .collect(),
            metric_mismatch: (ours != theirs).then(|| format!("{ours:?} != Decomp {theirs:?}")),
        });
    }

    let decomp_commit = Command::new("git")
        .arg("-C")
        .arg(&from)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let mut report = format!(
        "# Phase-0 parity, detailed (private)\n\nDecomp commit: {decomp_commit}\n\n\
         | function | address | Decomp | decovery | blockers | metrics |\n|---|---|---|---|---|---|\n"
    );
    for r in &rows {
        writeln!(
            report,
            "| {} | va:{:08X} | {} | {} | {} | {} |",
            r.name,
            r.address,
            r.recorded,
            r.verdict,
            summarize(&r.blockers),
            r.metric_mismatch.as_deref().unwrap_or("equal")
        )
        .unwrap();
    }
    std::fs::create_dir_all(&golden).unwrap();
    std::fs::write(golden.join("parity-phase-0.md"), &report).unwrap();

    let agree = |r: &&Row| (r.recorded == DECOMP_RESULT_IDENTICAL) == (r.verdict == "identical");
    let mut categories: BTreeMap<String, usize> = BTreeMap::new();
    for r in rows.iter().filter(|r| !agree(r)) {
        let key = format!(
            "Decomp {} / decovery {}: {}",
            r.recorded,
            r.verdict,
            summarize(&r.blockers)
        );
        *categories.entry(key).or_default() += 1;
    }
    println!(
        "compared {}, metrics equal {}, verdicts agree {}; Decomp commit {decomp_commit}",
        rows.len(),
        rows.iter().filter(|r| r.metric_mismatch.is_none()).count(),
        rows.iter().filter(agree).count()
    );
    for (k, n) in &categories {
        println!("  {n} x {k}");
    }
    let mismatches: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            r.metric_mismatch
                .as_ref()
                .map(|m| format!("{}: {m}", r.name))
        })
        .collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

fn decovery_core_migrate(from: &Path, to: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("migrate")
        .arg(from)
        .arg(to)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "migrate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Blocker kinds with their counts, e.g. `bytes_differ, wrong_absolute_ref x3`.
fn summarize(kinds: &[String]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for k in kinds {
        *counts.entry(k.as_str()).or_default() += 1;
    }
    counts
        .iter()
        .map(|(k, n)| {
            if *n == 1 {
                k.to_string()
            } else {
                format!("{k} x{n}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
