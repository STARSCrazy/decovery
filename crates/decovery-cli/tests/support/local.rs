//! Helpers of the local parity tests (`build_parity_local`, `link_local`): migrate a private Decomp workspace into a
//! temporary directory, edit its `decovery.toml`, run the CLI and record outcomes in the private parity document.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

use serde_json::Value;

// Decomp's on-disk names (its workspace is German).
pub const DECOMP_KNOWLEDGE_DIR: &str = "wissen";
pub const DECOMP_REBUILD_RECORDS_FILE: &str = "nachbau.toml";
pub const DECOMP_RECORD_TABLE: &str = "funktion";
pub const DECOMP_KEY_ADDRESS: &str = "adresse";
pub const DECOMP_KEY_FILE: &str = "datei";
pub const DECOMP_KEY_RESULT: &str = "ergebnis";
pub const DECOMP_RESULT_IDENTICAL: &str = "identisch";

pub fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

/// Runs `decovery <args> --workspace <workspace>`; returns the output and the wall time in milliseconds.
pub fn decovery(args: &[&str], workspace: &Path) -> (Output, u128) {
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(args)
        .arg("--workspace")
        .arg(workspace)
        .output()
        .expect("run decovery");
    (out, started.elapsed().as_millis())
}

/// The JSON response of a `--json` run.
pub fn response(out: &Output, what: &str) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "{what} printed no JSON: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

pub fn migrate(from: &Path, to: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("migrate")
        .arg(from)
        .arg(to)
        .output()
        .expect("run decovery migrate");
    assert!(
        out.status.success(),
        "migrate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Edits the workspace's `decovery.toml`.
pub fn edit_config(ws: &Path, edit: impl FnOnce(&mut toml::Table)) {
    let path = ws.join("decovery.toml");
    let mut config: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    edit(&mut config);
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
}

/// The sub-table `key` of `table`, created when missing.
pub fn table<'a>(table: &'a mut toml::Table, key: &str) -> &'a mut toml::Table {
    table
        .entry(key)
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .unwrap()
}

/// `[rebuild] tool_dir` from the environment variable `var`, when it is set.
pub fn set_tool_dir(config: &mut toml::Table, var: &str) {
    if let Some(dir) = std::env::var_os(var) {
        table(config, "rebuild").insert(
            "tool_dir".into(),
            toml::Value::String(PathBuf::from(dir).to_string_lossy().into_owned()),
        );
    }
}

/// Replaces (or appends) the section `## <title>` of `$DECOVERY_GOLDEN_DIR/parity-phase-2.md`.
pub fn record_parity(title: &str, body: &str) {
    let Some(dir) = std::env::var_os("DECOVERY_GOLDEN_DIR") else {
        return;
    };
    let path = PathBuf::from(dir).join("parity-phase-2.md");
    let old = std::fs::read_to_string(&path).unwrap_or_default();
    let mut sections: Vec<(String, String)> = Vec::new();
    for chunk in old.split("\n## ").skip(1) {
        let (t, b) = chunk.split_once('\n').unwrap_or((chunk, ""));
        sections.push((t.to_string(), b.trim_end().to_string()));
    }
    match sections.iter_mut().find(|(t, _)| t == title) {
        Some(s) => s.1 = body.trim_end().to_string(),
        None => sections.push((title.to_string(), body.trim_end().to_string())),
    }
    let mut text = String::from("# Parity phase 2 (private)\n");
    for (t, b) in sections {
        text.push_str(&format!("\n## {t}\n{b}\n"));
    }
    std::fs::write(path, text).unwrap();
}

/// The strings of a JSON array.
pub fn lines(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_string))
        .collect()
}

/// The `HEAD` commit of the Decomp workspace's repository, or `unknown`.
pub fn decomp_commit(workspace: &Path) -> String {
    Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
