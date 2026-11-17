//! `decovery bench report` and `bench compare` over hand-written run records.

use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;

fn record(id: &str, solved: &[bool]) -> Value {
    let tasks: Vec<Value> = solved
        .iter()
        .enumerate()
        .map(|(i, s)| {
            json!({
                "id": format!("t{i}"), "repeat": 0, "workspace": "ws", "profile": "p", "tags": ["x"],
                "solved": s, "verdict": "differs", "builds": 2, "tool_calls": 4, "searches": 0,
                "calls_by_tool": {"build": 2}, "wall_s": 3.0, "exit": "ok"
            })
        })
        .collect();
    json!({
        "schema": 1, "id": id, "suite": "s", "started": "2026-11-17T08:00:00Z", "state": "done",
        "tool_version": "0", "config_hash": "h", "driver": "d", "tools": "core", "seed": 0,
        "totals": {"tasks": 0, "solved": 0, "builds": 0, "tool_calls": 0, "searches": 0, "wall_s": 0.0},
        "tasks": tasks
    })
}

fn write(dir: &Path, name: &str, value: &Value) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, value.to_string()).unwrap();
    path
}

#[test]
fn report_and_compare_print_tables_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let a = write(
        dir.path(),
        "a.json",
        &record("a", &[true, false, true, true]),
    );
    let b = write(
        dir.path(),
        "b.json",
        &record("b", &[true, false, true, true]),
    );

    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(["bench", "report"])
        .arg(&a)
        .args(["--group-by", "tag"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("3/4") && text.contains("x "), "{text}");

    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(["bench", "compare"])
        .arg(&a)
        .arg(&b)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success() && text.contains("consistent within noise"),
        "{text}"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(["--json", "bench", "compare"])
        .arg(&a)
        .arg(&b)
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["consistent"], true);

    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(["bench", "report"])
        .arg(dir.path().join("missing.json"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
