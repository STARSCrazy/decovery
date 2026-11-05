use std::process::Command;

#[test]
fn prints_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("--version")
        .output()
        .expect("run decovery");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(stdout.starts_with("decovery 0.1.0"), "got {stdout:?}");
}

#[test]
fn compare_without_workspace_exits_with_2() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args([
            "compare",
            "--object",
            "a.obj",
            "--function",
            "f",
            "--workspace",
        ])
        .arg(dir.path())
        .output()
        .expect("run decovery");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("cannot open workspace"), "got {stderr:?}");
}

#[test]
fn compare_requires_object_and_function() {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("compare")
        .output()
        .expect("run decovery");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(
        stderr.contains("--object") && stderr.contains("--function"),
        "got {stderr:?}"
    );
}

const CONFIG: &str = r#"schema = 1

[target]
file = "t.exe"
sha256 = "aa"
format = "flat32"
processor = "x86"

[[target.segment]]
name = "code"
start = "flat:00010000"
length = 4096
file_offset = 512
file_length = 4096
permissions = "rx"
"#;

const SYMBOLS: &str = r#"schema = 1

[[symbol]]
address = "flat:00010010"
kind = "function"
name = "alpha"
source = "human"
confidence = "confirmed"
"#;

/// Workspace with one analyzed function `alpha`.
fn workspace() -> tempfile::TempDir {
    use decovery_core::{Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::write(root.join("decovery.toml"), CONFIG).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), SYMBOLS).unwrap();
    let lock = Workspace::open(root)
        .unwrap()
        .lock(std::time::Duration::ZERO)
        .unwrap();
    let mut analysis = Analysis::new(
        Provider::new("ghidra", "11.3"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-05",
    );
    analysis.functions = vec![AnalyzedFunction::new(
        Address::Flat(0x10010),
        Address::Flat(0x100FF),
        240,
    )];
    analysis.save(root, &lock).unwrap();
    Analysis::save_decompiled(
        root,
        Address::Flat(0x10010),
        "\nint alpha(void) { return 0; }\n",
        &lock,
    )
    .unwrap();
    drop(lock);
    dir
}

fn run(dir: &tempfile::TempDir, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(args)
        .arg("--workspace")
        .arg(dir.path())
        .output()
        .expect("run decovery")
}

#[test]
fn show_unknown_function_exits_2() {
    let dir = workspace();
    let out = run(&dir, &["show", "nosuch"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(
        stderr.contains("no function or symbol named nosuch"),
        "got {stderr:?}"
    );
}

#[test]
fn show_prints_text_and_json_envelope() {
    let dir = workspace();
    let out = run(&dir, &["show", "alpha"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        text.starts_with("/* @address    flat:00010010"),
        "got {text:?}"
    );
    assert!(
        text.ends_with(" */\n\nint alpha(void) { return 0; }\n"),
        "got {text:?}"
    );

    let out = run(&dir, &["show", "alpha", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["data"]["text"], text.as_str());
    assert_eq!(v["data"]["name"], "alpha");
    assert!(v["handles"].as_array().unwrap().is_empty());
}

#[test]
fn detail_pages_a_handle() {
    let dir = workspace();
    let handle = decovery_facade::store_handle(dir.path(), "function-text", "0123456789").unwrap();
    let out = run(
        &dir,
        &["detail", &handle.id, "--offset", "2", "--limit", "3"],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "234");
    let out = run(&dir, &["detail", "h_000000000000"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn status_prints_counts_and_json() {
    let dir = workspace();
    let out = run(&dir, &["status"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with("1/1 functions named (1 confirmed, 0 assumed)\n"),
        "got {text:?}"
    );
    assert!(
        text.contains("next: rebuild alpha: decovery show alpha\n"),
        "got {text:?}"
    );
    let out = run(&dir, &["status", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["data"]["named"], 1);
}

#[test]
fn find_prints_rows_and_rejects_bad_values() {
    let dir = workspace();
    let out = run(
        &dir,
        &["find", "functions", "--filter", "named", "--sort", "size"],
    );
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "1 functions\nflat:00010010\talpha\t240\t0\tconfirmed\tnot-tried\n"
    );
    let out = run(&dir, &["find", "names", "AL*"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "1 names\nflat:00010010\talpha\n"
    );
    let out = run(&dir, &["find", "functions", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["data"]["total"], 1);
    let out = run(&dir, &["find", "functions", "--filter", "nonsense"]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&dir, &["find", "xrefs", "nosuch"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn annotate_names_and_rejects_bad_input() {
    let d = workspace();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_decovery"))
            .arg("annotate")
            .args(args)
            .arg("--workspace")
            .arg(d.path())
            .output()
            .expect("run decovery")
    };
    // human by default: replaces nothing stronger, names a new address
    let out = run(&["flat:00010020", "--name", "helper", "--evidence", "seen"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("named flat:00010020 helper"),
        "{stdout:?}"
    );
    let symbols = std::fs::read_to_string(d.path().join("knowledge/symbols.toml")).unwrap();
    assert!(symbols.contains("helper") && symbols.contains("source = \"human\""));
    // an agent does not replace the human claim; reported, exit 0
    let out = run(&["alpha", "--name", "other", "--source", "agent"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with("no change: ")
    );
    assert!(String::from_utf8(out.stderr).unwrap().contains("warning: "));
    // validation errors exit 2
    let out = run(&["alpha", "--name", "while"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr).unwrap().contains("C keyword"));
    assert_eq!(run(&["alpha"]).status.code(), Some(2));
    // JSON envelope and --local
    let out = run(&["alpha", "--local", "param:1", "count", "int", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["data"]["action"], "local");
    assert_eq!(json["data"]["changed"], true);
}

/// `decovery analyze` with the user config directories pointed at an empty temp dir.
fn analyze_isolated(dir: &tempfile::TempDir, args: &[&str]) -> std::process::Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("analyze")
        .args(args)
        .arg("--workspace")
        .arg(dir.path())
        .env("APPDATA", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("HOME", home.path())
        .output()
        .expect("run decovery")
}

#[test]
fn analyze_without_plugin_config_exits_2() {
    let dir = workspace();
    let out = analyze_isolated(&dir, &[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no analyzer configured; run decovery setup ghidra"),
        "got {stderr:?}"
    );
    let out = analyze_isolated(&dir, &["--plugin", "decovery-test-none"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no analyzer configured for plugin decovery-test-none"),
        "got {stderr:?}"
    );
    let out = analyze_isolated(&dir, &["--plugin", "../x"]);
    assert_eq!(out.status.code(), Some(2));
}
