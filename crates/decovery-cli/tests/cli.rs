#[path = "../../decovery-facade/tests/support/build_fixture.rs"]
mod build_fixture;

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
fn jobs_must_be_positive() {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(["--jobs", "0", "status"])
        .output()
        .expect("run decovery");
    assert_eq!(out.status.code(), Some(2));
    let help = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(["build", "--help"])
        .output()
        .expect("run decovery");
    assert!(String::from_utf8_lossy(&help.stdout).contains("--jobs"));
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

/// Decomp's `decomp.toml` (its workspace format is German; this is input of `decovery migrate`).
const DECOMP_TOML: &str = r#"
[ziel]
datei = "spiel/PROGRAM.EXE"
sha256 = "ab12"
format = "le"
prozessor = "x86:LE:32:default"
segment = [
    { name = "obj1", start = "va:00010000", laenge = 4096, datei_offset = 512, datei_laenge = 4000, rechte = "rx" },
]
"#;

/// Header of one generated Decomp function file (Decomp's German keys and phrases).
const DECOMP_FUNCTION_HEADER: &str = "/* @adresse    va:00010010 .. va:0001001F (16 Bytes, datei 0x210)\n * @name       fun_00010010  [unbenannt]\n * @gerufen-von (keine)\n * @ruft       (keine)\n * @strings    (keine)\n * @globale    (keine)\n * @laufzeit   unbekannt\n * @nachbau    nicht-versucht\n */\n";
/// Decomp's output directory for generated function files.
const DECOMP_FUNCTIONS_PATH: &str = "ausgabe/funktionen/obj1";

/// A Decomp workspace whose output directory holds one function.
fn decomp_with_output() -> tempfile::TempDir {
    let from = tempfile::tempdir().unwrap();
    let f = from.path();
    std::fs::write(f.join("decomp.toml"), DECOMP_TOML).unwrap();
    let dir = f.join(DECOMP_FUNCTIONS_PATH);
    std::fs::create_dir_all(&dir).unwrap();
    let header = DECOMP_FUNCTION_HEADER;
    std::fs::write(
        dir.join("va_00010010_fun_00010010.c"),
        format!("{header}\nvoid f(void)\n{{\n  return;\n}}\n"),
    )
    .unwrap();
    from
}

#[test]
fn migrate_with_analysis_generates_output() {
    let from = decomp_with_output();
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("migrate")
        .arg(from.path())
        .arg(&ws)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("output generated: 1 files written"),
        "{stdout}"
    );
    let file = ws.join("output/functions/obj1/flat_00010010_fun_00010010.c");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.starts_with("/* @address    flat:00010010"), "{text}");
    assert!(
        text.ends_with("\nvoid f(void)\n{\n  return;\n}\n"),
        "{text}"
    );
    let index = std::fs::read_to_string(ws.join("output/index.md")).unwrap();
    assert!(
        index.contains("functions/obj1/flat_00010010_fun_00010010.c"),
        "{index}"
    );
    // `find code` reads the generated files
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(["find", "code", "return"])
        .arg("--workspace")
        .arg(&ws)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8(out.stdout).unwrap().contains("return;"));
}

#[test]
fn migrate_without_analysis_says_so_and_errors_exit_2() {
    let from = tempfile::tempdir().unwrap();
    std::fs::write(from.path().join("decomp.toml"), DECOMP_TOML).unwrap();
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    let migrate = || {
        Command::new(env!("CARGO_BIN_EXE_decovery"))
            .arg("migrate")
            .arg(from.path())
            .arg(&ws)
            .output()
            .unwrap()
    };
    let out = migrate();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("No analysis imported"),
    );
    assert!(!ws.join("output").exists());
    // the target workspace exists now: refused with exit code 2
    let out = migrate();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .starts_with("error: ")
    );
}

#[test]
fn setup_toolchain_writes_user_config() {
    let home = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    let setup = |profile: &str, dir: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_decovery"))
            .args(["setup", "toolchain", profile])
            .arg(dir)
            .env("APPDATA", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("HOME", home.path())
            .output()
            .expect("run decovery")
    };
    let config = home.path().join("decovery").join("config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "schema = 1\n\n[plugins.ghidra]\ncommand = [\"py\"]\n",
    )
    .unwrap();
    let out = setup("watcom-9.5", tools.path());
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = std::fs::read_to_string(&config).unwrap();
    let value: toml::Table = text.parse().unwrap();
    assert_eq!(value["schema"].as_integer(), Some(1));
    assert_eq!(
        value["plugins"]["ghidra"]["command"][0].as_str(),
        Some("py")
    );
    let dir = value["toolchains"]["watcom-9.5"].as_str().unwrap();
    assert_eq!(
        std::path::Path::new(dir).canonicalize().unwrap(),
        tools.path().canonicalize().unwrap()
    );
    let out = setup("no-such-profile", tools.path());
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("no-such-profile")
    );
}

fn build_cli(root: &std::path::Path, files: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("build")
        .args(files)
        .arg("--json")
        .arg("--workspace")
        .arg(root)
        .output()
        .expect("run decovery")
}

#[test]
fn build_exit_codes() {
    let python = python_or_skip!();
    let f = build_fixture::fixture(&python, "");
    let out = build_cli(f.root(), &["a.c"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["summary"], "a.c: 2 functions, 2 identical");

    let mut sub = build_fixture::SUB.to_vec();
    sub[6] = 0x33;
    f.write_obj("A", &[("_add", build_fixture::ADD), ("_sub", &sub)]);
    f.write_source("a.c", &format!("{}/* changed */\n", build_fixture::A_C));
    let out = build_cli(f.root(), &["a.c"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");

    std::fs::remove_file(f.objects.path().join("Z.OBJ")).unwrap();
    let out = build_cli(f.root(), &["z.c"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a failed file is not a success: {out:?}"
    );

    let out = build_cli(f.root(), &["missing.c"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8(out.stderr).unwrap().contains("missing.c"));
}

#[test]
fn build_variants_ranks_and_sets_exit_code() {
    let python = python_or_skip!();
    let f = build_fixture::fixture(&python, "");
    let mut worse = build_fixture::SUB.to_vec();
    worse[6] = 0x33;
    f.write_obj("V001", &[("_sub", &worse)]);
    f.write_obj("V002", &[("_sub", build_fixture::SUB)]);
    let source = "int sub(int a, int b)\n{\n    return a - b;\n}\n";
    let dir = tempfile::tempdir().unwrap();
    let (one, two) = (dir.path().join("one.c"), dir.path().join("two.c"));
    std::fs::write(&one, source).unwrap();
    std::fs::write(&two, format!("{source}/* two */\n")).unwrap();
    let run = |variants: &[&std::path::Path]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_decovery"));
        command.args(["build", "--function", "sub", "--json", "--workspace"]);
        command.arg(f.root());
        for v in variants {
            command.arg("--variant").arg(v);
        }
        command.output().expect("run decovery")
    };
    let out = run(&[&one, &two]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["data"]["best"], 2);
    assert_eq!(
        value["data"]["variants"][1]["label"],
        one.display().to_string()
    );
    // only the worse variant: exit 1
    let out = run(&[&one]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}

#[test]
fn build_variant_file_may_be_code_page_437() {
    let python = python_or_skip!();
    let f = build_fixture::fixture(&python, "");
    f.write_obj("V001", &[("_sub", build_fixture::SUB)]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp.c");
    // 0x84 is "ä" in code page 437 and not valid UTF-8
    let mut text = b"/* \x84 */\nint sub(int a, int b)\n{\n    return a - b;\n}\n".to_vec();
    std::fs::write(&path, &text).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_decovery"))
            .args(["build", "--function", "sub", "--json", "--workspace"])
            .arg(f.root())
            .arg("--variant")
            .arg(&path)
            .output()
            .expect("run decovery")
    };
    let out = run();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["data"]["variants"][0]["verdict"], "identical");
    text.clear();
}
