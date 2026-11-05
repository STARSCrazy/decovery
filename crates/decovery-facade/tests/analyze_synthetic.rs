//! `analyze` against a fake analyzer plugin (Python, built on the SDK) and a synthetic LE target.
//! The plugin tests are skipped (with a message) when no Python is found: set `DECOVERY_PYTHON` or put
//! `python` on PATH.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use decovery_core::{
    Address, Analysis, AnalyzedFunction, ArchMode, ClaimSource, Confidence, ExecutableFormat,
    Permissions, Program, Provider, Region, Workspace, knowledge_hash,
};
use decovery_facade::plugins::PluginConfig;
use decovery_facade::{
    AnalyzeOptions, AnnotateAction, Annotation, Budget, FacadeError, Progress, Session,
    analyze_with_user_plugins, annotate, program_description, show,
};
use serde_json::{Value, json};

fn flat(a: u32) -> Address {
    Address::Flat(a)
}

// -- synthetic LE image (one page size, no fixups) -----------------------------------------------------------

const PAGE: usize = 0x100;
const HEADER: usize = 0xAC;

struct Obj {
    base: u32,
    flags: u32,
    data: Vec<u8>,
}

fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

/// MZ stub + LE header + object table + page map + empty fixup tables + page data; entry `obj1:0x10`.
fn build_le(objects: &[Obj]) -> Vec<u8> {
    let pages_of = |o: &Obj| o.data.len().div_ceil(PAGE);
    let total_pages: usize = objects.iter().map(pages_of).sum();
    let last_page = match objects.last().map_or(0, |o| o.data.len() % PAGE) {
        0 => PAGE,
        rem => rem,
    };
    let k = 0x40usize;
    let obj_tab = HEADER;
    let page_map = obj_tab + 24 * objects.len();
    let fpt = page_map + 4 * total_pages;
    let frt = fpt + 4 * (total_pages + 1);
    let data_pages = k + frt;

    let mut out = vec![0u8; k + HEADER];
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3C, k as u32);
    let h = k;
    out[h..h + 2].copy_from_slice(b"LE");
    put32(&mut out, h + 0x14, total_pages as u32);
    put32(&mut out, h + 0x18, 1);
    put32(&mut out, h + 0x1C, 0x10);
    put32(&mut out, h + 0x20, objects.len() as u32);
    put32(&mut out, h + 0x24, 0x40);
    put32(&mut out, h + 0x28, PAGE as u32);
    put32(&mut out, h + 0x2C, last_page as u32);
    put32(&mut out, h + 0x40, obj_tab as u32);
    put32(&mut out, h + 0x44, objects.len() as u32);
    put32(&mut out, h + 0x48, page_map as u32);
    put32(&mut out, h + 0x68, fpt as u32);
    put32(&mut out, h + 0x6C, frt as u32);
    put32(&mut out, h + 0x80, data_pages as u32);

    let mut first = 0u32;
    for o in objects {
        for x in [
            o.data.len() as u32,
            o.base,
            o.flags,
            first + 1,
            pages_of(o) as u32,
            0,
        ] {
            out.extend_from_slice(&x.to_le_bytes());
        }
        first += pages_of(o) as u32;
    }
    for p in 1..=total_pages as u32 {
        out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8, 0]);
    }
    for _ in 0..=total_pages {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    assert_eq!(out.len(), data_pages);
    for o in objects {
        out.extend_from_slice(&o.data);
        out.resize(
            out.len() + o.data.len().next_multiple_of(PAGE) - o.data.len(),
            0,
        );
    }
    out.truncate(data_pages + (total_pages - 1) * PAGE + last_page);
    out
}

/// Code object above the 64 KiB inline limit (goes by file), small data object (inline).
const CODE_SIZE: usize = 0x11000;
const DATA_SIZE: usize = 0x100;

fn le_image() -> Vec<u8> {
    build_le(&[
        Obj {
            base: 0x10000,
            flags: 0x2025,
            data: (0..CODE_SIZE).map(|i| (i % 251) as u8).collect(),
        },
        Obj {
            base: 0x30000,
            flags: 0x2043,
            data: vec![0x11; DATA_SIZE],
        },
    ])
}

// -- workspace ------------------------------------------------------------------------------------------------

const CONFIG: &str = r#"schema = 1

[target]
file = "t.exe"
sha256 = "aa"
format = "le"
processor = "x86"

[[target.segment]]
name = "code"
start = "flat:00010000"
length = 69632
permissions = "rx"

[[target.segment]]
name = "data"
start = "flat:00030000"
length = 256
permissions = "rw"

[analysis]
prologues = []
calling_convention = "__watcall"
"#;

const SYMBOLS: &str = r#"schema = 1

[[symbol]]
address = "flat:00010010"
kind = "function"
name = "alpha"
signature = "int alpha(int x)"
source = "human"
confidence = "confirmed"

[[symbol]]
address = "flat:00010100"
kind = "function"
name = "wrong"
source = "agent"
confidence = "refuted"

[[symbol]]
address = "flat:00030000"
kind = "global"
name = "counter"
type = "int"
source = "agent"
confidence = "assumed"
"#;

const REFERENCES: &str = r#"schema = 1

[[reference]]
from = "flat:00010050"
to = "flat:00010200"
kind = "call"
source = "human"
"#;

fn python() -> Option<String> {
    let candidate = std::env::var("DECOVERY_PYTHON").unwrap_or_else(|_| "python".into());
    let ok = std::process::Command::new(&candidate)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then_some(candidate)
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_analyzer.py")
}

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// Workspace with LE target, knowledge and a stale analysis of an old function; `[plugins.fake]` points to the
/// fake analyzer when `python` is given.
fn workspace(python: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::write(root.join("t.exe"), le_image()).unwrap();
    let mut config = CONFIG.to_string();
    if let Some(python) = python {
        config.push_str(&format!(
            "\n[plugins.fake]\ncommand = [{}, {}]\nenv = {{ FAKE_VERSION = \"9.9\" }}\n",
            toml_string(python),
            toml_string(fixture().to_str().unwrap())
        ));
    }
    std::fs::write(root.join("decovery.toml"), config).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), SYMBOLS).unwrap();
    std::fs::write(root.join("knowledge/references.toml"), REFERENCES).unwrap();
    std::fs::write(root.join("knowledge/types.h"), "typedef int fake_t;\n").unwrap();
    // An earlier analysis with a function the plugin no longer reports.
    let ws = Workspace::open(root).unwrap();
    let lock = ws.lock(Duration::ZERO).unwrap();
    let mut old = Analysis::new(Provider::new("fake", "0"), "aa", "old", "2026-01-01");
    old.functions = vec![AnalyzedFunction::new(flat(0x10300), flat(0x1030F), 16)];
    old.save(root, &lock).unwrap();
    Analysis::save_decompiled(root, flat(0x10300), "void old(void) {}\n", &lock).unwrap();
    dir
}

fn options(functions: Option<Vec<&str>>) -> AnalyzeOptions {
    AnalyzeOptions {
        plugin: "fake".into(),
        functions: functions.map(|f| f.into_iter().map(String::from).collect()),
    }
}

fn run(root: &Path, functions: Option<Vec<&str>>) -> (Value, Vec<Progress>) {
    let seen = Mutex::new(Vec::new());
    let sink = |p: Progress| seen.lock().unwrap().push(p);
    let response =
        analyze_with_user_plugins(root, &options(functions), &BTreeMap::new(), &sink).unwrap();
    (response.data, seen.into_inner().unwrap())
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn body(root: &Path, at: u32) -> Option<String> {
    Analysis::decompiled(root, flat(at)).unwrap()
}

// -- tests ----------------------------------------------------------------------------------------------------

#[test]
fn program_description_shape() {
    let rx = Permissions {
        read: true,
        write: false,
        execute: true,
    };
    let rw = Permissions {
        read: true,
        write: true,
        execute: false,
    };
    let big: Vec<u8> = (0..CODE_SIZE).map(|i| (i % 7) as u8).collect();
    let program = Program::new(
        ExecutableFormat::Le,
        vec![
            Region::new(
                "obj1",
                flat(0x10000),
                CODE_SIZE as u64,
                big.clone(),
                rx,
                ArchMode::X86Flat32,
            ),
            Region::new(
                "obj2",
                flat(0x30000),
                0x200,
                b"Man".to_vec(),
                rw,
                ArchMode::X86Flat32,
            ),
        ],
        vec![flat(0x10010)],
        Vec::new(),
    );
    let d = program_description(&program);
    assert_eq!(d["format"], "le");
    assert_eq!(d["entry_points"], json!(["flat:00010010"]));
    let regions = d["regions"].as_array().unwrap();
    assert_eq!(regions.len(), 2);
    let hash = blake3::hash(&big).to_hex().to_string();
    assert_eq!(
        regions[0],
        json!({
            "name": "obj1", "start": "flat:00010000", "size": CODE_SIZE, "arch": "x86-flat-32",
            "permissions": "r-x",
            "blob": {"blob": {"path": format!("cache/blobs/{hash}"), "blake3": hash}},
        })
    );
    assert_eq!(
        regions[1],
        json!({
            "name": "obj2", "start": "flat:00030000", "size": 0x200, "arch": "x86-flat-32",
            "permissions": "rw-", "blob": {"inline_base64": "TWFu"},
        })
    );
    // Deterministic.
    assert_eq!(program_description(&program), d);
}

#[test]
fn analyze_with_fake_plugin_writes_analysis_and_output() {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
        return;
    };
    let dir = workspace(Some(&python));
    let root = dir.path();
    let (data, progress) = run(root, None);

    assert_eq!(data["provider"], "fake");
    assert_eq!(
        data["version"], "9.9",
        "env of the plugin config reaches the plugin"
    );
    assert_eq!(data["functions"], 3);
    assert_eq!(data["calls"], 2);
    assert_eq!(data["strings"], 1);
    assert_eq!(data["data_accesses"], 2);
    assert_eq!(data["decompiled"], 2);
    assert_eq!(data["failed"], 1);
    assert_eq!(data["warnings"], json!(["fake warning"]));
    assert!(data["written"].as_u64().unwrap() >= 3);
    assert!(
        progress
            .iter()
            .any(|p| p.message.as_deref() == Some("analyzing 2")),
        "plugin progress is forwarded: {progress:?}"
    );

    // analysis store
    let a = Analysis::load(root).unwrap().unwrap();
    assert_eq!(a.provider, Provider::new("fake", "9.9"));
    assert_eq!(a.target_sha256, "aa");
    assert_eq!(a.knowledge_hash, knowledge_hash(root).unwrap());
    assert_eq!(a.created.len(), 10);
    let starts: Vec<Address> = a.functions.iter().map(|f| f.start).collect();
    assert_eq!(starts, [flat(0x10010), flat(0x10100), flat(0x10200)]);
    assert_eq!(a.functions[0].end, flat(0x100FF));
    assert_eq!(a.functions[0].body_size, 240);
    assert_eq!(a.functions[0].provider_name, None);
    assert_eq!(a.functions[1].provider_name.as_deref(), Some("FUN_helper"));
    assert_eq!(a.functions[0].decompile_error, None);
    assert_eq!(
        a.functions[2].decompile_error.as_deref(),
        Some("fake timeout */ here")
    );
    assert_eq!(a.calls.len(), 2);
    assert_eq!(a.strings[0].text, "hello");
    assert_eq!(a.data_accesses.len(), 2);

    // bodies: line endings normalized, failure body with disassembly, vanished function removed
    assert_eq!(
        body(root, 0x10010).unwrap(),
        "\nvoid flat_00010010(void)\n{\n  /* run 1 */\n}\n"
    );
    assert_eq!(
        body(root, 0x10200).unwrap(),
        "/* decompilation failed: fake timeout * / here */\n/* Disassembly:\n\
         flat:00010200  PUSH EBP\nflat:00010201  RET\n*/\n"
    );
    assert_eq!(body(root, 0x10300), None, "body of a vanished function");

    // output
    let alpha = root.join("output/functions/code/flat_00010010_alpha.c");
    let text = std::fs::read_to_string(&alpha).unwrap();
    assert!(text.contains("/* run 1 */"), "{text}");
    let failed =
        std::fs::read_to_string(root.join("output/functions/code/flat_00010200_fun_00010200.c"))
            .unwrap();
    assert!(failed.contains("flat:00010201  RET"), "{failed}");
    let status = read_json(&root.join("output/status.json"));
    assert_eq!(status["analysis_stale"], false);

    // what the plugin received
    let project = root.join("cache").join("fake");
    let open = read_json(&project.join("open.json"));
    assert_eq!(
        Path::new(open["project_dir"].as_str().unwrap()),
        project.as_path()
    );
    let hash = open["program_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert_eq!(open["options"]["calling_convention"], "__watcall");
    assert_eq!(open["blob_sizes"], json!([CODE_SIZE, DATA_SIZE]));
    let code_blob = &open["program"]["regions"][0]["blob"]["blob"];
    let blob_path = PathBuf::from(code_blob["path"].as_str().unwrap());
    assert!(blob_path.is_absolute());
    assert!(blob_path.starts_with(root.join("cache").join("blobs")));
    let blob = std::fs::read(&blob_path).unwrap();
    assert_eq!(code_blob["blake3"], blake3::hash(&blob).to_hex().as_str());
    assert!(
        open["program"]["regions"][1]["blob"]["inline_base64"].is_string(),
        "small region inline"
    );
    let apply = read_json(&project.join("apply.json"));
    assert_eq!(apply["types_h"], "typedef int fake_t;\n");
    let symbols = apply["symbols"].as_array().unwrap();
    assert_eq!(symbols.len(), 2, "refuted symbol not applied: {symbols:?}");
    assert_eq!(symbols[0]["address"], "flat:00010010");
    assert_eq!(symbols[0]["kind"], "function");
    assert_eq!(symbols[0]["name"], "alpha");
    assert_eq!(symbols[0]["signature"], "int alpha(int x)");
    assert_eq!(symbols[1]["data_type"], "int");
    assert_eq!(
        apply["references"],
        json!([{"from": "flat:00010050", "to": "flat:00010200", "kind": "call"}])
    );
    let decompile = read_json(&project.join("decompile-1.json"));
    assert_eq!(
        decompile["addresses"],
        json!(["flat:00010010", "flat:00010100", "flat:00010200"])
    );
    assert!(project.join("shutdown.txt").is_file(), "plugin shut down");

    // a second run with the same program sends the same hash
    run(root, None);
    let again = read_json(&project.join("open.json"));
    assert_eq!(again["program_hash"], hash);
}

#[test]
fn analyze_selection_replaces_only_selected_bodies() {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
        return;
    };
    let dir = workspace(Some(&python));
    let root = dir.path();
    run(root, None);
    let (data, _) = run(root, Some(vec!["alpha"]));
    assert_eq!(data["decompiled"], 1);
    assert_eq!(data["failed"], 0);
    assert_eq!(data["functions"], 3);

    let decompile = read_json(&root.join("cache/fake/decompile-2.json"));
    assert_eq!(decompile["addresses"], json!(["flat:00010010"]));
    assert!(body(root, 0x10010).unwrap().contains("/* run 2 */"));
    assert!(body(root, 0x10100).unwrap().contains("/* run 1 */"));
    assert!(
        body(root, 0x10200)
            .unwrap()
            .starts_with("/* decompilation failed")
    );
    let a = Analysis::load(root).unwrap().unwrap();
    assert_eq!(a.functions.len(), 3);
    assert_eq!(
        a.functions[2].decompile_error.as_deref(),
        Some("fake timeout */ here"),
        "error of an unselected function is kept"
    );
    let alpha =
        std::fs::read_to_string(root.join("output/functions/code/flat_00010010_alpha.c")).unwrap();
    assert!(alpha.contains("/* run 2 */"), "{alpha}");

    // an unknown selection fails before anything is written
    let err = analyze_with_user_plugins(
        root,
        &options(Some(vec!["nosuchname"])),
        &BTreeMap::new(),
        &|_| {},
    )
    .unwrap_err();
    assert!(matches!(err, FacadeError::NotFound(_)), "{err}");
    assert!(body(root, 0x10010).unwrap().contains("/* run 2 */"));
}

#[test]
fn analyze_without_plugin_config_explains_setup() {
    let dir = workspace(None);
    let root = dir.path();
    let before = std::fs::read(root.join("knowledge/analysis/analysis.json")).unwrap();
    let opts = AnalyzeOptions::default();
    assert_eq!(opts.plugin, "ghidra");
    assert_eq!(opts.functions, None);
    let err = analyze_with_user_plugins(root, &opts, &BTreeMap::new(), &|_| {}).unwrap_err();
    match &err {
        FacadeError::Plugin(message) => {
            assert_eq!(message, "no analyzer configured; run decovery setup ghidra")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        std::fs::read(root.join("knowledge/analysis/analysis.json")).unwrap(),
        before
    );

    // A user config entry is used when the workspace has none; a broken command is reported as plugin error.
    let user = BTreeMap::from([(
        "ghidra".to_string(),
        PluginConfig::new(vec!["decovery-no-such-program-xyz".into()]),
    )]);
    let err = analyze_with_user_plugins(root, &opts, &user, &|_| {}).unwrap_err();
    match &err {
        FacadeError::Plugin(message) => assert!(message.starts_with("ghidra: "), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn annotate_after_analyze_marks_output_stale() {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
        return;
    };
    let dir = workspace(Some(&python));
    let root = dir.path();
    run(root, None);
    let index = std::fs::read_to_string(root.join("output/index.md")).unwrap();
    assert!(
        !index.contains("Analysis is older than the knowledge"),
        "{index}"
    );
    let session = Session::open(root).unwrap();
    assert_eq!(
        show(&session, "alpha", Budget::default()).unwrap().data["analysis_stale"],
        false
    );

    let request = Annotation {
        target: "flat:00010100".into(),
        action: AnnotateAction::Name("helper".into()),
        confidence: Confidence::Assumed,
        source: ClaimSource::Agent,
        evidence: None,
        force: false,
    };
    annotate(root, &request).unwrap();
    let status = read_json(&root.join("output/status.json"));
    assert_eq!(status["analysis_stale"], true);
    let index = std::fs::read_to_string(root.join("output/index.md")).unwrap();
    assert!(
        index.contains("Analysis is older than the knowledge"),
        "{index}"
    );
    let session = Session::open(root).unwrap();
    assert_eq!(
        show(&session, "helper", Budget::default()).unwrap().data["analysis_stale"],
        true
    );

    // analyze again: fresh
    run(root, None);
    let status = read_json(&root.join("output/status.json"));
    assert_eq!(status["analysis_stale"], false);
}

#[test]
fn selection_run_never_prunes() {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
        return;
    };
    // The workspace holds a body for flat:00010300, a function the fake export does not return.
    let dir = workspace(Some(&python));
    let root = dir.path();
    assert!(body(root, 0x10300).is_some());
    let (data, _) = run(root, Some(vec!["alpha"]));
    assert_eq!(data["decompiled"], 1);
    assert_eq!(
        body(root, 0x10300).as_deref(),
        Some("void old(void) {}\n"),
        "a selection run keeps every other body"
    );
    assert!(body(root, 0x10010).unwrap().contains("/* run 1 */"));
    // A full run prunes it.
    run(root, None);
    assert_eq!(body(root, 0x10300), None);
}
