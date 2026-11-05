//! Output generation on a synthetic workspace.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_core::{
    AccessKind, Address, Analysis, AnalyzedFunction, CallEdge, DataAccess, Provider, StringItem,
    Symbol, SymbolKind, Workspace, knowledge_hash,
};
use decovery_facade::Session;
use decovery_facade::output::{
    Change, function_path, render_function, status_counts, write_affected, write_all,
};

const SHA: &str = "aa";

fn flat(a: u32) -> Address {
    Address::Flat(a)
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

[[target.segment]]
name = "data"
start = "flat:00020000"
length = 4096
file_offset = 4608
file_length = 2048
permissions = "rw"
"#;

const SYMBOLS: &str = r#"schema = 1

[[symbol]]
address = "flat:00010010"
kind = "function"
name = "alpha"
source = "human"
confidence = "confirmed"

[[symbol]]
address = "flat:00010200"
kind = "function"
name = "gamma"
source = "agent"
confidence = "assumed"

[[symbol]]
address = "flat:00020000"
kind = "global"
name = "counter"
source = "agent"
confidence = "assumed"
"#;

const REBUILD: &str = r#"schema = 1

[[function]]
address = "flat:00010010"
name = "alpha"
file = "main.c"
compiler = "wcc"
flags = "-ox"
result = "identical"
equal = 200
gaps = 40
date = "2026-11-01"
"#;

const FAILED_BODY: &str =
    "/* Dekompilieren fehlgeschlagen: timeout */\n/* Disassembly:\n(nicht verfügbar)\n*/\n";

/// alpha calls the unnamed function at 0x10100 twice and gamma once; gamma calls alpha.
fn workspace() -> (tempfile::TempDir, Session) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::write(root.join("decovery.toml"), CONFIG).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), SYMBOLS).unwrap();
    std::fs::write(root.join("knowledge/rebuild.toml"), REBUILD).unwrap();
    let ws = Workspace::open(root).unwrap();
    let lock = ws.lock(Duration::ZERO).unwrap();
    let mut a = Analysis::new(
        Provider::new("ghidra", "11.3"),
        SHA,
        knowledge_hash(root).unwrap(),
        "2026-11-05",
    );
    let mut gamma = AnalyzedFunction::new(flat(0x10200), flat(0x1023F), 64);
    gamma.decompile_error = Some("timeout".into());
    a.functions = vec![
        AnalyzedFunction::new(flat(0x10010), flat(0x100FF), 240),
        AnalyzedFunction::new(flat(0x10100), flat(0x1017F), 128),
        gamma,
    ];
    a.calls = vec![
        CallEdge::new(flat(0x10020), flat(0x10010), flat(0x10100)),
        CallEdge::new(flat(0x10030), flat(0x10010), flat(0x10100)),
        CallEdge::new(flat(0x10040), flat(0x10010), flat(0x10200)),
        CallEdge::new(flat(0x10210), flat(0x10200), flat(0x10010)),
    ];
    a.strings = vec![StringItem::new(flat(0x20010), "hello", vec![flat(0x10010)])];
    a.data_accesses = vec![
        DataAccess::new(flat(0x10010), flat(0x20000), AccessKind::Read),
        DataAccess::new(flat(0x10100), flat(0x20000), AccessKind::Write),
    ];
    a.save(root, &lock).unwrap();
    Analysis::save_decompiled(
        root,
        flat(0x10010),
        "\nint alpha(void) { return 0; }\n",
        &lock,
    )
    .unwrap();
    Analysis::save_decompiled(root, flat(0x10100), "\nvoid fun_00010100(void) {}\n", &lock)
        .unwrap();
    Analysis::save_decompiled(root, flat(0x10200), FAILED_BODY, &lock).unwrap();
    drop(lock);
    let session = Session::open(root).unwrap();
    (dir, session)
}

fn functions_dir(root: &Path) -> PathBuf {
    root.join("output").join("functions").join("code")
}

/// Every file below `output/`, relative path to bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, base, out);
            } else {
                out.insert(
                    p.strip_prefix(base).unwrap().to_path_buf(),
                    std::fs::read(&p).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&root.join("output"), root, &mut out);
    out
}

const ALPHA: &str = "/* @address    flat:00010010 .. flat:000100FF (240 bytes, file 0x210)
 * @name       alpha  [human, confirmed]
 * @called-by  flat:00010200 gamma  (1)
 * @calls      flat:00010100 fun_00010100 (2×), flat:00010200 gamma  (2)
 * @strings    flat:00020010 \"hello\"  (1)
 * @globals    reads flat:00020000 counter
 * @rebuild    identical (main.c, wcc -ox, 200 fixed + 40 linker, 2026-11-01)
 */

int alpha(void) { return 0; }
";

#[test]
fn render_function_is_header_plus_stored_body() {
    let (_d, s) = workspace();
    assert_eq!(render_function(&s, flat(0x10010)).unwrap(), ALPHA);
}

#[test]
fn failed_decompilation_is_shown_in_english() {
    let (_d, s) = workspace();
    let text = render_function(&s, flat(0x10200)).unwrap();
    assert!(
        text.ends_with(
            " */\n/* decompilation failed: timeout */\n/* Disassembly:\n(not available)\n*/\n"
        ),
        "{text}"
    );
}

#[test]
fn write_all_creates_one_file_per_function() {
    let (dir, s) = workspace();
    let root = dir.path();
    let stale = functions_dir(root).join("flat_00010300_gone.c");
    std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
    std::fs::write(&stale, "old").unwrap();

    let lock = s.workspace.lock(Duration::ZERO).unwrap();
    let report = write_all(&s, &lock).unwrap();
    assert_eq!((report.written, report.removed), (3, 1));
    assert!(!stale.exists());
    let mut names: Vec<String> = std::fs::read_dir(functions_dir(root))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "flat_00010010_alpha.c",
            "flat_00010100_fun_00010100.c",
            "flat_00010200_gamma.c"
        ]
    );
    assert_eq!(
        function_path(&s, flat(0x10010)),
        Path::new("output")
            .join("functions")
            .join("code")
            .join("flat_00010010_alpha.c")
    );
    let alpha = std::fs::read_to_string(root.join(function_path(&s, flat(0x10010)))).unwrap();
    assert_eq!(alpha, ALPHA);
}

#[test]
fn index_files_are_written() {
    let (dir, s) = workspace();
    let root = dir.path();
    let lock = s.workspace.lock(Duration::ZERO).unwrap();
    write_all(&s, &lock).unwrap();
    let out = root.join("output");

    let index = std::fs::read_to_string(out.join("index.md")).unwrap();
    assert!(index.starts_with("<!-- generated by decovery; do not edit -->\n"));
    assert!(index.contains("| Address | Name | Size | Called by | Status | File |\n"));
    assert!(
        index.contains(
            "| flat:00010010 | alpha | 240 | 1 | confirmed | [c](functions/code/flat_00010010_alpha.c) |\n"
        ),
        "{index}"
    );
    assert!(index.contains(
        "| flat:00010100 | fun_00010100 | 128 | 1 | unnamed | [c](functions/code/flat_00010100_fun_00010100.c) |\n"
    ));

    let calls: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("calls.json")).unwrap()).unwrap();
    assert_eq!(calls["schema"], 1);
    let edges = calls["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 4);
    assert_eq!(
        edges[0],
        serde_json::json!({"caller": "flat:00010010", "site": "flat:00010020", "callee": "flat:00010100"})
    );
    assert_eq!(edges[3]["caller"], "flat:00010200");

    let strings = std::fs::read_to_string(out.join("strings.md")).unwrap();
    assert!(strings.starts_with("<!-- generated by decovery; do not edit -->\n"));
    assert!(strings.contains("| Address | Text | Used by |\n"));
    assert!(strings.contains("| flat:00020010 | hello | flat:00010010 alpha |\n"));

    let globals = std::fs::read_to_string(out.join("globals.md")).unwrap();
    assert!(globals.starts_with("<!-- generated by decovery; do not edit -->\n"));
    assert!(globals.contains("| Address | Name | Reads | Writes |\n"));
    assert!(globals.contains("| flat:00020000 | counter | alpha | fun_00010100 |\n"));

    let status: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("status.json")).unwrap()).unwrap();
    assert_eq!(
        status,
        serde_json::json!({
            "schema": 1, "functions": 3, "named": 2, "confirmed": 1, "assumed": 1, "unnamed": 1,
            "by_signature": 0, "rebuild_identical": 1, "rebuild_differs": 0, "rebuild_error": 0,
            "rebuild_not_tried": 2
        })
    );
    assert_eq!(status_counts(&s).named, 2);
}

#[test]
fn rename_moves_file_and_updates_callers() {
    let (dir, mut s) = workspace();
    let root = dir.path();
    let lock = s.workspace.lock(Duration::ZERO).unwrap();
    write_all(&s, &lock).unwrap();
    let old = functions_dir(root).join("flat_00010100_fun_00010100.c");
    assert!(old.exists());

    s.workspace
        .symbols
        .push(Symbol::new(flat(0x10100), SymbolKind::Function, "bravo"));
    s.workspace.save_symbols(&lock).unwrap();
    let report = write_affected(
        &s,
        &Change::Renamed {
            at: flat(0x10100),
            old: "fun_00010100".into(),
        },
        &lock,
    )
    .unwrap();

    assert!(!old.exists());
    let new = functions_dir(root).join("flat_00010100_bravo.c");
    let text = std::fs::read_to_string(&new).unwrap();
    assert!(
        text.contains("\n * @name       bravo  [human, assumed]\n"),
        "{text}"
    );
    assert_eq!(report.removed, 1);
    // the renamed function, its caller alpha; no other file of that address remains
    assert_eq!(report.written, 2);
    let alpha = std::fs::read_to_string(functions_dir(root).join("flat_00010010_alpha.c")).unwrap();
    assert!(
        alpha.contains("\n * @calls      flat:00010100 bravo (2×), flat:00010200 gamma  (2)\n"),
        "{alpha}"
    );
    assert!(alpha.contains(
        "\n * @analysis   stale: knowledge changed since analysis (run decovery analyze)\n"
    ));
    let count = std::fs::read_dir(functions_dir(root)).unwrap().count();
    assert_eq!(count, 3);
    let globals = std::fs::read_to_string(root.join("output/globals.md")).unwrap();
    assert!(globals.contains("| flat:00020000 | counter | alpha | bravo |\n"));
}

#[test]
fn symbol_change_rewrites_accessors_of_a_global() {
    let (dir, mut s) = workspace();
    let root = dir.path();
    let lock = s.workspace.lock(Duration::ZERO).unwrap();
    write_all(&s, &lock).unwrap();
    let counter = s
        .workspace
        .symbols
        .iter_mut()
        .find(|x| x.address == flat(0x20000))
        .unwrap();
    counter.name = "total".into();
    s.workspace.save_symbols(&lock).unwrap();
    let report = write_affected(
        &s,
        &Change::Renamed {
            at: flat(0x20000),
            old: "counter".into(),
        },
        &lock,
    )
    .unwrap();
    // alpha reads, the function at 0x10100 writes the global
    assert_eq!((report.written, report.removed), (2, 0));
    let alpha = std::fs::read_to_string(functions_dir(root).join("flat_00010010_alpha.c")).unwrap();
    assert!(
        alpha.contains(" * @globals    reads flat:00020000 total\n"),
        "{alpha}"
    );
}

#[test]
fn unchanged_output_is_byte_identical_on_rewrite() {
    let (dir, s) = workspace();
    let root = dir.path();
    let lock = s.workspace.lock(Duration::ZERO).unwrap();
    write_all(&s, &lock).unwrap();
    let first = snapshot(root);
    let report = write_all(&s, &lock).unwrap();
    assert_eq!((report.written, report.removed), (0, 0));
    assert_eq!(snapshot(root), first);
    assert!(first.keys().all(|p| !p.to_string_lossy().ends_with(".tmp")));
    assert_eq!(first.len(), 3 + 5);
}
