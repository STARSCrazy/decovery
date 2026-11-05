//! `show` and `detail` on a synthetic workspace.

use std::time::Duration;

use decovery_core::{
    AccessKind, Address, Analysis, AnalyzedFunction, CallEdge, DataAccess, Provider, StringItem,
    Workspace, knowledge_hash,
};
use decovery_facade::{Budget, FacadeError, Session, detail, function_path, show, store_handle};

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
fn show_prints_generated_file() {
    let (_d, s) = workspace();
    let r = show(&s, "alpha", Budget::default()).unwrap();
    assert_eq!(r.data["text"], ALPHA);
    assert_eq!(r.data["name"], "alpha");
    assert_eq!(r.data["address"], "flat:00010010");
    assert_eq!(
        r.data["file"],
        "output/functions/code/flat_00010010_alpha.c"
    );
    assert_eq!(r.data["analysis_stale"], false);
    assert_eq!(r.summary, "alpha at flat:00010010: 10 lines");
    assert!(r.handles.is_empty());
}

#[test]
fn show_writes_missing_file() {
    let (d, s) = workspace();
    let path = d.path().join(function_path(&s, Address::Flat(0x10010)));
    assert!(!path.exists());
    let r = show(&s, "flat:00010010", Budget::default()).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), ALPHA);
    assert_eq!(r.data["text"], ALPHA);
}

#[test]
fn show_writes_missing_file_under_the_name_on_disk() {
    let (d, s) = workspace();
    // another writer renames alpha after `s` was opened
    let symbols = d.path().join("knowledge/symbols.toml");
    let text = std::fs::read_to_string(&symbols).unwrap();
    std::fs::write(
        &symbols,
        text.replace("name = \"alpha\"", "name = \"renamed\""),
    )
    .unwrap();
    let r = show(&s, "flat:00010010", Budget::default()).unwrap();
    let dir = d.path().join("output/functions/code");
    assert!(dir.join("flat_00010010_renamed.c").exists());
    assert!(!dir.join("flat_00010010_alpha.c").exists());
    assert_eq!(r.data["name"], "renamed");
    assert_eq!(
        r.data["file"],
        "output/functions/code/flat_00010010_renamed.c"
    );
}

#[test]
fn show_reports_stale_analysis() {
    let (d, s) = workspace();
    std::fs::write(d.path().join("knowledge/types.h"), "struct x;\n").unwrap();
    let r = show(&s, "alpha", Budget::default()).unwrap();
    assert_eq!(r.data["analysis_stale"], true);
    assert!(
        r.summary
            .ends_with(" (analysis is older than the knowledge; run `decovery analyze`)"),
        "{}",
        r.summary
    );
}

#[test]
fn show_over_budget_returns_handle() {
    let (d, s) = workspace();
    let r = show(&s, "alpha", Budget { chars: 300 }).unwrap();
    let text = r.data["text"].as_str().unwrap();
    assert_eq!(r.handles.len(), 1);
    let h = &r.handles[0];
    assert!(h.id.starts_with("h_") && h.id.len() == 14, "{}", h.id);
    assert_eq!(h.kind, "function-text");
    assert_eq!(h.size, ALPHA.len() as u64);
    // header complete, body line cut
    assert!(text.starts_with(&ALPHA[..ALPHA.find("\n */\n").unwrap() + 5]));
    assert!(!text.contains("return 0"));
    assert!(text.ends_with(&format!(
        "/* \u{2026} truncated; full text: detail {} */\n",
        h.id
    )));
    let stored =
        std::fs::read_to_string(d.path().join("cache/handles").join(format!("{}.txt", h.id)))
            .unwrap();
    assert_eq!(stored, ALPHA);
}

#[test]
fn show_budget_smaller_than_header_keeps_header() {
    let (_d, s) = workspace();
    let r = show(&s, "alpha", Budget { chars: 10 }).unwrap();
    assert!(
        r.data["text"]
            .as_str()
            .unwrap()
            .contains(" */\n/* \u{2026} truncated")
    );
}

#[test]
fn show_unknown_function_is_not_found() {
    let (_d, s) = workspace();
    let e = show(&s, "nosuch", Budget::default()).unwrap_err();
    assert!(matches!(e, FacadeError::NotFound(_)), "{e}");
}

#[test]
fn detail_pages_handle() {
    let (d, _s) = workspace();
    let h = store_handle(d.path(), "function-text", "h\u{e4}llo world").unwrap();
    assert_eq!(
        h,
        store_handle(d.path(), "function-text", "h\u{e4}llo world").unwrap()
    );
    let r = detail(d.path(), &h.id, 1, 4).unwrap();
    assert_eq!(r.data["text"], "\u{e4}llo");
    assert_eq!(r.data["total"], 11);
    assert_eq!(r.data["offset"], 1);
    assert_eq!(r.data["limit"], 4);
    assert_eq!(r.data["handle"], h.id.as_str());
    assert_eq!(r.summary, "chars 1..5 of 11");
    let r = detail(d.path(), &h.id, 9, 100).unwrap();
    assert_eq!(r.data["text"], "ld");
    assert_eq!(r.summary, "chars 9..11 of 11");
}

#[test]
fn detail_unknown_handle_is_reported_as_handle() {
    let (d, _s) = workspace();
    for id in [
        "h_000000000000",
        "../../decovery.toml",
        "h_ABCDEF012345",
        "h_12",
    ] {
        let e = detail(d.path(), id, 0, 10).unwrap_err();
        assert!(matches!(e, FacadeError::UnknownHandle(_)), "{id}: {e}");
        assert_eq!(e.to_string(), format!("unknown handle {id}"));
        assert_eq!(e.exit_code(), 2);
    }
}
