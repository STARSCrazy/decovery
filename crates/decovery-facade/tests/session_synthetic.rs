//! Session and target resolution on a synthetic workspace.

use std::path::Path;

use decovery_core::{
    Address, Analysis, AnalyzedFunction, Confidence, Provider, SymbolKind, Workspace,
};
use decovery_facade::{FacadeError, Session, resolve};

const SHA: &str = "aa";

fn flat(a: u32) -> Address {
    Address::Flat(a)
}

fn write_workspace(root: &Path, symbols: &str) {
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::write(
        root.join("decovery.toml"),
        format!(
            r#"schema = 1

[target]
file = "t.exe"
sha256 = "{SHA}"
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
"#
        ),
    )
    .unwrap();
    if !symbols.is_empty() {
        std::fs::write(root.join("knowledge/symbols.toml"), symbols).unwrap();
    }
}

fn write_analysis(root: &Path, sha: &str) {
    let ws = Workspace::open(root).unwrap();
    let lock = ws.lock(std::time::Duration::ZERO).unwrap();
    let mut a = Analysis::new(Provider::new("ghidra", "11.3"), sha, "00", "2026-11-05");
    let mut second = AnalyzedFunction::new(flat(0x10100), flat(0x1017F), 128);
    second.provider_name = Some("FUN_00010100".into());
    a.functions = vec![
        AnalyzedFunction::new(flat(0x10010), flat(0x100FF), 240),
        second,
        AnalyzedFunction::new(flat(0x10200), flat(0x1023F), 64),
    ];
    a.save(root, &lock).unwrap();
}

const SYMBOLS: &str = r#"schema = 1

[[symbol]]
address = "flat:00010010"
kind = "function"
name = "choose"
source = "human"
confidence = "confirmed"

[[symbol]]
address = "flat:00010200"
kind = "function"
name = "old_name"
source = "agent"
confidence = "refuted"
"#;

fn session() -> (tempfile::TempDir, Session) {
    let dir = tempfile::tempdir().unwrap();
    write_workspace(dir.path(), SYMBOLS);
    write_analysis(dir.path(), SHA);
    let s = Session::open(dir.path()).unwrap();
    (dir, s)
}

#[test]
fn resolves_name() {
    let (_d, s) = session();
    let r = resolve(&s, "choose").unwrap();
    assert_eq!(r.function, flat(0x10010));
    assert_eq!(r.requested, flat(0x10010));
    // analysis provider name
    assert_eq!(resolve(&s, "FUN_00010100").unwrap().function, flat(0x10100));
    // canonical text
    assert_eq!(
        resolve(&s, "flat:00010100").unwrap().function,
        flat(0x10100)
    );
}

#[test]
fn resolves_default_name() {
    let (_d, s) = session();
    let r = resolve(&s, "fun_00010200").unwrap();
    assert_eq!(r.function, flat(0x10200));
    assert_eq!(s.name_of(flat(0x10200)).name, "fun_00010200");
    assert!(s.name_of(flat(0x10200)).is_default);
    let n = s.name_of(flat(0x10010));
    assert_eq!(n.name, "choose");
    assert!(!n.is_default);
}

#[test]
fn resolves_file_offset() {
    let (_d, s) = session();
    // file 0x210 is code segment offset 0x10
    let r = resolve(&s, "file:0x210").unwrap();
    assert_eq!(r.requested, flat(0x10010));
    assert_eq!(r.function, flat(0x10010));
    match resolve(&s, "file:0x10") {
        Err(FacadeError::Invalid(m)) => assert!(m.contains("file offset 0x10"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn resolves_address_inside_function() {
    let (_d, s) = session();
    let r = resolve(&s, "flat:00010050").unwrap();
    assert_eq!(r.function, flat(0x10010));
    assert_eq!(r.requested, flat(0x10050));
}

#[test]
fn address_in_no_function_names_nearest() {
    let (_d, s) = session();
    // 0x10190 is 0x11 after the end of the function at 0x10100 and 0x70 before the next start
    let err = resolve(&s, "flat:00010190").unwrap_err();
    match &err {
        FacadeError::NotInFunction { address, nearest } => {
            assert_eq!(*address, flat(0x10190));
            assert_eq!(nearest.as_ref().unwrap().0, flat(0x10100));
        }
        other => panic!("{other:?}"),
    }
    let text = err.to_string();
    assert!(text.contains("flat:00010190 is in no function"), "{text}");
    assert!(
        text.contains("(nearest: fun_00010100 at flat:00010100)"),
        "{text}"
    );
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn address_outside_map_is_rejected() {
    let (_d, s) = session();
    match resolve(&s, "flat:00050000") {
        Err(FacadeError::OutsideMap(a)) => assert_eq!(a, flat(0x50000)),
        other => panic!("{other:?}"),
    }
    let text = resolve(&s, "flat:00050000").unwrap_err().to_string();
    assert!(text.contains("outside the memory map"), "{text}");
}

#[test]
fn unknown_name_is_not_found() {
    let (_d, s) = session();
    match resolve(&s, "nothing_here") {
        Err(FacadeError::NotFound(n)) => assert_eq!(n, "nothing_here"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn missing_analysis_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    write_workspace(dir.path(), SYMBOLS);
    let err = Session::open(dir.path()).err().unwrap();
    assert!(matches!(err, FacadeError::NoAnalysis));
    assert_eq!(
        err.to_string(),
        "no analysis for this target; run `decovery analyze`"
    );
    assert_eq!(err.exit_code(), 2);
    let s = Session::open_without_analysis(dir.path()).unwrap();
    assert!(s.analysis.functions.is_empty());
    assert_eq!(s.analysis.provider.name, "none");
    assert_eq!(s.analysis.target_sha256, SHA);
    assert_eq!(s.name_of(flat(0x10010)).name, "choose");
}

#[test]
fn analysis_of_other_target_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write_workspace(dir.path(), SYMBOLS);
    write_analysis(dir.path(), "bb");
    match Session::open(dir.path()) {
        Err(FacadeError::AnalysisOfOtherTarget { expected, found }) => {
            assert_eq!(expected, "aa");
            assert_eq!(found, "bb");
        }
        other => panic!("{:?}", other.err()),
    }
    assert!(matches!(
        Session::open_without_analysis(dir.path()),
        Err(FacadeError::AnalysisOfOtherTarget { .. })
    ));
}

#[test]
fn refuted_symbol_is_not_used_for_names() {
    let (_d, s) = session();
    assert_eq!(s.name_of(flat(0x10200)).name, "fun_00010200");
    assert!(s.symbol_at(flat(0x10200)).is_none());
    assert!(matches!(
        resolve(&s, "old_name"),
        Err(FacadeError::NotFound(_))
    ));
    let sym = s.symbol_at(flat(0x10010)).unwrap();
    assert_eq!(sym.kind, SymbolKind::Function);
    assert_ne!(sym.confidence, Confidence::Refuted);
}

#[test]
fn empty_target_is_invalid() {
    let (_d, s) = session();
    for input in ["", "   "] {
        match resolve(&s, input) {
            Err(FacadeError::Invalid(m)) => assert_eq!(m, "empty target"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn odd_inputs_do_not_panic() {
    let (_d, s) = session();
    for input in ["file:0x", "file:0xFFFFFFFFFFFFFFFFFF", "flat:FFFFFFFFF"] {
        assert!(
            matches!(resolve(&s, input), Err(FacadeError::Invalid(_))),
            "{input}"
        );
    }
}
