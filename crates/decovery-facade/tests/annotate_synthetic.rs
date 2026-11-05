//! `annotate` on a synthetic workspace.

use std::path::Path;
use std::time::Duration;

use decovery_core::{
    AccessKind, Address, Analysis, AnalyzedFunction, CallEdge, ClaimSource, Confidence, DataAccess,
    Provider, Symbol, SymbolKind, Workspace, knowledge_hash,
};
use decovery_facade::{AnnotateAction, Annotation, FacadeError, Session, annotate, write_all};

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

fn write_files(root: &Path, symbols: &str, with_analysis: bool) {
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::write(root.join("decovery.toml"), CONFIG).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), symbols).unwrap();
    if !with_analysis {
        return;
    }
    let ws = Workspace::open(root).unwrap();
    let lock = ws.lock(Duration::ZERO).unwrap();
    let mut a = Analysis::new(
        Provider::new("ghidra", "11.3"),
        SHA,
        knowledge_hash(root).unwrap(),
        "2026-11-05",
    );
    a.functions = vec![
        AnalyzedFunction::new(flat(0x10010), flat(0x100FF), 240),
        AnalyzedFunction::new(flat(0x10100), flat(0x1017F), 128),
        AnalyzedFunction::new(flat(0x10200), flat(0x1023F), 64),
    ];
    a.calls = vec![
        CallEdge::new(flat(0x10020), flat(0x10010), flat(0x10100)),
        CallEdge::new(flat(0x10040), flat(0x10010), flat(0x10200)),
        CallEdge::new(flat(0x10210), flat(0x10200), flat(0x10010)),
    ];
    a.data_accesses = vec![
        DataAccess::new(flat(0x10010), flat(0x20000), AccessKind::Read),
        DataAccess::new(flat(0x10100), flat(0x20000), AccessKind::Write),
    ];
    a.save(root, &lock).unwrap();
    Analysis::save_decompiled(root, flat(0x10010), "\nint a(void) { return 0; }\n", &lock).unwrap();
    Analysis::save_decompiled(root, flat(0x10100), "\nvoid b(void) {}\n", &lock).unwrap();
    Analysis::save_decompiled(root, flat(0x10200), "\nvoid c(void) {}\n", &lock).unwrap();
    drop(lock);
}

/// Workspace with analysis and generated output.
fn workspace_with(symbols: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), symbols, true);
    let session = Session::open(dir.path()).unwrap();
    let lock = session.workspace.lock(Duration::ZERO).unwrap();
    write_all(&session, &lock).unwrap();
    drop(lock);
    dir
}

fn workspace() -> tempfile::TempDir {
    workspace_with(SYMBOLS)
}

fn request(target: &str, action: AnnotateAction) -> Annotation {
    Annotation {
        target: target.into(),
        action,
        confidence: Confidence::Assumed,
        source: ClaimSource::Human,
        evidence: None,
        force: false,
    }
}

fn agent(target: &str, action: AnnotateAction) -> Annotation {
    Annotation {
        source: ClaimSource::Agent,
        ..request(target, action)
    }
}

fn name(n: &str) -> AnnotateAction {
    AnnotateAction::Name(n.into())
}

fn symbols(root: &Path) -> Vec<Symbol> {
    Workspace::open(root).unwrap().symbols
}

fn symbol_at(root: &Path, at: u32) -> Symbol {
    symbols(root)
        .into_iter()
        .find(|s| s.address == flat(at))
        .unwrap()
}

fn functions_dir(root: &Path) -> std::path::PathBuf {
    root.join("output/functions/code")
}

fn symbols_bytes(root: &Path) -> Vec<u8> {
    std::fs::read(root.join("knowledge/symbols.toml")).unwrap()
}

fn invalid(result: Result<decovery_facade::Response, FacadeError>) -> String {
    match result {
        Err(FacadeError::Invalid(m)) => m,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn names_function_and_updates_output() {
    let d = workspace();
    let root = d.path();
    assert!(
        functions_dir(root)
            .join("flat_00010100_fun_00010100.c")
            .exists()
    );
    let r = annotate(root, &request("flat:00010100", name("beta"))).unwrap();
    assert_eq!(r.summary, "named flat:00010100 beta (was fun_00010100)");
    assert_eq!(r.data["changed"], true);
    assert_eq!(r.data["target"], "flat:00010100");
    assert_eq!(r.data["action"], "name");
    assert_eq!(r.data["warnings"], serde_json::json!([]));
    assert!(
        !functions_dir(root)
            .join("flat_00010100_fun_00010100.c")
            .exists()
    );
    assert!(functions_dir(root).join("flat_00010100_beta.c").exists());
    assert_eq!(r.data["output"]["removed"], 1);
    assert!(r.data["output"]["written"].as_u64().unwrap() >= 2);
    let caller =
        std::fs::read_to_string(functions_dir(root).join("flat_00010010_alpha.c")).unwrap();
    assert!(caller.contains("beta"), "{caller}");
    let s = symbol_at(root, 0x10100);
    assert_eq!(s.name, "beta");
    assert_eq!(s.kind, SymbolKind::Function);
    assert_eq!(
        (s.source, s.confidence),
        (ClaimSource::Human, Confidence::Assumed)
    );
}

#[test]
fn rejects_invalid_identifier() {
    let d = workspace();
    let before = symbols_bytes(d.path());
    for bad in ["9lives", "a-b", "\u{dc}n\u{ef}", "", "a b"] {
        let m = invalid(annotate(d.path(), &request("alpha", name(bad))));
        assert!(m.contains("[A-Za-z_][A-Za-z0-9_]*"), "{m}");
    }
    assert_eq!(symbols_bytes(d.path()), before);
}

#[test]
fn rejects_c_keyword() {
    let d = workspace();
    let before = symbols_bytes(d.path());
    for kw in ["while", "int", "_Bool", "restrict"] {
        let m = invalid(annotate(d.path(), &request("flat:00010100", name(kw))));
        assert!(m.contains("C keyword"), "{m}");
    }
    assert_eq!(symbols_bytes(d.path()), before);
}

#[test]
fn agent_assumed_does_not_replace_human_name() {
    let d = workspace();
    let before = symbols_bytes(d.path());
    let r = annotate(d.path(), &agent("alpha", name("renamed"))).unwrap();
    assert_eq!(r.data["changed"], false);
    assert!(r.summary.starts_with("no change: "), "{}", r.summary);
    let warnings = r.data["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].as_str().unwrap().contains("force"));
    assert_eq!(symbols_bytes(d.path()), before);
    // an agent's confirmed claim is still below a human's
    let mut req = agent("alpha", name("renamed"));
    req.confidence = Confidence::Confirmed;
    assert_eq!(annotate(d.path(), &req).unwrap().data["changed"], false);
    // but it replaces an agent's assumed one
    let r = annotate(d.path(), &agent("gamma", name("gamma2"))).unwrap();
    assert_eq!(r.data["changed"], true);
    assert_eq!(symbol_at(d.path(), 0x10200).name, "gamma2");
}

#[test]
fn force_replaces_and_records_history() {
    let d = workspace();
    let mut req = agent("alpha", name("renamed"));
    req.force = true;
    req.evidence = Some("seen in trace".into());
    let r = annotate(d.path(), &req).unwrap();
    assert_eq!(r.data["changed"], true);
    let s = symbol_at(d.path(), 0x10010);
    assert_eq!(s.name, "renamed");
    assert_eq!(s.source, ClaimSource::Agent);
    assert_eq!(s.evidence.as_deref(), Some("seen in trace"));
    assert_eq!(s.refuted.len(), 1);
    let h = &s.refuted[0];
    assert_eq!(h.name, "alpha");
    assert_eq!(h.source, Some(ClaimSource::Human));
    assert_eq!(h.confidence, Some(Confidence::Confirmed));
    assert_eq!(h.note.as_deref(), Some("replaced by renamed (forced)"));
    assert_eq!(h.date.as_ref().map(String::len), Some(10));
    assert!(
        functions_dir(d.path())
            .join("flat_00010010_renamed.c")
            .exists()
    );
    assert!(
        !functions_dir(d.path())
            .join("flat_00010010_alpha.c")
            .exists()
    );
}

#[test]
fn signature_source_name_goes_to_refuted_history() {
    let symbols = format!(
        "{SYMBOLS}\n[[symbol]]\naddress = \"flat:00010100\"\nkind = \"function\"\nname = \"memcpy_like\"\nsource = \"signature\"\nconfidence = \"assumed\"\nevidence = \"pattern\"\n"
    );
    let d = workspace_with(&symbols);
    let r = annotate(d.path(), &agent("flat:00010100", name("copy_block"))).unwrap();
    assert_eq!(r.data["changed"], true, "{}", r.summary);
    assert_eq!(
        r.summary,
        "named flat:00010100 copy_block (was memcpy_like)"
    );
    let s = symbol_at(d.path(), 0x10100);
    assert_eq!(s.refuted.len(), 1);
    assert_eq!(s.refuted[0].name, "memcpy_like");
    assert_eq!(s.refuted[0].source, Some(ClaimSource::Signature));
    assert_eq!(s.refuted[0].evidence.as_deref(), Some("pattern"));
    assert_eq!(s.refuted[0].note.as_deref(), Some("replaced by copy_block"));
    // an agent-sourced name replaced by an agent leaves no history
    annotate(d.path(), &agent("flat:00010200", name("gamma2"))).unwrap();
    assert!(symbol_at(d.path(), 0x10200).refuted.is_empty());
}

#[test]
fn comment_inside_function_is_line_comment() {
    let d = workspace();
    let r = annotate(
        d.path(),
        &request("flat:00010050", AnnotateAction::Comment("loop head".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    let s = symbol_at(d.path(), 0x10010);
    assert_eq!(s.comment, None);
    assert_eq!(s.line_comments.len(), 1);
    assert_eq!(s.line_comments[0].address, flat(0x10050));
    assert_eq!(s.line_comments[0].text, "loop head");
    assert_eq!(s.line_comments[0].source, ClaimSource::Human);
    // at the start it is the function comment, and a comment is never blocked by precedence
    let r = annotate(
        d.path(),
        &agent("flat:00010010", AnnotateAction::Comment("entry".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    let s = symbol_at(d.path(), 0x10010);
    assert_eq!(s.comment.as_deref(), Some("entry"));
    assert_eq!(s.name, "alpha");
    assert_eq!(s.source, ClaimSource::Human);
}

#[test]
fn refute_keeps_history() {
    let d = workspace();
    let r = annotate(
        d.path(),
        &request(
            "alpha",
            AnnotateAction::Refute {
                reason: "wrong, it writes".into(),
            },
        ),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    let s = symbol_at(d.path(), 0x10010);
    assert_eq!(s.confidence, Confidence::Refuted);
    assert_eq!(s.name, "alpha");
    assert_eq!(s.refuted.len(), 1);
    assert_eq!(s.refuted[0].name, "alpha");
    assert_eq!(s.refuted[0].evidence.as_deref(), Some("wrong, it writes"));
    assert_eq!(s.refuted[0].source, Some(ClaimSource::Human));
    // display name falls back to the default name, output follows
    assert!(
        !functions_dir(d.path())
            .join("flat_00010010_alpha.c")
            .exists()
    );
    assert!(
        functions_dir(d.path())
            .join("flat_00010010_fun_00010010.c")
            .exists()
    );
    // nothing left to refute
    let m = invalid(annotate(
        d.path(),
        &request(
            "flat:00010010",
            AnnotateAction::Refute { reason: "x".into() },
        ),
    ));
    assert!(m.contains("nothing to refute"), "{m}");
    // a new name starts over and keeps the history
    annotate(d.path(), &request("flat:00010010", name("alpha2"))).unwrap();
    let s = symbol_at(d.path(), 0x10010);
    assert_eq!(
        (s.name.as_str(), s.confidence),
        ("alpha2", Confidence::Assumed)
    );
    assert_eq!(s.refuted.len(), 1);
}

#[test]
fn add_type_appends_to_types_h() {
    let d = workspace();
    let path = d.path().join("knowledge/types.h");
    std::fs::write(&path, "struct a { int x; };\n").unwrap();
    let r = annotate(
        d.path(),
        &request("", AnnotateAction::AddType("struct b { int y; };".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "struct a { int x; };\n\nstruct b { int y; };\n"
    );
    let m = invalid(annotate(
        d.path(),
        &request("", AnnotateAction::AddType("struct c { int y; ".into())),
    ));
    assert!(m.contains("unbalanced"), "{m}");
    // empty file
    std::fs::remove_file(&path).unwrap();
    annotate(
        d.path(),
        &request("", AnnotateAction::AddType("typedef int T;".into())),
    )
    .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "typedef int T;\n");
}

#[test]
fn names_global_and_updates_accessors() {
    let d = workspace();
    let r = annotate(d.path(), &request("flat:00020000", name("total"))).unwrap();
    assert_eq!(r.data["changed"], true);
    let alpha =
        std::fs::read_to_string(functions_dir(d.path()).join("flat_00010010_alpha.c")).unwrap();
    assert!(
        alpha.contains("total") && !alpha.contains("counter"),
        "{alpha}"
    );
    let s = symbol_at(d.path(), 0x20000);
    assert_eq!(
        (s.source, s.confidence),
        (ClaimSource::Human, Confidence::Assumed)
    );
    // a new global at an address no function contains
    let r = annotate(d.path(), &request("flat:00020100", name("flags"))).unwrap();
    assert_eq!(r.data["changed"], true);
    assert_eq!(symbol_at(d.path(), 0x20100).kind, SymbolKind::Global);
    // outside the memory map
    let e = annotate(d.path(), &request("flat:00090000", name("nowhere"))).unwrap_err();
    assert!(matches!(e, FacadeError::OutsideMap(_)), "{e:?}");
    // name used elsewhere
    let m = invalid(annotate(d.path(), &request("flat:00010100", name("total"))));
    assert!(m.contains("already used"), "{m}");
}

#[test]
fn signature_data_type_and_local() {
    let d = workspace();
    let r = annotate(
        d.path(),
        &request(
            "flat:00010050",
            AnnotateAction::Signature("int alpha(int a);".into()),
        ),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    assert_eq!(
        symbol_at(d.path(), 0x10010).signature.as_deref(),
        Some("int alpha(int a)")
    );
    let weak = annotate(
        d.path(),
        &agent(
            "alpha",
            AnnotateAction::Signature("void alpha(void)".into()),
        ),
    )
    .unwrap();
    assert_eq!(weak.data["changed"], false);
    let m = invalid(annotate(
        d.path(),
        &request("alpha", AnnotateAction::Signature("no parens".into())),
    ));
    assert!(m.contains("C prototype"), "{m}");
    let r = annotate(
        d.path(),
        &agent(
            "flat:00020000",
            AnnotateAction::DataType("unsigned short".into()),
        ),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    assert_eq!(
        symbol_at(d.path(), 0x20000).data_type.as_deref(),
        Some("unsigned short")
    );
    let r = annotate(
        d.path(),
        &request(
            "alpha",
            AnnotateAction::Local {
                place: "param:1".into(),
                name: "count".into(),
                data_type: Some("int".into()),
            },
        ),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    let s = symbol_at(d.path(), 0x10010);
    assert_eq!(s.locals.len(), 1);
    assert_eq!(s.locals[0].place, "param:1");
    let m = invalid(annotate(
        d.path(),
        &request(
            "alpha",
            AnnotateAction::Local {
                place: "sp+4".into(),
                name: "x".into(),
                data_type: None,
            },
        ),
    ));
    assert!(m.contains("place"), "{m}");
}

#[test]
fn without_analysis_knowledge_is_saved_and_output_skipped() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), SYMBOLS, false);
    let r = annotate(dir.path(), &request("flat:00010100", name("beta"))).unwrap();
    assert_eq!(r.data["changed"], true);
    let warnings = r.data["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w == "no analysis; output not regenerated"),
        "{warnings:?}"
    );
    assert_eq!(symbol_at(dir.path(), 0x10100).name, "beta");
    assert!(!dir.path().join("output").exists());
}

#[test]
fn agent_cannot_replace_human_signature_on_unnamed_record() {
    let d = workspace();
    let at = "flat:00010100";
    annotate(
        d.path(),
        &agent(at, AnnotateAction::Comment("looks like a helper".into())),
    )
    .unwrap();
    let r = annotate(
        d.path(),
        &request(at, AnnotateAction::Signature("int helper(int a)".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    let s = symbol_at(d.path(), 0x10100);
    assert_eq!(
        (s.source, s.confidence),
        (ClaimSource::Human, Confidence::Assumed)
    );
    let r = annotate(
        d.path(),
        &agent(at, AnnotateAction::Signature("void helper(void)".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], false);
    assert_eq!(
        symbol_at(d.path(), 0x10100).signature.as_deref(),
        Some("int helper(int a)")
    );
}

#[test]
fn agent_local_keeps_agent_source() {
    let d = workspace();
    annotate(
        d.path(),
        &agent(
            "flat:00010100",
            AnnotateAction::Local {
                place: "param:1".into(),
                name: "count".into(),
                data_type: None,
            },
        ),
    )
    .unwrap();
    let s = symbol_at(d.path(), 0x10100);
    assert_eq!(s.source, ClaimSource::Agent);
    assert!(s.name.is_empty());
}

#[test]
fn rejects_overlong_name() {
    let d = workspace();
    let before = symbols_bytes(d.path());
    let m = invalid(annotate(
        d.path(),
        &request("flat:00010100", name(&"a".repeat(201))),
    ));
    assert!(m.contains("200"), "{m}");
    assert_eq!(symbols_bytes(d.path()), before);
    annotate(d.path(), &request("flat:00010100", name(&"a".repeat(200)))).unwrap();
}

#[test]
fn output_failure_after_save_is_a_warning() {
    let d = workspace();
    let out = d.path().join("output");
    std::fs::remove_dir_all(&out).unwrap();
    std::fs::write(&out, "not a directory").unwrap();
    let r = annotate(d.path(), &request("flat:00010100", name("beta"))).unwrap();
    assert_eq!(r.data["changed"], true);
    let w = r.data["warnings"][0].as_str().unwrap();
    assert!(
        w.starts_with("knowledge saved; output not regenerated: ")
            && w.ends_with("(run `decovery analyze` or `decovery show`)"),
        "{w}"
    );
    assert_eq!(symbol_at(d.path(), 0x10100).name, "beta");
}

#[test]
fn comment_and_signature_reject_bad_text() {
    let d = workspace();
    let m = invalid(annotate(
        d.path(),
        &request(
            "alpha",
            AnnotateAction::Signature("int f(void)\nint g(void)".into()),
        ),
    ));
    assert!(m.contains("C prototype"), "{m}");
}

#[test]
fn agent_signature_does_not_downgrade_human_type() {
    let d = workspace();
    let at = "flat:00010100";
    annotate(
        d.path(),
        &request(at, AnnotateAction::DataType("int".into())),
    )
    .unwrap();
    let r = annotate(
        d.path(),
        &agent(at, AnnotateAction::Signature("int helper(int a)".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], true);
    let s = symbol_at(d.path(), 0x10100);
    assert_eq!(s.source, ClaimSource::Human);
    let r = annotate(
        d.path(),
        &agent(at, AnnotateAction::DataType("long".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], false);
    assert_eq!(r.data["warnings"].as_array().unwrap().len(), 1);
    assert_eq!(
        symbol_at(d.path(), 0x10100).data_type.as_deref(),
        Some("int")
    );
}

#[test]
fn agent_local_does_not_downgrade_human_signature() {
    let d = workspace();
    let at = "flat:00010100";
    annotate(
        d.path(),
        &request(at, AnnotateAction::Signature("int helper(int a)".into())),
    )
    .unwrap();
    annotate(
        d.path(),
        &agent(
            at,
            AnnotateAction::Local {
                place: "param:1".into(),
                name: "count".into(),
                data_type: None,
            },
        ),
    )
    .unwrap();
    assert_eq!(symbol_at(d.path(), 0x10100).source, ClaimSource::Human);
    let r = annotate(
        d.path(),
        &agent(at, AnnotateAction::Signature("void helper(void)".into())),
    )
    .unwrap();
    assert_eq!(r.data["changed"], false);
    assert_eq!(
        symbol_at(d.path(), 0x10100).signature.as_deref(),
        Some("int helper(int a)")
    );
}
