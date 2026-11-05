//! `status` and `find` on a synthetic workspace.

use std::time::Duration;

use decovery_core::{
    AccessKind, Address, Analysis, AnalyzedFunction, CallEdge, DataAccess, Provider, StringItem,
    Workspace, knowledge_hash,
};
use decovery_facade::{
    Budget, FacadeError, FindQuery, FindWhat, FunctionFilter, FunctionSort, Session, find, status,
    write_all,
};
use serde_json::json;

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
result = "identical"
"#;

/// Five functions: alpha (confirmed, identical), gamma (assumed) and three unnamed ones. Distinct callers:
/// 0x10100 one (alpha, twice), 0x10300 two (alpha, gamma), 0x10400 none.
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
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-05",
    );
    a.functions = vec![
        AnalyzedFunction::new(flat(0x10010), flat(0x100FF), 240),
        AnalyzedFunction::new(flat(0x10100), flat(0x1017F), 128),
        AnalyzedFunction::new(flat(0x10200), flat(0x1023F), 64),
        AnalyzedFunction::new(flat(0x10300), flat(0x1031F), 32),
        AnalyzedFunction::new(flat(0x10400), flat(0x1052B), 300),
    ];
    a.calls = vec![
        CallEdge::new(flat(0x10020), flat(0x10010), flat(0x10100)),
        CallEdge::new(flat(0x10030), flat(0x10010), flat(0x10100)),
        CallEdge::new(flat(0x10040), flat(0x10010), flat(0x10200)),
        CallEdge::new(flat(0x10050), flat(0x10010), flat(0x10300)),
        CallEdge::new(flat(0x10210), flat(0x10200), flat(0x10010)),
        CallEdge::new(flat(0x10220), flat(0x10200), flat(0x10300)),
    ];
    a.strings = vec![
        StringItem::new(flat(0x20010), "Hello", vec![flat(0x10010)]),
        StringItem::new(flat(0x20020), "wor\tld", vec![]),
    ];
    a.data_accesses = vec![
        DataAccess::new(flat(0x10010), flat(0x20000), AccessKind::Read),
        DataAccess::new(flat(0x10100), flat(0x20000), AccessKind::Write),
    ];
    a.save(root, &lock).unwrap();
    drop(lock);
    let session = Session::open(root).unwrap();
    (dir, session)
}

fn query(what: FindWhat, pattern: Option<&str>) -> FindQuery {
    let mut q = FindQuery::new(what);
    q.pattern = pattern.map(str::to_string);
    q
}

#[test]
fn status_counts_named_and_unnamed() {
    let (_d, s) = workspace();
    let r = status(&s).unwrap();
    assert_eq!(r.data["functions"], 5);
    assert_eq!(r.data["named"], 2);
    assert_eq!(r.data["confirmed"], 1);
    assert_eq!(r.data["assumed"], 1);
    assert_eq!(r.data["unnamed"], 3);
    assert_eq!(r.data["by_signature"], 0);
    assert_eq!(
        r.data["rebuild"],
        json!({"identical": 1, "differs": 0, "error": 0, "not_tried": 4})
    );
    assert_eq!(
        r.data["analysis"],
        json!({"provider": "ghidra", "version": "11.3", "created": "2026-11-05", "stale": false})
    );
    assert_eq!(r.summary, "2/5 functions named (1 confirmed, 1 assumed)");
}

#[test]
fn status_next_step_is_most_called_unnamed() {
    let (_d, s) = workspace();
    let r = status(&s).unwrap();
    assert_eq!(
        r.data["next_step"],
        "name fun_00010300 (2 callers): decovery show fun_00010300"
    );
}

#[test]
fn status_reports_stale_analysis() {
    let (d, s) = workspace();
    std::fs::write(d.path().join("knowledge/types.h"), "struct x;\n").unwrap();
    let r = status(&s).unwrap();
    assert_eq!(r.data["analysis"]["stale"], true);
    assert!(
        r.summary
            .ends_with(" (analysis is older than the knowledge; run `decovery analyze`)"),
        "{}",
        r.summary
    );
}

#[test]
fn find_functions_filter_unnamed_sorted_by_callers() {
    let (_d, s) = workspace();
    let mut q = query(FindWhat::Functions, None);
    q.filter = vec![FunctionFilter::Unnamed];
    q.sort = FunctionSort::Callers;
    let r = find(&s, &q, Budget::default()).unwrap();
    assert_eq!(r.data["total"], 3);
    let items = r.data["items"].as_array().unwrap();
    let names: Vec<&str> = items.iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["fun_00010300", "fun_00010100", "fun_00010400"]);
    assert_eq!(
        items[0],
        json!({"address": "flat:00010300", "name": "fun_00010300", "size": 32, "callers": 2,
               "status": "unnamed", "rebuild": "not-tried"})
    );
    assert_eq!(r.summary, "3 functions");

    // filters combine with AND; size sort is descending
    let mut q = query(FindWhat::Functions, None);
    q.filter = vec![FunctionFilter::Named, FunctionFilter::NotTried];
    q.sort = FunctionSort::Size;
    let r = find(&s, &q, Budget::default()).unwrap();
    assert_eq!(r.data["items"].as_array().unwrap().len(), 1);
    assert_eq!(r.data["items"][0]["name"], "gamma");
    assert_eq!(r.data["items"][0]["status"], "assumed");
    let mut q = query(FindWhat::Functions, None);
    q.sort = FunctionSort::Size;
    let r = find(&s, &q, Budget::default()).unwrap();
    assert_eq!(r.data["items"][0]["name"], "fun_00010400");
    assert_eq!(r.data["items"][1]["name"], "alpha");
}

#[test]
fn find_names_wildcard() {
    let (_d, s) = workspace();
    let r = find(&s, &query(FindWhat::Names, Some("*A")), Budget::default()).unwrap();
    assert_eq!(
        r.data["items"],
        json!([
            {"address": "flat:00010010", "text": "alpha"},
            {"address": "flat:00010200", "text": "gamma"},
        ])
    );
    // without `*` anywhere in the name; default names of unnamed functions are searchable
    let r = find(&s, &query(FindWhat::Names, Some("0103")), Budget::default()).unwrap();
    assert_eq!(r.data["items"][0]["text"], "fun_00010300");
    let r = find(&s, &query(FindWhat::Names, Some("ount")), Budget::default()).unwrap();
    assert_eq!(r.data["items"][0]["address"], "flat:00020000");
}

#[test]
fn find_strings_case_insensitive() {
    let (_d, s) = workspace();
    let r = find(
        &s,
        &query(FindWhat::Strings, Some("HELLO")),
        Budget::default(),
    )
    .unwrap();
    assert_eq!(
        r.data["items"],
        json!([{"address": "flat:00020010", "text": "Hello"}])
    );
}

#[test]
fn find_code_lists_file_and_line() {
    let (d, s) = workspace();
    let r = find(&s, &query(FindWhat::Code, Some("alpha")), Budget::default()).unwrap();
    assert_eq!(
        r.summary,
        "output/ not generated; run `decovery show` or analyze"
    );
    let lock = s.workspace.lock(Duration::ZERO).unwrap();
    write_all(&s, &lock).unwrap();
    drop(lock);
    let r = find(
        &s,
        &query(FindWhat::Code, Some("*@name*alpha*")),
        Budget::default(),
    )
    .unwrap();
    let items = r.data["items"].as_array().unwrap();
    let alpha = items
        .iter()
        .find(|i| i["file"] == "output/functions/code/flat_00010010_alpha.c")
        .unwrap_or_else(|| panic!("{items:?}"));
    assert_eq!(alpha["line"], 2);
    assert_eq!(
        alpha["text"].as_str().unwrap(),
        "* @name       alpha  [human, confirmed]"
    );
    assert!(d.path().join("output/functions/code").is_dir());
    let e = find(&s, &query(FindWhat::Code, None), Budget::default()).unwrap_err();
    assert!(matches!(e, FacadeError::Invalid(_)), "{e}");
}

#[test]
fn find_xrefs_shape() {
    let (_d, s) = workspace();
    let r = find(
        &s,
        &query(FindWhat::Xrefs, Some("alpha")),
        Budget::default(),
    )
    .unwrap();
    assert_eq!(
        r.data,
        json!({
            "address": "flat:00010010",
            "name": "alpha",
            "called_by": [{"address": "flat:00010200", "name": "gamma", "site": "gamma+0x10"}],
            "calls": [
                {"address": "flat:00010100", "name": "fun_00010100", "site": "alpha+0x10"},
                {"address": "flat:00010100", "name": "fun_00010100", "site": "alpha+0x20"},
                {"address": "flat:00010200", "name": "gamma", "site": "alpha+0x30"},
                {"address": "flat:00010300", "name": "fun_00010300", "site": "alpha+0x40"},
            ],
            "accesses": [],
            "strings": [{"address": "flat:00020010", "text": "Hello"}],
        })
    );
    // an address inside the function resolves to the function
    let r = find(
        &s,
        &query(FindWhat::Xrefs, Some("flat:00010024")),
        Budget::default(),
    )
    .unwrap();
    assert_eq!(r.data["name"], "alpha");

    // a data address in no function is a global target
    let r = find(
        &s,
        &query(FindWhat::Xrefs, Some("counter")),
        Budget::default(),
    )
    .unwrap();
    assert_eq!(r.data["address"], "flat:00020000");
    assert_eq!(r.data["name"], "counter");
    assert_eq!(r.data["called_by"], json!([]));
    assert_eq!(
        r.data["accesses"],
        json!([
            {"function": "flat:00010010", "name": "alpha", "kind": "read"},
            {"function": "flat:00010100", "name": "fun_00010100", "kind": "write"},
        ])
    );
    let r = find(
        &s,
        &query(FindWhat::Xrefs, Some("flat:00020010")),
        Budget::default(),
    )
    .unwrap();
    assert_eq!(r.data["name"], "DAT_00020010");
    assert_eq!(
        r.data["strings"],
        json!([{"address": "flat:00020010", "text": "Hello"}])
    );

    let e = find(
        &s,
        &query(FindWhat::Xrefs, Some("flat:00090000")),
        Budget::default(),
    )
    .unwrap_err();
    assert!(matches!(e, FacadeError::OutsideMap(_)), "{e}");
    let e = find(&s, &query(FindWhat::Xrefs, None), Budget::default()).unwrap_err();
    assert!(matches!(e, FacadeError::Invalid(_)), "{e}");
}

#[test]
fn find_over_limit_returns_handle() {
    let (d, s) = workspace();
    let mut q = query(FindWhat::Functions, None);
    q.limit = 2;
    let r = find(&s, &q, Budget::default()).unwrap();
    assert_eq!(r.data["total"], 5);
    assert_eq!(r.data["items"].as_array().unwrap().len(), 2);
    assert_eq!(r.handles.len(), 1);
    let h = &r.handles[0];
    assert_eq!(h.kind, "find-results");
    assert_eq!(
        r.summary,
        format!("2 of 5 functions; full list: detail {}", h.id)
    );
    let stored =
        std::fs::read_to_string(d.path().join("cache/handles").join(format!("{}.txt", h.id)))
            .unwrap();
    assert_eq!(stored.lines().count(), 5);
    assert_eq!(
        stored.lines().next().unwrap(),
        "flat:00010010\talpha\t240\t1\tconfirmed\tidentical"
    );

    // the budget cuts as well
    let r = find(&s, &query(FindWhat::Functions, None), Budget { chars: 150 }).unwrap();
    let shown = r.data["items"].as_array().unwrap().len();
    assert!(shown > 0 && shown < 5, "{shown}");
    assert_eq!(r.handles.len(), 1);
    assert!(r.summary.starts_with(&format!("{shown} of 5 functions")));

    // tabs inside texts do not break the row format
    let r = find(
        &s,
        &query(FindWhat::Strings, Some("wor")),
        Budget { chars: 1 },
    )
    .unwrap();
    let id = &r.handles[0].id;
    let stored =
        std::fs::read_to_string(d.path().join("cache/handles").join(format!("{id}.txt"))).unwrap();
    assert_eq!(stored, "flat:00020020\twor\\tld\n");
}
