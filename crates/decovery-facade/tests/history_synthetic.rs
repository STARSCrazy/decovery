//! Attempts recorded by `build` (full, file, variants, the bridge's search candidate), the `history` tool and the
//! `parked` filter, on the synthetic MZ build workspace with the fake runner and the fake `decomp-legacy` plugin.
//! Skipped (with a message) without Python: set `DECOVERY_PYTHON` or put `python` on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use build_fixture::{A_C, ADD, ADD_AT, Fixture, SUB, SUB_AT, ZED_AT, fixture};
use decovery_core::{
    Address, AttemptOrigin, AttemptRecord, RebuildResult, VerdictId, archive_load, read_attempts,
    read_rebuild,
};
use decovery_facade::{
    Budget, BuildRequest, FindQuery, FindWhat, FunctionFilter, LegacyCall, LegacyOperation,
    Response, Session, Variant, build, find, history, history_archive, search,
};
use serde_json::{Value, json};

fn attempts(f: &Fixture, at: Address) -> Vec<AttemptRecord> {
    let (records, warnings) = read_attempts(f.root(), at).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    records
}

fn build_files(f: &Fixture, files: &[&str]) -> Response {
    let mut request = BuildRequest::default();
    request.files = files.iter().map(|s| s.to_string()).collect();
    build(
        f.root(),
        &request,
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap()
}

fn build_variants(f: &Fixture, variants: Vec<Variant>) -> Response {
    let mut request = BuildRequest::default();
    request.function = Some("sub".into());
    request.variants = variants;
    build(
        f.root(),
        &request,
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap()
}

fn sub_with(mark: &str) -> String {
    format!("int sub(int a, int b)\n{{\n    return a - b; /* {mark} */\n}}\n")
}

/// `sub` with one instruction wrong.
fn one_wrong() -> Vec<u8> {
    let mut sub = SUB.to_vec();
    sub[6] = 0x33;
    sub
}

/// `sub` with two instructions wrong.
fn two_wrong() -> Vec<u8> {
    let mut sub = one_wrong();
    sub[5] = 0x08;
    sub
}

/// Objects of function variants of `sub`: `F00n` the full file, `V00n` the shrunk one, for each body in order.
fn serve_function_variants(f: &Fixture, bodies: &[&[u8]]) {
    for (i, body) in bodies.iter().enumerate() {
        let n = i + 1;
        f.write_obj(&format!("F{n:03}"), &[("_add", ADD), ("_sub", body)]);
        f.write_obj(&format!("V{n:03}"), &[("_sub", body)]);
    }
}

#[test]
fn build_records_one_attempt_per_function() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    build_files(&f, &[]);
    let add = attempts(&f, ADD_AT);
    assert_eq!(add.len(), 1);
    let a = &add[0];
    assert_eq!(a.origin, AttemptOrigin::Build);
    assert_eq!(a.name, "add");
    assert_eq!(a.file.as_deref(), Some("a.c"));
    assert_eq!(a.result, RebuildResult::Identical);
    assert_eq!(a.verdict, Some(VerdictId::Identical));
    assert_eq!(a.actor.as_deref(), Some("library"));
    assert_eq!(
        (a.profile.as_str(), a.flags.as_str()),
        ("turbo-c-2.0", "-ms -O")
    );
    assert!(a.body_hash.starts_with("blake3:"), "{}", a.body_hash);
    assert_eq!(a.context_hash.len(), 64);
    assert_eq!(a.original_hash.len(), 64);
    assert_eq!(a.instructions_differing, Some(0));
    assert!(a.archive.is_some(), "identical attempts are archived");
    assert_eq!(attempts(&f, SUB_AT).len(), 1);
    assert_eq!(attempts(&f, ZED_AT).len(), 1);

    // an unchanged source repeats its last attempts: nothing is appended, nothing archived again
    let archived = std::fs::read_dir(f.root().join("cache/archive"))
        .unwrap()
        .count();
    build_files(&f, &[]);
    assert_eq!(attempts(&f, ADD_AT).len(), 1);
    assert_eq!(attempts(&f, ZED_AT).len(), 1);
    assert_eq!(
        std::fs::read_dir(f.root().join("cache/archive"))
            .unwrap()
            .count(),
        archived
    );

    // a changed body is a new attempt; the other file's function is unchanged
    f.write_source("a.c", &A_C.replace("a + b;", "a + b; /* again */"));
    build_files(&f, &["a.c"]);
    let add = attempts(&f, ADD_AT);
    assert_eq!(add.len(), 2);
    assert_ne!(add[0].body_hash, add[1].body_hash);
    assert_eq!(attempts(&f, ZED_AT).len(), 1);
}

#[test]
fn variants_record_each_variant_with_label() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let whole = A_C.replace("a - b;", "a - b; /* whole */");
    f.write_obj("V001", &[("_add", ADD), ("_sub", &one_wrong())]);
    f.write_obj("F002", &[("_add", ADD), ("_sub", SUB)]);
    f.write_obj("V002", &[("_sub", SUB)]);
    build_variants(
        &f,
        vec![
            Variant::new(whole).with_label("whole"),
            Variant::function(sub_with("def")).with_label("def"),
        ],
    );
    let sub = attempts(&f, SUB_AT);
    assert_eq!(sub.len(), 2, "{sub:?}");
    assert_eq!(sub[0].label.as_deref(), Some("whole"));
    assert_eq!(sub[0].origin, AttemptOrigin::Variant);
    assert_eq!(sub[0].verdict, Some(VerdictId::Differs));
    assert_eq!(sub[0].instructions_differing, Some(1));
    assert_eq!(sub[1].label.as_deref(), Some("def"));
    assert_eq!(sub[1].origin, AttemptOrigin::Function);
    assert_eq!(sub[1].verdict, Some(VerdictId::Identical));
    assert!(sub.iter().all(|r| r.actor.is_some() && r.name == "sub"));
    // the same original bytes for every variant of the function
    assert_eq!(sub[0].original_hash, sub[1].original_hash);
    assert!(
        attempts(&f, ADD_AT).is_empty(),
        "only the function is recorded"
    );
}

#[test]
fn identical_attempt_is_archived_with_function_source() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    serve_function_variants(&f, &[SUB, &one_wrong(), &two_wrong()]);
    build_variants(
        &f,
        vec![
            Variant::function(sub_with("fix")).with_label("fix"),
            Variant::function(sub_with("near")).with_label("near"),
            Variant::function(sub_with("far")).with_label("far"),
        ],
    );
    let sub = attempts(&f, SUB_AT);
    let by_label = |l: &str| sub.iter().find(|r| r.label.as_deref() == Some(l)).unwrap();
    let fix = by_label("fix");
    assert_eq!(fix.verdict, Some(VerdictId::Identical));
    // identical and the best of the others are archived, the rest is not
    assert!(by_label("near").archive.is_some());
    assert!(by_label("far").archive.is_none());
    let entry = archive_load(f.root(), fix.archive.as_deref().unwrap()).unwrap();
    assert_eq!(entry.files["function.c"], sub_with("fix").as_bytes());
    let module = String::from_utf8(entry.files["module.c"].clone()).unwrap();
    assert!(
        module.contains("int add(int a, int b)") && module.contains("/* fix */"),
        "{module}"
    );
    let comparison = String::from_utf8(entry.files["comparison.txt"].clone()).unwrap();
    assert!(comparison.contains("verdict: identical"), "{comparison}");
    assert!(entry.files.keys().any(|k| k.starts_with("objects/")));
    assert_eq!(entry.meta["file"], "a.c");
    assert_eq!(entry.meta["address"], "seg:0000:0020");
    assert_eq!(entry.meta["body_hash"], json!(fix.body_hash));
}

#[test]
fn history_lists_newest_first_with_best_and_budget() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    for (label, body) in [
        ("far", two_wrong()),
        ("near", one_wrong()),
        ("fix", SUB.to_vec()),
    ] {
        serve_function_variants(&f, &[&body]);
        build_variants(
            &f,
            vec![Variant::function(sub_with(label)).with_label(label)],
        );
    }
    for garbage in ["int x;\n", "int y;\n"] {
        build_variants(&f, vec![Variant::function(garbage).with_label("broken")]);
    }
    let response = history(f.root(), "sub", 20, Budget::default()).unwrap();
    assert_eq!(
        response.summary,
        "sub: 5 attempts, best identical, not parked"
    );
    let d = &response.data;
    let labels: Vec<&str> = d["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["broken", "broken", "fix", "near", "far"]);
    let first = &d["attempts"][2];
    for key in [
        "time",
        "origin",
        "label",
        "actor",
        "verdict",
        "result",
        "instructions_differing",
        "bytes_differing",
        "blockers",
        "archive",
    ] {
        assert!(first.get(key).is_some(), "attempt lacks {key}: {first}");
    }
    assert_eq!(first["origin"], "function");
    assert_eq!(d["best"]["distance"], 0);
    assert!(d["best"]["archive"].is_string(), "{}", d["best"]);
    assert_eq!(
        d["attempt_budget"],
        json!({"own": 3, "since_progress": 0, "limit": 30, "parked": false})
    );
    assert_eq!(
        d["failures"],
        json!([{
            "message": "variant 1 (broken): the function source must define exactly one function, sub; it defines none",
            "count": 2
        }])
    );
    assert!(response.handles.is_empty());

    // fewer listed than recorded: all of them in a handle
    let response = history(f.root(), "seg:0000:0020", 2, Budget::default()).unwrap();
    assert_eq!(response.data["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(response.data["attempts_total"], 5);
    assert_eq!(response.handles.len(), 1);
    assert!(
        response.summary.contains("detail h_"),
        "{}",
        response.summary
    );
}

#[test]
fn history_archive_returns_function_source() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    serve_function_variants(&f, &[SUB]);
    build_variants(
        &f,
        vec![Variant::function(sub_with("fix")).with_label("fix")],
    );
    let listed = history(f.root(), "sub", 20, Budget::default()).unwrap();
    let id = listed.data["attempts"][0]["archive"]
        .as_str()
        .unwrap()
        .to_string();
    let response = history_archive(f.root(), "sub", &id, Budget::default()).unwrap();
    assert_eq!(response.data["function_c"], sub_with("fix"));
    assert!(
        response.data["comparison"]
            .as_str()
            .unwrap()
            .contains("verdict: identical")
    );
    assert_eq!(response.data["archive"], id.as_str());
    // an entry of another function is refused, an id that is none too
    let error = history_archive(f.root(), "add", &id, Budget::default()).unwrap_err();
    assert!(
        error.to_string().contains("not an attempt at add"),
        "{error}"
    );
    assert!(history_archive(f.root(), "sub", "nope", Budget::default()).is_err());
}

#[test]
fn parked_filter_finds_spent_functions() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let config = std::fs::read_to_string(f.root().join("decovery.toml")).unwrap();
    std::fs::write(
        f.root().join("decovery.toml"),
        config.replace(
            "tool_dir = \"tools\"\n",
            "tool_dir = \"tools\"\nattempt_budget = 1\n",
        ),
    )
    .unwrap();
    f.write_obj("A", &[("_add", ADD), ("_sub", &one_wrong())]);
    build_files(&f, &["a.c", "z.c"]);
    f.write_source("a.c", &A_C.replace("a - b;", "a - b; /* again */"));
    build_files(&f, &["a.c"]);
    let mut query = FindQuery::new(FindWhat::Functions);
    query.filter = vec![FunctionFilter::Parked];
    let session = Session::open(f.root()).unwrap();
    let found = find(&session, &query, Budget::default()).unwrap();
    let names: Vec<&str> = found.data["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["sub"], "{}", found.data);
    let response = history(f.root(), "sub", 20, Budget::default()).unwrap();
    assert!(
        response.summary.ends_with(", parked"),
        "{}",
        response.summary
    );
    assert_eq!(response.data["attempt_budget"]["since_progress"], 1);
}

#[test]
fn variants_still_write_no_rebuild_record() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    serve_function_variants(&f, &[SUB]);
    build_variants(
        &f,
        vec![Variant::function(sub_with("fix")).with_label("fix")],
    );
    assert!(read_rebuild(f.root()).unwrap().is_empty());
    assert!(!f.rebuild_path().exists());
    assert!(!f.root().join("cache/rebuild/obj").exists());
    assert!(!f.root().join("output").exists());
    assert_eq!(attempts(&f, SUB_AT).len(), 1);
}

#[test]
fn build_reports_malformed_attempt_lines() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let dir = f.root().join("cache/attempts");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("seg_0000_0020.jsonl"), "{broken\n").unwrap();
    let response = build_files(&f, &["a.c"]);
    let warnings = response.data["warnings"].to_string();
    assert!(warnings.contains("seg_0000_0020.jsonl:1"), "{warnings}");
}

#[test]
fn parked_filter_reports_malformed_attempt_lines() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let dir = f.root().join("cache/attempts");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("seg_0000_0020.jsonl"), "{broken\n").unwrap();
    let mut query = FindQuery::new(FindWhat::Functions);
    query.filter = vec![FunctionFilter::Parked];
    let response = find(&Session::open(f.root()).unwrap(), &query, Budget::default()).unwrap();
    let warnings = response.data["warnings"].to_string();
    assert!(warnings.contains("seg_0000_0020.jsonl:1"), "{warnings}");
}

#[test]
fn parked_filter_does_not_hide_unreadable_attempt_shards() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    std::fs::create_dir_all(f.root().join("cache/attempts/seg_0000_0020.jsonl")).unwrap();
    let mut query = FindQuery::new(FindWhat::Functions);
    query.filter = vec![FunctionFilter::Parked];
    let error = find(&Session::open(f.root()).unwrap(), &query, Budget::default()).unwrap_err();
    assert!(error.to_string().contains("seg_0000_0020.jsonl"), "{error}");
}

// -- the bridge's search -------------------------------------------------------------------------------------

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// The build fixture with a Decomp workspace beside it and the fake `decomp-legacy` plugin.
fn bridge(python: &str) -> (Fixture, tempfile::TempDir) {
    let f = fixture(python, "");
    let decomp = tempfile::tempdir().unwrap();
    std::fs::write(decomp.path().join("decomp.toml"), "# Decomp\n").unwrap();
    let script: PathBuf = std::path::absolute(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_legacy.py"),
    )
    .unwrap();
    let mut config = std::fs::read_to_string(f.root().join("decovery.toml")).unwrap();
    config.push_str(&format!(
        "\n[legacy]\ndecomp_workspace = {}\n\n[plugins.decomp-legacy]\ncommand = [{}, {}]\n",
        toml_string(decomp.path().to_str().unwrap()),
        toml_string(python),
        toml_string(script.to_str().unwrap())
    ));
    std::fs::write(f.root().join("decovery.toml"), config).unwrap();
    (f, decomp)
}

#[test]
fn search_records_only_the_candidate() {
    let python = python_or_skip!();
    let (f, _decomp) = bridge(&python);
    let shadow = f.root().join("cache/legacy/decomp");
    std::fs::create_dir_all(&shadow).unwrap();
    let report = shadow.join("cache/nachbau/kette/sub/ergebnis.txt");
    let answer: Value = json!({
        "candidate": {"text": sub_with("found"), "kind": "function"},
        "artifacts": [report.to_string_lossy()],
    });
    std::fs::write(shadow.join("answer.json"), answer.to_string()).unwrap();
    // current (differs) and candidate (identical) as function variants; the applied file builds identical
    serve_function_variants(&f, &[&one_wrong(), SUB]);
    f.write_obj("A", &[("_add", ADD), ("_sub", SUB)]);
    let mut call = LegacyCall::new("sub", LegacyOperation::Chain);
    call.user_plugins = Some(BTreeMap::new());
    call.apply = true;
    let response = search(
        f.root(),
        &call,
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    assert_eq!(
        response.data["candidate"]["applied"], true,
        "{}",
        response.data
    );

    // one attempt: the candidate, not the current source and not the applied build of the same text
    let sub = attempts(&f, SUB_AT);
    assert_eq!(sub.len(), 1, "{sub:?}");
    let candidate = &sub[0];
    assert_eq!(candidate.origin, AttemptOrigin::Search);
    assert_eq!(candidate.label.as_deref(), Some("search:chain"));
    assert_eq!(candidate.verdict, Some(VerdictId::Identical));
    assert_eq!(
        candidate.extra["decomp_report"],
        json!(report.to_string_lossy())
    );
    assert!(candidate.actor.is_some());
    // the applied build records the file's other function as usual
    let add = attempts(&f, ADD_AT);
    assert_eq!(add.len(), 1);
    assert_eq!(add[0].origin, AttemptOrigin::Build);
}
