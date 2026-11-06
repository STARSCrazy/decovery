//! `build` on a synthetic MZ workspace with a fake runner. Skipped (with a message) without Python: set
//! `DECOVERY_PYTHON` or put `python` on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::time::Duration;

use build_fixture::{A_C, ADD, ADD_AT, Fixture, SUB, SUB_AT, ZED, ZED_AT, fixture};
use decovery_core::{
    BlockerRecord, Equivalence, RebuildRecord, RebuildResult, VerdictId, Workspace, read_rebuild,
    save_rebuild,
};
use decovery_facade::{BuildRequest, Response, Session, build, function_path};
use serde_json::Value;

fn run(f: &Fixture, files: &[&str]) -> Response {
    let mut request = BuildRequest::default();
    request.files = files.iter().map(|s| s.to_string()).collect();
    build(f.root(), &request, &|_| {}).unwrap()
}

fn records(f: &Fixture) -> Vec<RebuildRecord> {
    read_rebuild(f.root()).unwrap()
}

fn record(f: &Fixture, name: &str) -> RebuildRecord {
    records(f)
        .into_iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no record {name}"))
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

/// Seeds `knowledge/rebuild.toml`.
fn seed(f: &Fixture, text: &str) {
    std::fs::write(f.rebuild_path(), text).unwrap();
}

#[test]
fn identical_function_is_recorded() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let response = run(&f, &["a.c"]);
    assert_eq!(response.summary, "a.c: 2 functions, 2 identical");
    let add = record(&f, "add");
    assert_eq!(add.address, ADD_AT);
    assert_eq!(add.result, RebuildResult::Identical);
    assert_eq!(add.verdict, Some(VerdictId::Identical));
    assert!(add.blockers.is_empty());
    assert_eq!(add.file.as_deref(), Some("a.c"));
    assert_eq!(add.compiler.as_deref(), Some("turbo-c-2.0"));
    assert_eq!(add.flags.as_deref(), Some("-ms -O"));
    assert_eq!((add.bytes, add.differing), (11, 0));
    assert_eq!(add.code_hash.as_ref().map(String::len), Some(16));
    assert!(add.date.is_some());
    let d = &response.data;
    assert_eq!(d["counts"]["identical"], 2);
    assert_eq!(d["files"][0]["status"], "compiled");
    assert_eq!(d["timing"]["jobs"], 1);
    let obj_dir = f.root().join("cache/rebuild/obj");
    assert!(obj_dir.join("a.obj").is_file());
    let meta: Value =
        serde_json::from_str(&std::fs::read_to_string(obj_dir.join("a.json")).unwrap()).unwrap();
    assert_eq!(meta["schema"], 1);
    assert_eq!(meta["format"], "decovery-obj/1");
    assert_eq!(meta["identical"]["add"]["address"], "seg:0000:0010");
    assert!(meta["inputs"]["A.C"].is_string());
    let runs = f.root().join("cache/rebuild/runs");
    let left = std::fs::read_dir(&runs).map_or(0, |d| d.count());
    assert_eq!(left, 0, "build directory not removed");
}

#[test]
fn differing_function_has_blockers() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut sub = SUB.to_vec();
    sub[6] = 0x33;
    f.write_obj("A", &[("_add", ADD), ("_sub", &sub)]);
    let response = run(&f, &["a.c"]);
    let r = record(&f, "sub");
    assert_eq!(r.result, RebuildResult::Differs);
    assert_eq!(r.verdict, Some(VerdictId::Differs));
    assert!(
        r.blockers
            .contains(&BlockerRecord::new("bytes-differ", None, Some(1))),
        "{:?}",
        r.blockers
    );
    assert_eq!(r.differing, 1);
    assert_eq!(r.first_difference, Some(6));
    let functions = response.data["functions"].as_array().unwrap();
    let shown = functions.iter().find(|v| v["name"] == "sub").unwrap();
    assert_eq!(shown["verdict"], "differs");
    assert_eq!(shown["blockers"][0]["kind"], "bytes-differ");
    assert_eq!(response.summary, "a.c: 2 functions, 1 identical, 1 differ");
}

#[test]
fn unknown_function_is_a_hint() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("A", &[("_add", ADD), ("_sub", SUB), ("_ghost", ZED)]);
    let response = run(&f, &["a.c"]);
    let hints = strings(&response.data["hints"]);
    assert!(
        hints.contains(&"ghost: no counterpart in the original".to_string()),
        "{hints:?}"
    );
    assert!(records(&f).iter().all(|r| r.name != "ghost"));
    assert_eq!(records(&f).len(), 2);
}

#[test]
fn failing_file_does_not_stop_others() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    seed(
        &f,
        "schema = 1\n\n[[function]]\naddress = \"seg:0000:0030\"\nname = \"zed\"\nfile = \"z.c\"\nresult = \"identical\"\n",
    );
    std::fs::remove_file(f.objects.path().join("Z.OBJ")).unwrap();
    let response = run(&f, &[]);
    assert_eq!(record(&f, "add").verdict, Some(VerdictId::Identical));
    let zed = record(&f, "zed");
    assert_eq!(zed.result, RebuildResult::Error);
    assert_eq!(zed.verdict, Some(VerdictId::Unchecked));
    let message = zed.message.unwrap();
    assert!(message.starts_with("compiler exit code 1"), "{message}");
    assert!(message.contains("Z.C(1): Error"), "{message}");
    let files = response.data["files"].as_array().unwrap();
    let z = files.iter().find(|v| v["file"] == "z.c").unwrap();
    assert_eq!(z["status"], "error");
    assert_eq!(response.data["counts"]["failed_files"], 1);
    assert!(!f.root().join("cache/rebuild/obj/z.obj").exists());
}

#[test]
fn object_cache_skips_second_compile() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let first = run(&f, &[]);
    assert_eq!(f.log("requests.log"), ["2"], "all misses in one request");
    let mut tmp = f.log("tmp.log");
    tmp.sort();
    assert_eq!(
        tmp,
        ["TMP00000 exists", "TMP00001 exists"],
        "own work directory per job"
    );
    assert_eq!(first.data["timing"]["jobs"], 2);
    let second = run(&f, &["a.c"]);
    assert_eq!(f.log("calls.log").len(), 2, "{:?}", f.log("calls.log"));
    assert_eq!(f.log("requests.log"), ["2"]);
    assert_eq!(second.data["files"][0]["cached"], true);
    assert_eq!(second.data["timing"]["jobs"], 0);
    assert_eq!(second.data["timing"]["cached"], 1);
    assert_eq!(record(&f, "add").verdict, Some(VerdictId::Identical));
    // a changed source is compiled again
    f.write_source("a.c", &format!("{A_C}/* changed */\n"));
    run(&f, &["a.c"]);
    assert_eq!(f.log("calls.log").len(), 3);
}

#[test]
fn job_not_run_is_submitted_again() {
    let python = python_or_skip!();
    let f = fixture(&python, ", FAKE_NOT_RUN_ONCE = \"1\"");
    let response = run(&f, &[]);
    assert_eq!(f.log("requests.log"), ["2", "1"]);
    assert_eq!(response.data["counts"]["failed_files"], 0);
    assert_eq!(record(&f, "zed").verdict, Some(VerdictId::Identical));
    let warnings = strings(&response.data["warnings"]);
    assert!(
        warnings.iter().any(|w| w.contains("submitted once more")),
        "{warnings:?}"
    );
}

#[test]
fn inline_asm_downgrades() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_source(
        "a.c",
        "int add(int a, int b)\r\n{\r\n    _asm nop;\r\n    return a + b;\r\n}\r\n\r\nint sub(int a, int b)\r\n{\r\n    return a - b;\r\n}\r\n",
    );
    let response = run(&f, &["a.c"]);
    let add = record(&f, "add");
    assert_eq!(add.result, RebuildResult::Differs);
    assert_eq!(add.verdict, Some(VerdictId::Differs));
    assert!(
        add.blockers
            .contains(&BlockerRecord::new("inline-assembly", None, None))
    );
    assert!(add.message.unwrap().contains("line 3"));
    assert_eq!(record(&f, "sub").verdict, Some(VerdictId::Identical));
    let hints = strings(&response.data["hints"]);
    assert!(
        hints
            .iter()
            .any(|h| h.starts_with("a.c:3: inline-asm in add")),
        "{hints:?}"
    );
}

const OTHER_FILES: &str = r#"schema = 1

[[function]]
address = "seg:0000:0030"
name = "zed"
file = "z.c"
result = "differs"
differing = 3

[[function]]
address = "seg:0000:0040"
name = "old"
file = "gone.c"
result = "identical"
"#;

#[test]
fn merge_keeps_other_files() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    seed(&f, OTHER_FILES);
    run(&f, &["a.c"]);
    let zed = record(&f, "zed");
    assert_eq!(
        (zed.result, zed.differing, zed.verdict),
        (RebuildResult::Differs, 3, None)
    );
    assert_eq!(record(&f, "old").file.as_deref(), Some("gone.c"));
    assert_eq!(records(&f).len(), 4);
}

#[test]
fn build_all_drops_vanished_files() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    seed(&f, OTHER_FILES);
    run(&f, &[]);
    let names: Vec<String> = records(&f).into_iter().map(|r| r.name).collect();
    assert_eq!(names, ["add", "sub", "zed"]);
    assert_eq!(record(&f, "zed").verdict, Some(VerdictId::Identical));
}

fn set_equivalence(f: &Fixture, name: &str) {
    let ws = Workspace::open(f.root()).unwrap();
    let lock = ws.lock(Duration::from_secs(5)).unwrap();
    let mut all = records(f);
    let r = all.iter_mut().find(|r| r.name == name).unwrap();
    let mut e = Equivalence::default();
    e.verdict = Some("equivalent_tested".into());
    r.equivalence = Some(e);
    save_rebuild(f.root(), &all, &lock).unwrap();
}

#[test]
fn equivalence_survives_same_code() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    run(&f, &["a.c"]);
    set_equivalence(&f, "add");
    run(&f, &["a.c"]);
    let kept = record(&f, "add").equivalence.unwrap();
    assert_eq!(kept.verdict.as_deref(), Some("equivalent_tested"));
    // other code: the verdict no longer applies
    let mut add = ADD.to_vec();
    add[4] = 0x56;
    f.write_obj("A", &[("_add", &add), ("_sub", SUB)]);
    f.write_source("a.c", &format!("{A_C}/* changed */\n"));
    run(&f, &["a.c"]);
    assert!(record(&f, "add").equivalence.is_none());
}

#[test]
fn unknown_record_keys_are_preserved() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    seed(
        &f,
        r#"schema = 1

[[function]]
address = "seg:0000:0010"
name = "add"
file = "a.c"
result = "differs"
future = "x"

[function.equivalence]
verdict = "equivalent_tested"
reasons = ["same calls"]

[[function]]
address = "seg:0000:0030"
name = "zed"
file = "z.c"
result = "identical"
future = 1
"#,
    );
    run(&f, &["a.c"]);
    let add = record(&f, "add");
    assert_eq!(add.verdict, Some(VerdictId::Identical));
    assert_eq!(add.extra["future"].as_str(), Some("x"));
    let e = add.equivalence.unwrap();
    assert_eq!(e.extra["reasons"].as_array().unwrap().len(), 1);
    assert_eq!(record(&f, "zed").extra["future"].as_integer(), Some(1));
    let text = std::fs::read_to_string(f.rebuild_path()).unwrap();
    assert!(text.contains("reasons = [\"same calls\"]"), "{text}");
}

#[test]
fn rebuild_toml_is_byte_stable() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    run(&f, &[]);
    let first = std::fs::read(f.rebuild_path()).unwrap();
    run(&f, &[]);
    assert_eq!(std::fs::read(f.rebuild_path()).unwrap(), first);
    let ws = Workspace::open(f.root()).unwrap();
    let lock = ws.lock(Duration::from_secs(5)).unwrap();
    save_rebuild(f.root(), &records(&f), &lock).unwrap();
    assert_eq!(std::fs::read(f.rebuild_path()).unwrap(), first);
    assert!(!first.contains(&b'\r'));
}

#[test]
fn output_header_shows_new_result() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let session = Session::open(f.root()).unwrap();
    let path = f.root().join(function_path(&session, SUB_AT));
    let zed_path = f.root().join(function_path(&session, ZED_AT));
    run(&f, &["a.c"]);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("@rebuild    identical (a.c, turbo-c-2.0 -ms -O, 11 fixed + 0 linker, "),
        "{text}"
    );
    let mut sub = SUB.to_vec();
    sub[6] = 0x33;
    f.write_obj("A", &[("_add", ADD), ("_sub", &sub)]);
    f.write_source("a.c", &format!("{A_C}/* changed */\n"));
    run(&f, &["a.c"]);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("@rebuild    differs: 1 of 11 bytes"),
        "{text}"
    );
    let index = std::fs::read_to_string(f.root().join("output/index.md")).unwrap();
    assert!(
        index.contains("Rebuild: 1 identical, 1 differs, 0 error"),
        "{index}"
    );
    // files of functions not built are not written
    assert!(!zed_path.exists());
}

#[test]
fn assembler_source_is_not_compiled() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_source("asmpart.asm", "_TEXT segment\n_TEXT ends\nend\n");
    let response = run(&f, &[]);
    let files = response.data["files"].as_array().unwrap();
    let asm = files.iter().find(|v| v["file"] == "asmpart.asm").unwrap();
    assert_eq!(asm["status"], "error");
    assert!(
        asm["message"]
            .as_str()
            .unwrap()
            .starts_with("assembler sources are not built yet"),
        "{asm}"
    );
    assert!(f.log("calls.log").iter().all(|c| !c.contains("ASMPART")));
    assert_eq!(record(&f, "add").verdict, Some(VerdictId::Identical));
}
