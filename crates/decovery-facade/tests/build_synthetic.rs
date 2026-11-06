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
fn assembler_source_is_skipped_and_keeps_record_and_object() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_source("asmpart.asm", "_TEXT segment\n_TEXT ends\nend\n");
    seed(
        &f,
        "schema = 1\n\n[[function]]\naddress = \"seg:0000:0030\"\nname = \"zed\"\nfile = \"asmpart.asm\"\nresult = \"identical\"\n",
    );
    let obj_dir = f.root().join("cache/rebuild/obj");
    std::fs::create_dir_all(&obj_dir).unwrap();
    std::fs::write(obj_dir.join("asmpart.obj"), b"migrated object").unwrap();
    std::fs::remove_file(f.root().join("src/z.c")).unwrap();
    let response = run(&f, &[]);
    let files = response.data["files"].as_array().unwrap();
    let asm = files.iter().find(|v| v["file"] == "asmpart.asm").unwrap();
    assert_eq!(asm["status"], "skipped");
    assert!(asm.get("message").is_none(), "{asm}");
    let hints = strings(&response.data["hints"]);
    assert!(
        hints.contains(&"no assembler available for asmpart.asm".to_string()),
        "{hints:?}"
    );
    assert_eq!(response.data["counts"]["skipped_files"], 1);
    assert_eq!(response.data["counts"]["failed_files"], 0);
    assert!(
        response.summary.ends_with("; 1 skipped"),
        "{}",
        response.summary
    );
    assert!(f.log("calls.log").iter().all(|c| !c.contains("ASMPART")));
    let zed = record(&f, "zed");
    assert_eq!((zed.result, zed.verdict), (RebuildResult::Identical, None));
    assert_eq!(zed.file.as_deref(), Some("asmpart.asm"));
    assert_eq!(
        std::fs::read(obj_dir.join("asmpart.obj")).unwrap(),
        b"migrated object"
    );
    assert_eq!(record(&f, "add").verdict, Some(VerdictId::Identical));
}

#[test]
fn failed_compile_keeps_last_good_object() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    run(&f, &["a.c"]);
    let obj = f.root().join("cache/rebuild/obj/a.obj");
    let meta = f.root().join("cache/rebuild/obj/a.json");
    let good = std::fs::read(&obj).unwrap();
    std::fs::remove_file(f.objects.path().join("A.OBJ")).unwrap();
    f.write_source("a.c", &format!("{A_C}/* changed */\n"));
    let response = run(&f, &["a.c"]);
    assert_eq!(response.data["files"][0]["status"], "error");
    assert_eq!(record(&f, "add").result, RebuildResult::Error);
    assert_eq!(std::fs::read(&obj).unwrap(), good);
    assert!(meta.is_file());
}

#[test]
fn inline_asm_keeps_unchecked_verdict_and_message() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    // zed placed outside the program image: its original bytes are not available
    let symbols = f.root().join("knowledge/symbols.toml");
    let text = std::fs::read_to_string(&symbols)
        .unwrap()
        .replace("seg:0000:0030", "seg:0F00:0000");
    std::fs::write(&symbols, text).unwrap();
    f.write_source("z.c", "void zed(void)\n{\n    _asm nop;\n}\n");
    run(&f, &["z.c"]);
    let zed = record(&f, "zed");
    assert_eq!(zed.verdict, Some(VerdictId::Unchecked));
    assert_eq!(zed.result, RebuildResult::Error);
    assert!(
        zed.blockers
            .contains(&BlockerRecord::new("inline-assembly", None, None))
    );
    let message = zed.message.unwrap();
    assert!(
        message.starts_with("the original bytes of the function are not in the program"),
        "{message}"
    );
    assert!(message.contains("line 3: inline-asm"), "{message}");
}

#[test]
fn analysis_with_end_before_start_does_not_panic() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let root = f.root();
    let mut analysis = decovery_core::Analysis::load(root).unwrap().unwrap();
    analysis.functions[0].end = decovery_core::Address::Seg { seg: 0, off: 0x0F };
    let ws = Workspace::open(root).unwrap();
    let lock = ws.lock(Duration::from_secs(5)).unwrap();
    analysis.save(root, &lock).unwrap();
    drop(lock);
    run(&f, &["a.c"]);
    assert_eq!(record(&f, "add").verdict, Some(VerdictId::Identical));
}

// ---- variants (Task 12) ----

use decovery_facade::{FacadeError, Variant};

fn variant_request(function: Option<&str>, sources: &[&str]) -> BuildRequest {
    let mut request = BuildRequest::default();
    request.function = function.map(str::to_string);
    request.variants = sources.iter().map(|s| Variant::new(*s)).collect();
    request
}

fn run_variants(f: &Fixture, function: &str, sources: &[&str]) -> Response {
    build(f.root(), &variant_request(Some(function), sources), &|_| {}).unwrap()
}

fn order(response: &Response) -> Vec<u64> {
    response.data["variants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["index"].as_u64().unwrap())
        .collect()
}

const SUB_SOURCE: &str = "int sub(int a, int b)\n{\n    return a - b;\n}\n";

/// `n` different texts of the same function (equal texts are compiled once).
fn texts(n: usize) -> Vec<String> {
    (1..=n)
        .map(|i| format!("{SUB_SOURCE}/* text {i} */\n"))
        .collect()
}

fn refs(texts: &[String]) -> Vec<&str> {
    texts.iter().map(String::as_str).collect()
}

#[test]
fn variants_are_ranked() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut two = SUB.to_vec();
    two[6] = 0x33;
    two[7] = 0x00;
    let mut one = SUB.to_vec();
    one[6] = 0x33;
    // the objects also hold `add`, which is not the function asked for
    f.write_obj("V001", &[("_add", ADD), ("_sub", &two)]);
    f.write_obj("V002", &[("_add", ADD), ("_sub", SUB)]);
    f.write_obj("V003", &[("_sub", &one)]);
    let t = texts(3);
    let response = run_variants(&f, "sub", &refs(&t));
    assert_eq!(f.log("requests.log"), ["3"], "one runner request");
    assert_eq!(order(&response), [2, 3, 1]);
    let d = &response.data;
    assert_eq!(d["function"], "sub");
    assert_eq!(d["best"], 2);
    let v = d["variants"].as_array().unwrap();
    assert_eq!(v[0]["verdict"], "identical");
    assert_eq!(v[0]["differing"], 0);
    assert_eq!(v[1]["verdict"], "differs");
    assert_eq!(v[1]["differing"], 1);
    assert_eq!(v[2]["differing"], 2);
    assert_eq!(v[2]["blockers"][0]["kind"], "bytes-differ");
    assert!(v[2]["instructions_differing"].as_u64().unwrap() >= 1);
    assert!(
        response.summary.contains("variant 2"),
        "{}",
        response.summary
    );
}

#[test]
fn variant_labels_are_reported() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("V001", &[("_sub", SUB)]);
    let mut request = variant_request(Some("sub"), &[SUB_SOURCE]);
    request.variants[0] = Variant::new(SUB_SOURCE).with_label("plain");
    let response = build(f.root(), &request, &|_| {}).unwrap();
    assert_eq!(response.data["variants"][0]["label"], "plain");
}

#[test]
fn variant_compile_error_ranks_last() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    // no V001.OBJ: the fake compiler fails
    f.write_obj("V002", &[("_sub", SUB)]);
    f.write_obj("V003", &[("_sub", SUB)]);
    let t = texts(2);
    let response = run_variants(&f, "sub", &["int broken(", &t[0], &t[1]]);
    assert_eq!(order(&response), [2, 3, 1]);
    assert_eq!(response.data["best"], 2);
    let last = &response.data["variants"][2];
    assert_eq!(last["verdict"], "error");
    assert!(
        last["message"]
            .as_str()
            .unwrap()
            .starts_with("variant 1: compiler exit code 1")
            && last["message"].as_str().unwrap().contains("A.C(1): Error"),
        "{last}"
    );
    // nothing compiles: no best
    let f = fixture(&python, "");
    let response = run_variants(&f, "sub", &[SUB_SOURCE]);
    assert!(response.data["best"].is_null(), "{}", response.data);
    assert_eq!(response.data["variants"][0]["verdict"], "error");
}

#[test]
fn variant_without_the_function_is_unchecked_and_ranks_last() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("V001", &[("_add", ADD)]);
    let mut two = SUB.to_vec();
    two[6] = 0x33;
    f.write_obj("V002", &[("_sub", &two)]);
    let t = texts(2);
    let response = run_variants(&f, "sub", &refs(&t));
    assert_eq!(order(&response), [2, 1]);
    let last = &response.data["variants"][1];
    assert_eq!(last["verdict"], "unchecked");
    assert!(last["message"].as_str().unwrap().contains("sub"), "{last}");
}

#[test]
fn variants_do_not_write_records() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    seed(&f, OTHER_FILES);
    let before = std::fs::read(f.rebuild_path()).unwrap();
    f.write_obj("V001", &[("_sub", SUB)]);
    f.write_obj("V002", &[("_sub", SUB)]);
    let t = texts(2);
    run_variants(&f, "sub", &refs(&t));
    assert_eq!(std::fs::read(f.rebuild_path()).unwrap(), before);
    let root = f.root();
    assert!(!root.join("cache/rebuild/obj").exists());
    assert!(!root.join("output").exists());
    let runs = std::fs::read_dir(root.join("cache/rebuild/runs")).map_or(0, |d| d.count());
    assert_eq!(runs, 0, "build directory not removed");
}

#[test]
fn unchanged_variant_is_not_compiled_again() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("V001", &[("_sub", SUB)]);
    run_variants(&f, "sub", &[SUB_SOURCE]);
    assert_eq!(f.log("calls.log").len(), 1);
    let second = run_variants(&f, "sub", &[SUB_SOURCE]);
    assert_eq!(f.log("calls.log").len(), 1, "served from the object cache");
    assert_eq!(second.data["timing"]["cached"], 1);
    assert_eq!(second.data["timing"]["jobs"], 0);
    assert_eq!(second.data["variants"][0]["verdict"], "identical");
    // a changed variant is compiled
    run_variants(&f, "sub", &[&format!("{SUB_SOURCE}/* changed */\n")]);
    assert_eq!(f.log("calls.log").len(), 2);
}

#[test]
fn variant_with_inline_asm_is_not_identical() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("V001", &[("_sub", SUB)]);
    f.write_obj("V002", &[("_sub", SUB)]);
    let asm = "int sub(int a, int b)\r\n{\r\n    _asm nop;\r\n    return a - b;\r\n}\r\n";
    let response = run_variants(&f, "sub", &[asm, SUB_SOURCE]);
    // the plain variant wins although both objects are byte-identical
    assert_eq!(order(&response), [2, 1]);
    let v = &response.data["variants"][1];
    assert_eq!(v["verdict"], "differs");
    assert!(
        v["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["kind"] == "inline-assembly"),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("line 3"), "{v}");
}

#[test]
fn too_many_variants_is_rejected() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let many = vec![SUB_SOURCE; 65];
    let error = build(f.root(), &variant_request(Some("sub"), &many), &|_| {}).unwrap_err();
    assert!(
        matches!(&error, FacadeError::Invalid(m) if m.contains("at most 64")),
        "{error}"
    );
    assert!(f.log("requests.log").is_empty());
    // 64 are fine
    for i in 1..=64 {
        f.write_obj(&format!("V{i:03}"), &[("_sub", SUB)]);
    }
    let t = texts(64);
    let response = run_variants(&f, "sub", &refs(&t));
    assert_eq!(response.data["variants"].as_array().unwrap().len(), 64);
    assert_eq!(f.log("requests.log"), ["64"]);
}

#[test]
fn variants_need_function() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let error = build(f.root(), &variant_request(None, &[SUB_SOURCE]), &|_| {}).unwrap_err();
    assert!(
        matches!(&error, FacadeError::Invalid(m) if m.contains("function")),
        "{error}"
    );
    assert!(f.log("requests.log").is_empty());
}

#[test]
fn function_without_record_comes_from_the_only_defining_source() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("V001", &[("_sub", SUB)]);
    // no rebuild record: a.c is the only source that defines sub
    let response = run_variants(&f, "sub", &[SUB_SOURCE]);
    assert_eq!(response.data["variants"][0]["verdict"], "identical");
    let error = build(
        f.root(),
        &variant_request(Some("nosuch"), &[SUB_SOURCE]),
        &|_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("nosuch"), "{error}");
    // two sources defining it: ambiguous
    f.write_source("b.c", SUB_SOURCE);
    let error = build(
        f.root(),
        &variant_request(Some("sub"), &[SUB_SOURCE]),
        &|_| {},
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("a.c") && error.to_string().contains("b.c"),
        "{error}"
    );
}

#[test]
fn function_selects_its_file_without_variants() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut request = BuildRequest::default();
    request.function = Some("zed".to_string());
    let response = build(f.root(), &request, &|_| {}).unwrap();
    assert_eq!(f.log("calls.log"), ["Z.C"]);
    assert_eq!(response.data["files"].as_array().unwrap().len(), 1);
    assert_eq!(record(&f, "zed").verdict, Some(VerdictId::Identical));
}

// ---- variants, fix round 1 ----

/// `mov ax,[var]` plus `nop`s up to `len` bytes and a `ret`; the offset field is `field` (the original's word).
fn loader(field: u16, len: usize) -> Vec<u8> {
    let [lo, hi] = field.to_le_bytes();
    let mut code = vec![0xA1, lo, hi];
    code.resize(len - 1, 0x90);
    code.push(0xC3);
    code
}

/// Three loaders in the original (add -> g1, sub -> g3, zed -> g3) with the globals at `0200:0010`, `0014`, `0018`
/// (DGROUP at linear 0x2000), and the kept object of z.c (zed loads g3) from a full build of z.c. Variants of `sub`
/// replace a.c, so `zed` is the only other function that votes on the anchor besides the variant's own `add`.
fn anchored(f: &Fixture) {
    f.patch_original(0x10, &loader(0x10, 11));
    f.patch_original(0x20, &loader(0x18, 11));
    f.patch_original(0x30, &loader(0x18, 5));
    let mut symbols = std::fs::read_to_string(f.root().join("knowledge/symbols.toml")).unwrap();
    for (name, off) in [("g1", 0x10), ("g2", 0x14), ("g3", 0x18)] {
        symbols.push_str(&format!(
            "\n[[symbol]]\naddress = \"seg:0200:{off:04X}\"\nkind = \"global\"\nname = \"{name}\"\nsource = \"human\"\nconfidence = \"confirmed\"\n"
        ));
    }
    std::fs::write(f.root().join("knowledge/symbols.toml"), symbols).unwrap();
    f.write_raw_obj(
        "Z",
        &build_fixture::omf_with_refs(&[("_zed", &loader(0, 5), "_g3")]),
    );
    run(f, &["z.c"]);
    assert!(f.root().join("cache/rebuild/obj/z.obj").is_file());
}

#[test]
fn variant_is_judged_with_the_anchors_of_the_other_files() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    anchored(&f);
    // the variant's own add and the kept zed agree on DGROUP = 0x2000; sub loads g2 where the original has g3
    f.write_raw_obj(
        "V001",
        &build_fixture::omf_with_refs(&[
            ("_add", &loader(0, 11), "_g1"),
            ("_sub", &loader(0, 11), "_g2"),
        ]),
    );
    f.write_raw_obj(
        "V002",
        &build_fixture::omf_with_refs(&[
            ("_add", &loader(0, 11), "_g1"),
            ("_sub", &loader(0, 11), "_g3"),
        ]),
    );
    let t = texts(2);
    let response = run_variants(&f, "sub", &refs(&t));
    assert_eq!(order(&response), [2, 1], "{}", response.data);
    let v = response.data["variants"].as_array().unwrap();
    assert_eq!(v[0]["verdict"], "identical", "{}", v[0]);
    assert_eq!(v[1]["verdict"], "differs", "{}", v[1]);
    assert!(
        v[1]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["kind"] == "wrong-absolute-ref"),
        "{}",
        v[1]
    );
    assert_eq!(response.data["warnings"], serde_json::json!([]));

    // an out-of-date kept object is left out (and said so): the anchor is then the variant's own, weaker one
    f.write_source("z.c", &format!("{}/* changed */\n", build_fixture::Z_C));
    let response = run_variants(&f, "sub", &refs(&t));
    let warnings = strings(&response.data["warnings"]);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("z.c") && w.contains("out of date")),
        "{warnings:?}"
    );
}

#[test]
fn variant_shares_the_object_cache_with_a_full_build() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    run(&f, &["a.c"]);
    assert_eq!(f.log("calls.log").len(), 1);
    // the text of a.c itself: staged under its own name in a directory of its own, the same compile as the build
    let response = run_variants(&f, "sub", &[A_C]);
    assert_eq!(
        f.log("calls.log").len(),
        1,
        "served from the cache of the build"
    );
    assert_eq!(response.data["timing"]["cached"], 1);
    assert_eq!(response.data["variants"][0]["verdict"], "identical");
}

#[test]
fn variant_is_compiled_under_the_name_of_its_file() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("V001", &[("_sub", SUB)]);
    run_variants(&f, "sub", &[SUB_SOURCE]);
    // the job runs in the variant's directory and compiles A.C there, like the build does in the root
    assert_eq!(f.log("calls.log"), ["V001/A.C"]);
}

#[test]
fn equal_variant_texts_are_compiled_once() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut worse = SUB.to_vec();
    worse[6] = 0x33;
    f.write_obj("V001", &[("_sub", SUB)]);
    f.write_obj("V002", &[("_sub", &worse)]);
    let t = texts(2);
    // texts 1 and 3 are equal
    let response = run_variants(&f, "sub", &[&t[0], &t[1], &t[0]]);
    assert_eq!(f.log("requests.log"), ["2"]);
    assert_eq!(response.data["timing"]["jobs"], 2);
    assert_eq!(response.data["timing"]["distinct"], 2);
    assert_eq!(order(&response), [1, 3, 2]);
    let v = response.data["variants"].as_array().unwrap();
    assert_eq!(v.len(), 3, "every variant gets a result");
    assert_eq!(v[0]["verdict"], "identical");
    assert_eq!(v[1]["verdict"], "identical");
}

#[test]
fn variant_messages_name_the_variant_and_its_label() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut request = variant_request(Some("sub"), &["int broken("]);
    request.variants[0] = Variant::new("int broken(").with_label("first try");
    let response = build(f.root(), &request, &|_| {}).unwrap();
    let message = response.data["variants"][0]["message"].as_str().unwrap();
    assert!(
        message.starts_with("variant 1 (first try): compiler exit code 1"),
        "{message}"
    );
}

#[test]
fn variant_with_inline_asm_ranks_after_a_clean_variant_that_differs() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut worse = SUB.to_vec();
    worse[6] = 0x33;
    f.write_obj("V001", &[("_sub", SUB)]);
    f.write_obj("V002", &[("_sub", &worse)]);
    let asm = "int sub(int a, int b)\n{\n    _asm nop;\n    return a - b;\n}\n";
    let response = run_variants(&f, "sub", &[asm, SUB_SOURCE]);
    // the clean variant differs by an instruction; the inline-assembly one is byte-identical but never best
    assert_eq!(order(&response), [2, 1]);
    assert_eq!(response.data["best"], 2);
}

#[test]
fn variant_with_a_character_outside_cp437_is_an_error_result() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    f.write_obj("V002", &[("_sub", SUB)]);
    let t = texts(1);
    let response = run_variants(&f, "sub", &["int sub(void) { /* \u{20ac} */ }", &t[0]]);
    let v = response.data["variants"].as_array().unwrap();
    assert_eq!(v.len(), 2, "no variant is dropped");
    assert_eq!(order(&response), [2, 1]);
    assert_eq!(v[1]["verdict"], "error");
    let message = v[1]["message"].as_str().unwrap();
    assert!(
        message.starts_with("variant 1:") && message.contains("U+20AC"),
        "{message}"
    );
}

#[test]
fn variants_take_one_file_at_most() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut request = variant_request(Some("sub"), &[SUB_SOURCE]);
    request.files = vec!["a.c".into(), "z.c".into()];
    let error = build(f.root(), &request, &|_| {}).unwrap_err();
    assert!(error.to_string().contains("at most one file"), "{error}");
    request.files = vec!["nofile.c".into()];
    let error = build(f.root(), &request, &|_| {}).unwrap_err();
    assert!(error.to_string().contains("nofile.c"), "{error}");
}

#[test]
fn variant_build_forwards_what_the_runner_reports_per_job() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let t = texts(3);
    for i in 1..=3 {
        f.write_obj(&format!("V{i:03}"), &[("_sub", SUB)]);
    }
    let seen = std::cell::RefCell::new(Vec::new());
    build(f.root(), &variant_request(Some("sub"), &refs(&t)), &|p| {
        seen.borrow_mut().push(p.message.unwrap_or_default())
    })
    .unwrap();
    let seen = seen.into_inner();
    let jobs = seen.iter().filter(|m| m.contains(" of 3 done")).count();
    assert_eq!(jobs, 3, "{seen:?}");
}
