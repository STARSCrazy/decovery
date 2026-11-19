//! Exemplar index, `find similar` and the exemplars of `show` on the synthetic MZ workspace of `build_fixture`
//! (add, sub, zed). Rebuild records are seeded directly except in the build test, which needs Python (skipped
//! with a message without it: set `DECOVERY_PYTHON` or put `python` on PATH).

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::time::Instant;

use build_fixture::{ADD_AT, Fixture, SUB_AT, ZED_AT, fixture};
use decovery_core::Address;
use decovery_facade::{
    Budget, BuildRequest, EXEMPLARS_FILE, ExemplarIndex, FindQuery, FindWhat, Session, build,
    exemplar_index, find, show,
};
use serde_json::Value;

/// A fixture that never runs its fake runner (no Python needed), with a memory map so names resolve.
fn workspace() -> Fixture {
    let f = fixture("python", "");
    let path = f.root().join("decovery.toml");
    let config = std::fs::read_to_string(&path).unwrap().replacen(
        "processor = \"x86\"
",
        "processor = \"x86\"

[[target.segment]]
name = \"code\"
start = \"seg:0000:0000\"
length = 256
file_offset = 32
file_length = 256
permissions = \"rx\"
",
        1,
    );
    std::fs::write(path, config).unwrap();
    f
}

fn record(address: &str, name: &str, file: &str, result: &str) -> String {
    format!(
        "[[function]]\naddress = \"{address}\"\nname = \"{name}\"\nfile = \"{file}\"\ncompiler = \"turbo-c-2.0\"\nflags = \"-ms -O\"\nresult = \"{result}\"\n\n"
    )
}

fn seed(f: &Fixture, records: &[String]) {
    std::fs::write(
        f.rebuild_path(),
        format!("schema = 1\n\n{}", records.concat()),
    )
    .unwrap();
}

fn index_file(f: &Fixture) -> Value {
    serde_json::from_str(&std::fs::read_to_string(f.root().join(EXEMPLARS_FILE)).unwrap()).unwrap()
}

fn entry_names(index: &Value) -> Vec<String> {
    index["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn index_contains_only_identical_c_functions() {
    let f = workspace();
    seed(
        &f,
        &[
            record("seg:0000:0010", "add", "a.c", "identical"),
            record("seg:0000:0020", "sub", "a.c", "differs"),
        ],
    );
    let session = Session::open(f.root()).unwrap();
    let index = exemplar_index(&session).unwrap();
    assert_eq!(index.len(), 1);
    let file = index_file(&f);
    assert_eq!(file["schema"], 2);
    assert_eq!(file["target_sha256"], "aa");
    assert_eq!(entry_names(&file), ["add"]);
    let add = &file["entries"][0];
    assert_eq!(add["address"], "seg:0000:0010");
    assert_eq!(add["file"], "a.c");
    assert_eq!(add["flags"], "-ms -O");
    assert_eq!(add["forms"].as_array().unwrap().len(), 6);
    assert_eq!(add["minhash"].as_array().unwrap().len(), 64);
    let forms = file["forms"].as_array().unwrap();
    assert!(forms.iter().any(|s| s == "push bp"), "{forms:?}");

    // a library-classified function is no exemplar either
    let symbols = std::fs::read_to_string(f.root().join("knowledge/symbols.toml")).unwrap();
    let symbols = symbols.replacen(
        "name = \"add\"\n",
        "name = \"add\"\nlibrary = \"clib\"\n",
        1,
    );
    std::fs::write(f.root().join("knowledge/symbols.toml"), symbols).unwrap();
    let session = Session::open(f.root()).unwrap();
    assert_eq!(exemplar_index(&session).unwrap().len(), 0);
}

#[test]
fn assembler_functions_are_not_exemplars() {
    let f = workspace();
    seed(
        &f,
        &[
            record("seg:0000:0010", "add", "a.c", "identical"),
            record("seg:0000:0030", "zed", "z.asm", "identical"),
            record("seg:0000:0020", "sub", "s.S", "identical"),
        ],
    );
    let session = Session::open(f.root()).unwrap();
    exemplar_index(&session).unwrap();
    assert_eq!(entry_names(&index_file(&f)), ["add"]);
}

#[test]
fn function_is_not_its_own_exemplar() {
    let f = workspace();
    seed(
        &f,
        &[
            record("seg:0000:0010", "add", "a.c", "identical"),
            record("seg:0000:0020", "sub", "a.c", "identical"),
        ],
    );
    let session = Session::open(f.root()).unwrap();
    let index = exemplar_index(&session).unwrap();
    let similar = index.similar(&session, ADD_AT, 3).unwrap();
    let addresses: Vec<Address> = similar.iter().map(|e| e.address).collect();
    assert_eq!(addresses, [SUB_AT]);
    let zed = index.similar(&session, ZED_AT, 3).unwrap();
    assert_eq!(zed.len(), 2);
    assert!(zed.iter().all(|e| e.address != ZED_AT));
}

#[test]
fn empty_index_gives_hint() {
    let f = workspace();
    let session = Session::open(f.root()).unwrap();
    let mut query = FindQuery::new(FindWhat::Similar);
    query.pattern = Some("sub".into());
    let response = find(&session, &query, Budget::default()).unwrap();
    assert!(
        response
            .summary
            .contains("no solved functions to compare with"),
        "{}",
        response.summary
    );
    assert_eq!(response.data["items"], serde_json::json!([]));
    assert_eq!(response.data["total"], 0);
}

#[test]
fn changed_target_rebuilds_index() {
    let f = workspace();
    seed(&f, &[record("seg:0000:0010", "add", "a.c", "identical")]);
    let session = Session::open(f.root()).unwrap();
    exemplar_index(&session).unwrap();
    let mut file = index_file(&f);
    let good = file["entries"][0].clone();
    file["target_sha256"] = "an-older-target".into();
    file["entries"][0]["forms"] = serde_json::json!([]);
    file["entries"][0]["coarse"] = serde_json::json!([]);
    std::fs::write(f.root().join(EXEMPLARS_FILE), file.to_string()).unwrap();
    let index = exemplar_index(&session).unwrap();
    assert_eq!(index.len(), 1);
    let file = index_file(&f);
    assert_eq!(file["target_sha256"], "aa");
    assert_eq!(file["entries"][0]["forms"], good["forms"]);
    assert_eq!(file["entries"][0]["minhash"], good["minhash"]);
}

#[test]
fn removed_member_leaves_the_index() {
    let f = workspace();
    seed(
        &f,
        &[
            record("seg:0000:0010", "add", "a.c", "identical"),
            record("seg:0000:0020", "sub", "a.c", "identical"),
        ],
    );
    exemplar_index(&Session::open(f.root()).unwrap()).unwrap();
    seed(
        &f,
        &[
            record("seg:0000:0010", "add", "a.c", "identical"),
            record("seg:0000:0020", "sub", "a.c", "differs"),
        ],
    );
    exemplar_index(&Session::open(f.root()).unwrap()).unwrap();
    assert_eq!(entry_names(&index_file(&f)), ["add"]);
}

#[test]
fn build_refresh_adds_new_identical_function() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let mut request = BuildRequest::default();
    request.files = vec!["a.c".into()];
    build(
        f.root(),
        &request,
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    let mut names = entry_names(&index_file(&f));
    names.sort();
    assert_eq!(names, ["add", "sub"]);
    request.files = vec!["z.c".into()];
    build(
        f.root(),
        &request,
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    let mut names = entry_names(&index_file(&f));
    names.sort();
    assert_eq!(names, ["add", "sub", "zed"]);
}

#[test]
fn find_similar_returns_source_and_reason() {
    let f = workspace();
    seed(&f, &[record("seg:0000:0010", "add", "a.c", "identical")]);
    let session = Session::open(f.root()).unwrap();
    let mut query = FindQuery::new(FindWhat::Similar);
    query.pattern = Some("sub".into());
    query.limit = 3;
    let response = find(&session, &query, Budget::default()).unwrap();
    let items = response.data["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{}", response.data);
    let add = &items[0];
    assert_eq!(add["name"], "add");
    assert_eq!(add["address"], "seg:0000:0010");
    assert_eq!(add["file"], "a.c");
    assert_eq!(add["flags"], "-ms -O");
    assert_eq!(add["twin"], false);
    assert!(add["similarity"].as_f64().unwrap() > 0.5);
    let source = add["source"].as_str().unwrap();
    assert!(source.contains("return a + b;"), "{source}");
    assert!(!source.contains("return a - b;"), "only add's definition");
    let reason = add["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("similarity ") && reason.contains(", coverage "),
        "{reason}"
    );
    // add and sub (six instructions each) share no window of six: no stretch to name
    assert_eq!(add["coverage"], 0.0);
    assert!(!reason.contains("shared stretches"), "{reason}");
    assert!(response.summary.contains("add"), "{}", response.summary);

    // a tiny budget keeps the rows and moves the source texts into a handle
    let response = find(&session, &query, Budget { chars: 120 }).unwrap();
    assert_eq!(response.handles.len(), 1, "{}", response.data);
    assert_eq!(response.handles[0].kind, "find-results");
    assert_eq!(response.data["items"][0]["name"], "add");
}

#[test]
fn show_lists_exemplars_and_current_source() {
    let f = workspace();
    seed(&f, &[record("seg:0000:0010", "add", "a.c", "identical")]);
    let session = Session::open(f.root()).unwrap();
    let response = show(&session, "sub", Budget::default()).unwrap();
    let exemplars = response.data["exemplars"].as_array().unwrap();
    assert_eq!(exemplars.len(), 1);
    assert_eq!(exemplars[0]["name"], "add");
    assert_eq!(exemplars[0]["address"], "seg:0000:0010");
    assert_eq!(exemplars[0]["file"], "a.c");
    assert!(exemplars[0].get("source").is_none());
    assert!(exemplars[0]["coverage"].is_number());
    assert_eq!(exemplars[0]["twin"], false);
    assert_eq!(response.data["source"]["file"], "a.c");
    let text = response.data["source"]["text"].as_str().unwrap();
    assert!(text.contains("return a - b;"), "{text}");
    assert!(!text.contains("return a + b;"), "{text}");
    assert!(
        response.summary.contains("; exemplars: add ("),
        "{}",
        response.summary
    );
    // the generated file stays as it was
    let generated =
        std::fs::read_to_string(f.root().join(response.data["file"].as_str().unwrap())).unwrap();
    assert!(!generated.contains("exemplar"));
}

#[test]
fn show_without_exemplars_has_no_summary_suffix() {
    let f = workspace();
    let session = Session::open(f.root()).unwrap();
    let response = show(&session, "zed", Budget::default()).unwrap();
    assert_eq!(response.data["exemplars"], serde_json::json!([]));
    assert!(!response.summary.contains("exemplars"));
    assert_eq!(response.data["source"]["file"], "z.c");
    assert!(!f.root().join(EXEMPLARS_FILE).exists());
}

/// Deterministic pseudo-random numbers (splitmix64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// 10 000 random sequences of 30 to 200 forms out of 400, and a query: member 4321 with one form changed.
fn synthetic() -> (ExemplarIndex, Vec<u32>) {
    let mut rng = Rng(7);
    let sequences: Vec<Vec<u32>> = (0..10_000)
        .map(|_| {
            let len = 30 + rng.below(171) as usize;
            (0..len).map(|_| rng.below(400) as u32).collect()
        })
        .collect();
    let mut query = sequences[4321].clone();
    let middle = query.len() / 2;
    query[middle] = 9_999;
    (ExemplarIndex::from_sequences(&sequences), query)
}

#[test]
fn lookup_of_10000_members_is_fast() {
    // ruling preflight row 13: the candidate set from the LSH buckets is asserted, not the wall time
    let (index, query) = synthetic();
    assert_eq!(index.len(), 10_000);
    let candidates = index.candidates(&query);
    assert!(candidates.contains(&4321));
    assert!(
        candidates.len() <= 100,
        "{} candidates of 10 000",
        candidates.len()
    );
    let ranked = index.rank_forms(&query, &query, None, 3);
    assert_eq!(ranked[0].candidate, 4321);
}

#[test]
#[ignore = "perf: wall time, run with --release -- --ignored"]
fn lookup_of_10000_members_is_fast_in_wall_time() {
    let (index, query) = synthetic();
    let started = Instant::now();
    let ranked = index.rank_forms(&query, &query, None, 3);
    let elapsed = started.elapsed();
    assert_eq!(ranked[0].candidate, 4321);
    let limit_ms = if cfg!(debug_assertions) { 50 } else { 5 };
    assert!(elapsed.as_millis() < limit_ms, "{elapsed:?}");
}

#[test]
fn changed_range_redecodes_entry() {
    // the analysed range of a member changes under the same target: its forms must follow the new range
    let f = workspace();
    seed(&f, &[record("seg:0000:0010", "add", "a.c", "identical")]);
    exemplar_index(&Session::open(f.root()).unwrap()).unwrap();
    assert_eq!(
        index_file(&f)["entries"][0]["forms"]
            .as_array()
            .unwrap()
            .len(),
        6
    );

    let root = f.root();
    let workspace = decovery_core::Workspace::open(root).unwrap();
    let lock = workspace.lock(std::time::Duration::from_secs(5)).unwrap();
    let mut analysis = decovery_core::Analysis::new(
        decovery_core::Provider::new("test", "1"),
        "aa",
        decovery_core::knowledge_hash(root).unwrap(),
        "2026-11-06",
    );
    let seg = |off: u16| Address::Seg { seg: 0, off };
    analysis.functions = vec![
        // `push bp; mov bp, sp` only
        decovery_core::AnalyzedFunction::new(seg(0x10), seg(0x12), 3),
        decovery_core::AnalyzedFunction::new(seg(0x20), seg(0x2A), 11),
        decovery_core::AnalyzedFunction::new(seg(0x30), seg(0x34), 5),
    ];
    analysis.save(root, &lock).unwrap();
    drop(lock);

    exemplar_index(&Session::open(root).unwrap()).unwrap();
    assert_eq!(
        index_file(&f)["entries"][0]["forms"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn show_budget_covers_source_text() {
    // the current definition counts against the budget like the pseudo-C; beyond it, it becomes a handle
    let f = workspace();
    let long = format!(
        "int add(int a, int b)\n{{\n    return a + b;\n}}\n\nint sub(int a, int b)\n{{\n    /* {} */\n    return a - b;\n}}\n",
        "x".repeat(9000)
    );
    std::fs::write(f.root().join("src/a.c"), long).unwrap();
    let session = Session::open(f.root()).unwrap();
    let response = show(&session, "sub", Budget::default()).unwrap();
    assert_eq!(response.data["source"]["file"], "a.c");
    assert!(
        response.data["source"]["text"].is_null(),
        "{}",
        response.data["source"]
    );
    let handle = response
        .handles
        .iter()
        .find(|h| h.kind == "source-text")
        .expect("a source-text handle");
    assert_eq!(response.data["source"]["handle"], handle.id.as_str());
}

#[test]
fn find_similar_names_exemplars_by_the_knowledge() {
    // the rebuild record still carries the default name; the knowledge calls the function `add`
    let f = workspace();
    seed(
        &f,
        &[record("seg:0000:0010", "fun_0000_0010", "a.c", "identical")],
    );
    let session = Session::open(f.root()).unwrap();
    let mut query = FindQuery::new(FindWhat::Similar);
    query.pattern = Some("sub".into());
    query.limit = 3;
    let response = find(&session, &query, Budget::default()).unwrap();
    let items = response.data["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{}", response.data);
    assert_eq!(items[0]["name"], "add");
}
