//! The Decomp legacy bridge (`diagnose` with `deep`, `search`, `verify`) against a fake `decomp-legacy` plugin
//! (`tests/fixtures/fake_legacy.py`) on the synthetic MZ build workspace. Skipped (with a message) without Python:
//! set `DECOVERY_PYTHON` or put `python` on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use build_fixture::{A_C, ADD, Fixture, SUB, fixture};
use decovery_core::read_rebuild;
use decovery_facade::{
    CancelToken, Control, FacadeError, LegacyCall, LegacyOperation, LegacyOptions, Progress,
    Response, diagnose_deep, search, verify,
};
use serde_json::{Value, json};

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn script() -> PathBuf {
    std::path::absolute(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_legacy.py"))
        .unwrap()
}

/// The build fixture with a Decomp workspace beside it, `[legacy]` and `[plugins.decomp-legacy]` (the fake).
struct Bridge {
    f: Fixture,
    decomp: tempfile::TempDir,
}

impl Bridge {
    fn root(&self) -> &Path {
        self.f.root()
    }

    fn shadow(&self) -> PathBuf {
        self.root().join("cache/legacy/decomp")
    }

    fn answer(&self, value: Value) {
        std::fs::create_dir_all(self.shadow()).unwrap();
        std::fs::write(self.shadow().join("answer.json"), value.to_string()).unwrap();
    }

    fn requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.shadow().join("requests.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn bridge(python: &str, with_legacy: bool, with_plugin: bool) -> Bridge {
    let f = fixture(python, "");
    let decomp = tempfile::tempdir().unwrap();
    std::fs::write(decomp.path().join("decomp.toml"), "# Decomp\n").unwrap();
    let mut config = std::fs::read_to_string(f.root().join("decovery.toml")).unwrap();
    if with_legacy {
        config.push_str(&format!(
            "\n[legacy]\ndecomp_workspace = {}\n",
            toml_string(decomp.path().to_str().unwrap())
        ));
    }
    if with_plugin {
        config.push_str(&format!(
            "\n[plugins.decomp-legacy]\ncommand = [{}, {}]\n",
            toml_string(python),
            toml_string(script().to_str().unwrap())
        ));
    }
    std::fs::write(f.root().join("decovery.toml"), config).unwrap();
    Bridge { f, decomp }
}

fn call(target: &str, operation: LegacyOperation) -> LegacyCall {
    let mut call = LegacyCall::new(target, operation);
    // never the user's own config
    call.user_plugins = Some(BTreeMap::new());
    call
}

type Tool = fn(&Path, &LegacyCall, &Control) -> Result<Response, FacadeError>;

fn run(b: &Bridge, tool: Tool, call: &LegacyCall) -> (Result<Response, FacadeError>, Vec<String>) {
    let seen = Mutex::new(Vec::new());
    let sink = |p: Progress| seen.lock().unwrap().push(p.message.unwrap_or_default());
    let result = tool(b.root(), call, &Control::progress_only(&sink));
    (result, seen.into_inner().unwrap())
}

#[test]
fn deep_diagnosis_sends_paths_symbols_and_decovery_addresses() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    let mut c = call("sub", LegacyOperation::Registers);
    c.options.all = true;
    let (result, progress) = run(&b, diagnose_deep, &c);
    let response = result.unwrap();
    let requests = b.requests();
    assert_eq!(requests.len(), 1);
    let r = &requests[0];
    let root = std::path::absolute(b.root()).unwrap();
    assert_eq!(r["operation"], "registers");
    assert_eq!(r["function"], "seg:0000:0020");
    assert_eq!(r["options"], json!({"all": true}));
    assert_eq!(
        Path::new(r["decomp_workspace"].as_str().unwrap()),
        b.decomp.path()
    );
    assert_eq!(
        Path::new(r["shadow_dir"].as_str().unwrap()),
        root.join("cache/legacy/decomp")
    );
    assert_eq!(
        Path::new(r["sources_dir"].as_str().unwrap()),
        root.join("src")
    );
    assert!(r["timeout_s"].as_u64().unwrap() >= 900);
    let symbols = r["symbols"].as_array().unwrap();
    assert!(
        symbols.contains(&json!({"address": "seg:0000:0010", "kind": "function", "name": "add"}))
    );
    assert_eq!(symbols.len(), 3, "{symbols:?}");
    // progress passes through
    assert!(
        progress.iter().any(|m| m == "Schritt 1 von 2"),
        "{progress:?}"
    );
    // Decomp's report, unchanged, and decovery's own diagnosis (no object built yet)
    let d = &response.data;
    assert_eq!(
        d["report"],
        "Bericht registers für seg:0000:0020\nZeile 2\n"
    );
    assert_eq!(d["report_language"], "de");
    assert_eq!(d["operation"], "registers");
    assert_eq!(d["function"]["name"], "sub");
    // no rebuild yet: decovery's own diagnosis says why there is none
    assert!(d["decovery"]["error"].is_string(), "{}", d["decovery"]);
    assert!(
        response
            .summary
            .starts_with("sub: Decomp registers report (2 lines")
    );
}

#[test]
fn options_outside_the_closed_set_are_rejected_before_the_plugin() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    let mut c = call("sub", LegacyOperation::Context);
    c.options = LegacyOptions::default();
    c.options.minutes = Some(5.0);
    let error = run(&b, diagnose_deep, &c).0.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("minutes does not apply to context"),
        "{error}"
    );
    // a search strategy is not a deep diagnosis
    let error = run(&b, diagnose_deep, &call("sub", LegacyOperation::Chain))
        .0
        .unwrap_err();
    assert!(
        error.to_string().contains("chain is not a deep diagnosis"),
        "{error}"
    );
    let mut c = call("sub", LegacyOperation::Equivalence);
    c.apply = true;
    assert!(run(&b, verify, &c).0.is_err());
    assert!(b.requests().is_empty(), "the plugin must not be called");

    // the source option becomes an absolute path
    let source = b.root().join("try.c");
    std::fs::write(&source, "int sub(int a, int b) { return 0; }\n").unwrap();
    let mut c = call("sub", LegacyOperation::Slots);
    c.options.source = Some(source.clone());
    c.options.minutes = Some(1.5);
    run(&b, diagnose_deep, &c).0.unwrap();
    let r = &b.requests()[0];
    assert_eq!(Path::new(r["options"]["source"].as_str().unwrap()), source);
    assert_eq!(r["options"]["minutes"], 1.5);
}

#[test]
fn missing_setup_steps_are_named() {
    let python = python_or_skip!();
    let b = bridge(&python, false, true);
    let error = run(&b, diagnose_deep, &call("sub", LegacyOperation::Context))
        .0
        .unwrap_err();
    assert!(
        error.to_string().contains("[legacy] decomp_workspace"),
        "{error}"
    );
    assert!(error.to_string().contains("decovery migrate"), "{error}");

    let b = bridge(&python, true, false);
    let error = run(&b, diagnose_deep, &call("sub", LegacyOperation::Context))
        .0
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("run `decovery setup decomp-legacy --decomp <Decomp checkout>`"),
        "{error}"
    );
}

#[test]
fn plugin_errors_are_mapped() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    b.answer(
        json!({"error": {"code": -32022, "message": "nachbau kontext failed",
        "data": {"exit_code": 2, "stderr_tail": "Fehler: Funktion unbekannt"}}}),
    );
    let error = run(&b, diagnose_deep, &call("sub", LegacyOperation::Context))
        .0
        .unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("exit code 2") && text.contains("Fehler: Funktion unbekannt"),
        "{text}"
    );
    b.answer(json!({"error": {"code": -32020, "message": "import decomp failed"}}));
    let text = run(&b, diagnose_deep, &call("sub", LegacyOperation::Context))
        .0
        .unwrap_err()
        .to_string();
    assert!(
        text.contains("Decomp is unavailable") && text.contains("setup decomp-legacy"),
        "{text}"
    );
}

fn sub_with(mark: &str) -> String {
    format!("int sub(int a, int b)\n{{\n    return a - b; /* {mark} */\n}}\n")
}

fn wrong_sub() -> Vec<u8> {
    let mut sub = SUB.to_vec();
    sub[6] = 0x33;
    sub
}

/// Objects for a function-level attempt with two variants (current, candidate): `F001`/`F002` are the full files
/// (shrink check and confirmation), `V001`/`V002` the shrunk ones.
fn serve_attempt(b: &Bridge, current: &[u8], candidate: &[u8]) {
    let f = &b.f;
    f.write_obj("F001", &[("_add", ADD), ("_sub", current)]);
    f.write_obj("V001", &[("_sub", current)]);
    f.write_obj("F002", &[("_add", ADD), ("_sub", candidate)]);
    f.write_obj("V002", &[("_sub", candidate)]);
}

#[test]
fn cancelled_search_applies_nothing() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    // a better candidate that `apply` would write, from a search that blocks until cancelled
    serve_attempt(&b, &wrong_sub(), SUB);
    b.f.write_obj("A", &[("_add", ADD), ("_sub", SUB)]);
    b.answer(json!({"block": true, "candidate": {"text": sub_with("found"), "kind": "function"}}));
    let mut c = call("sub", LegacyOperation::Chain);
    c.apply = true;
    let token = CancelToken::new();
    let block_log = b.shadow().join("block.log");
    let canceller = {
        let token = token.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            while !block_log.exists() && start.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(20));
            }
            token.cancel();
        })
    };
    let result = search(b.root(), &c, &Control::new(&|_| {}, token));
    canceller.join().unwrap();
    let error = result.unwrap_err();
    assert!(matches!(error, FacadeError::Cancelled), "{error}");
    assert_eq!(b.requests().len(), 1, "the plugin had the request");
    // the plugin got `$/cancel` (the real one kills the Decomp subprocess then)
    let cancel_log = b.shadow().join("cancel.log");
    let start = Instant::now();
    while !cancel_log.exists() && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        std::fs::read_to_string(&cancel_log)
            .unwrap_or_default()
            .trim_end(),
        "cancelled"
    );
    assert_eq!(
        std::fs::read_to_string(b.root().join("src/a.c")).unwrap(),
        A_C
    );
    assert!(read_rebuild(b.root()).unwrap().is_empty());
    assert!(!b.root().join("cache/attempts").exists(), "no attempt");
    assert!(b.f.log("calls.log").is_empty(), "nothing was built");
}

#[test]
fn search_candidate_is_built_by_decovery_and_applied_only_when_better() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    // the current source differs, the candidate is identical
    serve_attempt(&b, &wrong_sub(), SUB);
    b.answer(json!({"candidate": {"text": sub_with("found"), "kind": "function"}}));
    let mut c = call("sub", LegacyOperation::Chain);
    c.options.minutes = Some(1.0);
    let response = run(&b, search, &c).0.unwrap();
    let candidate = &response.data["candidate"];
    assert_eq!(candidate["evaluated_as"], "function", "{candidate}");
    assert_eq!(candidate["verdict"]["verdict"], "identical", "{candidate}");
    assert_eq!(candidate["current"]["verdict"], "differs", "{candidate}");
    assert_eq!(candidate["improved"], true);
    assert_eq!(candidate["applied"], false);
    assert_eq!(response.data["strategy"], "chain");
    // without apply nothing in src/ changes and nothing is recorded
    assert_eq!(
        std::fs::read_to_string(b.root().join("src/a.c")).unwrap(),
        A_C
    );
    assert!(read_rebuild(b.root()).unwrap().is_empty());

    // with apply the function is spliced in and recorded by a normal build
    b.f.write_obj("A", &[("_add", ADD), ("_sub", SUB)]);
    c.apply = true;
    let response = run(&b, search, &c).0.unwrap();
    let candidate = &response.data["candidate"];
    assert_eq!(candidate["applied"], true, "{candidate}");
    let written = std::fs::read_to_string(b.root().join("src/a.c")).unwrap();
    assert!(
        written.contains("/* found */") && written.contains("int add(int a, int b)"),
        "{written}"
    );
    let records = read_rebuild(b.root()).unwrap();
    let sub = records
        .iter()
        .find(|r| r.name == "sub")
        .expect("sub recorded");
    assert_eq!(sub.verdict, Some(decovery_core::VerdictId::Identical));
    assert!(response.summary.contains("applied"), "{}", response.summary);
}

#[test]
fn worse_candidate_is_not_applied() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    let mut worse = wrong_sub();
    worse[7] = 0x00;
    serve_attempt(&b, &wrong_sub(), &worse);
    // a whole module from Decomp: the function is taken from it
    let module = A_C.replace("a - b;", "a - b; /* worse */");
    b.answer(json!({"candidate": {"text": module, "kind": "module"}}));
    let mut c = call("sub", LegacyOperation::Permute);
    c.apply = true;
    let response = run(&b, search, &c).0.unwrap();
    let candidate = &response.data["candidate"];
    assert_eq!(candidate["kind"], "module");
    assert_eq!(candidate["evaluated_as"], "function", "{candidate}");
    assert_eq!(candidate["improved"], false, "{candidate}");
    assert_eq!(candidate["applied"], false);
    assert!(
        candidate["note"]
            .as_str()
            .unwrap()
            .starts_with("not applied")
    );
    assert_eq!(
        std::fs::read_to_string(b.root().join("src/a.c")).unwrap(),
        A_C
    );
    assert!(read_rebuild(b.root()).unwrap().is_empty());
}

#[test]
fn search_without_candidate_reports_decomp_only() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    let response = run(&b, search, &call("sub", LegacyOperation::Beam))
        .0
        .unwrap();
    assert!(response.data["candidate"].is_null());
    assert!(
        response.summary.ends_with("no candidate"),
        "{}",
        response.summary
    );
}

#[test]
fn verify_reports_evidence_and_never_writes_verdicts() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    let rebuild = b.f.rebuild_path();
    let before = std::fs::read(&rebuild).ok();
    b.answer(json!({"json": {"funktionen": [{"adresse": "va:00000020", "urteil": "gleichwertig_belegt"}]}}));
    let mut c = call("sub", LegacyOperation::Equivalence);
    c.options.minutes = Some(2.0);
    let response = run(&b, verify, &c).0.unwrap();
    let d = &response.data;
    assert_eq!(d["evidence"]["source"], "decomp");
    assert_eq!(d["evidence"]["decomp_verdict"], "gleichwertig_belegt");
    assert_eq!(d["json"]["funktionen"][0]["urteil"], "gleichwertig_belegt");
    assert!(response.summary.contains("not a decovery verdict"));
    assert_eq!(
        std::fs::read(&rebuild).ok(),
        before,
        "rebuild records untouched"
    );

    let mut c = call("sub", LegacyOperation::Behavior);
    c.options.run = Some("login".into());
    run(&b, verify, &c).0.unwrap();
    let requests = b.requests();
    assert_eq!(requests.last().unwrap()["options"], json!({"run": "login"}));
    assert_eq!(std::fs::read(&rebuild).ok(), before);
}

#[test]
fn long_reports_go_into_handles() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    let mut c = call("sub", LegacyOperation::Context);
    c.budget = decovery_facade::Budget { chars: 10 };
    let response = run(&b, diagnose_deep, &c).0.unwrap();
    let id = response.data["report_handle"].as_str().unwrap();
    assert!(response.handles.iter().any(|h| h.id == id));
    assert!(
        response.data["report"]
            .as_str()
            .unwrap()
            .contains("truncated")
    );
}

#[test]
fn deep_diagnosis_carries_decoverys_own_diagnosis_after_a_build() {
    let python = python_or_skip!();
    let b = bridge(&python, true, true);
    b.f.write_obj("A", &[("_add", ADD), ("_sub", &wrong_sub())]);
    let mut request = decovery_facade::BuildRequest::default();
    request.files = vec!["a.c".into()];
    decovery_facade::build(
        b.root(),
        &request,
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    let response = run(&b, diagnose_deep, &call("sub", LegacyOperation::Joint))
        .0
        .unwrap();
    let own = &response.data["decovery"];
    assert!(own["error"].is_null(), "{own}");
    assert_eq!(own["data"]["function"]["name"], "sub");
    assert!(
        own["data"]["function"]["instructions_differing"]
            .as_u64()
            .unwrap()
            >= 1
    );
}
