//! Real CLI/MCP and native comparisons; only the external compiler and agent are synthetic.
#[path = "../../decovery-facade/tests/support/build_fixture.rs"]
mod build_fixture;

use decovery_bench::{DriverConfig, RunOptions, RunRecord, Suite, read_suite, run_suite};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn quote(path: &Path) -> String {
    toml::Value::String(path.to_string_lossy().into_owned()).to_string()
}
struct Case {
    _fixture: build_fixture::Fixture,
    dir: tempfile::TempDir,
    suite: Suite,
    driver: DriverConfig,
    options: RunOptions,
}
fn case(python: &str, mode: &str, tasks: usize) -> Case {
    let fixture = build_fixture::fixture(python, ", FAKE_OMF_REQUIRED_TEXT = \"return a - b;\"");
    let mut wrong = build_fixture::SUB.to_vec();
    wrong[6] = 0x33;
    fixture.write_obj(
        "FALLBACK",
        &[("_add", build_fixture::ADD), ("_sub", &wrong)],
    );
    decovery_facade::build(
        fixture.root(),
        &decovery_facade::BuildRequest::default(),
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("suite.toml");
    let entries: String = (0..tasks).map(|i| format!("[[task]]\nid = \"case/{i}:sub\"\nworkspace = {}\nfunction = \"sub\"\ntags = [\"tiny\"]\n", quote(fixture.root()))).collect();
    std::fs::write(&path, format!("schema = 1\nname = \"synthetic\"\n[defaults]\nmax_builds = 4\nmax_tool_calls = 8\n{entries}")).unwrap();
    let mut suite = read_suite(&path).unwrap();
    // single-session behaviour unless a test is about continuations
    suite.defaults.max_continuations = 0;
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../decovery-bench/tests/fixtures/fake_driver.py")
        .canonicalize()
        .unwrap();
    let mut driver = DriverConfig::default();
    driver.command = vec![
        python.into(),
        "-B".into(),
        script.to_string_lossy().into_owned(),
        "--mcp".into(),
        "{mcp_config}".into(),
        "--result".into(),
        "{result}".into(),
        "--workdir".into(),
        "{workdir}".into(),
        "--prompt".into(),
        "{prompt}".into(),
    ];
    driver.env.insert("FAKE_MODE".into(), mode.into());
    driver.env.insert(
        "FAKE_SOURCE".into(),
        "int sub(int a, int b)\n{\n return a - b;\n}\n".into(),
    );
    let mut options = RunOptions::new("fake", PathBuf::from(env!("CARGO_BIN_EXE_decovery")));
    options.copies_dir = Some(dir.path().join("copies"));
    options.seed = 17;
    Case {
        _fixture: fixture,
        dir,
        suite,
        driver,
        options,
    }
}
fn execute(case: &Case) -> RunRecord {
    run_suite(&case.suite, &case.driver, &case.options, &|_| {}).unwrap()
}
fn calls(case: &mut Case, value: Value) {
    case.driver
        .env
        .insert("FAKE_CALLS".into(), value.to_string());
}
fn driver_answers(run: &RunRecord) -> String {
    run.tasks[0].extra["driver_extra"]["calls"].to_string()
}

#[test]
fn solving_driver_is_solved_by_decovery_verdict() {
    let python = python_or_skip!();
    let c = case(&python, "solve", 1);
    let run = execute(&c);
    assert_eq!(run.state, "done");
    assert!(run.tasks[0].solved);
    assert_eq!(run.tasks[0].verdict, "identical");
    assert_eq!(
        run.tasks[0].builds, 1,
        "harness builds do not spend the agent budget"
    );
    assert_eq!(run.tasks[0].start_distance, Some(1));
    assert_eq!(run.tasks[0].best_distance, Some(0));
    let logs = c.dir.path().join("bench").join(&run.id);
    assert!(logs.is_dir());
    assert!(
        std::fs::read_dir(c.options.copies_dir.as_ref().unwrap().join(&run.id))
            .unwrap()
            .next()
            .is_none()
    );
    let log = PathBuf::from(run.tasks[0].log.as_ref().unwrap());
    assert!(log.parent().unwrap().join("calls").is_dir());
    assert!(log.parent().unwrap().join("usage.json").is_file());
}

#[test]
fn idle_driver_is_unsolved_with_start_distance() {
    let python = python_or_skip!();
    let c = case(&python, "idle", 1);
    let run = execute(&c);
    assert!(!run.tasks[0].solved);
    assert_eq!(run.tasks[0].start_distance, Some(1));
    assert_eq!(run.tasks[0].best_distance, Some(1));
    assert_eq!(run.tasks[0].builds, 0);
    assert_eq!(run.tasks[0].exit, "ok");
}
#[test]
fn hanging_driver_is_killed_and_evaluated() {
    let python = python_or_skip!();
    let mut c = case(&python, "hang", 1);
    c.suite.defaults.wall_minutes = 0;
    let run = execute(&c);
    let task = &run.tasks[0];
    assert_eq!(task.exit, "timeout");
    assert_eq!(task.verdict, "differs");
    assert_ne!(
        task.extra["driver_exit_code"],
        json!(0),
        "the hanging process must not finish naturally"
    );
}
#[test]
fn crashing_driver_is_recorded() {
    let python = python_or_skip!();
    let c = case(&python, "crash", 1);
    let run = execute(&c);
    assert_eq!(run.tasks[0].exit, "driver-error");
    assert_eq!(run.tasks[0].extra["driver_exit_code"], 7);
    assert_eq!(run.tasks[0].best_distance, Some(1));
}
#[test]
fn tool_calls_beyond_limit_are_refused() {
    let python = python_or_skip!();
    let mut c = case(&python, "calls", 1);
    c.suite.defaults.max_tool_calls = 1;
    calls(
        &mut c,
        json!([{"name":"status","arguments":{}},{"name":"status","arguments":{}}]),
    );
    let run = execute(&c);
    assert!(driver_answers(&run).contains("limit reached"));
    assert_eq!(
        run.tasks[0].tool_calls, 2,
        "refused calls are still logged and counted"
    );
    assert_eq!(run.tasks[0].exit, "call-limit");
}
#[test]
fn variants_count_as_builds() {
    let python = python_or_skip!();
    let mut c = case(&python, "calls", 1);
    c.suite.defaults.max_builds = 2;
    let source = c.driver.env["FAKE_SOURCE"].clone();
    calls(
        &mut c,
        json!([{"name":"build","arguments":{"function":"sub","variants":[{"function_source":source},{"function_source":"int sub(int a,int b) { return a - b; /* other */ }"}]}},{"name":"build","arguments":{"function":"sub"}}]),
    );
    let run = execute(&c);
    assert_eq!(run.tasks[0].builds, 2);
    assert!(driver_answers(&run).contains("2 of 2 builds used"));
    assert_eq!(run.tasks[0].exit, "call-limit");
}
#[test]
fn core_tool_set_refuses_bridge_tools() {
    let python = python_or_skip!();
    let mut c = case(&python, "calls", 1);
    calls(
        &mut c,
        json!([{"name":"search","arguments":{"function":"sub"}},{"name":"verify","arguments":{"function":"sub"}},{"name":"diagnose","arguments":{"target":"sub","deep":"registers"}}]),
    );
    let run = execute(&c);
    assert_eq!(run.tasks[0].tool_calls, 3);
    assert_eq!(
        driver_answers(&run)
            .matches("not available in this bench run")
            .count(),
        3
    );
}
#[test]
fn driver_result_tokens_are_recorded() {
    let python = python_or_skip!();
    let c = case(&python, "idle", 1);
    let run = execute(&c);
    let t = &run.tasks[0];
    assert_eq!(t.input_tokens, Some(12));
    assert_eq!(t.output_tokens, Some(3));
    assert_eq!(t.cache_read_tokens, Some(7));
    assert_eq!(t.cache_write_tokens, Some(2));
    assert_eq!(t.cost_kind.as_deref(), Some("estimate"));
    assert_eq!(t.cost_usd, Some(0.001));
}
#[test]
fn run_limit_stops_new_tasks() {
    let python = python_or_skip!();
    let mut c = case(&python, "idle", 2);
    c.options.max_total_tokens = Some(17);
    let run = execute(&c);
    assert_eq!(run.state, "stopped-at-limit");
    assert_eq!(run.tasks[0].exit, "ok");
    assert_eq!(run.tasks[1].exit, "not-run");
}
#[test]
fn quota_pauses_and_resume_continues() {
    let python = python_or_skip!();
    let mut c = case(&python, "quota", 2);
    c.driver.env.insert(
        "FAKE_QUOTA_MARKER".into(),
        c.dir
            .path()
            .join("quota.marker")
            .to_string_lossy()
            .into_owned(),
    );
    let first = execute(&c);
    assert_eq!(first.state, "paused");
    assert_eq!(first.tasks[0].exit, "quota");
    c.options.resume = Some(first.id.clone());
    let second = execute(&c);
    assert_eq!(second.id, first.id);
    assert_eq!(second.seed, first.seed);
    assert_eq!(second.state, "done");
    assert!(second.tasks.iter().all(|t| t.solved));
}
#[test]
fn parallel_tasks_give_same_results_as_serial() {
    let python = python_or_skip!();
    let mut c = case(&python, "solve", 2);
    let serial = execute(&c);
    c.options.parallel = 2;
    let parallel = execute(&c);
    let metrics = |r: &RunRecord| {
        r.tasks
            .iter()
            .map(|t| (t.id.clone(), t.repeat, t.solved, t.builds, t.best_distance))
            .collect::<Vec<_>>()
    };
    assert_eq!(metrics(&serial), metrics(&parallel));
}
#[test]
fn run_record_matches_schema() {
    let python = python_or_skip!();
    let c = case(&python, "idle", 1);
    let run = execute(&c);
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/bench-run.schema.json")).unwrap();
    fn required(schema: &Value, value: &Value) {
        if let Some(keys) = schema["required"].as_array() {
            for key in keys {
                assert!(value.get(key.as_str().unwrap()).is_some(), "missing {key}");
            }
        }
        if let Some(properties) = schema["properties"].as_object() {
            for (key, child) in properties {
                if let Some(v) = value.get(key) {
                    required(child, v);
                }
            }
        }
        if let Some(items) = schema.get("items") {
            for item in value.as_array().into_iter().flatten() {
                required(items, item);
            }
        }
    }
    required(&schema, &serde_json::to_value(&run).unwrap());
    assert_eq!(serde_json::to_value(run).unwrap()["schema"], 1);
}

#[test]
fn cli_bench_run_uses_the_configured_driver() {
    let python = python_or_skip!();
    let c = case(&python, "solve", 1);
    let appdata = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(appdata.path().join("decovery")).unwrap();
    let command: Vec<String> = c
        .driver
        .command
        .iter()
        .map(|a| toml::Value::String(a.clone()).to_string())
        .collect();
    let env: Vec<String> = c
        .driver
        .env
        .iter()
        .map(|(k, v)| format!("{k} = {}", toml::Value::String(v.clone())))
        .collect();
    let config = format!(
        "schema = 1
[bench]
copies_dir = {}
[bench.drivers.fake]
command = [{}]
env = {{ {} }}
",
        quote(c.options.copies_dir.as_ref().unwrap()),
        command.join(", "),
        env.join(", ")
    );
    for dir in [
        appdata.path().join("decovery"),
        appdata.path().join(".config/decovery"),
    ] {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), &config).unwrap();
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_decovery"))
        .env("APPDATA", appdata.path())
        .env("XDG_CONFIG_HOME", appdata.path().join(".config"))
        .args(["--json", "bench", "run"])
        .arg(c.dir.path().join("suite.toml"))
        .args(["--driver", "fake", "--seed", "5"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(run["state"], "done");
    assert_eq!(run["seed"], 5);
    assert_eq!(run["tasks"][0]["solved"], true);
    let id = run["id"].as_str().unwrap();
    assert!(
        c.dir
            .path()
            .join("bench")
            .join(format!("{id}.json"))
            .is_file()
    );
    let unknown = std::process::Command::new(env!("CARGO_BIN_EXE_decovery"))
        .env("APPDATA", appdata.path())
        .env("XDG_CONFIG_HOME", appdata.path().join(".config"))
        .args(["bench", "run"])
        .arg(c.dir.path().join("suite.toml"))
        .args(["--driver", "missing"])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("missing"));
}

#[test]
fn default_suite_allows_one_continuation() {
    assert_eq!(decovery_bench::TaskDefaults::default().max_continuations, 1);
}
#[test]
fn unsolved_driver_with_budget_left_is_continued() {
    let python = python_or_skip!();
    let mut c = case(&python, "idle-then-solve", 1);
    c.suite.defaults.max_continuations = 1;
    let run = execute(&c);
    let t = &run.tasks[0];
    assert!(t.solved, "the continuation session solves the task");
    assert_eq!(t.continuations, 1);
    assert_eq!(t.exit, "ok");
    let prompt = t.extra["driver_extra"]["prompt"].as_str().unwrap();
    assert!(prompt.starts_with("This is continuation 1 of at most 1"));
    assert!(prompt.contains("verdict is differs, best distance 1 (start distance 1)"));
    assert!(prompt.contains("Recover the implementation of sub"));
    assert_eq!(t.extra["session_logs"].as_array().unwrap().len(), 2);
    assert_eq!(
        serde_json::to_value(&run).unwrap()["tasks"][0]["continuations"],
        1
    );
}
#[test]
fn solved_task_is_not_continued() {
    let python = python_or_skip!();
    let mut c = case(&python, "solve", 1);
    c.suite.defaults.max_continuations = 3;
    let t = &execute(&c).tasks[0];
    assert!(t.solved);
    assert_eq!(t.continuations, 0);
    assert_eq!(t.input_tokens, Some(12));
}
#[test]
fn task_at_a_limit_is_not_continued() {
    let python = python_or_skip!();
    let mut c = case(&python, "calls", 1);
    c.suite.defaults.max_continuations = 3;
    c.suite.defaults.max_tool_calls = 1;
    calls(&mut c, json!([{"name":"status","arguments":{}}]));
    let t = &execute(&c).tasks[0];
    assert_eq!(t.continuations, 0, "tool calls are spent");
    assert_eq!(t.tool_calls, 1);
    let mut c = case(&python, "idle", 1);
    c.suite.defaults.max_continuations = 3;
    c.suite.defaults.max_tokens = Some(30);
    let t = &execute(&c).tasks[0];
    assert_eq!(
        t.continuations, 1,
        "15 tokens per session, the second session reaches 30"
    );
    assert_eq!(t.input_tokens, Some(24));
    let mut c = case(&python, "idle", 1);
    c.suite.defaults.max_continuations = 3;
    c.suite.defaults.max_cost_usd = Some(0.001);
    assert_eq!(execute(&c).tasks[0].continuations, 0, "cost is spent");
}
#[test]
fn continuations_stop_at_the_maximum_and_totals_accumulate() {
    let python = python_or_skip!();
    let mut c = case(&python, "calls", 1);
    c.suite.defaults.max_continuations = 2;
    c.suite.defaults.max_builds = 10;
    c.suite.defaults.max_tool_calls = 10;
    calls(
        &mut c,
        json!([{"name":"build","arguments":{"function":"sub"}}]),
    );
    let run = execute(&c);
    let t = &run.tasks[0];
    assert!(!t.solved);
    assert_eq!(t.continuations, 2);
    assert_eq!(t.builds, 3);
    assert_eq!(t.tool_calls, 3);
    assert_eq!(t.input_tokens, Some(36));
    assert_eq!(t.output_tokens, Some(9));
    assert_eq!(t.cache_read_tokens, Some(21));
    assert_eq!(t.cache_write_tokens, Some(6));
    assert!((t.cost_usd.unwrap() - 0.003).abs() < 1e-9);
    assert_eq!(run.totals.builds, 3);
    assert_eq!(run.totals.input_tokens, Some(36));
    let mut c = case(&python, "idle", 1);
    c.suite.defaults.max_continuations = 0;
    assert_eq!(
        execute(&c).tasks[0].continuations,
        0,
        "0 disables continuations"
    );
}
