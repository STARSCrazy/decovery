//! Runners against a fake `runner` plugin (Python, built on the SDK) and the native runner. The tests that need
//! Python are skipped (with a message) when none is found: set `DECOVERY_PYTHON` or put `python` on PATH.

use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_core::{UserConfig, Workspace};
use decovery_toolchain::{
    JobStatus, Mount, NativeRunner, RunJob, RunRequest, Runner, RunnerError, open_runners,
    run_with_fallback,
};

fn python() -> Option<String> {
    let candidate = std::env::var("DECOVERY_PYTHON").unwrap_or_else(|_| "python".into());
    let ok = std::process::Command::new(&candidate)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then_some(candidate)
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_runner.py")
}

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

const CONFIG: &str = r#"schema = 1

[target]
file = "t.exe"
sha256 = "aa"
format = "le"
processor = "x86"
"#;

/// Workspace whose `[plugins.fake]` runs the fake runner and `[plugins.refuse]` runs it refusing every call.
fn workspace(python: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let mut config = CONFIG.to_string();
    for (name, env) in [
        ("fake", ""),
        ("refuse", "env = { FAKE_REFUSE_ALL = \"1\" }\n"),
    ] {
        config.push_str(&format!(
            "\n[plugins.{name}]\ncommand = [{}, {}]\n{env}",
            toml_string(python),
            toml_string(fixture().to_str().unwrap())
        ));
    }
    std::fs::write(dir.path().join("decovery.toml"), config).unwrap();
    dir
}

fn open(ws_dir: &Path, names: &[&str]) -> (Vec<Box<dyn Runner>>, Vec<String>) {
    let ws = Workspace::open(ws_dir).unwrap();
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    open_runners(&names, &ws, &UserConfig::default())
}

fn request(build: &Path, jobs: Vec<RunJob>, timeout: Duration) -> RunRequest {
    let tools = build.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    RunRequest::new(
        vec![Mount::new('C', build, true), Mount::new('D', tools, false)],
        jobs,
        timeout,
    )
}

fn job(commands: &[&str], expected: &[&str]) -> RunJob {
    RunJob::new(
        commands.iter().map(|s| s.to_string()).collect(),
        expected.iter().map(|s| s.to_string()).collect(),
    )
}

macro_rules! python_or_skip {
    () => {
        match python() {
            Some(p) => p,
            None => {
                eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
                return;
            }
        }
    };
}

#[test]
fn plugin_runner_produces_expected_file() {
    let python = python_or_skip!();
    let ws = workspace(&python);
    let (runners, warnings) = open(ws.path(), &["fake"]);
    assert!(warnings.is_empty(), "{warnings:?}");
    let build = tempfile::tempdir().unwrap();
    let req = request(
        build.path(),
        vec![job(
            &["ECHO hello", "WRITE OUT.OBJ obj-bytes"],
            &["OUT.OBJ", "NOPE.LST"],
        )],
        Duration::from_secs(10),
    );
    let (outcomes, warnings) = run_with_fallback(&runners, &req, None).unwrap();
    assert!(warnings.is_empty());
    let o = &outcomes[0];
    assert_eq!(o.status, JobStatus::Done);
    assert_eq!(o.exit_code, Some(0));
    assert_eq!(o.runner, "fake");
    assert_eq!(o.stdout, "hello\r\n");
    assert_eq!(o.produced, ["OUT.OBJ"]);
    assert!(!o.succeeded(), "NOPE.LST was not produced");

    let req = request(
        build.path(),
        vec![job(&["WRITE A.OBJ x"], &["A.OBJ"])],
        Duration::from_secs(10),
    );
    let (outcomes, _) = run_with_fallback(&runners, &req, None).unwrap();
    assert!(outcomes[0].succeeded());
    assert_eq!(
        std::fs::read_to_string(build.path().join("A.OBJ")).unwrap(),
        "x"
    );
}

#[test]
fn unchanged_existing_file_is_not_produced() {
    let python = python_or_skip!();
    let ws = workspace(&python);
    let (runners, _) = open(ws.path(), &["fake"]);
    let build = tempfile::tempdir().unwrap();
    std::fs::write(build.path().join("OLD.OBJ"), "old").unwrap();
    let req = request(
        build.path(),
        vec![job(&["ECHO nothing"], &["OLD.OBJ"])],
        Duration::from_secs(10),
    );
    let (outcomes, _) = run_with_fallback(&runners, &req, None).unwrap();
    assert!(outcomes[0].produced.is_empty());
    assert!(!outcomes[0].succeeded());
}

#[test]
fn exit_code_failure_is_reported() {
    let python = python_or_skip!();
    let ws = workspace(&python);
    let (runners, _) = open(ws.path(), &["fake"]);
    let build = tempfile::tempdir().unwrap();
    let req = request(
        build.path(),
        vec![job(&["WRITE A.OBJ x", "EXIT 2"], &["A.OBJ"])],
        Duration::from_secs(10),
    );
    let (outcomes, _) = run_with_fallback(&runners, &req, None).unwrap();
    let o = &outcomes[0];
    assert_eq!(o.status, JobStatus::Done);
    assert_eq!(o.exit_code, Some(2));
    assert_eq!(o.produced, ["A.OBJ"]);
    assert!(!o.succeeded());
}

#[test]
fn timeout_job_is_reported() {
    let python = python_or_skip!();
    let ws = workspace(&python);
    let (runners, _) = open(ws.path(), &["fake"]);
    let build = tempfile::tempdir().unwrap();
    let req = request(
        build.path(),
        vec![
            job(&["WRITE PART.OBJ half", "SLEEP 30"], &["PART.OBJ"]),
            job(&["WRITE B.OBJ ok"], &["B.OBJ"]),
        ],
        Duration::from_millis(500),
    );
    let (outcomes, _) = run_with_fallback(&runners, &req, None).unwrap();
    assert_eq!(outcomes[0].status, JobStatus::Timeout);
    assert!(outcomes[0].produced.is_empty());
    assert!(!outcomes[0].succeeded());
    assert!(
        !build.path().join("PART.OBJ").exists(),
        "partial output is deleted"
    );
    assert!(outcomes[1].succeeded(), "later jobs still run");
}

#[test]
fn unsupported_falls_back_to_next_runner() {
    let python = python_or_skip!();
    let ws = workspace(&python);
    let (runners, warnings) = open(ws.path(), &["refuse", "fake"]);
    assert!(warnings.is_empty(), "{warnings:?}");
    let build = tempfile::tempdir().unwrap();
    let req = request(
        build.path(),
        vec![job(&["WRITE A.OBJ x"], &["A.OBJ"])],
        Duration::from_secs(10),
    );
    let (outcomes, warnings) = run_with_fallback(&runners, &req, None).unwrap();
    assert_eq!(outcomes[0].runner, "fake");
    assert!(outcomes[0].succeeded());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("refuse"), "{warnings:?}");

    let (only_refusing, _) = open(ws.path(), &["refuse"]);
    let err = run_with_fallback(&only_refusing, &req, None).unwrap_err();
    assert!(matches!(err, RunnerError::Unsupported(_)), "{err:?}");
}

#[test]
fn unconfigured_runner_is_skipped_with_warning() {
    let ws = tempfile::tempdir().unwrap();
    std::fs::write(ws.path().join("decovery.toml"), CONFIG).unwrap();
    let (runners, warnings) = open(ws.path(), &["dosbox-lab", "native"]);
    assert_eq!(runners.len(), 1);
    assert_eq!(runners[0].name(), "native");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("dosbox-lab"), "{warnings:?}");
    assert!(warnings[0].contains("[plugins.dosbox-lab]"), "{warnings:?}");

    let (none, _) = open(ws.path(), &["dosbox-lab"]);
    let build = tempfile::tempdir().unwrap();
    let req = request(build.path(), vec![], Duration::from_secs(1));
    let err = run_with_fallback(&none, &req, None).unwrap_err();
    assert!(matches!(err, RunnerError::Unavailable(_)), "{err:?}");
}

#[test]
fn long_command_line_is_rejected() {
    let ok = "A".repeat(126);
    let long = "A".repeat(127);
    let build = tempfile::tempdir().unwrap();
    let req = request(
        build.path(),
        vec![job(&[&long], &[]), job(&[&ok], &[])],
        Duration::from_secs(5),
    );
    let outcomes = NativeRunner.run(&req, None).unwrap();
    assert_eq!(outcomes[0].status, JobStatus::Failed);
    assert!(
        outcomes[0].message.as_deref().unwrap().contains("127"),
        "{:?}",
        outcomes[0].message
    );
    // 126 characters pass the check (and fail later: there is no such program).
    assert_eq!(outcomes[1].status, JobStatus::Failed);
    assert!(
        !outcomes[1].message.as_deref().unwrap().contains("limit"),
        "{:?}",
        outcomes[1].message
    );
}

#[test]
fn native_runner_maps_drives_and_env() {
    let python = python_or_skip!();
    if python.contains(':') {
        eprintln!("SKIP: DECOVERY_PYTHON is a drive path, which the native runner would map");
        return;
    }
    let build = tempfile::tempdir().unwrap();
    let tools = build.path().join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::write(tools.join("in.txt"), "tool data").unwrap();
    std::fs::write(
        build.path().join("t.py"),
        concat!(
            "import os, sys\n",
            "data = open(sys.argv[1]).read()\n",
            "open('out.txt', 'w').write(data + '|' + os.environ['FOO'] + '|' + os.environ['INC'])\n",
            "print('cwd', os.path.basename(os.getcwd()))\n",
        ),
    )
    .unwrap();
    let req = request(
        build.path(),
        vec![job(
            &[
                "set FOO=bar",
                "SET INC=D:\\a;D:\\b",
                &format!("{python} C:\\t.py D:\\in.txt"),
            ],
            &["out.txt"],
        )],
        Duration::from_secs(30),
    );
    let outcomes = NativeRunner.run(&req, None).unwrap();
    let o = &outcomes[0];
    assert_eq!(o.status, JobStatus::Done, "{o:?}");
    assert!(o.succeeded(), "{o:?}");
    assert_eq!(o.runner, "native");
    assert!(
        o.stdout
            .contains(build.path().file_name().unwrap().to_str().unwrap()),
        "{}",
        o.stdout
    );
    let out = std::fs::read_to_string(build.path().join("out.txt")).unwrap();
    let inc = [tools.join("a"), tools.join("b")]
        .map(|p| p.to_string_lossy().into_owned())
        .join(";");
    assert_eq!(out, format!("tool data|bar|{inc}"));
}

#[test]
fn native_runner_kills_at_timeout() {
    let python = python_or_skip!();
    if python.contains(':') {
        return;
    }
    let build = tempfile::tempdir().unwrap();
    let req = request(
        build.path(),
        vec![job(
            &[&format!("{python} -c \"import time; time.sleep(60)\"")],
            &[],
        )],
        Duration::from_millis(500),
    );
    let started = std::time::Instant::now();
    let outcomes = NativeRunner.run(&req, None).unwrap();
    assert_eq!(outcomes[0].status, JobStatus::Timeout);
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn native_runner_kills_grandchild_at_timeout() {
    let python = python_or_skip!();
    if python.contains(':') {
        return;
    }
    let build = tempfile::tempdir().unwrap();
    // The child starts a sleeping grandchild that shares stdout/stderr, then sleeps itself.
    std::fs::write(
        build.path().join("p.py"),
        concat!(
            "import subprocess, sys, time\n",
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n",
            "time.sleep(60)\n",
        ),
    )
    .unwrap();
    let timeout = Duration::from_millis(500);
    let req = request(
        build.path(),
        vec![job(&[&format!("{python} C:\\p.py")], &[])],
        timeout,
    );
    let started = std::time::Instant::now();
    let outcomes = NativeRunner.run(&req, None).unwrap();
    assert_eq!(outcomes[0].status, JobStatus::Timeout);
    assert!(
        started.elapsed() < timeout + Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn native_runner_cd_changes_the_directory_of_later_commands() {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
        return;
    };
    let build = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(build.path().join("v001")).unwrap();
    let write = format!("{python} -c \"open('out.txt','w').write('x')\"");
    let req = request(
        build.path(),
        vec![
            job(&["CD v001", &write], &["v001/out.txt"]),
            job(&["CD nowhere", &write], &["out.txt"]),
        ],
        Duration::from_secs(30),
    );
    let outcomes = NativeRunner.run(&req, None).unwrap();
    assert!(outcomes[0].succeeded(), "{:?}", outcomes[0]);
    assert!(build.path().join("v001/out.txt").is_file());
    assert!(!build.path().join("out.txt").exists());
    assert_eq!(outcomes[1].status, JobStatus::Failed);
    assert!(
        outcomes[1].message.as_deref().unwrap().contains("nowhere"),
        "{:?}",
        outcomes[1]
    );
}
