//! The job runner, the `job` tool and jobs registered by the CLI, on the synthetic MZ build workspace with the
//! fake runner (and the fake `decomp-legacy` plugin for `search`). Skipped (with a message) without Python: set
//! `DECOVERY_PYTHON` or put `python` on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use build_fixture::{Fixture, fixture};
use decovery_core::{JobRecord, JobState, job_create, job_lease, job_list, job_load, job_save};
use decovery_facade::{
    BuildRequest, FacadeError, JobAction, JobOperation, JobRunner, Session, background_by_default,
    detail, job_tool, run_as_job, status,
};
use serde_json::{Value, json};

/// Generous: the machine running the tests may be loaded.
const WAIT: Duration = Duration::from_secs(90);

/// Polls the job until `until` holds for it; panics after [`WAIT`].
fn wait_job(root: &Path, id: &str, until: impl Fn(&JobRecord) -> bool) -> JobRecord {
    let start = Instant::now();
    loop {
        if let Ok(job) = job_load(root, id)
            && until(&job)
        {
            return job;
        }
        assert!(
            start.elapsed() < WAIT,
            "job {id} did not get there: {:?}",
            job_load(root, id)
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_final(root: &Path, id: &str) -> JobRecord {
    wait_job(root, id, |j| j.state.is_final())
}

fn wait_file(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < WAIT, "{} did not appear", path.display());
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn build_spec(files: &[&str]) -> Value {
    let mut request = BuildRequest::default();
    request.files = files.iter().map(|s| s.to_string()).collect();
    JobOperation::Build(request).spec()
}

/// A fixture whose runner blocks until it gets `$/cancel`.
fn blocking_fixture(python: &str) -> Fixture {
    fixture(python, ", FAKE_OMF_BLOCK = \"1\"")
}

#[test]
fn background_build_returns_job_and_finishes() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let runner = JobRunner::start(f.root().to_path_buf(), 2);
    let job = runner.submit("build", build_spec(&["a.c"])).unwrap();
    assert!(job.id.starts_with("j_"), "{}", job.id);
    assert_eq!(job.kind, "build");
    assert!(!job.state.is_final());
    let done = wait_final(f.root(), &job.id);
    assert_eq!(done.state, JobState::Done, "{done:?}");
    assert_eq!(
        done.summary.as_deref(),
        Some("a.c: 2 functions, 2 identical")
    );
    assert!(done.result.as_deref().is_some_and(|h| h.starts_with("h_")));
    assert!(done.started.is_some() && done.finished.is_some());
    assert!(
        f.rebuild_path().is_file(),
        "the build recorded its verdicts"
    );
    // a spec that is no request of the kind is refused before it is queued
    assert!(runner.submit("build", json!({"files": 3})).is_err());
    assert!(runner.submit("dance", json!({})).is_err());
}

#[test]
fn poll_shows_progress() {
    let python = python_or_skip!();
    let f = blocking_fixture(&python);
    let runner = JobRunner::start(f.root().to_path_buf(), 2);
    let job = runner.submit("build", build_spec(&["a.c"])).unwrap();
    let running = wait_job(f.root(), &job.id, |j| {
        j.state == JobState::Running && j.progress.is_some()
    });
    let progress = running.progress.unwrap();
    assert!(
        progress
            .message
            .as_deref()
            .is_some_and(|m| m.contains("compiling")),
        "{progress:?}"
    );
    let poll = job_tool(f.root(), JobAction::Poll(job.id.clone())).unwrap();
    assert_eq!(poll.data["job"]["state"], "running", "{}", poll.data);
    assert!(poll.data["job"]["progress"]["message"].is_string());
    assert!(poll.summary.contains("running"), "{}", poll.summary);
    job_tool(f.root(), JobAction::Cancel(job.id.clone())).unwrap();
    wait_final(f.root(), &job.id);
}

#[test]
fn cancel_running_job_ends_cancelled() {
    let python = python_or_skip!();
    let f = blocking_fixture(&python);
    let runner = JobRunner::start(f.root().to_path_buf(), 2);
    let job = runner.submit("build", build_spec(&["a.c"])).unwrap();
    wait_file(&f.objects.path().join("block.log"));
    let answer = job_tool(f.root(), JobAction::Cancel(job.id.clone())).unwrap();
    assert!(answer.summary.contains("cancel"), "{}", answer.summary);
    let end = wait_final(f.root(), &job.id);
    assert_eq!(end.state, JobState::Cancelled, "{end:?}");
    assert!(end.result.is_none());
    assert_eq!(
        f.log("cancel.log"),
        ["cancelled"],
        "the runner got $/cancel"
    );
    assert!(
        !f.rebuild_path().exists(),
        "a cancelled build records nothing"
    );
    // cancelling an ended job changes nothing
    let again = job_tool(f.root(), JobAction::Cancel(job.id.clone())).unwrap();
    assert!(again.summary.contains("already"), "{}", again.summary);
    assert_eq!(
        job_load(f.root(), &job.id).unwrap().state,
        JobState::Cancelled
    );
}

#[test]
fn search_runs_in_background_by_default() {
    let python = python_or_skip!();
    assert!(background_by_default("search"));
    assert!(background_by_default("verify"));
    assert!(!background_by_default("build"));
    assert!(!background_by_default("link"));
    assert!(!background_by_default("analyze"));
    assert!(!background_by_default("diagnose-deep"));
    let f = fixture(&python, "");
    let script = std::path::absolute(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_legacy.py"),
    )
    .unwrap();
    let decomp = tempfile::tempdir().unwrap();
    std::fs::write(decomp.path().join("decomp.toml"), "# Decomp\n").unwrap();
    let toml_string = |s: &str| toml::Value::String(s.to_string()).to_string();
    let mut config = std::fs::read_to_string(f.root().join("decovery.toml")).unwrap();
    config.push_str(&format!(
        "\n[legacy]\ndecomp_workspace = {}\n\n[plugins.decomp-legacy]\ncommand = [{}, {}]\n",
        toml_string(decomp.path().to_str().unwrap()),
        toml_string(&python),
        toml_string(script.to_str().unwrap())
    ));
    std::fs::write(f.root().join("decovery.toml"), config).unwrap();
    let runner = JobRunner::start(f.root().to_path_buf(), 2);
    let spec = json!({"target": "sub", "operation": "chain", "options": {"minutes": 1.0}});
    let job = runner.submit("search", spec).unwrap();
    let end = wait_final(f.root(), &job.id);
    assert_eq!(end.state, JobState::Done, "{end:?}");
    let requests = std::fs::read_to_string(f.root().join("cache/legacy/decomp/requests.jsonl"))
        .unwrap_or_default();
    assert_eq!(requests.lines().count(), 1, "{requests}");
    // a search spec is not accepted as another kind
    let verify = json!({"target": "sub", "operation": "chain"});
    assert!(runner.submit("verify", verify).is_err());
}

const CHILD_ROOT: &str = "DECOVERY_TEST_JOB_ROOT";
const CHILD_ID: &str = "DECOVERY_TEST_JOB_ID";

/// Run by [`restart_requeues_running_job_once`] in a child process: holds the job's lease as a server running it
/// would, writes `held`, then waits to be killed. Without the environment variables it does nothing.
#[test]
fn job_holder_child() {
    let (Ok(root), Ok(id)) = (std::env::var(CHILD_ROOT), std::env::var(CHILD_ID)) else {
        return;
    };
    let root = Path::new(&root);
    let _lease = job_lease(root, &id).unwrap().expect("the lease is free");
    std::fs::write(root.join("held"), "").unwrap();
    std::thread::sleep(WAIT * 2);
}

#[test]
fn restart_requeues_running_job_once() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let root = f.root();
    let mut job = job_create(root, "build", build_spec(&["a.c"])).unwrap();
    job.state = JobState::Running;
    job_save(root, &job).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["job_holder_child", "--exact", "--test-threads=1"])
        .env(CHILD_ROOT, root)
        .env(CHILD_ID, &job.id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_file(&root.join("held"));
    // while the other process holds the lease, a starting runner leaves the job alone
    let runner = JobRunner::start(root.to_path_buf(), 2);
    std::thread::sleep(Duration::from_millis(300));
    let untouched = job_load(root, &job.id).unwrap();
    assert_eq!((untouched.state, untouched.resumed), (JobState::Running, 0));
    drop(runner);
    // the server dies: the OS releases the lease
    child.kill().unwrap();
    child.wait().unwrap();
    let start = Instant::now();
    while job_lease(root, &job.id).unwrap().is_none() {
        assert!(start.elapsed() < WAIT, "the lease was not released");
        std::thread::sleep(Duration::from_millis(25));
    }
    let _runner = JobRunner::start(root.to_path_buf(), 2);
    let end = wait_final(root, &job.id);
    assert_eq!(end.state, JobState::Done, "{end:?}");
    assert_eq!(end.resumed, 1);
    assert_eq!(
        end.summary.as_deref(),
        Some("a.c: 2 functions, 2 identical")
    );
}

#[test]
fn second_loss_ends_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut job = job_create(root, "link", json!({})).unwrap();
    job.state = JobState::Running;
    job.resumed = 1;
    job_save(root, &job).unwrap();
    let queued = job_create(root, "dance", json!({})).unwrap();
    let _runner = JobRunner::start(root.to_path_buf(), 1);
    // resuming happens before `start` returns
    let end = job_load(root, &job.id).unwrap();
    assert_eq!(end.state, JobState::Interrupted, "{end:?}");
    assert_eq!(
        end.error.as_deref(),
        Some("the server stopped twice while the job ran")
    );
    assert!(end.finished.is_some());
    assert_eq!(end.resumed, 1);
    // a queued job of an unknown kind fails instead of stopping the runner
    let failed = wait_final(root, &queued.id);
    assert_eq!(failed.state, JobState::Failed, "{failed:?}");
    assert!(failed.error.is_some());
}

#[test]
fn detail_pages_job_result() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    let runner = JobRunner::start(f.root().to_path_buf(), 2);
    let job = runner.submit("build", build_spec(&["a.c"])).unwrap();
    let end = wait_final(f.root(), &job.id);
    let handle = end.result.expect("a result handle");
    let page = detail(f.root(), &handle, 0, 1_000_000).unwrap();
    let text = page.data["text"].as_str().unwrap();
    let response: Value = serde_json::from_str(text).unwrap();
    assert_eq!(response["summary"], "a.c: 2 functions, 2 identical");
    assert_eq!(response["data"]["counts"]["identical"], 2);
    let poll = job_tool(f.root(), JobAction::Poll(job.id.clone())).unwrap();
    assert_eq!(poll.data["job"]["result"], handle.as_str());
    assert!(poll.summary.contains(&handle), "{}", poll.summary);
    let list = job_tool(f.root(), JobAction::List).unwrap();
    assert_eq!(list.data["jobs"][0]["id"], job.id.as_str());
    assert!(job_tool(f.root(), JobAction::Poll("j_000000000000".into())).is_err());
    assert!(job_tool(f.root(), JobAction::Poll("../x".into())).is_err());
}

#[test]
fn status_lists_running_jobs() {
    let python = python_or_skip!();
    let f = blocking_fixture(&python);
    let runner = JobRunner::start(f.root().to_path_buf(), 2);
    let job = runner.submit("build", build_spec(&["a.c"])).unwrap();
    wait_job(f.root(), &job.id, |j| j.state == JobState::Running);
    let response = status(&Session::open(f.root()).unwrap()).unwrap();
    let jobs = response.data["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    assert_eq!(jobs[0]["id"], job.id.as_str());
    assert_eq!(jobs[0]["state"], "running");
    let next = response.data["next_step"].as_str().unwrap();
    assert!(next.contains(&job.id), "{next}");
    job_tool(f.root(), JobAction::Cancel(job.id.clone())).unwrap();
    wait_final(f.root(), &job.id);
    let response = status(&Session::open(f.root()).unwrap()).unwrap();
    assert_eq!(response.data["jobs"], json!([]));
}

#[test]
fn cli_build_is_visible_as_job() {
    let python = python_or_skip!();
    let f = blocking_fixture(&python);
    let root = f.root().to_path_buf();
    let mut request = BuildRequest::default();
    request.files = vec!["a.c".into()];
    let operation = JobOperation::Build(request);
    let cli = std::thread::spawn(move || run_as_job(&root, &operation, &|_| {}));
    wait_file(&f.objects.path().join("block.log"));
    let jobs = job_list(f.root()).unwrap();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!((job.kind.as_str(), job.state), ("build", JobState::Running));
    assert!(
        job_lease(f.root(), &job.id).unwrap().is_none(),
        "the CLI holds the lease"
    );
    // the job of the CLI is cancelled like a background one
    job_tool(f.root(), JobAction::Cancel(job.id.clone())).unwrap();
    let result = cli.join().unwrap();
    assert!(matches!(result, Err(FacadeError::Cancelled)), "{result:?}");
    assert_eq!(
        job_load(f.root(), &job.id).unwrap().state,
        JobState::Cancelled
    );

    // a finished CLI build is a done job with its result
    let g = fixture(&python, "");
    let mut request = BuildRequest::default();
    request.files = vec!["a.c".into()];
    let response = run_as_job(g.root(), &JobOperation::Build(request), &|_| {}).unwrap();
    let jobs = job_list(g.root()).unwrap();
    assert_eq!(jobs[0].state, JobState::Done);
    assert_eq!(jobs[0].summary.as_deref(), Some(response.summary.as_str()));
}
