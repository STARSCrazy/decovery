//! The global job limit and the providers' declared `max_parallel`: what a runner request may run at once. The
//! tests that need Python are skipped (with a message) when none is found: set `DECOVERY_PYTHON` or put `python`
//! on PATH.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use decovery_core::{UserConfig, Workspace};
use decovery_toolchain::{JobSlots, Mount, PluginRunner, RunJob, RunRequest, Runner};

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

/// Workspace whose `[plugins.limited]` declares `max_parallel = 3` and `[plugins.plain]` declares nothing.
fn workspace(python: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let mut config = "schema = 1\n\n[target]\nfile = \"t.exe\"\nsha256 = \"aa\"\nformat = \"le\"\n\
                      processor = \"x86\"\n"
        .to_string();
    for (name, env) in [
        ("limited", "env = { FAKE_MAX_PARALLEL = \"3\" }\n"),
        ("plain", ""),
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

fn start(ws_dir: &Path, name: &str) -> PluginRunner {
    let ws = Workspace::open(ws_dir).unwrap();
    let config = decovery_core::plugin_config(&ws, &UserConfig::default().plugins, name).unwrap();
    PluginRunner::start(name, &config, ws_dir).unwrap()
}

/// `count` jobs that each report the share (`options.jobs`) the plugin got.
fn request(build: &Path, count: usize) -> RunRequest {
    let tools = build.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    RunRequest::new(
        vec![Mount::new('C', build, true), Mount::new('D', tools, false)],
        (0..count)
            .map(|_| RunJob::new(vec!["SHARE".into()], Vec::new()))
            .collect(),
        Duration::from_secs(20),
    )
}

fn shares(runner: &PluginRunner, request: &RunRequest) -> Vec<String> {
    runner
        .run(request, None)
        .unwrap()
        .into_iter()
        .map(|o| o.stdout.trim().to_string())
        .collect()
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
fn slots_are_shared_and_returned() {
    let slots = JobSlots::new(4);
    let a = slots.acquire(3);
    assert_eq!(a.count(), 3);
    let b = slots.acquire(3);
    assert_eq!(b.count(), 1, "only one slot was left");
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let c = slots.acquire(2);
            tx.send(c.count()).unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "a request must wait while every slot is taken"
        );
        drop(b);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
    });
    drop(a);
    assert_eq!(slots.acquire(10).count(), 4);
}

#[test]
fn host_caps_in_flight_jobs_to_jobs_and_max_parallel() {
    let python = python_or_skip!();
    let ws = workspace(&python);
    let build = ws.path().join("build");
    std::fs::create_dir_all(&build).unwrap();
    let ten = request(&build, 10);

    // the provider's max_parallel caps the share
    let runner = start(ws.path(), "limited").with_slots(JobSlots::new(16));
    assert_eq!(shares(&runner, &ten), vec!["share=3"; 10]);
    // the global limit caps it
    let runner = start(ws.path(), "limited").with_slots(JobSlots::new(2));
    assert_eq!(shares(&runner, &ten), vec!["share=2"; 10]);
    // so does the number of jobs
    let runner = start(ws.path(), "limited").with_slots(JobSlots::new(16));
    assert_eq!(shares(&runner, &request(&build, 2)), vec!["share=2"; 2]);
    // a provider without declared limits runs one job at a time
    let runner = start(ws.path(), "plain").with_slots(JobSlots::new(16));
    assert_eq!(shares(&runner, &ten), vec!["share=1"; 10]);

    // slots held by another request count against the global limit, and the request returns its own
    let slots = JobSlots::new(4);
    let runner = start(ws.path(), "limited").with_slots(slots.clone());
    let held = slots.acquire(3);
    assert_eq!(shares(&runner, &ten), vec!["share=1"; 10]);
    drop(held);
    assert_eq!(shares(&runner, &ten), vec!["share=3"; 10]);
    assert_eq!(slots.acquire(4).count(), 4, "every slot is free again");
}
