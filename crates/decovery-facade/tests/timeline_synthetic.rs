//! The build's timeline and throughput figures (plan decision 5, risk R1): phases and compile jobs from a fake
//! runner with scripted job times, the saturation and lower bound on scripted spans, and the parallel writing of
//! the affected output files. The build tests are skipped (with a message) without Python: set `DECOVERY_PYTHON`
//! or put `python` on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use build_fixture::fixture;
use decovery_core::Workspace;
use decovery_facade::{BuildRequest, Response, Session, build, write_all};
use decovery_toolchain::{JobSpan, throughput};

fn run(root: &Path) -> Response {
    build(
        root,
        &BuildRequest::default(),
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap()
}

fn span(queued_ms: u64, start_ms: u64, end_ms: u64) -> JobSpan {
    JobSpan {
        queued_ms,
        start_ms,
        end_ms,
    }
}

#[test]
fn timeline_lists_phases_and_jobs() {
    let python = python_or_skip!();
    let f = fixture(&python, ", FAKE_JOB_TIMES = \"10:50:30\"");
    let response = run(f.root());
    let timing = &response.data["timing"];
    let timeline = &timing["timeline"];

    let phases = timeline["phases"].as_array().unwrap();
    let names: Vec<&str> = phases.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["stage", "compile", "compare", "record", "attempts"],
        "{timing}"
    );
    let mut last = 0;
    for phase in phases {
        let (start, end) = (
            phase["start_ms"].as_u64().unwrap(),
            phase["end_ms"].as_u64().unwrap(),
        );
        assert!(last <= start && start <= end, "{timing}");
        last = end;
    }
    assert_eq!(phases[0]["start_ms"], 0);
    assert_eq!(Some(last), timing["total_ms"].as_u64(), "{timing}");

    let jobs = timeline["jobs"].as_array().unwrap();
    let mut files: Vec<&str> = jobs.iter().map(|j| j["file"].as_str().unwrap()).collect();
    files.sort_unstable();
    assert_eq!(files, ["a.c", "z.c"], "{timing}");
    let compile = &phases[1];
    for job in jobs {
        let queued = job["queued_ms"].as_u64().unwrap();
        assert!(queued >= compile["start_ms"].as_u64().unwrap(), "{timing}");
        assert_eq!(job["start_ms"].as_u64().unwrap(), queued + 10, "{timing}");
        assert_eq!(job["end_ms"].as_u64().unwrap(), queued + 50, "{timing}");
        assert_eq!(job["cpu_ms"], 30, "{timing}");
    }
    assert!(timing["slots"].as_u64().unwrap() >= 1, "{timing}");
    assert!(timing["lower_bound_ms"].as_u64().is_some(), "{timing}");
    assert!(timing["efficiency"].as_f64().is_some(), "{timing}");
}

#[test]
fn saturation_of_full_slots_is_one() {
    // two slots, four jobs, every slot busy from the request on until the queue runs dry
    let jobs = [
        span(0, 0, 100),
        span(0, 0, 100),
        span(0, 100, 200),
        span(0, 100, 200),
    ];
    let t = throughput(&jobs, 2, 200, 200);
    assert_eq!(t.saturation, Some(1.0));
    assert_eq!(t.lower_bound_ms, 200);
    assert!((t.efficiency - 1.0).abs() < 1e-9);
}

#[test]
fn worker_start_up_is_not_counted_in_saturation() {
    // the request is sent at 0, the first job starts at 100 (workers spawning): that interval is excluded
    let jobs = [span(0, 100, 200), span(0, 100, 200)];
    let t = throughput(&jobs, 2, 200, 200);
    assert_eq!(t.saturation, Some(1.0));
    // idle time after the first start still counts
    let jobs = [span(0, 100, 200), span(0, 150, 250)];
    let t = throughput(&jobs, 2, 250, 250);
    // [100,150): 1 busy of 2; [150,200): 2 of 2; after 200 fewer than 2 runnable
    let expected = (50.0 + 100.0) / 200.0;
    assert!(
        (t.saturation.unwrap() - expected).abs() < 1e-9,
        "{:?}",
        t.saturation
    );
}

#[test]
fn idle_slot_with_queued_job_lowers_saturation() {
    // the second slot stays idle for 50 ms although three jobs are queued (a worker starting up)
    let jobs = [span(0, 0, 100), span(0, 50, 150), span(0, 100, 200)];
    let t = throughput(&jobs, 2, 200, 200);
    // runnable >= 2 over [0, 150): busy 1 x 50 + 2 x 100 of 2 x 150 offered
    let expected = (50.0 + 200.0) / 300.0;
    assert!(
        (t.saturation.unwrap() - expected).abs() < 1e-9,
        "{:?}",
        t.saturation
    );
    // fewer jobs than slots are never "runnable >= slots": no saturation
    assert_eq!(throughput(&[span(0, 0, 10)], 2, 10, 10).saturation, None);
}

#[test]
fn lower_bound_uses_longest_job() {
    // one long job dominates: 900 ms of 4 slots' 1200 ms total; 100 ms serial outside the compile phase
    let jobs = [
        span(0, 0, 900),
        span(0, 0, 100),
        span(0, 0, 100),
        span(0, 0, 100),
    ];
    let t = throughput(&jobs, 4, 1100, 1000);
    assert_eq!(t.lower_bound_ms, 100 + 900);
    assert!((t.efficiency - 1000.0 / 1100.0).abs() < 1e-9);
    // many equal jobs: the spread over the slots dominates
    let many: Vec<JobSpan> = (0..8).map(|_| span(0, 0, 100)).collect();
    assert_eq!(throughput(&many, 2, 400, 400).lower_bound_ms, 400);
}

/// Every file below `output/` by path, with its bytes.
fn output_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.join("output")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(name, std::fs::read(&path).unwrap());
            }
        }
    }
    out
}

#[test]
fn affected_outputs_are_written_in_parallel_with_same_bytes() {
    let python = python_or_skip!();
    let f = fixture(&python, "");
    run(f.root());
    let built = output_files(f.root());
    let functions = built.keys().filter(|k| k.ends_with(".c")).count();
    assert_eq!(functions, 3, "{:?}", built.keys().collect::<Vec<_>>());

    // the sequential full regeneration writes the same bytes: nothing changes
    let session = Session::open(f.root()).unwrap();
    let lock = Workspace::open(f.root())
        .unwrap()
        .lock(Duration::from_secs(5))
        .unwrap();
    let report = write_all(&session, &lock).unwrap();
    drop(lock);
    assert_eq!(report.written, 0);
    assert_eq!(output_files(f.root()), built);
}
