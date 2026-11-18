//! The persistent job store (`cache/jobs/`).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use decovery_core::{
    JOBS_DIR, JobProgress, JobState, job_cancel_requested, job_create, job_lease, job_list,
    job_load, job_request_cancel, job_save,
};
use serde_json::json;

#[test]
fn job_round_trip_keeps_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut job = job_create(root, "build", json!({"files": ["a.c"]})).unwrap();
    assert!(job.id.starts_with("j_") && job.id.len() == 14, "{}", job.id);
    assert_eq!(job.state, JobState::Queued);
    assert_eq!(job.schema, 1);
    assert_eq!(job_load(root, &job.id).unwrap(), job);

    job.state = JobState::Running;
    job.started = Some("2026-11-17T08:15:02Z".into());
    job.progress = Some(JobProgress::new(1, Some(3), Some("compiling".into())));
    job.extra.insert("future".into(), json!({"k": [1, 2]}));
    job_save(root, &job).unwrap();

    // a key a later version writes survives a rewrite by this one
    let path = root.join(JOBS_DIR).join(&job.id).join("job.json");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"state\": \"running\""), "{text}");
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["later"] = json!("kept");
    std::fs::write(&path, value.to_string()).unwrap();
    let back = job_load(root, &job.id).unwrap();
    assert_eq!(back.extra["later"], json!("kept"));
    assert_eq!(back.extra["future"], json!({"k": [1, 2]}));
    job_save(root, &back).unwrap();
    assert_eq!(
        job_load(root, &job.id).unwrap().extra["later"],
        json!("kept")
    );

    assert!(job_load(root, "../x").is_err());
    assert!(job_load(root, "j_000000000000").is_err());
}

#[test]
fn list_is_newest_first() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    assert!(job_list(root).unwrap().is_empty());
    let ids: Vec<String> = (0..4)
        .map(|i| job_create(root, "link", json!({ "n": i })).unwrap().id)
        .collect();
    let listed: Vec<String> = job_list(root).unwrap().into_iter().map(|j| j.id).collect();
    let mut expected = ids.clone();
    expected.reverse();
    assert_eq!(listed, expected);
    // a stray directory is no job
    std::fs::create_dir_all(root.join(JOBS_DIR).join("other")).unwrap();
    assert_eq!(job_list(root).unwrap().len(), 4);
}

#[test]
fn cancel_flag_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let job = job_create(root, "search", json!({})).unwrap();
    assert!(!job_cancel_requested(root, &job.id));
    job_request_cancel(root, &job.id).unwrap();
    assert!(job_cancel_requested(root, &job.id));
    assert!(root.join(JOBS_DIR).join(&job.id).join("cancel").is_file());
    assert!(job_request_cancel(root, "j_0123456789ab").is_err());
    assert!(!job_cancel_requested(root, "j_0123456789ab"));
}

const CHILD_ROOT: &str = "DECOVERY_TEST_LEASE_ROOT";
const CHILD_ID: &str = "DECOVERY_TEST_LEASE_ID";

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{} did not appear",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Run by [`lease_is_exclusive_across_processes`] in a child process: takes the lease, writes `held`, waits for
/// `release`. Without the environment variables it does nothing.
#[test]
fn lease_child() {
    let (Ok(root), Ok(id)) = (std::env::var(CHILD_ROOT), std::env::var(CHILD_ID)) else {
        return;
    };
    let root = Path::new(&root);
    let lease = job_lease(root, &id).unwrap().expect("the lease is free");
    std::fs::write(root.join("held"), "").unwrap();
    wait_for(&root.join("release"));
    drop(lease);
}

#[test]
fn lease_is_exclusive_across_processes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let job = job_create(root, "build", json!({})).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["lease_child", "--exact", "--test-threads=1"])
        .env(CHILD_ROOT, root)
        .env(CHILD_ID, &job.id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for(&root.join("held"));
    assert!(job_lease(root, &job.id).unwrap().is_none());
    std::fs::write(root.join("release"), "").unwrap();
    assert!(child.wait().unwrap().success());
    let lease = job_lease(root, &job.id).unwrap();
    assert!(lease.is_some());
    // exclusive within one process too
    assert!(job_lease(root, &job.id).unwrap().is_none());
    drop(lease);
    assert!(job_lease(root, &job.id).unwrap().is_some());
}
