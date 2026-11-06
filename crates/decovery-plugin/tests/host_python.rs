//! Host tests against the Python SDK. Skipped (with a message) when no Python is found:
//! set `DECOVERY_PYTHON` or put `python` on PATH.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use decovery_plugin::{CallOptions, CancelToken, Limits, PluginError, PluginHost, Progress};
use serde_json::json;

fn python() -> Option<OsString> {
    let candidate = std::env::var_os("DECOVERY_PYTHON").unwrap_or_else(|| "python".into());
    let ok = std::process::Command::new(&candidate)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then_some(candidate)
}

fn spawn() -> Option<PluginHost> {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
        return None;
    };
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/echo_plugin.py");
    let command = [python, fixture.into_os_string()];
    Some(
        PluginHost::spawn(&command, Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("spawn echo plugin"),
    )
}

fn opts(timeout: Duration) -> CallOptions<'static> {
    CallOptions {
        timeout,
        cancel: None,
        on_progress: None,
    }
}

const LONG: Duration = Duration::from_secs(20);

#[test]
fn round_trip() {
    let Some(host) = spawn() else { return };
    assert_eq!(host.info().name, "echo");
    assert_eq!(host.info().protocol, "decovery-plugin/1");
    assert_eq!(
        host.info().capabilities,
        [("echo".to_string(), 1u32)].into()
    );
    assert_eq!(host.info().limits("echo"), Limits::new(3, Some(64)));
    let out = host.call("echo/ping", json!({"x": 1}), opts(LONG)).unwrap();
    assert_eq!(out, json!({"x": 1}));
    let err = host.call("nope/x", json!({}), opts(LONG)).unwrap_err();
    assert!(
        matches!(err, PluginError::Remote { code: -32001, .. }),
        "{err:?}"
    );
    let err = host.call("echo/other", json!({}), opts(LONG)).unwrap_err();
    assert!(
        matches!(err, PluginError::Remote { code: -32601, .. }),
        "{err:?}"
    );
    host.shutdown().unwrap();
}

#[test]
fn timeout_sends_cancel() {
    let Some(host) = spawn() else { return };
    let marker: PathBuf =
        std::env::temp_dir().join(format!("decovery-cancel-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let started = Instant::now();
    let err = host
        .call(
            "echo/sleep",
            json!({"seconds": 2, "marker": marker.to_str().unwrap()}),
            opts(Duration::from_millis(100)),
        )
        .unwrap_err();
    assert!(matches!(err, PluginError::Timeout), "{err:?}");
    assert!(started.elapsed() < Duration::from_millis(1500));
    // The plugin saw $/cancel: it wakes early and writes the marker.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(marker.exists(), "plugin never received $/cancel");
    let _ = std::fs::remove_file(&marker);
    // The host still works and the late response did not confuse routing.
    let out = host.call("echo/ping", json!({"y": 2}), opts(LONG)).unwrap();
    assert_eq!(out, json!({"y": 2}));
    host.shutdown().unwrap();
}

#[test]
fn explicit_cancel_returns_cancelled() {
    let Some(host) = spawn() else { return };
    let token = CancelToken::new();
    let t2 = token.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        t2.cancel();
    });
    let err = host
        .call(
            "echo/sleep",
            json!({"seconds": 5}),
            CallOptions {
                timeout: LONG,
                cancel: Some(token),
                on_progress: None,
            },
        )
        .unwrap_err();
    canceller.join().unwrap();
    assert!(matches!(err, PluginError::Cancelled), "{err:?}");
    host.shutdown().unwrap();
}

#[test]
fn progress_is_reported() {
    let Some(host) = spawn() else { return };
    let seen: Mutex<Vec<Progress>> = Mutex::new(Vec::new());
    let sink = |p: Progress| seen.lock().unwrap().push(p);
    let out = host
        .call(
            "echo/count",
            json!({"n": 3}),
            CallOptions {
                timeout: LONG,
                cancel: None,
                on_progress: Some(&sink),
            },
        )
        .unwrap();
    assert_eq!(out, json!(3));
    let seen = seen.into_inner().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].done, 1);
    assert_eq!(seen[2].done, 3);
    assert_eq!(seen[2].total, Some(3));
    assert_eq!(seen[1].message.as_deref(), Some("step 2"));
    host.shutdown().unwrap();
}

#[test]
fn overlapping_calls_from_two_threads() {
    let Some(host) = spawn() else { return };
    let started = Instant::now();
    std::thread::scope(|s| {
        let a = s.spawn(|| host.call("echo/sleep", json!({"seconds": 0.5}), opts(LONG)));
        let b = s.spawn(|| host.call("echo/sleep", json!({"seconds": 0.5}), opts(LONG)));
        assert_eq!(a.join().unwrap().unwrap()["slept"], json!(0.5));
        assert_eq!(b.join().unwrap().unwrap()["slept"], json!(0.5));
    });
    assert!(
        started.elapsed() < Duration::from_millis(950),
        "calls did not overlap: {:?}",
        started.elapsed()
    );
    host.shutdown().unwrap();
}

#[test]
fn plugin_exit_is_reported() {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python");
        return;
    };
    let command = [python, "-c".into(), "pass".into()];
    let Err(err) = PluginHost::spawn(&command, Path::new(env!("CARGO_MANIFEST_DIR"))) else {
        panic!("a plugin that exits immediately must not initialize");
    };
    assert!(
        matches!(err, PluginError::Exited | PluginError::Protocol(_)),
        "{err:?}"
    );
}
