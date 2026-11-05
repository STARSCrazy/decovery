use std::process::Command;

#[test]
fn prints_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("--version")
        .output()
        .expect("run decovery");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(stdout.starts_with("decovery 0.1.0"), "got {stdout:?}");
}

#[test]
fn compare_without_workspace_exits_with_2() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args([
            "compare",
            "--object",
            "a.obj",
            "--function",
            "f",
            "--workspace",
        ])
        .arg(dir.path())
        .output()
        .expect("run decovery");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(stderr.contains("cannot open workspace"), "got {stderr:?}");
}

#[test]
fn compare_requires_object_and_function() {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("compare")
        .output()
        .expect("run decovery");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(
        stderr.contains("--object") && stderr.contains("--function"),
        "got {stderr:?}"
    );
}
