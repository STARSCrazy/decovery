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
