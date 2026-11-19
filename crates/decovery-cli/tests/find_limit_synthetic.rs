//! `find --limit` on a synthetic overlay workspace (three functions).

#[path = "../../decovery-facade/tests/support/overlay_fixture.rs"]
mod overlay_fixture;

use std::process::{Command, Output};

fn decovery(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("--workspace")
        .arg(root)
        .args(args)
        .output()
        .expect("run decovery")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_cut_list_says_how_many_more_and_all_shows_everything() {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), false);
    let cut = decovery(dir.path(), &["find", "functions", "--limit", "1"]);
    assert_eq!(cut.status.code(), Some(0), "{cut:?}");
    let text = stdout(&cut);
    assert!(
        text.contains("1 of 3 functions; 2 more, use --limit"),
        "{text}"
    );
    let all = decovery(dir.path(), &["find", "functions", "--limit", "all"]);
    assert_eq!(all.status.code(), Some(0), "{all:?}");
    let text = stdout(&all);
    assert!(text.starts_with("3 functions"), "{text}");
    let bad = decovery(dir.path(), &["find", "functions", "--limit", "many"]);
    assert_eq!(bad.status.code(), Some(2));
}
