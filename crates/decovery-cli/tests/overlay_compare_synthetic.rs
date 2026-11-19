//! `compare` and `diagnose` on overlay functions of a synthetic Aztec C86 overlay workspace.

#[path = "../../decovery-facade/tests/support/overlay_fixture.rs"]
mod overlay_fixture;

use std::process::{Command, Output};

use overlay_fixture::{A_AT, B_AT};

fn decovery(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("--workspace")
        .arg(root)
        .args(args)
        .output()
        .expect("run decovery")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn compare_finds_overlay_functions_by_name_and_address() {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), false);
    for target in ["B_ovmain", B_AT, "fun_B_0000_5000"] {
        let out = decovery(
            dir.path(),
            &[
                "compare",
                "--object",
                "cache/rebuild/obj/b.obj",
                "--function",
                target,
            ],
        );
        let t = text(&out);
        assert_eq!(out.status.code(), Some(0), "{target}: {t}");
        assert!(t.contains(&format!("B_ovmain at {B_AT}: identical")), "{t}");
    }
    let out = decovery(
        dir.path(),
        &[
            "compare",
            "--object",
            "cache/rebuild/obj/a.obj",
            "--function",
            A_AT,
        ],
    );
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("differs"), "{t}");
    // the C name alone is in both overlays
    let out = decovery(
        dir.path(),
        &[
            "compare",
            "--object",
            "cache/rebuild/obj/a.obj",
            "--function",
            "ovmain",
        ],
    );
    let t = text(&out);
    assert_eq!(out.status.code(), Some(2), "{t}");
    assert!(
        t.contains("ambiguous") && t.contains("A_ovmain") && t.contains("B_ovmain"),
        "{t}"
    );
}

#[test]
fn diagnose_reads_the_overlay_bytes() {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), false);
    let out = decovery(dir.path(), &["diagnose", A_AT]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(!t.contains("no instructions compared"), "{t}");
    assert!(t.contains("mov ax,1"), "{t}");
}

#[test]
fn deep_diagnosis_rejects_overlay_functions_and_unknown_modes() {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), false);
    let out = decovery(dir.path(), &["diagnose", "--deep", "context", A_AT]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(2), "{t}");
    assert!(t.contains("not available for overlay functions"), "{t}");
    assert!(!t.contains("not a decovery address"), "{t}");
    // `--deep` without a mode: a following name is the function, the mode is `joint`
    for args in [
        &["diagnose", "--deep", "A_ovmain"][..],
        &["diagnose", "A_ovmain", "--deep"],
    ] {
        let out = decovery(dir.path(), args);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {t}");
        assert!(
            t.contains("not available for overlay functions"),
            "{args:?}: {t}"
        );
    }
    // a word that is no mode next to a function is an error naming the modes
    let out = decovery(dir.path(), &["diagnose", "A_ovmain", "--deep", "bogus"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(2), "{t}");
    assert!(t.contains("invalid value 'bogus'"), "{t}");
    for mode in ["context", "structure", "registers", "slots", "joint"] {
        assert!(t.contains(mode), "{t}");
    }
}
