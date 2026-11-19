//! `diagnose` (and `diagnose` with `deep`) on overlay functions of a synthetic Aztec C86 overlay workspace.

#[path = "support/overlay_fixture.rs"]
mod overlay_fixture;

use decovery_facade::{Budget, Control, LegacyCall, LegacyOperation, Session, diagnose_deep};
use overlay_fixture::{A_AT, B_AT};

fn workspace(main_ovmain: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), main_ovmain);
    dir
}

#[test]
fn overlay_function_is_diagnosed_from_the_overlay_bytes() {
    let dir = workspace(false);
    let session = Session::open(dir.path()).unwrap();
    for target in ["A_ovmain", A_AT, "fun_A_0000_5000"] {
        let r = decovery_facade::diagnose(&session, target, Budget::default()).unwrap();
        assert!(
            !r.summary.contains("no instructions compared"),
            "{target}: {}",
            r.summary
        );
        assert_eq!(r.data["function"]["address"], A_AT, "{target}");
        assert_eq!(r.data["function"]["name"], "A_ovmain", "{target}");
        assert_eq!(r.data["function"]["file"], "a.c", "{target}");
        assert_eq!(r.data["function"]["instructions_differing"], 1, "{target}");
        let text = r.data["pairs_text"].as_str().unwrap();
        assert!(text.contains("mov ax,1"), "{text}");
    }
    let b = decovery_facade::diagnose(&session, "B_ovmain", Budget::default()).unwrap();
    assert_eq!(b.data["function"]["address"], B_AT);
    assert_eq!(b.summary, "B_ovmain: no differing instructions");
}

#[test]
fn ambiguous_overlay_name_lists_candidates() {
    let dir = workspace(false);
    let session = Session::open(dir.path()).unwrap();
    let e = decovery_facade::diagnose(&session, "ovmain", Budget::default())
        .unwrap_err()
        .to_string();
    assert!(e.contains("ambiguous"), "{e}");
    assert!(e.contains("A_ovmain") && e.contains(A_AT), "{e}");
    assert!(e.contains("B_ovmain") && e.contains(B_AT), "{e}");
}

#[test]
fn exact_name_wins_over_overlay_qualified_names() {
    let dir = workspace(true);
    let session = Session::open(dir.path()).unwrap();
    // the main program's own `ovmain` has no rebuild record: the exact name is found, not an overlay's copy
    let e = decovery_facade::diagnose(&session, "ovmain", Budget::default())
        .unwrap_err()
        .to_string();
    assert_eq!(
        e,
        "no rebuilt object for ovmain; run `decovery build <file>`"
    );
}

#[test]
fn deep_diagnosis_of_an_overlay_function_is_refused_clearly() {
    let dir = workspace(false);
    for target in [A_AT, "A_ovmain"] {
        let call = LegacyCall::new(target, LegacyOperation::Context);
        let e = diagnose_deep(dir.path(), &call, &Control::progress_only(&|_| {}))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("not available for overlay functions"),
            "{target}: {e}"
        );
        assert!(!e.contains("not a decovery address"), "{e}");
    }
}
