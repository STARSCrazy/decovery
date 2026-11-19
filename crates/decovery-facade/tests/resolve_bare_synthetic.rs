//! Bare hexadecimal targets (`show 5000`) on a synthetic overlay workspace.

#[path = "support/overlay_fixture.rs"]
mod overlay_fixture;

use decovery_facade::{FacadeError, Session, resolve};

fn session() -> (tempfile::TempDir, Session) {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), false);
    let session = Session::open(dir.path()).unwrap();
    (dir, session)
}

#[test]
fn a_unique_bare_offset_resolves() {
    let (_d, session) = session();
    for input in ["0100", "0x100", "100"] {
        let r = resolve(&session, input).unwrap();
        assert_eq!(r.function.to_string(), "seg:0000:0100", "{input}");
    }
}

#[test]
fn an_ambiguous_bare_offset_lists_the_candidates() {
    let (_d, session) = session();
    let Err(FacadeError::Invalid(m)) = resolve(&session, "5000") else {
        panic!("expected Invalid");
    };
    assert!(m.contains("ambiguous"), "{m}");
    assert!(m.contains("A_ovmain (ovl:A:0000:5000)"), "{m}");
    assert!(m.contains("B_ovmain (ovl:B:0000:5000)"), "{m}");
}

#[test]
fn an_unknown_bare_offset_is_not_found() {
    let (_d, session) = session();
    assert!(matches!(
        resolve(&session, "7777"),
        Err(FacadeError::NotFound(_))
    ));
}
