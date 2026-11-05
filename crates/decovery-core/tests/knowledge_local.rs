//! Local test against a private Decomp workspace. Run with `cargo test -- --ignored`.

use std::path::PathBuf;
use std::time::Duration;

use decovery_core::{Workspace, migrate_decomp, read_rebuild, read_references};

#[test]
#[ignore = "local: private Decomp workspace"]
fn migrated_symbols_round_trip() {
    let from = PathBuf::from(
        std::env::var_os("DECOVERY_LOCAL_WORKSPACE").expect("DECOVERY_LOCAL_WORKSPACE is not set"),
    );
    let to = tempfile::tempdir().unwrap();
    migrate_decomp(&from, to.path()).unwrap();

    let symbols_path = to.path().join("knowledge").join("symbols.toml");
    let before = std::fs::read(&symbols_path).unwrap();
    let ws = Workspace::open(to.path()).unwrap();
    let lock = ws.lock(Duration::from_secs(1)).unwrap();
    ws.save_symbols(&lock).unwrap();
    assert_eq!(std::fs::read(&symbols_path).unwrap(), before);

    let count = |file: &str, marker: &str| {
        std::fs::read_to_string(from.join("wissen").join(file))
            .map(|t| t.matches(marker).count())
            .unwrap_or(0)
    };
    assert_eq!(
        read_rebuild(to.path()).unwrap().len(),
        count("nachbau.toml", "[[funktion]]")
    );
    assert_eq!(
        read_references(to.path()).unwrap().len(),
        count("verweise.toml", "[[verweis]]")
    );
}
