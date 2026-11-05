//! Local test against the private second target; needs `DECOVERY_TARGET_MZ`.

use decovery_loaders::load_mz;

#[test]
#[ignore = "local: second target"]
fn second_target_matches_workspace_segments() {
    let path = std::env::var("DECOVERY_TARGET_MZ")
        .expect("DECOVERY_TARGET_MZ must point to the second target (PROGRAM.EXE)");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let image = load_mz(&bytes).unwrap();
    assert_eq!(image.image_offset, 512);
    assert!(image.image_len > 0);
}
