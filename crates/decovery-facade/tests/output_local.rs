//! Local check against a private Decomp workspace: rendered headers equal Decomp's after a fixed
//! German-to-English mapping. Run with `cargo test -- --ignored`.

#[path = "support/decomp_mapping.rs"]
mod decomp_mapping;

use std::path::PathBuf;

use decomp_mapping::{decomp_files, expected, first_difference, read_decomp};
use decovery_core::migrate_decomp;
use decovery_facade::{Session, render_function};

const SAMPLE: usize = 30;

#[test]
#[ignore = "local: private Decomp workspace"]
fn header_lines_match_decomp_sample() {
    let from = PathBuf::from(
        std::env::var_os("DECOVERY_LOCAL_WORKSPACE").expect("DECOVERY_LOCAL_WORKSPACE is not set"),
    );
    let to = tempfile::tempdir().unwrap();
    migrate_decomp(&from, to.path()).unwrap();
    let session = Session::open(to.path()).unwrap();

    let limit = std::env::var("DECOVERY_OUTPUT_SAMPLE")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(SAMPLE);
    let mut mismatches: Vec<String> = Vec::new();
    let mut by_key: std::collections::BTreeMap<String, usize> = Default::default();
    let files = decomp_files(&from);
    let mut compared = 0;
    for (at, path) in files.iter().take(limit) {
        let want = expected(&read_decomp(path));
        let got = render_function(&session, *at).unwrap();
        compared += 1;
        let Some((key, line, wl, gl)) = first_difference(&want, &got) else {
            continue;
        };
        *by_key.entry(key).or_default() += 1;
        mismatches.push(format!(
            "{at} line {line}:\n  decomp:   {wl}\n  decovery: {gl}"
        ));
    }
    assert!(compared > 0, "no Decomp function files found");
    assert!(
        mismatches.is_empty(),
        "{} of {compared} functions differ (by key {by_key:?}); first:\n{}",
        mismatches.len(),
        mismatches[..mismatches.len().min(5)].join("\n")
    );
}
