//! The Aztec C86 reader on real compiler output (private, not in the repository). Run with
//! `cargo test -j 2 -p decovery-objects --test aztec_local -- --ignored --nocapture` and
//!
//! - `DECOVERY_TOOLCHAIN_AZTEC42=<Aztec C86 4.2b directory>`: every `.LIB` and `.O` under its `LIB` directory;
//! - optional `DECOVERY_AZTEC_OBJECT_OUT=<dir>`: objects compiled from the third target's sources (written by
//!   `decovery-toolchain/tests/aztec_compile_local.rs`);
//! - optional `DECOVERY_GOLDEN_DIR=<private dir>`: when `aztec/reader-counts.json` exists there (file name →
//!   function count from Decomp's reader on the same files), every count must match.
//!
//! - optional `DECOVERY_AZTEC_LIST=<file name>`: list the modules of that file.
//!
//! Every file must read without error; no relocation may have an unknown target.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use decovery_objects::{RefTarget, functions, read_aztec};
use serde_json::Value;

fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("o") || x.eq_ignore_ascii_case("lib"))
        })
        .collect();
    files.sort();
    files
}

#[test]
#[ignore = "local: Aztec C86 4.2b libraries and compiled objects"]
fn aztec_reader_reads_real_files() {
    let tool = PathBuf::from(
        std::env::var("DECOVERY_TOOLCHAIN_AZTEC42").expect("set DECOVERY_TOOLCHAIN_AZTEC42"),
    );
    let mut files = files_in(&tool.join("LIB"));
    if let Ok(dir) = std::env::var("DECOVERY_AZTEC_OBJECT_OUT") {
        files.extend(files_in(Path::new(&dir)));
    }
    assert!(!files.is_empty());
    let golden: Option<BTreeMap<String, Value>> = std::env::var("DECOVERY_GOLDEN_DIR")
        .ok()
        .map(|d| Path::new(&d).join("aztec/reader-counts.json"))
        .filter(|p| p.is_file())
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap());
    let (mut total, mut compared) = (0usize, 0usize);
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let bytes = std::fs::read(path).unwrap();
        let file = read_aztec(&bytes, &name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let count: usize = file.modules.iter().map(|m| functions(m).len()).sum();
        let relocs: usize = file
            .modules
            .iter()
            .flat_map(|m| &m.sections)
            .flat_map(|s| &s.relocs)
            .inspect(|r| assert_ne!(r.target, RefTarget::Unknown, "{name}"))
            .count();
        println!(
            "{name}: {} modules, {count} functions, {relocs} relocations",
            file.modules.len()
        );
        if std::env::var("DECOVERY_AZTEC_LIST").is_ok_and(|l| l.eq_ignore_ascii_case(&name)) {
            for m in &file.modules {
                println!("  {}: {} functions", m.name, functions(m).len());
            }
        }
        total += count;
        if let Some(expected) = golden.as_ref().and_then(|g| g.get(&name)) {
            assert_eq!(
                count as u64,
                expected.as_u64().unwrap(),
                "{name}: function count"
            );
            compared += 1;
        }
    }
    println!(
        "{} files, {total} functions, {compared} counts compared",
        files.len()
    );
}
