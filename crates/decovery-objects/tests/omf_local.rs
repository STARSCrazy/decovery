//! Parity with Decomp's OMF reader on the objects of a private Decomp workspace (`DECOVERY_LOCAL_WORKSPACE`) (reference data from `tools/golden/omf_golden.py`).

use std::path::PathBuf;

use decovery_objects::{functions, read_omf};
use serde_json::Value;

// Decomp's rebuild object cache below its workspace (its workspace is German).
const DECOMP_OBJECT_DIR: &str = "cache/nachbau/obj";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn pairs_u32_str(v: &Value) -> Vec<(u32, String)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_u64().unwrap() as u32,
                p[1].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
#[ignore = "local: private Decomp workspace"]
fn matches_decomp_on_all_objects() {
    let obj_dir = env_path("DECOVERY_LOCAL_WORKSPACE").join(DECOMP_OBJECT_DIR);
    let golden_dir = env_path("DECOVERY_GOLDEN_DIR").join("omf");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&obj_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("obj")))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no objects in {obj_dir:?}");
    let mut total = 0;
    for path in &files {
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        let golden: Value = serde_json::from_slice(
            &std::fs::read(golden_dir.join(format!("{stem}.json"))).unwrap(),
        )
        .unwrap();
        let object = read_omf(&std::fs::read(path).unwrap(), &file_name)
            .unwrap_or_else(|e| panic!("{file_name}: {e}"));
        let mut mine = Vec::new();
        for m in &object.modules {
            for f in functions(m) {
                mine.push((format!("{file_name}:{}", m.name), f));
            }
        }
        let expected = golden["functions"].as_array().unwrap();
        assert_eq!(mine.len(), expected.len(), "{file_name}: function count");
        for ((origin, f), g) in mine.iter().zip(expected) {
            let ctx = format!("{file_name}::{}", f.name);
            assert_eq!(f.name, g["name"].as_str().unwrap(), "{ctx}: name");
            assert_eq!(origin, g["origin"].as_str().unwrap(), "{ctx}: origin");
            assert_eq!(
                u64::from(f.start),
                g["start"].as_u64().unwrap(),
                "{ctx}: start"
            );

            let gaps = f.gaps();
            let want_gaps: Vec<u32> = g["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(
                gaps.iter().copied().collect::<Vec<_>>(),
                want_gaps,
                "{ctx}: gaps"
            );

            // Decomp zeroes own-section reference fields it could name; everything else is raw.
            let want_code = hex(g["code"].as_str().unwrap());
            let code = f.code();
            assert_eq!(code.len(), want_code.len(), "{ctx}: code length");
            for (i, (a, b)) in code.iter().zip(&want_code).enumerate() {
                let in_gap = gaps.contains(&(i as u32));
                assert!(
                    a == b || (in_gap && *b == 0),
                    "{ctx}: code byte {i}: {a:#04x} vs {b:#04x}"
                );
            }

            let refs: Vec<(u32, String)> = f
                .references()
                .into_iter()
                .map(|(p, n)| (p, n.to_string()))
                .collect();
            assert_eq!(refs, pairs_u32_str(&g["references"]), "{ctx}: references");

            let rel: Vec<u32> = f.relative_offsets().into_iter().collect();
            let want_rel: Vec<u32> = g["relative"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(rel, want_rel, "{ctx}: relative");

            let add: Vec<(u32, i64)> = f.addends();
            let want_add: Vec<(u32, i64)> = g["addends"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p[0].as_u64().unwrap() as u32, p[1].as_i64().unwrap()))
                .collect();
            assert_eq!(add, want_add, "{ctx}: addends");
            total += 1;
        }
    }
    eprintln!("{total} functions in {} objects match", files.len());
}
