//! Phase 4, Task 6: the third target's overlays added through `decovery overlay add` in a scratch workspace; every
//! overlay loads and its header-derived segments and entry equal Decomp's `[[overlay]]` entries.
//! Run with
//! `cargo test -j 1 -p decovery-cli --test overlay_local -- --ignored --nocapture` and
//! `DECOVERY_LOCAL_WORKSPACE_AZTEC=<Decomp workspace of the third target>` (read only: `decomp.toml` names the main
//! program and the overlay files).

use std::path::PathBuf;
use std::process::Command;

use decovery_core::Workspace;

fn s<'a>(v: &'a toml::Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or_default()
}

/// Decomp's `rel:`/`ovl:` text in decovery's form.
fn canonical(text: &str) -> String {
    text.parse::<decovery_core::Address>()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| text.to_string())
}

#[test]
#[ignore = "local: third target"]
fn overlays_load_and_match_decomp() {
    let decomp = PathBuf::from(
        std::env::var("DECOVERY_LOCAL_WORKSPACE_AZTEC")
            .expect("set DECOVERY_LOCAL_WORKSPACE_AZTEC"),
    );
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(decomp.join("decomp.toml")).unwrap()).unwrap();
    let main = s(&config["ziel"], "datei").to_string();
    let main_sha = s(&config["ziel"], "sha256").to_string();
    let overlays = config["overlay"].as_array().unwrap().clone();
    assert!(!overlays.is_empty());

    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path();
    std::fs::write(
        ws.join("decovery.toml"),
        format!(
            "schema = 1\n\n[target]\nfile = \"{main}\"\nsha256 = \"{main_sha}\"\nformat = \"mz\"\nprocessor = \"x86\"\n"
        ),
    )
    .unwrap();
    let mut args = vec!["overlay".to_string(), "add".to_string()];
    args.extend(overlays.iter().map(|o| s(o, "datei").to_string()));
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(&args)
        .args(["--json", "--workspace"])
        .arg(ws)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let answer: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    println!("loader: {}", answer["loader"]);

    let w = Workspace::open(ws).unwrap();
    let (regions, warnings) = decovery_facade::program::overlay_regions(&w);
    assert!(warnings.is_empty(), "{warnings:?}");
    let mut mismatches = Vec::new();
    for o in &overlays {
        let name = s(o, "name");
        let mine = w
            .config
            .overlays
            .iter()
            .find(|x| x.name.as_str() == name)
            .unwrap_or_else(|| panic!("overlay {name} missing"));
        let entry = mine.entry.map(|a| a.to_string()).unwrap_or_default();
        if entry != canonical(s(o, "einsprung")) {
            mismatches.push(format!("{name}: entry {entry} vs {}", s(o, "einsprung")));
        }
        let theirs = o
            .get("segment")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let ours: Vec<_> = w
            .config
            .target
            .segments
            .iter()
            .filter(|x| x.start.overlay() == Some(mine.name))
            .collect();
        if ours.len() != theirs.len() {
            mismatches.push(format!(
                "{name}: {} segments vs {}",
                ours.len(),
                theirs.len()
            ));
        }
        for (a, b) in ours.iter().zip(&theirs) {
            let want = (
                canonical(s(b, "start")),
                b["laenge"].as_integer().unwrap_or(-1) as u64,
                b.get("datei_offset")
                    .and_then(|x| x.as_integer())
                    .map(|x| x as u64),
                b.get("datei_laenge")
                    .and_then(|x| x.as_integer())
                    .map(|x| x as u64),
            );
            let got = (a.start.to_string(), a.length, a.file_offset, a.file_length);
            if got != want {
                mismatches.push(format!("{name}/{}: {got:?} vs {want:?}", a.name));
            }
        }
        let bytes: usize = regions
            .iter()
            .filter(|r| r.start.overlay() == Some(mine.name))
            .map(|r| r.data.len())
            .sum();
        println!(
            "{name}: entry {entry}, {} segments, {bytes} file bytes, file {} bytes",
            ours.len(),
            mine.size
        );
    }
    println!(
        "{} overlays, {} mismatches",
        overlays.len(),
        mismatches.len()
    );
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}
