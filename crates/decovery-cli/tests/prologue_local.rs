//! Phase 4, Task 7 (risk R2): prologue search in the third target's overlays and decoding of their code.
//! Run with
//! `cargo test -j 1 -p decovery-cli --test prologue_local -- --ignored --nocapture` and
//! `DECOVERY_LOCAL_WORKSPACE_AZTEC=<Decomp workspace>` (read only), `DECOVERY_GOLDEN_DIR=<private dir>` (frozen
//! baseline `aztec/baseline-*.json`, newest, or `DECOVERY_AZTEC_BASELINE`).
//!
//! Per overlay: prologue matches (profile pattern, call target = Decomp's `$csav` address) against the baseline's
//! function addresses (every match must be a baseline function; the baseline also has frameless functions); the code segment decoded function by function (16-bit) must cover the code size exactly,
//! and 386-prefixed (66h/67h) instructions are counted.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use decovery_core::{Address, Workspace};
use decovery_x86::find_prologues;

fn s<'a>(v: &'a toml::Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or_default()
}

fn baseline(golden: &Path) -> serde_json::Value {
    let path = std::env::var("DECOVERY_AZTEC_BASELINE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let dir = golden.join("aztec");
            let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("baseline-") && n.ends_with(".json"))
                })
                .collect();
            found.sort();
            found.pop().unwrap()
        });
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
#[ignore = "local: third target"]
fn overlay_prologues_and_decoding() {
    let decomp = PathBuf::from(std::env::var("DECOVERY_LOCAL_WORKSPACE_AZTEC").unwrap());
    let golden = PathBuf::from(std::env::var("DECOVERY_GOLDEN_DIR").unwrap());
    let base = baseline(&golden);
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(decomp.join("decomp.toml")).unwrap()).unwrap();
    let main = s(&config["ziel"], "datei").to_string();
    let main_sha = s(&config["ziel"], "sha256").to_string();
    let overlays = config["overlay"].as_array().unwrap().clone();
    // Decomp's pattern names the helper by address: "... >rel:SSSS:OOOO"
    let pattern_text = config["analyse"]["prologe"][0].as_str().unwrap();
    let (_, target) = pattern_text.split_once('>').unwrap();
    let (seg_text, off_text) = target
        .trim()
        .trim_start_matches("rel:")
        .split_once(':')
        .unwrap();
    let csav_seg = u16::from_str_radix(seg_text, 16).unwrap();
    let csav_off = u16::from_str_radix(off_text, 16).unwrap();
    let profile = decovery_toolchain::profile("aztec-c86-4.2b").unwrap();
    let pattern = profile.prologue_pattern.clone().unwrap();
    let call = pattern.call_target.clone().unwrap();
    let resolve = |a: Address| match a {
        Address::Ovl { seg, off, .. } | Address::Seg { seg, off }
            if seg == csav_seg && off == csav_off =>
        {
            Some(call.clone())
        }
        _ => None,
    };

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
    let w = Workspace::open(ws).unwrap();
    let (regions, warnings) = decovery_facade::program::overlay_regions(&w);
    assert!(warnings.is_empty(), "{warnings:?}");

    let mut by_overlay: BTreeMap<String, BTreeSet<Address>> = BTreeMap::new();
    for key in base["functions"].as_object().unwrap().keys() {
        if let Ok(a @ Address::Ovl { overlay, .. }) = key.parse::<Address>() {
            by_overlay.entry(overlay.to_string()).or_default().insert(a);
        }
    }
    let mut problems = Vec::new();
    let (mut total_found, mut total_base, mut total_both) = (0, 0, 0);
    for o in &w.config.overlays {
        let name = o.name.to_string();
        let code = regions
            .iter()
            .find(|r| r.start.overlay() == Some(o.name) && r.name.ends_with(".code"))
            .unwrap_or_else(|| panic!("{name}: no code region"));
        let found: BTreeSet<Address> = find_prologues(&code.data, code.start, &pattern, &resolve)
            .into_iter()
            .collect();
        let theirs = by_overlay.remove(&name).unwrap_or_default();
        let both = found.intersection(&theirs).count();
        let only_ours: Vec<String> = found.difference(&theirs).map(|a| a.to_string()).collect();
        let only_theirs: Vec<String> = theirs.difference(&found).map(|a| a.to_string()).collect();
        // decode function by function: [start of function i, start of function i+1), the first piece from the
        // segment start
        let mut starts: Vec<u64> = theirs
            .iter()
            .filter_map(|a| a.bytes_from(code.start))
            .filter(|&d| d < code.data.len() as u64)
            .collect();
        starts.insert(0, 0);
        starts.dedup();
        starts.push(code.data.len() as u64);
        let (mut sum, mut invalid, mut prefixed) = (0u64, 0u64, 0u64);
        for win in starts.windows(2) {
            let piece = &code.data[win[0] as usize..win[1] as usize];
            for d in decovery_x86::decode_detailed(piece, 16, 0, &Default::default()) {
                sum += u64::from(d.len);
                if matches!(d.kind, decovery_x86::DecodedKind::Invalid) {
                    invalid += 1;
                }
                let at = d.offset as usize;
                if d.kind == decovery_x86::DecodedKind::Code
                    && piece[at..at + d.len as usize]
                        .iter()
                        .take_while(|b| {
                            matches!(b, 0x66 | 0x67 | 0x26 | 0x2E | 0x36 | 0x3E | 0xF2 | 0xF3)
                        })
                        .any(|b| matches!(b, 0x66 | 0x67))
                {
                    prefixed += 1;
                }
            }
        }
        println!(
            "{name}: code {} bytes, decoded {sum}, invalid {invalid}, 386-prefixed {prefixed}; prologues {} found, {} in baseline, {both} both; only ours {only_ours:?}; only baseline {only_theirs:?}",
            code.data.len(),
            found.len(),
            theirs.len()
        );
        if sum != code.data.len() as u64 {
            problems.push(format!("{name}: decoded {sum} of {}", code.data.len()));
        }
        // Decomp also lists functions without the frame (found by calls); a match it does not list is a problem
        if !only_ours.is_empty() {
            problems.push(format!(
                "{name}: prologues not in the baseline {only_ours:?}"
            ));
        }
        total_found += found.len();
        total_base += theirs.len();
        total_both += both;
    }
    println!("total: {total_found} found, {total_base} baseline, {total_both} both");
    assert!(problems.is_empty(), "{problems:#?}");
}
