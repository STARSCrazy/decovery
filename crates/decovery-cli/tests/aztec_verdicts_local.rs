//! Phase 4, Task 4: first verdicts on the main-program functions of the third target (Aztec C86 4.2b, no linker),
//! object against image with link gaps (`decovery_diff::compare_with_gaps`), against Decomp's frozen baseline.
//! Run with
//! `cargo test -j 1 -p decovery-cli --test aztec_verdicts_local -- --ignored --nocapture --test-threads 1` and
//!
//! - `DECOVERY_LOCAL_WORKSPACE_AZTEC=<Decomp workspace of the third target>` (its `decomp.toml` names the program
//!   file and the flags, `nachbau/*.c` are the sources; nothing is written there);
//! - `DECOVERY_GOLDEN_DIR=<private dir>`: the newest `aztec/baseline-<date>.json` (written once by
//!   `tools/parity/aztec_baseline.py`) or the file named by `DECOVERY_AZTEC_BASELINE`;
//! - optional `DECOVERY_TOOLCHAIN_AZTEC42=<Aztec C86 4.2b directory>`, `DECOVERY_AZTEC_RUNNER` (default
//!   `dosbox-lab`).
//!
//! Every source is compiled; every object function whose C name the baseline places in the main program
//! (`rel:` address) is compared with the program image at that address. Overlay functions wait for Task 6.
//! Prints the comparison per function and every disagreement with the baseline; fails on a disagreement.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use decovery_core::{Address, Workspace, read_user_config};
use decovery_diff::{Decoration, Verdict, compare_with_gaps};
use decovery_objects::{functions, read_aztec};
use decovery_toolchain::{SourceJob, compile, find_sources, open_runners, profile, stage};

const PROFILE: &str = "aztec-c86-4.2b";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("set {name}")))
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
            found
                .pop()
                .unwrap_or_else(|| panic!("no baseline in {}", dir.display()))
        });
    println!("baseline {}", path.display());
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `rel:SSSS:OOOO` → segment and offset.
fn rel(text: &str) -> Option<(u16, u16)> {
    let rest = text.strip_prefix("rel:")?;
    let (seg, off) = rest.split_once(':')?;
    Some((
        u16::from_str_radix(seg, 16).ok()?,
        u16::from_str_radix(off, 16).ok()?,
    ))
}

#[test]
#[ignore = "local: third target + Aztec C86 4.2b"]
fn aztec_verdicts_local() {
    let decomp = env_path("DECOVERY_LOCAL_WORKSPACE_AZTEC");
    let golden = env_path("DECOVERY_GOLDEN_DIR");
    let runner = std::env::var("DECOVERY_AZTEC_RUNNER").unwrap_or_else(|_| "dosbox-lab".into());
    let config: toml::Table = std::fs::read_to_string(decomp.join("decomp.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let program_file = config["ziel"]["datei"].as_str().unwrap().to_string();
    let rebuild = config["nachbau"].as_table().unwrap();
    let global = rebuild
        .get("optionen")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let per_file = rebuild
        .get("optionen_je_datei")
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_default();

    let base = baseline(&golden);
    let verdicts = base["functions"].as_object().unwrap();
    let names = base["names"].as_object().unwrap();
    // C name → main-program address
    let main: BTreeMap<&str, &str> = names
        .iter()
        .filter(|(a, _)| a.starts_with("rel:"))
        .map(|(a, n)| (n.as_str().unwrap(), a.as_str()))
        .collect();

    // the program image (MZ: load module behind the header)
    let exe = std::fs::read(&program_file).unwrap();
    let header = usize::from(u16::from_le_bytes([exe[8], exe[9]])) * 16;
    let image = &exe[header..];

    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for entry in std::fs::read_dir(decomp.join("nachbau")).unwrap() {
        let path = entry.unwrap().path();
        if path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("c"))
        {
            std::fs::copy(&path, src.join(path.file_name().unwrap())).unwrap();
        }
    }
    let mut ws_config = format!(
        "schema = 1\n\n[target]\nfile = \"t.exe\"\nsha256 = \"aa\"\nformat = \"mz\"\nprocessor = \"x86\"\n\n\
         [rebuild]\ncompiler = \"{PROFILE}\"\nrunners = [{}]\n",
        toml::Value::String(runner.clone())
    );
    if let Ok(dir) = std::env::var("DECOVERY_TOOLCHAIN_AZTEC42") {
        ws_config.push_str(&format!("tool_dir = {}\n", toml::Value::String(dir)));
    }
    std::fs::write(root.path().join("decovery.toml"), ws_config).unwrap();
    let ws = Workspace::open(root.path()).unwrap();
    let profile = profile(PROFILE).unwrap();
    let build = root.path().join("build");
    std::fs::create_dir(&build).unwrap();
    let staged = stage(&find_sources(&src, &[]).unwrap(), &build).unwrap();
    let jobs: Vec<SourceJob> = staged
        .iter()
        .map(|name| {
            let flags = per_file
                .get(&name.to_lowercase())
                .and_then(|v| v.as_str())
                .map_or(global.clone(), str::to_string);
            SourceJob::new(name.clone(), flags)
        })
        .collect();
    let user = read_user_config().unwrap();
    let (runners, warnings) = open_runners(std::slice::from_ref(&runner), &ws, &user);
    assert!(!runners.is_empty(), "runner {runner}: {warnings:?}");
    let started = Instant::now();
    let (files, warnings) = compile(&ws, &profile, &jobs, &build, &runners, None).unwrap();
    println!(
        "{runner}: {} sources in {} ms wall; warnings {warnings:?}",
        files.len(),
        started.elapsed().as_millis()
    );

    let decoration = Decoration::new(
        profile.decoration.function.clone(),
        profile.decoration.data.clone(),
    );
    let mut ours: BTreeMap<String, &'static str> = BTreeMap::new();
    for file in &files {
        let object = file
            .object
            .as_deref()
            .unwrap_or_else(|| panic!("{} not compiled: {}", file.file, file.message));
        let read = read_aztec(object, &file.file).unwrap();
        for module in &read.modules {
            for f in functions(module) {
                let name = decoration.undecorate(f.name);
                let Some(&address) = main.get(name) else {
                    continue;
                };
                let (seg, off) = rel(address).unwrap();
                let at = usize::from(seg) * 16 + usize::from(off);
                let original = image.get(at..).unwrap_or(&[]);
                let c = compare_with_gaps(&f, original, Address::Seg { seg, off });
                let word = match c.verdict {
                    Verdict::Identical => "identisch",
                    Verdict::Differs => "abweichend",
                    _ => "fehler",
                };
                println!(
                    "  {address} {name} ({}): {word}; {} bytes, {} equal, {} gaps, {} differing, refs ok {} \
                     wrong {} unchecked {}; {:?}",
                    file.file,
                    c.metrics.bytes,
                    c.metrics.equal,
                    c.metrics.gaps,
                    c.metrics.differing,
                    c.metrics.refs_ok,
                    c.metrics.refs_wrong,
                    c.metrics.refs_unchecked,
                    c.blockers
                );
                ours.insert(address.to_string(), word);
            }
        }
    }

    let mut same = 0;
    let mut disagreements = Vec::new();
    for (address, verdict) in verdicts.iter().filter(|(a, _)| a.starts_with("rel:")) {
        let decomp_word = verdict.as_str().unwrap();
        let our = ours.get(address).copied().unwrap_or("nicht-versucht");
        if our == decomp_word {
            same += 1;
        } else {
            disagreements.push(format!(
                "{address} {}: decovery {our}, Decomp {decomp_word}",
                names.get(address).and_then(|n| n.as_str()).unwrap_or("?")
            ));
        }
    }
    println!(
        "main program: {} functions, {} built and compared, {same} equal verdicts, {} disagreements",
        same + disagreements.len(),
        ours.len(),
        disagreements.len()
    );
    for d in &disagreements {
        println!("  {d}");
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}
