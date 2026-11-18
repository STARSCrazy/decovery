//! Phase 4, Task 8: the third target's overlay sources built and compared, per function (object against the
//! overlay code with link gaps) and per module (code, data, relocations and BSS, `compare_overlay_module`), against
//! Decomp's frozen baseline.
//! Run with
//! `cargo test -j 1 -p decovery-cli --test aztec_overlay_local -- --ignored --nocapture --test-threads 1` and the
//! environment of `aztec_verdicts_local` (`DECOVERY_LOCAL_WORKSPACE_AZTEC`, `DECOVERY_GOLDEN_DIR`, optional
//! `DECOVERY_TOOLCHAIN_AZTEC42`, `DECOVERY_AZTEC_RUNNER`). A source belongs to the overlay of its stem
//! (`vpcmk.c` -> `VPCMK`); main-program sources are skipped here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use decovery_core::{Address, OverlayName, Workspace, read_user_config};
use decovery_diff::{Decoration, Verdict, compare_overlay_module, compare_with_gaps};
use decovery_loaders::read_overlay;
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

#[test]
#[ignore = "local: third target + Aztec C86 4.2b"]
fn aztec_overlay_local() {
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
    let _ = &program_file;
    // overlay name → file
    let overlay_files: BTreeMap<String, String> = config["overlay"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            (
                o["name"].as_str().unwrap().to_string(),
                o["datei"].as_str().unwrap().to_string(),
            )
        })
        .collect();

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
        let stem = file
            .file
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let Some(path) = overlay_files.get(&stem) else {
            continue; // main-program source (aztec_verdicts_local)
        };
        let overlay = read_overlay(&std::fs::read(path).unwrap(), &stem).unwrap();
        let corg = overlay.header.corg;
        let overlay_name = OverlayName::new(&stem).unwrap();
        // C name → address of this overlay in the baseline
        let prefix = format!("ovl:{stem}:");
        let here: BTreeMap<&str, &str> = names
            .iter()
            .filter(|(a, _)| a.starts_with(&prefix))
            .map(|(a, n)| (n.as_str().unwrap(), a.as_str()))
            .collect();
        let read = read_aztec(object, &file.file).unwrap();
        for module in &read.modules {
            for f in functions(module) {
                let name = decoration.undecorate(f.name);
                // Decomp names a C name every overlay defines (`ovmain`) `<OVERLAY>_<name>` in its knowledge
                let Some(&address) = here
                    .get(name)
                    .or_else(|| here.get(format!("{stem}_{name}").as_str()))
                else {
                    println!("  {stem}: {name} not in the baseline");
                    continue;
                };
                let Ok(Address::Ovl { seg, off, .. }) = address.parse::<Address>() else {
                    panic!("{address}");
                };
                let original = overlay
                    .code
                    .get(usize::from(off.wrapping_sub(corg))..)
                    .unwrap_or(&[]);
                let at = Address::Ovl {
                    overlay: overlay_name,
                    seg,
                    off,
                };
                let c = compare_with_gaps(&f, original, at);
                let word = match c.verdict {
                    Verdict::Identical => "identisch",
                    Verdict::Differs => "abweichend",
                    _ => "fehler",
                };
                if word != "identisch" {
                    println!("  {address} {name}: {word}; {:?}", c.blockers);
                }
                ours.insert(address.to_string(), word);
            }
        }
        let v = compare_overlay_module(&[&read], &overlay);
        println!(
            "{stem} module: identical {}; code {}/{} bytes (equal {}, differing {}, gaps {}), refs ok {} wrong {} \
             unchecked {}; data {}/{} bytes, {} differing (first {:?}); BSS {:#x}/{:#x}; {} externals; \
             ambiguous {:?}; blockers {:?}",
            v.identical,
            v.code_size.1,
            v.code_size.0,
            v.code.metrics.equal,
            v.code.metrics.differing,
            v.code.metrics.gaps,
            v.code.metrics.refs_ok,
            v.code.metrics.refs_wrong,
            v.code.metrics.refs_unchecked,
            v.data_size.1,
            v.data_size.0,
            v.data_diffs.len(),
            v.data_diffs.iter().take(8).collect::<Vec<_>>(),
            v.bss.1,
            v.bss.0,
            v.externals.len(),
            v.ambiguous.iter().take(5).collect::<Vec<_>>(),
            v.code.blockers.iter().take(8).collect::<Vec<_>>()
        );
    }

    // per overlay: verdicts against the baseline
    let mut disagreements = Vec::new();
    let mut table: BTreeMap<String, [usize; 6]> = BTreeMap::new();
    for (address, verdict) in verdicts.iter().filter(|(a, _)| a.starts_with("ovl:")) {
        let stem = address.split(':').nth(1).unwrap_or_default().to_string();
        let decomp_word = verdict.as_str().unwrap();
        let our = ours.get(address).copied().unwrap_or("nicht-versucht");
        let row = table.entry(stem).or_default();
        row[0] += 1;
        row[1] += usize::from(decomp_word == "identisch");
        row[2] += usize::from(our == "identisch");
        row[3] += usize::from(our == "abweichend");
        row[4] += usize::from(our == "nicht-versucht");
        if our == decomp_word {
            row[5] += 1;
        } else {
            disagreements.push(format!(
                "{address} {}: decovery {our}, Decomp {decomp_word}",
                names.get(address).and_then(|n| n.as_str()).unwrap_or("?")
            ));
        }
    }
    println!("overlay  functions  decomp-identical  identical  differ  not-tried  equal-verdicts");
    for (stem, r) in &table {
        println!(
            "{stem:8} {:9} {:17} {:10} {:7} {:10} {:15}",
            r[0], r[1], r[2], r[3], r[4], r[5]
        );
    }
    println!("{} disagreements", disagreements.len());
    for d in &disagreements {
        println!("  {d}");
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}
