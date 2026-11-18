//! Risk checkpoint R1 of phase 4: the Aztec C86 4.2b compiler chain (`CC` → pass 1 → `CGEN` → `AS`, each pass
//! loaded in place by the one before) runs in a runner with the profile's `SET CLIB/INCLUDE/PATH` prelude and
//! writes an object. Run with
//! `cargo test -j 2 -p decovery-toolchain --test aztec_compile_local -- --ignored --nocapture --test-threads 1` and
//!
//! - `DECOVERY_LOCAL_WORKSPACE_AZTEC=<Decomp workspace of the third target>` (its `nachbau/*.c` and the flags of
//!   its `[nachbau]` table are read, nothing is written there);
//! - optional `DECOVERY_TOOLCHAIN_AZTEC42=<Aztec C86 4.2b directory>` (else the user config's toolchain entry);
//! - optional `DECOVERY_AZTEC_RUNNER=<runner id>` (default `dosbox-lab`);
//! - optional `DECOVERY_GOLDEN_DIR=<private dir>`: when `aztec/objects/<NAME>.O` exists there (an object Decomp
//!   compiled from the same source and flags), the object must equal it byte for byte.
//!
//! The three smallest sources are compiled into a temporary workspace (object cache off: a fresh directory). Until
//! the Aztec object reader exists (phase 4, Task 2) an object counts when it was written, is not empty and starts
//! with an Aztec object magic.

use std::path::{Path, PathBuf};
use std::time::Instant;

use decovery_core::{Workspace, read_user_config};
use decovery_toolchain::{SourceJob, compile, find_sources, open_runners, profile, stage};

const PROFILE: &str = "aztec-c86-4.2b";
/// The two magics an Aztec C86 object starts with (little-endian words).
const OBJECT_MAGICS: [[u8; 2]; 2] = [[0x66, 0x54], [0x0C, 0x02]];

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("set {name}")))
}

/// The global flags and the per-file flags of the Decomp workspace's `[nachbau]` table.
fn flags(decomp: &Path) -> (String, toml::Table) {
    let text = std::fs::read_to_string(decomp.join("decomp.toml")).unwrap();
    let config: toml::Table = text.parse().unwrap();
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
    (global, per_file)
}

#[test]
#[ignore = "local: third target + Aztec C86 4.2b"]
fn aztec_compile_local() {
    let decomp = env_path("DECOVERY_LOCAL_WORKSPACE_AZTEC");
    let runner = std::env::var("DECOVERY_AZTEC_RUNNER").unwrap_or_else(|_| "dosbox-lab".into());
    let (global, per_file) = flags(&decomp);

    let mut sources: Vec<(u64, PathBuf)> = std::fs::read_dir(decomp.join("nachbau"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("c")))
        .map(|p| (std::fs::metadata(&p).unwrap().len(), p))
        .collect();
    sources.sort();
    sources.truncate(3);
    assert!(!sources.is_empty(), "no C sources in {}", decomp.display());

    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for (_, path) in &sources {
        std::fs::copy(path, src.join(path.file_name().unwrap())).unwrap();
    }
    let mut config = format!(
        "schema = 1\n\n[target]\nfile = \"t.exe\"\nsha256 = \"aa\"\nformat = \"mz\"\nprocessor = \"x86\"\n\n\
         [rebuild]\ncompiler = \"{PROFILE}\"\nrunners = [{}]\n",
        toml::Value::String(runner.clone())
    );
    if let Ok(dir) = std::env::var("DECOVERY_TOOLCHAIN_AZTEC42") {
        config.push_str(&format!("tool_dir = {}\n", toml::Value::String(dir)));
    }
    std::fs::write(root.path().join("decovery.toml"), config).unwrap();
    let ws = Workspace::open(root.path()).unwrap();

    let profile = profile(PROFILE).unwrap();
    let build = root.path().join("build");
    std::fs::create_dir(&build).unwrap();
    let names = stage(&find_sources(&src, &[]).unwrap(), &build).unwrap();
    let jobs: Vec<SourceJob> = names
        .iter()
        .map(|name| {
            let lower = name.to_lowercase();
            let flags = per_file
                .get(&lower)
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
    let wall = started.elapsed();
    println!(
        "{runner}: {} sources in {} ms wall; warnings {warnings:?}",
        files.len(),
        wall.as_millis()
    );
    let golden = std::env::var("DECOVERY_GOLDEN_DIR")
        .ok()
        .map(|d| Path::new(&d).join("aztec/objects"));
    for (file, job) in files.iter().zip(&jobs) {
        let object = file.object.as_deref().unwrap_or_else(|| {
            panic!(
                "{} ({}) not compiled: {}",
                file.file, job.flags, file.message
            )
        });
        println!(
            "  {} ({}): {} bytes, {:?}",
            file.file,
            job.flags,
            object.len(),
            file.times
        );
        assert!(
            object.len() >= 2 && OBJECT_MAGICS.iter().any(|m| object[..2] == m[..]),
            "{}: not an Aztec object",
            file.file
        );
        let reference = golden
            .as_ref()
            .map(|dir| dir.join(profile.object_name(&file.file)))
            .filter(|p| p.is_file());
        if let Some(reference) = reference {
            assert_eq!(
                object,
                std::fs::read(&reference).unwrap(),
                "{} differs from {}",
                file.file,
                reference.display()
            );
        }
    }
}
