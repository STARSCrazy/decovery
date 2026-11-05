//! `analyze` with the real Ghidra plugin against a migrated private Decomp workspace. Run with
//! `cargo test -p decovery-facade --test analyze_local -- --ignored`; needs `DECOVERY_LOCAL_WORKSPACE`,
//! `GHIDRA_INSTALL_DIR` (environment or the plugin config's env) and either a `[plugins.ghidra]` user config
//! (`decovery setup ghidra`) or `DECOVERY_PYTHON` (a Python with pyghidra); fails when they are missing. Body differences go to `$DECOVERY_GOLDEN_DIR/analyze-phase-1.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use decovery_core::{Address, Analysis, migrate_decomp};
use decovery_facade::plugins::{PluginConfig, user_plugins};
use decovery_facade::{AnalyzeOptions, Progress, analyze_with_user_plugins};

const SAMPLE: usize = 50;
const FAILED_DE: &str = "/* Dekompilieren fehlgeschlagen: ";
const FAILED_EN: &str = "/* decompilation failed: ";

/// The Ghidra plugin: the user config entry, else `DECOVERY_PYTHON -m decovery_ghidra` from this repository.
fn ghidra_plugin() -> Option<PluginConfig> {
    if let Some(config) = user_plugins().remove("ghidra") {
        return Some(config);
    }
    let python = std::env::var("DECOVERY_PYTHON").ok()?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let paths = [
        repo.join("plugins/ghidra"),
        repo.join("plugins/decovery-plugin-sdk"),
    ];
    let python_path = std::env::join_paths(paths).ok()?;
    let mut config = PluginConfig::new(vec![python, "-m".into(), "decovery_ghidra".into()]);
    config.env.insert(
        "PYTHONPATH".into(),
        python_path.to_string_lossy().into_owned(),
    );
    Some(config)
}

fn sets(a: &Analysis, f: Address) -> (BTreeSet<Address>, BTreeSet<Address>) {
    let index = a.index();
    let callers = index.callers(f).iter().map(|e| e.caller).collect();
    let callees = index.callees(f).iter().map(|e| e.callee).collect();
    (callers, callees)
}

fn english(body: &str) -> String {
    match body.strip_prefix(FAILED_DE) {
        Some(rest) => format!(
            "{FAILED_EN}{}",
            rest.replacen("(nicht verfügbar)", "(not available)", 1)
        ),
        None => body.to_string(),
    }
}

#[test]
#[ignore = "local: private Decomp workspace + Ghidra"]
fn ghidra_bodies_match_decomp() {
    let from = PathBuf::from(
        std::env::var_os("DECOVERY_LOCAL_WORKSPACE").expect("DECOVERY_LOCAL_WORKSPACE is not set"),
    );
    // Explicitly requested run: missing prerequisites fail instead of passing silently (R28).
    let plugin = ghidra_plugin().expect(
        "no Ghidra plugin configured: run `decovery setup ghidra` or set DECOVERY_PYTHON (a Python with pyghidra)",
    );
    assert!(
        std::env::var_os("GHIDRA_INSTALL_DIR").is_some()
            || plugin.env.contains_key("GHIDRA_INSTALL_DIR"),
        "GHIDRA_INSTALL_DIR is set neither in the environment nor in the plugin config's env"
    );
    let to = tempfile::tempdir().unwrap();
    let root = to.path();
    migrate_decomp(&from, root).unwrap();

    // The imported analysis, kept aside.
    let imported = Analysis::load(root)
        .unwrap()
        .expect("migrate imports an analysis");
    let mut sample: Vec<_> = imported.functions.clone();
    sample.sort_by_key(|f| f.start);
    sample.truncate(SAMPLE);
    let mut before = Vec::new();
    for f in &sample {
        let body = Analysis::decompiled(root, f.start).unwrap();
        before.push((f.clone(), sets(&imported, f.start), body));
    }

    let user = BTreeMap::from([("ghidra".to_string(), plugin)]);
    let progress = |p: Progress| {
        eprintln!(
            "{}/{} {}",
            p.done,
            p.total.map_or_else(|| "?".into(), |t| t.to_string()),
            p.message.unwrap_or_default()
        )
    };
    let response =
        analyze_with_user_plugins(root, &AnalyzeOptions::default(), &user, &progress).unwrap();
    eprintln!("{}", response.summary);
    let fresh = Analysis::load(root).unwrap().unwrap();
    let index = fresh.index();

    let mut range_diffs = Vec::new();
    let mut size_diffs = Vec::new();
    let mut call_diffs = Vec::new();
    let mut body_diffs = Vec::new();
    for (old, (callers, callees), body) in &before {
        let Some(new) = index.function_at(old.start) else {
            range_diffs.push(format!("{}: missing", old.start));
            continue;
        };
        if new.end != old.end {
            range_diffs.push(format!("{}: end {} vs {}", old.start, new.end, old.end));
        }
        if new.body_size != old.body_size {
            size_diffs.push(format!(
                "{}: body size {} vs {}",
                old.start, new.body_size, old.body_size
            ));
        }
        if sets(&fresh, old.start) != (callers.clone(), callees.clone()) {
            call_diffs.push(format!("{}: callers/callees differ", old.start));
        }
        let new_body = Analysis::decompiled(root, old.start).unwrap();
        let old_body = body.as_deref().map(english);
        if new_body != old_body {
            body_diffs.push((old.start, old_body, new_body));
        }
    }

    let mut report = format!(
        "# analyze phase 1: Ghidra bodies vs Decomp\n\nSample: first {} functions. Body differences: {}. \
         Body size differences: {}.\n",
        before.len(),
        body_diffs.len(),
        size_diffs.len()
    );
    for line in &size_diffs {
        report.push_str(&format!("\n- {line}"));
    }
    for (at, old, new) in &body_diffs {
        report.push_str(&format!(
            "\n\n## {at}\n\n### Decomp\n\n```c\n{}\n```\n\n### decovery\n\n```c\n{}\n```\n",
            old.as_deref().unwrap_or("(none)"),
            new.as_deref().unwrap_or("(none)")
        ));
    }
    let golden =
        std::env::var_os("DECOVERY_GOLDEN_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let path = golden.join("analyze-phase-1.md");
    std::fs::write(&path, report).unwrap();
    eprintln!(
        "{} body differences, {} body size differences; report: {}",
        body_diffs.len(),
        size_diffs.len(),
        path.display()
    );
    assert!(range_diffs.is_empty(), "ranges differ: {range_diffs:#?}");
    assert!(call_diffs.is_empty(), "call sets differ: {call_diffs:#?}");
}
