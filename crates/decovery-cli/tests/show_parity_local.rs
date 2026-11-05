//! Phase-1 parity of `decovery show` against Decomp's `zeige` on a private Decomp workspace. Run with
//! `DECOVERY_LOCAL_WORKSPACE=<Decomp workspace> DECOVERY_GOLDEN_DIR=<private dir>
//! cargo test -p decovery-cli --test show_parity_local -- --ignored`.
//!
//! Migrates the workspace with the binary, then runs `decovery show <start>` for every function file below
//! Decomp's `ausgabe/funktionen/` and compares the text exactly (body included) with Decomp's file after the
//! fixed German-to-English mapping shared with decovery-facade's `output_local` test. Mismatches are written
//! by header key to `$DECOVERY_GOLDEN_DIR/parity-phase-1.md` (one section per workspace; names functions,
//! stays private).

#[path = "../../decovery-facade/tests/support/decomp_mapping.rs"]
mod decomp_mapping;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use decomp_mapping::{EXCLUDED_KEYS, decomp_files, expected, first_difference, read_decomp};
use decovery_core::{Address, ClaimSource, Confidence, Symbol, SymbolKind, Workspace};

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn decovery(args: &[&str], workspace: Option<&Path>) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_decovery"));
    cmd.args(args);
    if let Some(ws) = workspace {
        cmd.arg("--workspace").arg(ws);
    }
    cmd.output().expect("run decovery")
}

fn migrate(from: &Path, to: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .arg("migrate")
        .arg(from)
        .arg(to)
        .output()
        .expect("run decovery migrate");
    assert!(
        out.status.success(),
        "migrate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `decovery show <at>` as text; `Err` with stderr on failure.
fn show(workspace: &Path, at: Address) -> Result<String, String> {
    let out = decovery(&["show", &at.to_string()], Some(workspace));
    if out.status.success() {
        String::from_utf8(out.stdout).map_err(|e| e.to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

struct Mismatch {
    at: Address,
    key: String,
    line: usize,
    decomp: String,
    decovery: String,
}

/// Replaces (or appends) the section `## <title>` in `path`.
fn write_section(path: &Path, title: &str, body: &str) {
    let old = std::fs::read_to_string(path).unwrap_or_default();
    let mut sections: Vec<(String, String)> = Vec::new();
    for chunk in old.split("\n## ").skip(1) {
        let (t, b) = chunk.split_once('\n').unwrap_or((chunk, ""));
        sections.push((t.to_string(), b.trim_end().to_string()));
    }
    match sections.iter_mut().find(|(t, _)| t == title) {
        Some(s) => s.1 = body.trim_end().to_string(),
        None => sections.push((title.to_string(), body.trim_end().to_string())),
    }
    let mut text = String::from(
        "# Phase-1 parity of `decovery show` against Decomp (private)\n\n\
         Written by `show_parity_local::show_equals_zeige_for_all_functions`.\n",
    );
    for (t, b) in &sections {
        let _ = write!(text, "\n## {t}\n{b}\n");
    }
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
#[ignore = "local: private Decomp workspace"]
fn show_equals_zeige_for_all_functions() {
    let from = env_path("DECOVERY_LOCAL_WORKSPACE");
    let golden = env_path("DECOVERY_GOLDEN_DIR");
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    migrate(&from, &ws);

    let files = decomp_files(&from);
    assert!(!files.is_empty(), "no Decomp function files found");
    let mismatches = Mutex::new(Vec::<Mismatch>::new());
    let next = Mutex::new(files.iter());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let Some((at, path)) = next.lock().unwrap().next() else {
                        break;
                    };
                    let want = expected(&read_decomp(path));
                    let got = show(&ws, *at).unwrap_or_else(|e| format!("<error: {e}>\n"));
                    if let Some((key, line, decomp, decovery)) = first_difference(&want, &got) {
                        mismatches.lock().unwrap().push(Mismatch {
                            at: *at,
                            key,
                            line,
                            decomp,
                            decovery,
                        });
                    }
                }
            });
        }
    });
    let mut mismatches = mismatches.into_inner().unwrap();
    mismatches.sort_by_key(|m| m.at);

    let mut by_key: BTreeMap<&str, Vec<&Mismatch>> = BTreeMap::new();
    for m in &mismatches {
        by_key.entry(&m.key).or_default().push(m);
    }
    let title = from.file_name().map_or_else(
        || from.display().to_string(),
        |n| n.to_string_lossy().into(),
    );
    let mut body = format!(
        "\nDecomp workspace `{}`: {} functions, {} equal, {} differ. Excluded keys: {}.\n",
        from.display(),
        files.len(),
        files.len() - mismatches.len(),
        mismatches.len(),
        EXCLUDED_KEYS.join(", ")
    );
    for (key, list) in &by_key {
        let _ = write!(body, "\n### {key} ({})\n\n", list.len());
        for m in list {
            let _ = write!(
                body,
                "- {} line {}\n  - decomp:   `{}`\n  - decovery: `{}`\n",
                m.at, m.line, m.decomp, m.decovery
            );
        }
    }
    write_section(&golden.join("parity-phase-1.md"), &title, &body);

    let counts: Vec<String> = by_key
        .iter()
        .map(|(k, v)| format!("{k} {}", v.len()))
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} functions differ (by key: {}); details in {}",
        mismatches.len(),
        files.len(),
        counts.join(", "),
        golden.join("parity-phase-1.md").display()
    );
}

/// The active record of `at` (named first), as `annotate` picks it.
fn record(ws: &Workspace, at: Address) -> &Symbol {
    ws.symbols
        .iter()
        .filter(|s| s.address == at)
        .min_by_key(|s| (s.confidence == Confidence::Refuted, s.name.is_empty()))
        .expect("record")
}

fn annotate(workspace: &Path, at: Address, flag: &str, value: &str) {
    let out = decovery(
        &[
            "annotate",
            &at.to_string(),
            flag,
            value,
            "--source",
            "human",
        ],
        Some(workspace),
    );
    assert!(
        out.status.success(),
        "annotate {at} {flag} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "local: private Decomp workspace"]
fn knowledge_round_trips() {
    let from = env_path("DECOVERY_LOCAL_WORKSPACE");
    let to = tempfile::tempdir().unwrap();
    let root = to.path().join("ws");
    migrate(&from, &root);

    let before = Workspace::open(&root).unwrap();
    // A human claim outranks every other source, so no target carries a human record. The refutation needs
    // an active name; name, comment and signature go to the first other function starts, named or not.
    let records = |at: Address| before.symbols.iter().filter(move |s| s.address == at);
    let starts: Vec<Address> = decomp_files(&from)
        .into_iter()
        .map(|(at, _)| at)
        .filter(|&at| records(at).all(|s| s.source != ClaimSource::Human))
        .collect();
    let refuted = *starts
        .iter()
        .find(|&&at| {
            records(at).count() == 1
                && records(at).all(|s| {
                    s.kind == SymbolKind::Function
                        && !s.name.is_empty()
                        && s.confidence != Confidence::Refuted
                })
        })
        .expect("a function named by a non-human source");
    let others: Vec<Address> = starts
        .iter()
        .copied()
        .filter(|&at| at != refuted)
        .take(3)
        .collect();
    assert_eq!(
        others.len(),
        3,
        "fewer than four functions without a human record"
    );
    let [named, commented, signed] = [others[0], others[1], others[2]];
    let display_name = |ws: &Workspace, at: Address| {
        ws.symbols
            .iter()
            .filter(|s| s.address == at && s.confidence != Confidence::Refuted)
            .map(|s| s.name.clone())
            .find(|n| !n.is_empty())
            .unwrap_or_default()
    };
    let old_name = display_name(&before, refuted);

    let new_name = "parity_round_trip_name";
    let comment = "Parity round trip: comment written through the CLI.";
    let signature = "int __cdecl parity_round_trip(int value)";
    let reason = "parity round trip: the name does not hold";
    annotate(&root, named, "--name", new_name);
    annotate(&root, commented, "--comment", comment);
    annotate(&root, signed, "--signature", signature);
    annotate(&root, refuted, "--refute", reason);

    let after = Workspace::open(&root).unwrap();
    let s = record(&after, named);
    assert_eq!(s.name, new_name);
    assert_eq!(
        (s.source, s.confidence),
        (ClaimSource::Human, Confidence::Assumed)
    );
    let s = record(&after, commented);
    assert_eq!(s.comment.as_deref(), Some(comment));
    assert_eq!(
        display_name(&after, commented),
        display_name(&before, commented)
    );
    let s = record(&after, signed);
    assert_eq!(s.signature.as_deref(), Some(signature));
    assert_eq!(display_name(&after, signed), display_name(&before, signed));
    let s = record(&after, refuted);
    assert_eq!(s.confidence, Confidence::Refuted);
    let last = s.refuted.last().expect("refutation history");
    assert_eq!(last.name, old_name);
    assert_eq!(last.evidence.as_deref(), Some(reason));

    // nothing else changed
    let touched = [named, commented, signed, refuted];
    let rest = |ws: &Workspace| -> Vec<Symbol> {
        ws.symbols
            .iter()
            .filter(|s| !touched.contains(&s.address))
            .cloned()
            .collect()
    };
    assert_eq!(rest(&after), rest(&before));

    // a second save writes the same bytes
    let path = root.join("knowledge").join("symbols.toml");
    let bytes = std::fs::read(&path).unwrap();
    let lock = after.lock(Duration::from_secs(10)).unwrap();
    after.save_symbols(&lock).unwrap();
    drop(lock);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);

    // and `show` reflects the new state
    let text = show(&root, named).unwrap();
    assert!(text.contains(&format!("@name       {new_name}  [human, assumed]")));
}
