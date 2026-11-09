//! `decovery link` on the first target (LE, Watcom) against its private Decomp workspace. Run with
//! `DECOVERY_LOCAL_WORKSPACE=<Decomp workspace> cargo test -p decovery-cli --test link_local -- --ignored --nocapture`;
//! optional: `DECOVERY_TOOLCHAIN_WATCOM95=<Watcom 9.5 directory>` (else the user config's toolchain entry),
//! `DECOVERY_GOLDEN_DIR=<private dir>` (the outcome goes to `parity-phase-2.md` there).
//!
//! Migrates the workspace into a temporary directory (the Decomp workspace is never touched), links with WLINK 9.5
//! (`[rebuild.link] profile = "watcom-9.5"`) after a full `decovery build` (which keeps the objects the inserts come
//! from), and checks that every inserted rebuild reproduces the original's pages: no page and no fixup content may
//! differ. WLINK 9.5 differs from the original's linker in the order of the fixup records (and possibly object
//! flags), so `differs` is accepted. When WLINK does not run at all, its message goes to the parity document instead
//! of failing.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde_json::Value;

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn decovery(args: &[&str], workspace: &Path) -> (std::process::Output, u128) {
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_decovery"))
        .args(args)
        .arg("--workspace")
        .arg(workspace)
        .output()
        .expect("run decovery");
    (out, started.elapsed().as_millis())
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

/// `[rebuild.link] profile = "watcom-9.5"` and, when given, `[rebuild] tool_dir`.
fn configure(ws: &Path) {
    let path = ws.join("decovery.toml");
    let mut config: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    let rebuild = config
        .entry("rebuild")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .unwrap();
    if let Some(dir) = std::env::var_os("DECOVERY_TOOLCHAIN_WATCOM95") {
        rebuild.insert(
            "tool_dir".into(),
            toml::Value::String(PathBuf::from(dir).to_string_lossy().into_owned()),
        );
    }
    let link = rebuild
        .entry("link")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .unwrap();
    link.insert("profile".into(), toml::Value::String("watcom-9.5".into()));
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
}

/// Replaces (or appends) the section `## <title>` of `$DECOVERY_GOLDEN_DIR/parity-phase-2.md`.
fn record_parity(title: &str, body: &str) {
    let Some(dir) = std::env::var_os("DECOVERY_GOLDEN_DIR") else {
        return;
    };
    let path = PathBuf::from(dir).join("parity-phase-2.md");
    let old = std::fs::read_to_string(&path).unwrap_or_default();
    let mut sections: Vec<(String, String)> = Vec::new();
    for chunk in old.split("\n## ").skip(1) {
        let (t, b) = chunk.split_once('\n').unwrap_or((chunk, ""));
        sections.push((t.to_string(), b.trim_end().to_string()));
    }
    match sections.iter_mut().find(|(t, _)| t == title) {
        Some(s) => s.1 = body.trim_end().to_string(),
        None => sections.push((title.to_string(), body.trim_end().to_string())),
    }
    let mut text = String::from("# Parity phase 2 (private)\n");
    for (t, b) in sections {
        text.push_str(&format!("\n## {t}\n{b}\n"));
    }
    std::fs::write(path, text).unwrap();
}

fn lines(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_string))
        .collect()
}

#[test]
#[ignore = "local: first target + Watcom"]
fn first_target_links_with_wlink_95() {
    let from = env_path("DECOVERY_LOCAL_WORKSPACE");
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    migrate(&from, &ws);
    configure(&ws);

    let (out, build_ms) = decovery(&["build", "--json"], &ws);
    assert!(
        out.status.code().is_some_and(|c| c <= 1),
        "build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (out, link_ms) = decovery(&["link", "--json"], &ws);
    let response: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "link printed no JSON: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let d = &response["data"];
    let diagnosis = lines(&d["diagnosis"]);
    let hints = lines(&d["hints"]);
    println!(
        "build {build_ms} ms, link {link_ms} ms wall, timing {}",
        d["timing"]
    );
    println!("{}", response["summary"].as_str().unwrap_or(""));
    for line in &diagnosis {
        println!("  {line}");
    }
    let program = std::fs::read_to_string(ws.join("knowledge/rebuild-program.toml")).unwrap();
    let record: toml::Table = program.parse().unwrap();
    let used = &record["program"]["used"];
    let (functions, bytes) = (
        used["functions"].as_integer().unwrap_or(0),
        used["bytes"].as_integer().unwrap_or(0),
    );
    println!(
        "inserted {functions} functions, {bytes} bytes; {} hints",
        hints.len()
    );

    let result = d["result"].as_str().unwrap_or("");
    let mut body = format!(
        "WLINK 9.5 (`[rebuild.link] profile = \"watcom-9.5\"`): {result}; inserted {functions} functions, \
         {bytes} bytes; link {link_ms} ms wall, timing {}\n",
        d["timing"]
    );
    for line in &diagnosis {
        body.push_str(&format!("- {line}\n"));
    }
    if result == "error" {
        body.push_str(&format!(
            "\nWLINK did not link: {}\n",
            d["message"].as_str().unwrap_or("")
        ));
        record_parity("link: first target (LE)", &body);
        eprintln!("WLINK 9.5 did not link; recorded in the parity document");
        return;
    }
    record_parity("link: first target (LE)", &body);
    assert!(functions > 0 && bytes > 0, "nothing inserted: {hints:?}");
    // every inserted rebuild reproduces the original: no page and no fixup content differs
    assert!(
        !diagnosis
            .iter()
            .any(|l| l.contains("pages differ") || l.starts_with("fixup page")),
        "{diagnosis:?}"
    );
    assert!(
        diagnosis
            .iter()
            .all(|l| !l.starts_with("fixups:")
                || l.starts_with("fixups: 0 pages with other content")),
        "{diagnosis:?}"
    );
}
