//! Smoke suite of `decovery bench run` over the two local targets with the fake driver (no model cost). Run with
//! `cargo test -j 2 -p decovery-cli --test bench_local -- --ignored --nocapture` and
//!
//! - first target: `DECOVERY_LOCAL_WORKSPACE=<Decomp workspace>`, optional `DECOVERY_TOOLCHAIN_WATCOM95`;
//! - second target: `DECOVERY_LOCAL_WORKSPACE_MZ=<Decomp workspace>`, `DECOVERY_TARGET_MZ=<the original program>`,
//!   optional `DECOVERY_TOOLCHAIN_TC20`;
//! - optional `DECOVERY_PYTHON` (else `python` on the path) runs the fake driver of `decovery-bench`.
//!
//! The Decomp workspaces are only read: each is copied into a temporary directory (of its top-level `cache/` only
//! `cache/nachbau/`), migrated and built there. Three tasks of the migrated workspaces (two of the first target at
//! the first and third quartile of the rebuild record sizes, one of the second at the median; assembler sources
//! never) are copied with `prepare_copy`; every pristine copy must hold no trace of its function's definition,
//! compiled object or code hash (Review Focus 1). Then the fake driver runs the three tasks: an idle one (the
//! start distance), one that submits the definition through MCP (decovery's verdict must say identical) and one
//! that exceeds its tool-call limit. Names of functions are never printed or written anywhere.

#[path = "support/local.rs"]
mod local;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use decovery_bench::{
    DriverConfig, RunOptions, RunRecord, StartPoint, SuiteTask, ToolSet, prepare_copy, read_suite,
    run_suite,
};
use decovery_core::{RebuildRecord, VerdictId, read_rebuild};
use decovery_toolchain::from_cp437;
use local::{decovery, edit_config, env_path, migrate, response, set_tool_dir, table};
use serde_json::json;

fn quote(path: &Path) -> String {
    toml::Value::String(path.to_string_lossy().into_owned()).to_string()
}

fn python() -> String {
    let candidate = std::env::var("DECOVERY_PYTHON").unwrap_or_else(|_| "python".into());
    let ok = std::process::Command::new(&candidate)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(ok, "no Python: set DECOVERY_PYTHON or put `python` on PATH");
    candidate
}

/// Copies a Decomp workspace; of its top-level `cache/` only `cache/nachbau/` (what `migrate` reads).
fn copy_decomp(from: &Path, to: &Path, top: bool) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let target = to.join(entry.file_name());
        if kind.is_dir() && top && entry.file_name() == "cache" {
            let nachbau = entry.path().join("nachbau");
            if nachbau.is_dir() {
                copy_decomp(&nachbau, &target.join("nachbau"), false);
            }
        } else if kind.is_dir() {
            copy_decomp(&entry.path(), &target, false);
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Migrates and builds a copy of the Decomp workspace in `scratch`; returns the decovery workspace.
fn prepare_workspace(
    scratch: &Path,
    name: &str,
    source: &Path,
    tool_var: &str,
    target_var: Option<&str>,
    link_first: bool,
) -> PathBuf {
    let ws = scratch.join(format!("{name}-ws"));
    let ready = scratch.join(format!("{name}.ready"));
    if ready.exists() {
        println!("{name}: reusing the prepared workspace");
        return ws;
    }
    let decomp = scratch.join(format!("{name}-decomp"));
    copy_decomp(source, &decomp, true);
    migrate(&decomp, &ws);
    edit_config(&ws, |config| {
        set_tool_dir(config, tool_var);
        if let Some(var) = target_var {
            table(config, "target").insert(
                "file".into(),
                toml::Value::String(env_path(var).to_string_lossy().into_owned()),
            );
        }
    });
    if link_first {
        let (out, _) = decovery(&["link", "--json"], &ws);
        assert_eq!(response(&out, "link")["data"]["result"], "identical");
    }
    let (out, ms) = decovery(&["build", "--json"], &ws);
    assert!(
        out.status.code().is_some_and(|c| c <= 1),
        "build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "{name}: {}; {ms} ms wall",
        response(&out, "build")["summary"].as_str().unwrap_or("")
    );
    std::fs::remove_dir_all(&decomp).unwrap();
    std::fs::write(ready, "").unwrap();
    ws
}

/// Candidate functions of a workspace: native identical records of non-assembler files, smallest first.
fn candidates(ws: &Path) -> Vec<RebuildRecord> {
    let mut records: Vec<RebuildRecord> = read_rebuild(ws)
        .unwrap()
        .into_iter()
        .filter(|r| r.verdict == Some(VerdictId::Identical))
        .filter(|r| {
            r.file.as_deref().is_some_and(|f| {
                let f = f.to_ascii_lowercase();
                !f.ends_with(".asm") && !f.ends_with(".s")
            })
        })
        .collect();
    records.sort_by_key(|r| (r.bytes, r.address.to_string()));
    records
}

struct Picked {
    task: SuiteTask,
}

/// The first candidate at or after quantile `q` (per mille) whose pristine copy can be made.
fn pick(ws: &Path, q: usize, taken: &BTreeSet<String>, scratch: &Path) -> Picked {
    let all = candidates(ws);
    assert!(!all.is_empty(), "no identical record to pick from");
    let start = q * (all.len() - 1) / 1000;
    let mut skipped = 0;
    let mut last = String::new();
    for offset in 0..all.len() {
        let record = &all[(start + offset) % all.len()];
        if record.bytes == 0 || taken.contains(&record.name) {
            continue;
        }
        let mut task = SuiteTask::new(ws.to_path_buf(), record.name.clone());
        task.id = format!("task-{}", taken.len());
        let probe = scratch.join(format!("probe-{}-{offset}/ws", task.id));
        match prepare_copy(&task, StartPoint::Stub, ToolSet::Core, &probe) {
            Ok(_) => {
                println!(
                    "picked a function of {} bytes ({skipped} skipped)",
                    record.bytes
                );
                return Picked { task };
            }
            Err(error) => {
                skipped += 1;
                last = error.to_string();
            }
        }
    }
    panic!("no function of the workspace can be copied; last error: {last}");
}

/// Every file below `root`, following links (cycles are an error).
fn files(root: &Path, seen: &mut Vec<PathBuf>) -> Vec<PathBuf> {
    let canonical = root.canonicalize().unwrap();
    assert!(!seen.contains(&canonical), "linked directory cycle");
    seen.push(canonical);
    let mut result = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            result.extend(files(&path, seen));
        } else {
            result.push(path);
        }
    }
    seen.pop();
    result
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// What must not occur in a copy: the definition (whitespace-normalised, as UTF-8 and as CP437), the code hash of
/// its rebuild record and the kept object of its file.
struct Secrets {
    address: String,
    definition: String,
    hash: Option<String>,
    object: Option<Vec<u8>>,
}

fn secrets(ws: &Path, task: &SuiteTask, solution: &str) -> Secrets {
    let record = read_rebuild(ws)
        .unwrap()
        .into_iter()
        .find(|r| r.name == task.function)
        .unwrap();
    let file = record.file.clone().unwrap();
    let stem = Path::new(&file).file_stem().unwrap().to_ascii_lowercase();
    let object = files(&ws.join("cache/rebuild/obj"), &mut Vec::new())
        .into_iter()
        .filter(|p| {
            p.extension().is_some_and(|e| e.eq_ignore_ascii_case("obj"))
                && p.file_stem().unwrap().to_ascii_lowercase() == stem
        })
        .map(|p| std::fs::read(p).unwrap())
        .next();
    Secrets {
        address: record.address.to_string(),
        definition: compact(solution),
        hash: record.code_hash.filter(|h| !h.is_empty()),
        object: object.filter(|o| !o.is_empty()),
    }
}

/// Review Focus 1: returns the number of files and bytes scanned.
/// `pristine` is a copy straight from `prepare_copy`; after a run the harness's builds have legitimately created
/// `output/`, call logs and so on, so only the content scans and `.git` apply.
fn assert_no_trace(root: &Path, secrets: &Secrets, pristine: bool) -> (usize, u64) {
    assert!(!secrets.definition.is_empty());
    let (mut count, mut total) = (0, 0);
    for path in files(root, &mut Vec::new()) {
        let bytes = std::fs::read(&path).unwrap();
        count += 1;
        total += bytes.len() as u64;
        assert!(
            !compact(&String::from_utf8_lossy(&bytes)).contains(&secrets.definition),
            "definition leaked through {}",
            path.display()
        );
        assert!(
            !compact(&from_cp437(&bytes)).contains(&secrets.definition),
            "definition (CP437) leaked through {}",
            path.display()
        );
        // The analysis exports describe the original program (the function's own bytes included).
        if path.starts_with(root.join("knowledge/analysis")) {
            continue;
        }
        if let Some(hash) = &secrets.hash {
            let text = String::from_utf8_lossy(&bytes);
            for (at, _) in text.match_indices(hash.as_str()) {
                // A twin (another function whose compiled code is byte-identical, built from its own source
                // that stays in the copy) carries the same hash in its own rebuild record: not a leak.
                let owner = text[..at].rfind("address = \"").map(|n| {
                    let rest = &text[n + "address = \"".len()..];
                    rest[..rest.find('"').unwrap_or(0)].to_string()
                });
                let twin = path == root.join("knowledge/rebuild.toml")
                    && owner.as_deref().is_some_and(|o| o != secrets.address);
                assert!(
                    twin,
                    "code hash leaked through {} line {}",
                    path.display(),
                    text[..at].lines().count()
                );
                println!("  (a twin function's record carries the same code hash)");
            }
        }
        if let Some(object) = &secrets.object {
            assert!(
                !bytes.windows(object.len()).any(|w| w == object.as_slice()),
                "object leaked through {}",
                path.display()
            );
        }
    }
    assert!(!root.join(".git").exists(), ".git was copied");
    if pristine {
        for forbidden in [
            "output",
            "cache/handles",
            "cache/rebuild/shrink",
            "cache/rebuild/runs",
            "cache/rebuild/objects",
            "cache/calls",
            "cache/jobs",
            "cache/legacy",
            "cache/exemplars",
        ] {
            assert!(!root.join(forbidden).exists(), "{forbidden} was copied");
        }
    }
    (count, total)
}

fn write_suite(dir: &Path, picked: &[(&Picked, &str)], max_tool_calls: u32) -> PathBuf {
    let tasks: String = picked
        .iter()
        .map(|(p, tag)| {
            format!(
                "[[task]]\nid = {}\nworkspace = {}\nfunction = {}\ntags = [\"{tag}\"]\n",
                toml::Value::String(p.task.id.clone()),
                quote(&p.task.workspace),
                toml::Value::String(p.task.function.clone()),
            )
        })
        .collect();
    let path = dir.join("suite.toml");
    std::fs::write(
        &path,
        format!(
            "schema = 1\nname = \"local-smoke\"\n[defaults]\nmax_builds = 4\nmax_tool_calls = {max_tool_calls}\nwall_minutes = 5\n{tasks}"
        ),
    )
    .unwrap();
    path
}

struct Harness<'a> {
    python: &'a str,
    scratch: &'a Path,
    suite: &'a Path,
}

impl Harness<'_> {
    /// One run of one task with the fake driver in `mode`.
    fn run(&self, id: &str, mode: &str, env: &[(&str, String)], keep: bool) -> RunRecord {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../decovery-bench/tests/fixtures/fake_driver.py")
            .canonicalize()
            .unwrap();
        let mut driver = DriverConfig::default();
        driver.command = vec![
            self.python.into(),
            "-B".into(),
            script.to_string_lossy().into_owned(),
            "--mcp".into(),
            "{mcp_config}".into(),
            "--result".into(),
            "{result}".into(),
            "--workdir".into(),
            "{workdir}".into(),
        ];
        driver.env.insert("FAKE_MODE".into(), mode.into());
        for (k, v) in env {
            driver.env.insert((*k).into(), v.clone());
        }
        let mut options = RunOptions::new("fake", PathBuf::from(env!("CARGO_BIN_EXE_decovery")));
        options.copies_dir = Some(self.scratch.join("copies"));
        options.only = vec![id.to_string()];
        options.seed = 3;
        options.keep = keep;
        let suite = read_suite(self.suite).unwrap();
        let run = run_suite(&suite, &driver, &options, &|_| {}).unwrap();
        assert_eq!(run.tasks.len(), 1);
        run
    }
}

#[test]
#[ignore = "local: bench"]
fn smoke_suite_with_the_fake_driver() {
    let python = python();
    // `DECOVERY_BENCH_SCRATCH=<dir>` keeps the migrated and built workspaces between runs (migrating the first
    // target takes minutes); everything else in it is removed at the start.
    let temporary = tempfile::tempdir().unwrap();
    let scratch = match std::env::var_os("DECOVERY_BENCH_SCRATCH") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            std::fs::create_dir_all(&dir).unwrap();
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                let keep = path.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.ends_with("-ws") || n.ends_with(".ready")
                });
                if !keep {
                    let _ = std::fs::remove_dir_all(&path).or_else(|_| std::fs::remove_file(&path));
                }
            }
            dir
        }
        None => temporary.path().to_path_buf(),
    };
    let scratch = &scratch;
    let first = prepare_workspace(
        scratch,
        "first",
        &env_path("DECOVERY_LOCAL_WORKSPACE"),
        "DECOVERY_TOOLCHAIN_WATCOM95",
        None,
        false,
    );
    let second = prepare_workspace(
        scratch,
        "second",
        &env_path("DECOVERY_LOCAL_WORKSPACE_MZ"),
        "DECOVERY_TOOLCHAIN_TC20",
        Some("DECOVERY_TARGET_MZ"),
        true,
    );

    let mut taken = BTreeSet::new();
    let a = pick(&first, 250, &taken, scratch);
    taken.insert(a.task.function.clone());
    let b = pick(&first, 750, &taken, scratch);
    taken.insert(b.task.function.clone());
    let mut c = pick(&second, 500, &BTreeSet::new(), scratch);
    c.task.id = "task-2".into();
    assert_eq!(a.task.id, "task-0");
    assert_eq!(b.task.id, "task-1");

    // Review Focus 1 on every pristine copy (core tool set, both start points).
    for (picked, start) in [
        (&a, StartPoint::Stub),
        (&a, StartPoint::PseudoC),
        (&b, StartPoint::Stub),
        (&c, StartPoint::Stub),
    ] {
        let into = scratch.join(format!("leak-{}-{start:?}/ws", picked.task.id));
        let copy = prepare_copy(&picked.task, start, ToolSet::Core, &into).unwrap();
        let secrets = secrets(&picked.task.workspace, &picked.task, &copy.solution);
        let (count, bytes) = assert_no_trace(&copy.root, &secrets, true);
        let config = std::fs::read_to_string(copy.root.join("decovery.toml")).unwrap();
        assert!(
            !config.contains("[legacy]"),
            "core copy has a legacy section"
        );
        println!(
            "{} {start:?}: copy of {count} files, {bytes} bytes; object checked: {}; hash checked: {}",
            picked.task.id,
            secrets.object.is_some(),
            secrets.hash.is_some()
        );
    }

    let suite = write_suite(
        scratch,
        &[(&a, "first-q1"), (&b, "first-q3"), (&c, "second-median")],
        8,
    );
    let h = Harness {
        python: &python,
        scratch,
        suite: &suite,
    };

    // 1. an idle driver: the start distance, nothing spent, and the copy after the run is still solution-free.
    let run = h.run("task-0", "idle", &[], true);
    let t = &run.tasks[0];
    println!(
        "idle: state {}, exit {}, solved {}, verdict {}, start {:?}, best {:?}, builds {}, calls {}, wall {:.1} s",
        run.state,
        t.exit,
        t.solved,
        t.verdict,
        t.start_distance,
        t.best_distance,
        t.builds,
        t.tool_calls,
        t.wall_s
    );
    assert_eq!(run.state, "done");
    assert_eq!(t.exit, "ok");
    assert!(!t.solved, "an idle driver must not solve a stub");
    assert!(t.start_distance.is_some());
    assert_eq!(t.best_distance, t.start_distance);
    assert_eq!(t.builds, 0);
    assert_eq!(t.tool_calls, 0);
    let kept = scratch.join("copies").join(&run.id);
    let copy = std::fs::read_dir(&kept)
        .unwrap()
        .map(|e| e.unwrap().path().join("workspace"))
        .find(|p| p.is_dir())
        .expect("the kept copy");
    let solution = prepare_copy(
        &a.task,
        StartPoint::Stub,
        ToolSet::Core,
        &scratch.join("solution-a/ws"),
    )
    .unwrap()
    .solution;
    let (count, bytes) = assert_no_trace(&copy, &secrets(&first, &a.task, &solution), false);
    println!("idle: kept copy after the run holds {count} files, {bytes} bytes, no trace");

    // 2. a driver that submits the definition through MCP: only decovery's verdict solves the task.
    let solution_b = prepare_copy(
        &b.task,
        StartPoint::Stub,
        ToolSet::Core,
        &scratch.join("solution-b/ws"),
    )
    .unwrap()
    .solution;
    let call = json!([{"name": "build", "arguments": {
        "function": b.task.function, "variants": [{"function_source": solution_b, "label": "proposed"}]}}]);
    let run = h.run(
        "task-1",
        "calls",
        &[("FAKE_CALLS", call.to_string())],
        false,
    );
    let t = &run.tasks[0];
    println!(
        "solve: exit {}, solved {}, verdict {}, start {:?}, best {:?}, builds {}, calls {}, by tool {:?}, wall {:.1} s",
        t.exit,
        t.solved,
        t.verdict,
        t.start_distance,
        t.best_distance,
        t.builds,
        t.tool_calls,
        t.calls_by_tool,
        t.wall_s
    );
    assert!(t.solved, "the submitted definition must be identical");
    assert_eq!(t.verdict, "identical");
    assert_eq!(t.best_distance, Some(0));
    assert_eq!(t.builds, 1);
    assert!(
        !scratch
            .join("copies")
            .join(&run.id)
            .join("task-1-attempt-1")
            .exists(),
        "copies are deleted without --keep"
    );

    // 3. limits on the second target: one tool call allowed, two made.
    let suite = write_suite(
        scratch,
        &[(&a, "first-q1"), (&b, "first-q3"), (&c, "second-median")],
        1,
    );
    let h = Harness {
        python: &python,
        scratch,
        suite: &suite,
    };
    let calls = json!([{"name": "status", "arguments": {}}, {"name": "status", "arguments": {}}]);
    let run = h.run(
        "task-2",
        "calls",
        &[("FAKE_CALLS", calls.to_string())],
        false,
    );
    let t = &run.tasks[0];
    println!(
        "limit: exit {}, solved {}, verdict {}, start {:?}, best {:?}, builds {}, calls {}, wall {:.1} s",
        t.exit,
        t.solved,
        t.verdict,
        t.start_distance,
        t.best_distance,
        t.builds,
        t.tool_calls,
        t.wall_s
    );
    assert_eq!(t.exit, "call-limit");
    assert_eq!(
        t.tool_calls, 2,
        "a refused call is still logged and counted"
    );
    assert!(
        t.extra["driver_extra"]["calls"]
            .to_string()
            .contains("limit reached")
    );
    assert!(!t.solved);
    assert!(t.start_distance.is_some());
}
