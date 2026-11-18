//! All source, object and target data is synthetic.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_bench::{StartPoint, SuiteTask, ToolSet, copies_dir, prepare_copy, read_suite};
use decovery_core::{
    Address, Analysis, AnalyzedFunction, Provider, Workspace, archive_save, read_rebuild,
};

#[path = "../../decovery-facade/tests/support/build_fixture.rs"]
mod build_fixture;

const SOLUTION: &str = "int solve(int x)\n{\n    return x * 7183 + 29;\n}\n";
const SIBLING: &str = "int sibling(void)\n{\n    return 11;\n}\n";
const OBJECT: &[u8] = b"synthetic OMF object with the known solution and its relocation records";
const HASH: &str = "ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0ace0";

fn write(root: &Path, name: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn quoted(path: &Path) -> String {
    toml::Value::String(path.to_string_lossy().into_owned()).to_string()
}

fn workspace(profile: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "decovery.toml",
        format!(
            "schema = 1\n[target]\nfile = \"target/original.com\"\nsha256 = \"synthetic\"\nformat = \"com\"\nprocessor = \"x86:LE:16:Real Mode\"\n[rebuild]\ncompiler = \"{profile}\"\ntool_dir = \"tools\"\n"
        ),
    );
    write(root, "target/original.com", OBJECT);
    std::fs::create_dir_all(root.join("tools")).unwrap();
    write(root, "src/bundle.c", format!("{SOLUTION}\n{SIBLING}"));
    write(
        root,
        "knowledge/rebuild.toml",
        format!(
            "schema = 1\n[[function]]\naddress = \"flat:00000010\"\nname = \"solve\"\nfile = \"bundle.c\"\ncompiler = \"{profile}\"\nresult = \"identical\"\nverdict = \"identical\"\ncode_hash = \"{HASH}\"\n[[function]]\naddress = \"flat:00000040\"\nname = \"sibling\"\nfile = \"bundle.c\"\ncompiler = \"{profile}\"\nresult = \"identical\"\nverdict = \"identical\"\nfuture = \"kept\"\n"
        ),
    );
    let ws = Workspace::open(root).unwrap();
    let lock = ws.lock(Duration::ZERO).unwrap();
    let mut analysis = Analysis::new(Provider::new("synthetic", "1"), "synthetic", "", "");
    analysis.functions.push(AnalyzedFunction::new(
        Address::Flat(0x10),
        Address::Flat(0x20),
        17,
    ));
    analysis.save(root, &lock).unwrap();
    Analysis::save_decompiled(
        root,
        Address::Flat(0x10),
        "int solve(int x)\n{\n    return x + 5;\n}\n",
        &lock,
    )
    .unwrap();
    drop(lock);
    dir
}

fn task(root: &Path) -> SuiteTask {
    SuiteTask::new(root.to_path_buf(), "solve")
}
fn destination() -> (tempfile::TempDir, PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("case-1/workspace");
    (parent, path)
}
fn normalize(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Follow only the links the copy contract permits; detect cycles so the test cannot hide a linked leak.
fn files(root: &Path, seen: &mut Vec<PathBuf>) -> Vec<PathBuf> {
    let canonical = root.canonicalize().unwrap();
    assert!(
        !seen.contains(&canonical),
        "linked directory cycle: {root:?}"
    );
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

fn assert_no_solution(root: &Path) {
    for path in files(root, &mut Vec::new()) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !normalize(&String::from_utf8_lossy(&bytes)).contains(&normalize(SOLUTION)),
            "source leaked through {path:?}"
        );
        let analysis = path.starts_with(root.join("knowledge/analysis"));
        if !analysis {
            assert!(
                !bytes.windows(OBJECT.len()).any(|w| w == OBJECT),
                "object leaked through {path:?}"
            );
            assert!(
                !String::from_utf8_lossy(&bytes).contains(HASH),
                "hash leaked through {path:?}"
            );
        }
    }
}

#[test]
fn suite_reads_defaults_and_tasks() {
    let ws = workspace("synthetic-a");
    let suite = tempfile::tempdir().unwrap();
    let path = suite.path().join("suite.toml");
    write(
        suite.path(),
        "suite.toml",
        format!(
            "schema = 1\nname = \"probe\"\n[defaults]\nmax_tokens = 500\nprompt = \"prompt.md\"\n[[task]]\nworkspace = {}\nfunction = \"solve\"\ntags = [\"tiny\"]\n",
            quoted(ws.path())
        ),
    );
    let result = read_suite(&path).unwrap();
    assert_eq!(result.defaults.start, StartPoint::Stub);
    assert_eq!(result.defaults.tools, ToolSet::Core);
    assert_eq!(
        (
            result.defaults.max_builds,
            result.defaults.max_tool_calls,
            result.defaults.max_searches,
            result.defaults.wall_minutes
        ),
        (40, 120, 0, 15)
    );
    assert_eq!(result.defaults.max_tokens, Some(500));
    assert_eq!(result.defaults.prompt, Some(suite.path().join("prompt.md")));
    assert_eq!(result.tasks[0].tags, ["tiny"]);
    assert!(result.tasks[0].id.ends_with("/solve"));
}

#[test]
fn suite_rejects_unsolved_function() {
    let ws = workspace("synthetic-a");
    let path = ws.path().join("knowledge/rebuild.toml");
    let text = std::fs::read_to_string(&path).unwrap().replacen(
        "verdict = \"identical\"",
        "verdict = \"differs\"",
        1,
    );
    std::fs::write(path, text).unwrap();
    write(
        ws.path(),
        "suite.toml",
        "schema = 1\nname = \"probe\"\n[[task]]\nworkspace = \".\"\nfunction = \"solve\"\n",
    );
    let error = read_suite(&ws.path().join("suite.toml"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("solve") && error.contains("identical"),
        "{error}"
    );
}

#[test]
fn copy_contains_no_trace_of_the_solution() {
    let ws = workspace("synthetic-a");
    for name in [
        ".git/config",
        "output/solve.c",
        "cache/handles/h_x.txt",
        "cache/rebuild/objects/x.obj",
        "cache/rebuild/runs/1/file.c",
        "cache/rebuild/shrink/key.c",
        "cache/rebuild/REBUILD.EXE",
        "cache/legacy/decomp/nachbau/file.c",
        "cache/calls/2026-11.jsonl",
        "cache/jobs/one/spec.json",
        "cache/exemplars/index.json",
    ] {
        write(ws.path(), name, format!("{SOLUTION}{HASH}"));
    }
    write(
        ws.path(),
        "knowledge/notes.md",
        format!("A saved definition:\n```c\n{SOLUTION}```\n"),
    );
    write(ws.path(), "cache/rebuild/obj/BUNDLE.OBJ", OBJECT);
    write(
        ws.path(),
        "cache/rebuild/obj/BUNDLE.JSON",
        format!("{{\"file\":\"bundle.c\",\"object\":\"{HASH}\"}}"),
    );
    write(
        ws.path(),
        "cache/rebuild/obj/other.obj",
        b"unrelated retained object",
    );
    write(
        ws.path(),
        "cache/rebuild/obj/other.json",
        "{\"schema\":1,\"file\":\"other.c\"}",
    );
    write(
        ws.path(),
        "cache/attempts/flat_00000010.jsonl",
        format!("{SOLUTION}{HASH}"),
    );
    write(
        ws.path(),
        "cache/attempts/flat_00000040.jsonl",
        "{\"schema\":1,\"note\":\"retained sibling\"}\n",
    );
    let mut archive = BTreeMap::new();
    archive.insert(
        "module.c".into(),
        format!("{SOLUTION}{SIBLING}").into_bytes(),
    );
    archive_save(
        ws.path(),
        &serde_json::json!({"address":"flat:00000040", "file":"bundle.c"}),
        &archive,
    )
    .unwrap();
    let (_parent, into) = destination();
    let copy = prepare_copy(&task(ws.path()), StartPoint::Stub, ToolSet::Core, &into).unwrap();
    assert_eq!(copy.solution, SOLUTION);
    assert_no_solution(&into);
    assert!(
        !into.join("cache/archive").exists(),
        "sibling archive modules leak the solution"
    );
    assert!(into.join("cache/rebuild/obj/other.obj").is_file());
    assert!(!into.join("cache/rebuild/obj/BUNDLE.OBJ").exists());
    assert!(!into.join("cache/attempts/flat_00000010.jsonl").exists());
    assert!(into.join("cache/attempts/flat_00000040.jsonl").is_file());
    let config = Workspace::open(&into).unwrap().config;
    assert_eq!(
        Path::new(&config.target.file).canonicalize().unwrap(),
        ws.path()
            .join("target/original.com")
            .canonicalize()
            .unwrap()
    );
    assert!(Path::new(config.rebuild.as_ref().unwrap().tool_dir.as_ref().unwrap()).is_absolute());
    assert!(!into.join("target").exists());
    assert_eq!(
        std::fs::read(ws.path().join("src/bundle.c")).unwrap(),
        format!("{SOLUTION}\n{SIBLING}").as_bytes(),
        "source workspace unchanged"
    );
}

#[test]
fn core_copy_has_no_legacy_section() {
    let ws = workspace("synthetic-a");
    let mut config = std::fs::read_to_string(ws.path().join("decovery.toml")).unwrap();
    config.push_str("\n[legacy]\ndecomp_workspace = \"private-source\"\n");
    write(ws.path(), "decovery.toml", config);
    let (_parent, into) = destination();
    let copy = prepare_copy(&task(ws.path()), StartPoint::Stub, ToolSet::Core, &into).unwrap();
    assert!(Workspace::open(&copy.root).unwrap().config.legacy.is_none());
    assert!(copy.legacy_view.is_none());
}

#[test]
fn stub_start_keeps_head() {
    let ws = workspace("synthetic-a");
    let (_parent, into) = destination();
    prepare_copy(&task(ws.path()), StartPoint::Stub, ToolSet::Core, &into).unwrap();
    assert_eq!(
        std::fs::read_to_string(into.join("src/bundle.c")).unwrap(),
        format!("int solve(int x)\n{{\n}}\n\n{SIBLING}")
    );
}

#[test]
fn pseudo_c_start_uses_decompiled_body() {
    let ws = workspace("synthetic-a");
    let (_parent, into) = destination();
    prepare_copy(&task(ws.path()), StartPoint::PseudoC, ToolSet::Core, &into).unwrap();
    let source = std::fs::read_to_string(into.join("src/bundle.c")).unwrap();
    assert!(
        source.starts_with("int solve(int x)\n{\n    return x + 5;\n}"),
        "{source}"
    );
    std::fs::remove_file(
        ws.path()
            .join("knowledge/analysis/decompiled/flat_00000010.c"),
    )
    .unwrap();
    let (_other, into) = destination();
    let copy = prepare_copy(&task(ws.path()), StartPoint::PseudoC, ToolSet::Core, &into).unwrap();
    assert!(!copy.warnings.is_empty());
    assert!(
        std::fs::read_to_string(into.join("src/bundle.c"))
            .unwrap()
            .starts_with("int solve(int x)\n{\n}\n")
    );
}

#[test]
fn suite_over_two_profiles() {
    let a = workspace("synthetic-a");
    let b = workspace("synthetic-b");
    let suite = tempfile::tempdir().unwrap();
    write(
        suite.path(),
        "suite.toml",
        format!(
            "schema = 1\nname = \"mixed\"\n[defaults]\ntools = \"core+legacy\"\n[[task]]\nid = \"one\"\nworkspace = {}\nfunction = \"solve\"\ntags = [\"a\"]\n[[task]]\nid = \"two\"\nworkspace = {}\nfunction = \"flat:00000010\"\ntags = [\"b\"]\n",
            quoted(a.path()),
            quoted(b.path())
        ),
    );
    let suite = read_suite(&suite.path().join("suite.toml")).unwrap();
    assert_eq!(suite.defaults.tools, ToolSet::CoreLegacy);
    assert_eq!(suite.defaults.max_searches, 2);
    assert_eq!(
        serde_json::to_value(suite.defaults.tools).unwrap(),
        "core-legacy"
    );
    for (task, profile) in suite.tasks.iter().zip(["synthetic-a", "synthetic-b"]) {
        let (_parent, into) = destination();
        let copy = prepare_copy(task, StartPoint::Stub, ToolSet::Core, &into).unwrap();
        assert_eq!(copy.profile, profile);
    }
}

#[test]
fn copies_dir_has_no_claude_md_ancestor() {
    let candidate = copies_dir();
    assert!(candidate.is_absolute());
    let ws = workspace("synthetic-a");
    let parent = tempfile::tempdir().unwrap();
    write(parent.path(), "CLAUDE.md", "should never be inherited");
    let error = prepare_copy(
        &task(ws.path()),
        StartPoint::Stub,
        ToolSet::Core,
        &parent.path().join("task/workspace"),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("CLAUDE.md"), "{error}");
    assert!(!parent.path().join("task").exists());
}

#[test]
fn legacy_view_has_no_trace_of_the_solution() {
    let ws = workspace("synthetic-a");
    let legacy = tempfile::tempdir().unwrap();
    write(
        legacy.path(),
        "decomp.toml",
        "[ziel]\ndatei = \"game/original.exe\"\n",
    );
    write(legacy.path(), "game/original.exe", b"original executable");
    write(legacy.path(), "nachbau/bundle.c", SOLUTION);
    write(legacy.path(), "cache/nachbau/versuche.jsonl", SOLUTION);
    write(legacy.path(), "cache/entpackt.exe", b"unpacked original");
    write(
        legacy.path(),
        "wissen/nachbau.toml",
        "[[funktion]]\nadresse = \"va:10\"\nname = \"solve\"\ndatei = \"bundle.c\"\n[[funktion]]\nadresse = \"va:00000040\"\nname = \"sibling\"\ndatei = \"bundle.c\"\n",
    );
    write(legacy.path(), "wissen/notizen.md", SOLUTION);
    write(
        legacy.path(),
        "wissen/nachbau-programm.toml",
        format!("schema = 1\nsource = '''{SOLUTION}'''\n"),
    );
    let config = std::fs::read_to_string(ws.path().join("decovery.toml")).unwrap();
    write(
        ws.path(),
        "decovery.toml",
        format!(
            "{config}\n[legacy]\ndecomp_workspace = {}\n",
            quoted(legacy.path())
        ),
    );
    let (_parent, into) = destination();
    let copy = prepare_copy(
        &task(ws.path()),
        StartPoint::Stub,
        ToolSet::CoreLegacy,
        &into,
    )
    .unwrap();
    let view = copy.legacy_view.unwrap();
    assert_eq!(view, into.parent().unwrap().join("legacy-view"));
    assert_no_solution(&into);
    assert_no_solution(&view);
    assert!(!view.join("nachbau").exists());
    assert!(!view.join("cache/nachbau").exists());
    assert_eq!(
        std::fs::read(view.join("cache/entpackt.exe")).unwrap(),
        b"unpacked original"
    );
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(view.join("decomp.toml")).unwrap()).unwrap();
    assert!(Path::new(config["ziel"]["datei"].as_str().unwrap()).is_absolute());
    let records: toml::Value =
        toml::from_str(&std::fs::read_to_string(view.join("wissen/nachbau.toml")).unwrap())
            .unwrap();
    assert_eq!(records["funktion"].as_array().unwrap().len(), 1);
    assert_eq!(records["funktion"][0]["name"].as_str(), Some("sibling"));
    assert!(
        std::fs::read_to_string(legacy.path().join("wissen/notizen.md"))
            .unwrap()
            .contains(SOLUTION)
    );
}

#[test]
fn other_functions_stay_identical_in_copy() {
    let python = python_or_skip!();
    let fixture = build_fixture::fixture(&python, "");
    decovery_facade::build(
        fixture.root(),
        &decovery_facade::BuildRequest::default(),
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    let task = SuiteTask::new(fixture.root().to_path_buf(), "sub");
    let (_parent, into) = destination();
    prepare_copy(&task, StartPoint::Stub, ToolSet::Core, &into).unwrap();
    let records = read_rebuild(&into).unwrap();
    assert!(records.iter().all(|r| r.name != "sub"));
    assert!(
        records
            .iter()
            .any(|r| r.name == "add" && r.verdict == Some(decovery_core::VerdictId::Identical))
    );
    let response = decovery_facade::build(
        &into,
        &decovery_facade::BuildRequest::default(),
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    assert!(
        read_rebuild(&into)
            .unwrap()
            .iter()
            .any(|r| r.name == "add" && r.verdict == Some(decovery_core::VerdictId::Identical)),
        "{}",
        response.data
    );
}

#[test]
fn native_rebuild_address_spelling_cannot_preserve_the_target() {
    let ws = workspace("synthetic-a");
    let path = ws.path().join("knowledge/rebuild.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replacen("flat:00000010", "flat:10", 1);
    std::fs::write(path, text).unwrap();
    let (_parent, into) = destination();
    prepare_copy(&task(ws.path()), StartPoint::Stub, ToolSet::Core, &into).unwrap();
    assert!(
        read_rebuild(&into)
            .unwrap()
            .iter()
            .all(|r| r.address != Address::Flat(0x10))
    );
}

#[test]
fn legacy_source_is_not_modified_by_a_bad_destination() {
    let ws = workspace("synthetic-a");
    let legacy = tempfile::tempdir().unwrap();
    write(
        legacy.path(),
        "decomp.toml",
        "[ziel]\ndatei = \"original.exe\"\n",
    );
    let text = std::fs::read_to_string(ws.path().join("decovery.toml")).unwrap();
    write(
        ws.path(),
        "decovery.toml",
        format!(
            "{text}\n[legacy]\ndecomp_workspace = {}\n",
            quoted(legacy.path())
        ),
    );
    let into = legacy.path().join("case/workspace");
    assert!(
        prepare_copy(
            &task(ws.path()),
            StartPoint::Stub,
            ToolSet::CoreLegacy,
            &into
        )
        .is_err()
    );
    assert!(
        !legacy.path().join("case").exists(),
        "reject before writing into the original Decomp source"
    );
}

#[test]
fn rejected_linked_resource_is_not_deleted_or_modified() {
    let ws = workspace("synthetic-a");
    let legacy = tempfile::tempdir().unwrap();
    write(
        legacy.path(),
        "decomp.toml",
        "[ziel]\ndatei = \"original.exe\"\n",
    );
    write(legacy.path(), "cache/laufzeit/leaked.c", SOLUTION);
    let text = std::fs::read_to_string(ws.path().join("decovery.toml")).unwrap();
    write(
        ws.path(),
        "decovery.toml",
        format!(
            "{text}\n[legacy]\ndecomp_workspace = {}\n",
            quoted(legacy.path())
        ),
    );
    let (_parent, into) = destination();
    let error = prepare_copy(
        &task(ws.path()),
        StartPoint::Stub,
        ToolSet::CoreLegacy,
        &into,
    )
    .unwrap_err();
    assert!(error.to_string().contains("known definition"), "{error}");
    assert_eq!(
        std::fs::read_to_string(legacy.path().join("cache/laufzeit/leaked.c")).unwrap(),
        SOLUTION
    );
    assert!(!into.exists());
    assert!(!into.parent().unwrap().join("legacy-view").exists());
}

#[test]
fn bench_copy_has_no_exemplar_entry_of_the_function() {
    // ruling P15: the copy never carries `cache/exemplars/`; the index refreshed in the copy lacks the function
    // because its rebuild record is gone
    let python = python_or_skip!();
    let fixture = build_fixture::fixture(&python, "");
    decovery_facade::build(
        fixture.root(),
        &decovery_facade::BuildRequest::default(),
        &decovery_facade::Control::progress_only(&|_| {}),
    )
    .unwrap();
    let original = decovery_facade::Session::open(fixture.root()).unwrap();
    assert!(
        decovery_facade::exemplar_index(&original)
            .unwrap()
            .contains(build_fixture::SUB_AT)
    );
    let task = SuiteTask::new(fixture.root().to_path_buf(), "sub");
    let (_parent, into) = destination();
    prepare_copy(&task, StartPoint::Stub, ToolSet::Core, &into).unwrap();
    assert!(!into.join("cache/exemplars").exists());
    let copy = decovery_facade::Session::open(&into).unwrap();
    let index = decovery_facade::exemplar_index(&copy).unwrap();
    assert!(!index.contains(build_fixture::SUB_AT));
    assert!(index.contains(build_fixture::ADD_AT));
    let index_text = std::fs::read_to_string(into.join(decovery_facade::EXEMPLARS_FILE)).unwrap();
    assert!(!index_text.contains("\"sub\""));
}
