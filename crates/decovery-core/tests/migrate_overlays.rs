//! Migration of an Aztec overlay workspace; synthetic inputs only, no private workspace data.
use std::path::Path;

use decovery_core::{Address, Workspace, migrate_decomp};

const CONFIG: &str = r#"
[ziel]
datei = "D:/games/PROGRAM.EXE"
sha256 = "ab12"
format = "mz"
prozessor = "x86:LE:16:Real Mode"
segment = [
    { name = "bild", start = "rel:0000:0000", laenge = 4096, datei_offset = 512, rechte = "rwx" },
]

[[overlay]]
name = "OVA"
datei = "D:/games/OVA.OVR"
sha256 = "cd34"
format = "aztec-c86"
einsprung = "ovl:OVA:0000:1180"

[overlay.register]
ds = "0100"

[[overlay.segment]]
name = "OVA.code"
start = "ovl:OVA:0000:1000"
laenge = 400
datei_offset = 14
rechte = "rwx"

[[overlay.segment]]
name = "OVA.daten"
start = "ovl:OVA:0100:2000"
laenge = 40
datei_offset = 414
datei_laenge = 30
rechte = "rw"

[nachbau]
compiler = "aztec-c86-4.2b"
optionen = "+b"

[nachbau.optionen_je_datei]
"ova.c" = "+b +c"
"#;

const RULES: &str = r#"
[[regel]]
id = "aztec-frame"
compiler = ["aztec-c86-4.2b"]
status = "belegt"
text = "Rahmen mit $csav."
vorschlag = "+b verwenden."
hilft_nicht = ["ohne +b"]

[[regel.beleg]]
ziel = "synthetic"
funktion = "f (ovl:OVA:0000:1000)"
datum = "2026-11-16"
ergebnis = "identisch"

[[regel]]
id = "other-compiler"
compiler = ["watcom-10.6"]
status = "vermutet"
text = "nicht fuer Aztec"
vorschlag = ""
hilft_nicht = []
"#;

/// A Decomp repository layout: `<root>/compilerwissen/` next to `<root>/ziele/<name>/`.
fn setup(config: &str) -> (tempfile::TempDir, std::path::PathBuf, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let from = root.path().join("ziele/synthetic");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::write(from.join("decomp.toml"), config).unwrap();
    std::fs::create_dir_all(root.path().join("compilerwissen")).unwrap();
    std::fs::write(root.path().join("compilerwissen/aztec.toml"), RULES).unwrap();
    (root, from, tempfile::tempdir().unwrap())
}

fn migrate(from: &Path, to: &Path) -> decovery_core::MigrationReport {
    migrate_decomp(from, to).unwrap()
}

#[test]
fn overlays_are_migrated() {
    let (_root, from, to) = setup(CONFIG);
    let report = migrate(&from, to.path());
    assert!(report.unmapped.is_empty(), "{:?}", report.unmapped);
    let ws = Workspace::open(to.path()).unwrap();
    assert_eq!(ws.config.overlays.len(), 1);
    let o = &ws.config.overlays[0];
    assert_eq!(o.name.as_str(), "OVA");
    assert_eq!(o.file, "D:/games/OVA.OVR");
    assert_eq!(o.sha256, "cd34");
    assert_eq!(o.format, "aztec-c86");
    assert_eq!(o.file_offset, 0);
    assert_eq!(o.size, 444, "end of the last segment in the file");
    assert_eq!(o.entry, Some("ovl:OVA:0000:1180".parse().unwrap()));
    let segs: Vec<_> = ws
        .config
        .target
        .segments
        .iter()
        .filter(|s| s.start.overlay().is_some())
        .collect();
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0].name, "OVA.code");
    assert_eq!(
        segs[0].start,
        "ovl:OVA:0000:1000".parse::<Address>().unwrap()
    );
    assert_eq!(
        (segs[0].length, segs[0].file_offset, segs[0].file_length),
        (400, Some(14), None)
    );
    assert_eq!(segs[1].name, "OVA.data", "segment names are English");
    assert_eq!(segs[1].permissions, "rw");
    assert_eq!(
        (segs[1].length, segs[1].file_offset, segs[1].file_length),
        (40, Some(414), Some(30))
    );
}

#[test]
fn overlay_register_that_disagrees_with_the_data_segment_is_unmapped() {
    let (_root, from, to) = setup(&CONFIG.replace("ds = \"0100\"", "ds = \"0200\""));
    let report = migrate(&from, to.path());
    assert_eq!(report.unmapped, ["overlay.register.ds=0200"]);
}

#[test]
fn bad_overlay_name_is_an_error() {
    let (_root, from, to) = setup(&CONFIG.replace("name = \"OVA\"", "name = \"OV-A\""));
    assert!(migrate_decomp(&from, to.path()).is_err());
}

#[test]
fn aztec_profile_is_mapped() {
    let (_root, from, to) = setup(CONFIG);
    migrate(&from, to.path());
    let ws = Workspace::open(to.path()).unwrap();
    let rebuild = ws.config.rebuild.as_ref().unwrap();
    assert_eq!(rebuild.compiler.as_deref(), Some("aztec-c86-4.2b"));
    assert_eq!(rebuild.flags.as_deref(), Some("+b"));
    assert_eq!(rebuild.file_flags["ova.c"], "+b +c");
}

#[test]
fn compiler_rules_become_workspace_knowledge() {
    let (_root, from, to) = setup(CONFIG);
    let report = migrate(&from, to.path());
    assert!(
        report
            .converted
            .contains(&std::path::PathBuf::from("knowledge/compiler-rules.toml"))
    );
    let text = std::fs::read_to_string(to.path().join("knowledge/compiler-rules.toml")).unwrap();
    let table: toml::Table = toml::from_str(&text).unwrap();
    let rules = table["rule"].as_array().unwrap();
    assert_eq!(rules.len(), 1, "only the rules of the workspace's compiler");
    let r = &rules[0];
    assert_eq!(r["id"].as_str(), Some("aztec-frame"));
    assert_eq!(
        r["compilers"].as_array().unwrap()[0].as_str(),
        Some("aztec-c86-4.2b")
    );
    assert_eq!(r["status"].as_str(), Some("confirmed"));
    assert_eq!(r["text"].as_str(), Some("Rahmen mit $csav."));
    assert_eq!(r["suggestion"].as_str(), Some("+b verwenden."));
    assert_eq!(r["does_not_help"].as_array().unwrap().len(), 1);
    let e = &r["evidence"].as_array().unwrap()[0];
    assert_eq!(e["target"].as_str(), Some("synthetic"));
    assert_eq!(e["function"].as_str(), Some("f (ovl:OVA:0000:1000)"));
    assert_eq!(e["date"].as_str(), Some("2026-11-16"));
    assert_eq!(e["result"].as_str(), Some("identisch"));
}

#[test]
fn workspace_without_compiler_knowledge_writes_no_rules() {
    let (root, from, to) = setup(CONFIG);
    std::fs::remove_dir_all(root.path().join("compilerwissen")).unwrap();
    let report = migrate(&from, to.path());
    assert!(!to.path().join("knowledge/compiler-rules.toml").exists());
    assert!(report.unmapped.is_empty());
}

#[test]
fn second_migration_changes_nothing() {
    let (_root, from, to) = setup(CONFIG);
    migrate(&from, to.path());
    let before = std::fs::read(to.path().join("decovery.toml")).unwrap();
    assert!(
        migrate_decomp(&from, to.path()).is_err(),
        "existing workspace"
    );
    assert_eq!(
        std::fs::read(to.path().join("decovery.toml")).unwrap(),
        before
    );
    let again = decovery_core::migrate::migrate_attempts(&from, to.path()).unwrap();
    assert_eq!(again.attempts, 0);
}
