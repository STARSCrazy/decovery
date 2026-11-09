//! `link` on a synthetic LE workspace: the identical rebuild of `foo` is inserted from the kept object of the last
//! build, the fake runner takes the WLINK job and serves a prepared `REBUILD.EXE`. Skipped (with a message) without
//! Python: set `DECOVERY_PYTHON` or put `python` on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;
#[path = "../../decovery-loaders/tests/support/le_builder.rs"]
mod le_builder;

use std::path::Path;

use decovery_core::{RebuildResult, read_program_record};
use decovery_facade::{Response, link};
use decovery_objects::{WriteFixup, WriteFixupKind, WriteSegment, read_omf, write_omf_module};
use decovery_toolchain::{assemble_listing, response_file, to_dos_bytes};
use le_builder::{Fix, Le, Obj, pattern};
use serde_json::json;

/// Where `build` keeps the objects of the last build, with the format of their metadata.
const OBJECTS_DIR: &str = "cache/rebuild/obj";
const OBJECT_FORMAT: &str = "decovery-obj/1";
const A_C: &str = "int baz(void);\nint foo(void)\n{\n    return baz();\n}\n";
/// `foo` as the original holds it at 0x40 of object 1 (field at 0x41 relocated to `baz` at 0x80).
const FOO: [u8; 11] = [0xB8, 0x80, 0, 0, 0, 0xE8, 0x36, 0, 0, 0, 0xC3];

const SYMBOLS: &str = r#"schema = 1

[[symbol]]
address = "flat:00010040"
kind = "function"
name = "foo"
source = "human"
confidence = "confirmed"

[[symbol]]
address = "flat:00010080"
kind = "function"
name = "baz"
source = "human"
confidence = "confirmed"
"#;

const REBUILD: &str = r#"schema = 1

[[function]]
address = "flat:00010040"
name = "foo"
file = "a.c"
compiler = "watcom-9.5"
result = "identical"
verdict = "identical"
"#;

/// The original: code object 1 with `foo` at 0x40 and `baz` at 0x80, auto data object 2; `retarget` moves the fixup
/// of `foo` to the data object (a rebuilt program that differs).
fn original(retarget: bool) -> Vec<u8> {
    let mut code = pattern(0x200, 1);
    code[0x40..0x4B].copy_from_slice(&FOO);
    code[0x80] = 0xC3;
    let mut objects = vec![
        Obj::new(0x10000, 0x2045, code),
        Obj::new(0x20000, 0x2043, pattern(0x60, 7)),
    ];
    objects[1].size = 0x2000;
    let target = if retarget { 2 } else { 1 };
    let mut le = Le::new(objects, vec![Fix::new(0, 0x41, 0x07, target, 0x80)]);
    le.auto_data = 2;
    le.stack = (2, 0x2000);
    le.build()
}

/// The object `build` keeps for `a.c`: `foo_` (`mov eax, offset baz_`, `call baz_`, `ret`) and `baz_`.
fn kept_object() -> Vec<u8> {
    let code = vec![0xB8, 0x0B, 0, 0, 0, 0xE8, 0x01, 0, 0, 0, 0xC3, 0xC3];
    write_omf_module(
        "a.c",
        &[WriteSegment::new("_TEXT", "CODE", code.len() as u32, true)],
        &[],
        &[("foo_".to_string(), 1, 0), ("baz_".to_string(), 1, 0x0B)],
        &[(1, code)],
        &[WriteFixup::new(1, 1, WriteFixupKind::Off32, 1, None)],
        None,
    )
    .unwrap()
}

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

struct LeFixture {
    ws: tempfile::TempDir,
    served: tempfile::TempDir,
}

impl LeFixture {
    fn root(&self) -> &Path {
        self.ws.path()
    }
}

fn le_fixture(python: &str) -> LeFixture {
    let ws = tempfile::tempdir().unwrap();
    let served = tempfile::tempdir().unwrap();
    let root = ws.path();
    let script = std::path::absolute(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/omf_runner.py"),
    )
    .unwrap();
    for dir in ["knowledge", "src", "tools", OBJECTS_DIR] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("t.exe"), original(false)).unwrap();
    let config = format!(
        r#"schema = 1

[target]
file = "t.exe"
sha256 = "aa"
format = "le"
processor = "x86"

[rebuild]
compiler = "watcom-9.5"
flags = "-ox"
runners = ["fake"]
tool_dir = "tools"

[rebuild.link]
profile = "watcom-9.5"
stack = 4096

[plugins.fake]
command = [{}, {}]
env = {{ FAKE_OMF_DIR = {} }}
"#,
        toml_string(python),
        toml_string(script.to_str().unwrap()),
        toml_string(served.path().to_str().unwrap()),
    );
    std::fs::write(root.join("decovery.toml"), config).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), SYMBOLS).unwrap();
    std::fs::write(root.join("knowledge/rebuild.toml"), REBUILD).unwrap();
    std::fs::write(root.join("src/a.c"), A_C).unwrap();
    let object = kept_object();
    let staged = to_dos_bytes("a.c", A_C).unwrap();
    let meta = json!({
        "schema": 1,
        "format": OBJECT_FORMAT,
        "file": "a.c",
        "profile": "watcom-9.5",
        "flags": "-ox",
        "inputs": { "A.C": blake3::hash(&staged).to_hex().to_string() },
        "object": blake3::hash(&object).to_hex().to_string(),
        "identical": { "foo": { "address": "flat:00010040" } },
    });
    std::fs::write(root.join(OBJECTS_DIR).join("a.obj"), &object).unwrap();
    std::fs::write(
        root.join(OBJECTS_DIR).join("a.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    LeFixture { ws, served }
}

fn run(f: &LeFixture) -> Response {
    link(f.root(), &|_| {}).unwrap()
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn le_link_inserts_identical_function() {
    let python = python_or_skip!();
    let f = le_fixture(&python);
    std::fs::write(f.served.path().join("REBUILD.EXE"), original(false)).unwrap();
    let response = run(&f);
    assert_eq!(response.data["result"], "identical", "{:#}", response.data);
    assert!(
        strings(&response.data["hints"]).is_empty(),
        "{:#}",
        response.data
    );
    assert_eq!(
        response.data["used"],
        json!({ "functions": 1, "bytes": 11 })
    );
    let r = read_program_record(f.root()).unwrap().unwrap();
    assert_eq!(r.result, RebuildResult::Identical);
    assert_eq!(r.compiler.as_deref(), Some("watcom-9.5"));
    let used = r.used.unwrap();
    assert_eq!((used.functions, used.bytes), (1, 11));
    let text = std::fs::read_to_string(f.root().join("knowledge/rebuild-program.toml")).unwrap();
    assert!(text.contains("[program.used]"), "{text}");

    // what the linker got: the response file without `option start`, the stub, the module with foo inserted
    let linked = f.served.path().join("linked");
    assert_eq!(
        std::fs::read_to_string(linked.join("NB.LNK")).unwrap(),
        response_file("REBUILD", false)
    );
    assert_eq!(
        std::fs::read(linked.join("STUB.EXE")).unwrap(),
        original(false)[..0x40]
    );
    let module = read_omf(&std::fs::read(linked.join("NB.OBJ")).unwrap(), "NB.OBJ").unwrap();
    let text = &module.modules[0].sections[0];
    assert_eq!(text.name, "_TEXT");
    assert_eq!(&text.data[0x40..0x4B], &FOO);
    assert_eq!(
        std::fs::read_to_string(f.served.path().join("link.log"))
            .unwrap()
            .trim(),
        "WLINK @NB"
    );
}

#[test]
fn le_link_names_differences_and_stale_objects() {
    let python = python_or_skip!();
    let f = le_fixture(&python);
    std::fs::write(f.served.path().join("REBUILD.EXE"), original(true)).unwrap();
    // the source changed since the last build: the kept object is not used
    std::fs::write(f.root().join("src/a.c"), format!("{A_C}\n")).unwrap();
    let response = run(&f);
    assert_eq!(response.data["result"], "differs", "{:#}", response.data);
    let hints = strings(&response.data["hints"]);
    assert_eq!(
        hints,
        [
            "foo: the kept object is stale (source, headers, flags or compiler changed); run `decovery build a.c` first, not inserted"
        ]
    );
    let r = read_program_record(f.root()).unwrap().unwrap();
    assert_eq!(r.used.as_ref().map(|u| u.functions), Some(0));
    assert!(
        r.diagnosis
            .iter()
            .any(|l| l
                == "fixup page 1: flat:00010041 targets object 2 +0x80 instead of object 1 +0x80"),
        "{:?}",
        r.diagnosis
    );
}

/// `foo` as a byte listing: the field of `mov eax, offset baz` and the call by name.
const A_ASM: &str = "\t.386p\n\textrn baz_:near\n_TEXT0001\tsegment byte public use32 'CODE'\n\tpublic foo_\n\
                     foo_:\n\tdb 0B8h\t; mov eax, offset baz\n\tdd baz_\n\tcall baz_\n\tdb 0C3h\n_TEXT0001\tends\n\tend\n";

#[test]
fn le_link_inserts_function_of_assembler_source() {
    let python = python_or_skip!();
    let f = le_fixture(&python);
    let root = f.root();
    std::fs::remove_file(root.join("src/a.c")).unwrap();
    std::fs::write(root.join("src/a.asm"), A_ASM).unwrap();
    std::fs::write(
        root.join("knowledge/rebuild.toml"),
        REBUILD
            .replace("a.c", "a.asm")
            .replace("watcom-9.5", "builtin-asm"),
    )
    .unwrap();
    // what `build` keeps for an assembler source the built-in assembler built
    let object = assemble_listing("A.ASM", A_ASM).unwrap();
    let staged = to_dos_bytes("a.asm", A_ASM).unwrap();
    let meta = json!({
        "schema": 1,
        "format": OBJECT_FORMAT,
        "file": "a.asm",
        "profile": "builtin-asm",
        "flags": "",
        "inputs": { "A.ASM": blake3::hash(&staged).to_hex().to_string() },
        "object": blake3::hash(&object).to_hex().to_string(),
        "identical": { "foo": { "address": "flat:00010040" } },
    });
    std::fs::write(root.join(OBJECTS_DIR).join("a.obj"), &object).unwrap();
    std::fs::write(
        root.join(OBJECTS_DIR).join("a.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();
    std::fs::write(f.served.path().join("REBUILD.EXE"), original(false)).unwrap();
    let response = run(&f);
    assert_eq!(response.data["result"], "identical", "{:#}", response.data);
    assert!(
        strings(&response.data["hints"]).is_empty(),
        "{:#}",
        response.data
    );
    assert_eq!(
        response.data["used"],
        json!({ "functions": 1, "bytes": 11 })
    );
    let module = read_omf(
        &std::fs::read(f.served.path().join("linked/NB.OBJ")).unwrap(),
        "NB.OBJ",
    )
    .unwrap();
    assert_eq!(&module.modules[0].sections[0].data[0x40..0x4B], &FOO);
}
