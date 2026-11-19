//! `build` on the data of Aztec main-program objects (synthetic MZ workspace): which DS was used, and what a build
//! of a single file says.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use decovery_core::{Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash};
use decovery_facade::{BuildRequest, Control, Response, build};
use decovery_objects::{
    AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget, write_aztec,
};

const DS: u16 = 0x0010;
/// Where the data starts in DS in the original.
const START: u16 = 0x0004;
const FUNC_AT: u16 = 0x20;

/// A source file's object: `amain_` = `mov ax,[data+0]; ret` with its data `11 22 33 44`.
fn main_object() -> Vec<u8> {
    write_aztec(&AztecModuleSpec {
        name: "M".into(),
        code: vec![0xA1, 0, 0, 0xC3],
        data: vec![0x11, 0x22, 0x33, 0x44],
        named: vec![AztecSymbolSpec {
            name: "amain_".into(),
            section: AztecSection::Code,
            value: 0,
            public: true,
        }],
        refs: vec![AztecRefSpec {
            section: AztecSection::Code,
            offset: 1,
            width: 2,
            relative: false,
            target: AztecTarget::Section(AztecSection::Data, 0),
            addend: 0,
        }],
        ..AztecModuleSpec::default()
    })
}

/// An object with data only, no function.
fn data_only_object() -> Vec<u8> {
    write_aztec(&AztecModuleSpec {
        name: "D".into(),
        data: vec![0x55, 0x66],
        ..AztecModuleSpec::default()
    })
}

/// MZ file: entry `mov bp, DS` (field relocated), `amain_` at 0020 naming the data at DS:START, the data there.
fn mz() -> Vec<u8> {
    let mut image = vec![0u8; 0x200];
    image[0..3].copy_from_slice(&[0xBD, DS as u8, (DS >> 8) as u8]);
    image[usize::from(FUNC_AT)..usize::from(FUNC_AT) + 4].copy_from_slice(&[
        0xA1,
        START as u8,
        (START >> 8) as u8,
        0xC3,
    ]);
    let d = usize::from(DS) * 16 + usize::from(START);
    image[d..d + 4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let total = 32 + image.len();
    let words: [u16; 14] = [
        0x5A4D,
        (total % 512) as u16,
        total.div_ceil(512) as u16,
        1,
        2,
        0,
        0xFFFF,
        0,
        0x0100,
        0,
        0,
        0,
        0x1C,
        0,
    ];
    let mut v = vec![0u8; 32];
    for (i, w) in words.iter().enumerate() {
        v[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    v[0x1C..0x20].copy_from_slice(&[1, 0, 0, 0]); // relocation at 0000:0001
    v.extend_from_slice(&image);
    v
}

fn quote(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// The workspace; `frames` is appended to `[rebuild]`.
fn workspace(python: &str, frames: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let ws = tempfile::tempdir().unwrap();
    let objects = tempfile::tempdir().unwrap();
    let root = ws.path();
    let script = std::path::absolute(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/omf_runner.py"),
    )
    .unwrap();
    for dir in ["knowledge", "src", "tools/BIN"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("tools/BIN/CC.EXE"), b"fake compiler").unwrap();
    std::fs::write(root.join("t.exe"), mz()).unwrap();
    std::fs::write(
        root.join("decovery.toml"),
        format!(
            "schema = 1\n\n[target]\nfile = \"t.exe\"\nsha256 = \"aa\"\nformat = \"mz\"\nprocessor = \"x86\"\n\n\
             [rebuild]\ncompiler = \"aztec-c86-4.2b\"\nrunners = [\"fake\"]\ntool_dir = \"tools\"\n{frames}\n\
             [plugins.fake]\ncommand = [{}, {}]\nenv = {{ FAKE_OMF_DIR = {}, FAKE_OBJ_EXT = \"O\" }}\n",
            quote(python),
            quote(script.to_str().unwrap()),
            quote(objects.path().to_str().unwrap()),
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("knowledge/symbols.toml"),
        "schema = 1\n\n[[symbol]]\naddress = \"seg:0000:0020\"\nkind = \"function\"\nname = \"amain\"\n\
         size = 4\nsource = \"human\"\nconfidence = \"confirmed\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/dsmain.c"),
        "int g[2];\nint amain()\n{\n    return g[0];\n}\n",
    )
    .unwrap();
    std::fs::write(root.join("src/dsdata.c"), "int h[1];\n").unwrap();
    std::fs::write(objects.path().join("DSMAIN.OBJ"), main_object()).unwrap();
    std::fs::write(objects.path().join("DSDATA.OBJ"), data_only_object()).unwrap();
    let workspace = Workspace::open(root).unwrap();
    let lock = workspace.lock(std::time::Duration::from_secs(5)).unwrap();
    let mut analysis = Analysis::new(
        Provider::new("test", "1"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-19",
    );
    let at = Address::Seg {
        seg: 0,
        off: FUNC_AT,
    };
    analysis.functions = vec![AnalyzedFunction::new(at, at, 4)];
    analysis.save(root, &lock).unwrap();
    drop(lock);
    (ws, objects)
}

fn run(root: &std::path::Path, files: &[&str]) -> Response {
    let mut request = BuildRequest::default();
    request.files = files.iter().map(|f| f.to_string()).collect();
    build(root, &request, &Control::progress_only(&|_| {})).unwrap()
}

#[test]
fn summary_and_data_name_the_data_segment_and_its_source() {
    let python = python_or_skip!();
    let (ws, _objects) = workspace(&python, "");
    let response = run(ws.path(), &["dsmain.c"]);
    assert!(
        response
            .summary
            .contains("main program data: 1 of 1 equal (DS 0010 from startup)"),
        "{}",
        response.summary
    );
    assert_eq!(
        response.data["main_data_ds"],
        serde_json::json!({"value": "0010", "source": "startup"})
    );
    let entry = &response.data["main_data"][0];
    assert_eq!(entry["state"], "equal", "{entry}");
    assert_eq!(entry["ds"], "0010");
    assert_eq!(entry["ds_source"], "startup");
}

#[test]
fn configured_frame_is_named_as_the_source() {
    let python = python_or_skip!();
    let (ws, _objects) = workspace(&python, "frames = { DATA = \"seg:0010:0000\" }\n");
    let response = run(ws.path(), &["dsmain.c"]);
    assert!(
        response.summary.contains("(DS 0010 from frame DATA)"),
        "{}",
        response.summary
    );
    assert_eq!(response.data["main_data_ds"]["source"], "frame DATA");
}

#[test]
fn single_data_only_file_is_listed_as_unchecked_with_a_reason() {
    let python = python_or_skip!();
    let (ws, _objects) = workspace(&python, "");
    let response = run(ws.path(), &["dsdata.c"]);
    let entry = &response.data["main_data"][0];
    assert_eq!(entry["state"], "unchecked", "{}", response.data);
    assert_eq!(entry["ds"], "0010");
    assert!(
        entry["findings"][0]
            .as_str()
            .unwrap()
            .contains("none of the object's functions is placed"),
        "{entry}"
    );
    assert_eq!(response.data["main_data_ds"]["source"], "startup");
}
