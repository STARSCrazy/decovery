//! `build` and the library resolver on Aztec library members (ADR 0016), with a synthetic MZ workspace and a
//! synthetic library from the test-only writer (no toolchain files).

#[path = "support/build_fixture.rs"]
mod build_fixture;

use decovery_core::{
    Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash, read_rebuild,
};
use decovery_facade::tools::library::{LibraryFile, library_function};
use decovery_facade::{BuildRequest, Control, Response, build};
use decovery_objects::{
    AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget, write_aztec,
    write_aztec_library,
};

const AMAIN: [u8; 4] = [0xA1, 0x04, 0x00, 0xC3];

fn sym(name: &str, section: AztecSection, value: u16, public: bool) -> AztecSymbolSpec {
    AztecSymbolSpec {
        name: name.into(),
        section,
        value,
        public,
    }
}

/// `strcmp_`: a call to an external (relocated field) and a frame.
fn strcmp_member() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "strcmp".into(),
        code: vec![0xE8, 0, 0, 0x55, 0x8B, 0xEC, 0x5D, 0xC3],
        named: vec![
            sym("strcmp_", AztecSection::Code, 0, true),
            sym("foo_", AztecSection::Extern, 0, true),
        ],
        refs: vec![AztecRefSpec {
            section: AztecSection::Code,
            offset: 1,
            width: 2,
            relative: true,
            target: AztecTarget::Named(1),
            addend: 0,
        }],
        ..AztecModuleSpec::default()
    }
}

/// `$csav` and `$cret`: the knowledge names the pair `aztec_csav` (one function).
fn csav_member() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "csav".into(),
        code: vec![
            0x5B, 0x55, 0x8B, 0xEC, 0x56, 0x57, 0xFF, 0xE3, 0x5F, 0x5E, 0x5D, 0xC3,
        ],
        named: vec![
            sym("$csav", AztecSection::Code, 0, true),
            sym("$cret", AztecSection::Code, 8, true),
        ],
        ..AztecModuleSpec::default()
    }
}

/// `strlen_` and a static helper `count`; the original's `strlen` differs in one byte.
fn strlen_member() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "strlen".into(),
        code: vec![0x55, 0x8B, 0xEC, 0x90, 0x31, 0xC0, 0xC3],
        named: vec![
            sym("strlen_", AztecSection::Code, 0, true),
            sym("count", AztecSection::Code, 4, false),
        ],
        ..AztecModuleSpec::default()
    }
}

/// A one-byte member: too short to be placed by its bytes.
fn tiny_member() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "tiny".into(),
        code: vec![0xC3],
        named: vec![sym("tiny_", AztecSection::Code, 0, true)],
        ..AztecModuleSpec::default()
    }
}

/// A two-byte member, placed only because it fills the room between `strlen` and `OVBGN.O` exactly.
fn fltinit_member() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "fltinit".into(),
        code: vec![0x90, 0xC3],
        named: vec![sym("$fltinit", AztecSection::Code, 0, true)],
        ..AztecModuleSpec::default()
    }
}

/// A single library object (`OVBGN.O`).
fn ovbgn_object() -> Vec<u8> {
    write_aztec(&AztecModuleSpec {
        name: "ovbgn".into(),
        code: vec![0xB8, 0x01, 0x00, 0xC3, 0xCC, 0xCC],
        named: vec![sym("$ovbgn", AztecSection::Code, 0, true)],
        ..AztecModuleSpec::default()
    })
}

fn main_object() -> Vec<u8> {
    write_aztec(&AztecModuleSpec {
        name: "M".into(),
        code: vec![0xA1, 0, 0, 0xC3],
        named: vec![sym("amain_", AztecSection::Code, 0, true)],
        ..AztecModuleSpec::default()
    })
}

/// Functions of the original: (offset, knowledge name, bytes).
fn original() -> Vec<(u16, &'static str, Vec<u8>)> {
    vec![
        (0x20, "amain", AMAIN.to_vec()),
        (
            0x30,
            "strcmp",
            vec![0xE8, 0x12, 0x34, 0x55, 0x8B, 0xEC, 0x5D, 0xC3],
        ),
        (
            0x40,
            "aztec_csav",
            vec![
                0x5B, 0x55, 0x8B, 0xEC, 0x56, 0x57, 0xFF, 0xE3, 0x5F, 0x5E, 0x5D, 0xC3,
            ],
        ),
        (0x50, "strlen", vec![0x55, 0x8B, 0xEC, 0x91]),
        (0x54, "fun_0000_0054", vec![0x31, 0xC0, 0xC3]),
        (0x57, "aztec_fltinit", vec![0x90, 0xC3]),
        (
            0x59,
            "overlay_begin",
            vec![0xB8, 0x01, 0x00, 0xC3, 0xCC, 0xCC],
        ),
        (0x70, "other", vec![0xC3]),
    ]
}

fn mz() -> Vec<u8> {
    let mut image = vec![0u8; 0x200];
    for (at, _, bytes) in original() {
        image[usize::from(at)..usize::from(at) + bytes.len()].copy_from_slice(&bytes);
    }
    let total = 32 + image.len();
    let words: [u16; 14] = [
        0x5A4D,
        (total % 512) as u16,
        total.div_ceil(512) as u16,
        0,
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
    v.extend_from_slice(&image);
    v
}

fn quote(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn at(off: u16) -> Address {
    Address::Seg { seg: 0, off }
}

fn workspace(python: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let ws = tempfile::tempdir().unwrap();
    let objects = tempfile::tempdir().unwrap();
    let root = ws.path();
    let script = std::path::absolute(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/omf_runner.py"),
    )
    .unwrap();
    for dir in ["knowledge", "src", "tools/BIN", "tools/LIB"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("tools/BIN/CC.EXE"), b"fake compiler").unwrap();
    std::fs::write(
        root.join("tools/LIB/C.LIB"),
        write_aztec_library(&[
            tiny_member(),
            strcmp_member(),
            csav_member(),
            strlen_member(),
            fltinit_member(),
        ]),
    )
    .unwrap();
    std::fs::write(root.join("tools/LIB/OVBGN.O"), ovbgn_object()).unwrap();
    std::fs::write(root.join("t.exe"), mz()).unwrap();
    std::fs::write(
        root.join("decovery.toml"),
        format!(
            "schema = 1\n\n[target]\nfile = \"t.exe\"\nsha256 = \"aa\"\nformat = \"mz\"\nprocessor = \"x86\"\n\n\
             [rebuild]\ncompiler = \"aztec-c86-4.2b\"\nrunners = [\"fake\"]\ntool_dir = \"tools\"\n\
             libraries = [\"C.LIB\"]\nlibrary_objects = [\"OVBGN.O\"]\n\n\
             [plugins.fake]\ncommand = [{}, {}]\nenv = {{ FAKE_OMF_DIR = {}, FAKE_OBJ_EXT = \"O\" }}\n",
            quote(python),
            quote(script.to_str().unwrap()),
            quote(objects.path().to_str().unwrap()),
        ),
    )
    .unwrap();
    let mut symbols = String::from("schema = 1\n");
    for (off, name, bytes) in original() {
        if name.starts_with("fun_") {
            continue;
        }
        symbols.push_str(&format!(
            "\n[[symbol]]\naddress = \"seg:0000:{off:04X}\"\nkind = \"function\"\nname = \"{name}\"\n\
             size = {}\nsource = \"human\"\nconfidence = \"confirmed\"\n",
            bytes.len()
        ));
    }
    std::fs::write(root.join("knowledge/symbols.toml"), symbols).unwrap();
    std::fs::write(root.join("src/dsmain.c"), "int amain()\n{\n}\n").unwrap();
    std::fs::write(objects.path().join("DSMAIN.OBJ"), main_object()).unwrap();
    let workspace = Workspace::open(root).unwrap();
    let lock = workspace.lock(std::time::Duration::from_secs(5)).unwrap();
    let mut analysis = Analysis::new(
        Provider::new("test", "1"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-19",
    );
    analysis.functions = original()
        .iter()
        .map(|(off, _, bytes)| {
            AnalyzedFunction::new(at(*off), at(*off + bytes.len() as u16 - 1), 1)
        })
        .collect();
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
fn full_build_compares_the_library_members_at_their_functions() {
    let python = python_or_skip!();
    let (ws, _objects) = workspace(&python);
    let response = run(ws.path(), &[]);
    assert!(
        response
            .summary
            .contains("library: 5 of 6 functions identical (not identical: strlen)"),
        "{}",
        response.summary
    );
    assert!(
        response
            .summary
            .contains("1 functions rebuilt by neither a source nor a library"),
        "{}",
        response.summary
    );
    let lib = &response.data["library"];
    assert_eq!(lib["functions"], 6, "{lib}");
    assert_eq!(lib["remaining"][0], "other (seg:0000:0070)", "{lib}");
    let members: Vec<(&str, &str, &str)> = lib["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["source"].as_str().unwrap(),
                m["address"].as_str().unwrap(),
                m["anchor"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        members,
        [
            ("C.LIB(strcmp)", "seg:0000:0030", "name strcmp_"),
            ("C.LIB(csav)", "seg:0000:0040", "bytes"),
            ("C.LIB(strlen)", "seg:0000:0050", "name strlen_"),
            ("C.LIB(fltinit)", "seg:0000:0057", "bytes"),
            ("OVBGN.O", "seg:0000:0059", "bytes"),
        ]
    );

    let records = read_rebuild(ws.path()).unwrap();
    let by = |off: u16| records.iter().find(|r| r.address == at(off)).unwrap();
    assert_eq!(by(0x20).file.as_deref(), Some("dsmain.c"));
    let csav = by(0x40);
    assert_eq!(csav.file.as_deref(), Some("C.LIB(csav)"));
    assert_eq!(csav.name, "aztec_csav");
    // $csav and $cret are one knowledge function
    assert_eq!(csav.bytes, 12);
    assert_eq!(csav.extra["symbol"].as_str(), Some("$csav"));
    assert_eq!(by(0x30).gaps, 2);
    assert_eq!(by(0x50).differing, 1);
    assert_eq!(by(0x54).file.as_deref(), Some("C.LIB(strlen)"));
    assert_eq!(by(0x54).extra["symbol"].as_str(), Some("count"));
    assert!(records.iter().all(|r| r.address != at(0x70)));

    // a file build keeps the library records
    run(ws.path(), &["dsmain.c"]);
    let again = read_rebuild(ws.path()).unwrap();
    assert_eq!(again.len(), records.len());
}

#[test]
fn library_function_resolves_object_symbols_and_knowledge_addresses() {
    let python = python_or_skip!();
    let (ws, _objects) = workspace(&python);
    let workspace = Workspace::open(ws.path()).unwrap();
    let analysis = Analysis::load(ws.path()).unwrap();
    let program = decovery_facade::program::load(&workspace).unwrap();
    let profile = decovery_toolchain::profile("aztec-c86-4.2b").unwrap();
    let lib = LibraryFile::read(&ws.path().join("tools/LIB/C.LIB"), "C.LIB").unwrap();
    let find = |target: &str, address: Option<Address>| {
        library_function(
            &workspace,
            analysis.as_ref(),
            &program,
            &profile.decoration,
            &lib,
            target,
            address,
        )
        .map(|f| (f.at, f.view.start, f.view.len))
    };
    assert_eq!(find("$csav", None), Some((at(0x40), 0, 12)));
    // `$cret` lies inside the knowledge's function
    assert_eq!(find("$cret", None), Some((at(0x40), 0, 12)));
    assert_eq!(find("strcmp", None), Some((at(0x30), 0, 8)));
    assert_eq!(find("strcmp_", None), Some((at(0x30), 0, 8)));
    assert_eq!(find("aztec_csav", Some(at(0x40))), Some((at(0x40), 0, 12)));
    assert_eq!(find("count", None), Some((at(0x54), 4, 3)));
    assert_eq!(find("tiny_", None), None);
}
