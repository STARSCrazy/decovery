//! `build` with `[link]` (ADR 0018): the whole-program link of an Aztec C86 root program and its overlay through the
//! fake runner's LN, compared with the original files. Synthetic workspace, objects and linked files only.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::path::Path;

use decovery_core::{Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash};
use decovery_facade::{BuildRequest, Control, Response, build};
use decovery_objects::{AztecModuleSpec, AztecSection, AztecSymbolSpec, write_aztec};

fn object(name: &str, code: &[u8]) -> Vec<u8> {
    write_aztec(&AztecModuleSpec {
        name: name.into(),
        code: code.to_vec(),
        named: vec![AztecSymbolSpec {
            name: format!("{name}_"),
            section: AztecSection::Code,
            value: 0,
            public: true,
        }],
        ..AztecModuleSpec::default()
    })
}

const MAIN: [u8; 4] = [0xB8, 0x07, 0x00, 0xC3];
const VONE: [u8; 4] = [0xB8, 0x01, 0x00, 0xC3];

fn mz() -> Vec<u8> {
    let mut image = vec![0u8; 0x40];
    image[0x20..0x24].copy_from_slice(&MAIN);
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
    let mut v: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    v.resize(32, 0);
    v.extend_from_slice(&image);
    v
}

fn overlay(code: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = [0xF2u16, 0x5000, code.len() as u16, 0x9000, 0, 0, 0x5000]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    out.extend(code);
    out
}

fn quote(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// A workspace with `dsmain.c` (root) and `vone.c` (overlay VONE) and the fake runner; `link` is the `[link]` TOML.
fn workspace(python: &str, link: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let ws = tempfile::tempdir().unwrap();
    let objects = tempfile::tempdir().unwrap();
    let root = ws.path();
    let script = std::path::absolute(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/omf_runner.py"),
    )
    .unwrap();
    for dir in ["knowledge", "src", "tools/BIN", "tools/LIB"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("tools/BIN/CC.EXE"), b"fake compiler").unwrap();
    std::fs::write(root.join("tools/LIB/OVLD.O"), object("ovld", &[0xCB])).unwrap();
    std::fs::write(root.join("tools/LIB/OVBGN.O"), object("ovbgn", &[0xCB])).unwrap();
    std::fs::write(root.join("t.exe"), mz()).unwrap();
    std::fs::write(root.join("VONE.OVR"), overlay(&VONE)).unwrap();
    std::fs::write(
        root.join("decovery.toml"),
        format!(
            "schema = 1\n\n[target]\nfile = \"t.exe\"\nsha256 = \"aa\"\nformat = \"mz\"\nprocessor = \"x86\"\n\n\
             [[target.segment]]\nname = \"code\"\nstart = \"seg:0000:0000\"\nlength = 64\nfile_offset = 32\n\
             permissions = \"rwx\"\n\n\
             [[target.segment]]\nname = \"VONE.code\"\nstart = \"ovl:VONE:0000:5000\"\nlength = 4\n\
             file_offset = 14\npermissions = \"rx\"\n\n\
             [[overlay]]\nname = \"VONE\"\nfile = \"VONE.OVR\"\nsha256 = \"bb\"\nformat = \"aztec-c86\"\nsize = 18\n\n\
             [rebuild]\ncompiler = \"aztec-c86-4.2b\"\nrunners = [\"fake\"]\ntool_dir = \"tools\"\n\
             libraries = [\"C.LIB\"]\nlibrary_objects = [\"OVLD.O\", \"OVBGN.O\"]\n\n\
             [plugins.fake]\ncommand = [{}, {}]\nenv = {{ FAKE_OMF_DIR = {}, FAKE_OBJ_EXT = \"O\" }}\n\n{link}",
            quote(python),
            quote(script.to_str().unwrap()),
            quote(objects.path().to_str().unwrap()),
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("knowledge/symbols.toml"),
        "schema = 1\n\n[[symbol]]\naddress = \"seg:0000:0020\"\nkind = \"function\"\nname = \"main\"\nsize = 4\n\
         source = \"human\"\nconfidence = \"confirmed\"\n\n\
         [[symbol]]\naddress = \"ovl:VONE:0000:5000\"\nkind = \"function\"\nname = \"vone\"\nsize = 4\n\
         source = \"human\"\nconfidence = \"confirmed\"\n",
    )
    .unwrap();
    std::fs::write(root.join("src/dsmain.c"), "int main()\n{\n}\n").unwrap();
    std::fs::write(root.join("src/vone.c"), "int vone()\n{\n}\n").unwrap();
    std::fs::write(objects.path().join("DSMAIN.OBJ"), object("main", &MAIN)).unwrap();
    std::fs::write(objects.path().join("VONE.OBJ"), object("vone", &VONE)).unwrap();
    let workspace = Workspace::open(root).unwrap();
    let lock = workspace.lock(std::time::Duration::from_secs(5)).unwrap();
    let mut analysis = Analysis::new(
        Provider::new("test", "1"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-19",
    );
    let at = |s: &str| s.parse::<Address>().unwrap();
    analysis.functions = vec![
        AnalyzedFunction::new(at("seg:0000:0020"), at("seg:0000:0023"), 1),
        AnalyzedFunction::new(at("ovl:VONE:0000:5000"), at("ovl:VONE:0000:5003"), 1),
    ];
    analysis.save(root, &lock).unwrap();
    drop(lock);
    (ws, objects)
}

const LINK: &str = "[link]\nobjects = [\"dsmain.c\", \"OVLD.O\"]\nflags = \"+c af02\"\n\
                    overlay_objects = [\"OVBGN.O\"]\n\n[[link.overlay]]\nname = \"VONE\"\n";

fn run(root: &Path) -> Response {
    build(
        root,
        &BuildRequest::default(),
        &Control::progress_only(&|_| {}),
    )
    .unwrap()
}

fn log(objects: &Path) -> Vec<String> {
    std::fs::read_to_string(objects.join("link.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn full_build_links_root_and_overlay_and_compares_whole_files() {
    let python = python_or_skip!();
    let (ws, objects) = workspace(&python, LINK);
    std::fs::write(objects.path().join("T.EXE"), mz()).unwrap();
    std::fs::write(objects.path().join("VONE.OVR"), overlay(&VONE)).unwrap();
    let response = run(ws.path());
    assert!(
        response
            .summary
            .contains("link: root equal; overlays 1 of 1 equal"),
        "{}",
        response.summary
    );
    assert_eq!(
        log(objects.path()),
        [
            r"LN +c af02 -r -o T.EXE DSMAIN.O D:\LIB\OVLD.O -lc",
            r"LN -o VONE.OVR VONE.O D:\LIB\OVBGN.O T.RSM -lc",
        ]
    );
    let link = &response.data["link"];
    assert_eq!(link["equal"], true, "{link}");
    assert_eq!(link["root"]["result"], "equal", "{link}");
    assert_eq!(link["overlays"][0]["result"], "equal", "{link}");
    assert_eq!(
        std::fs::read(ws.path().join("cache/rebuild/link/VONE.OVR")).unwrap(),
        overlay(&VONE)
    );
}

#[test]
fn differences_are_named_by_region_header_field_and_knowledge_name() {
    let python = python_or_skip!();
    let (ws, objects) = workspace(&python, LINK);
    let mut exe = mz();
    exe[0x10] = 0x02; // sp
    exe[32 + 0x21] = 0x08; // main+0x1
    std::fs::write(objects.path().join("T.EXE"), exe).unwrap();
    std::fs::write(
        objects.path().join("VONE.OVR"),
        overlay(&[0xB8, 0x01, 0x09, 0xC3]),
    )
    .unwrap();
    let response = run(ws.path());
    assert!(
        response
            .summary
            .contains("link: root differs; overlays 0 of 1 equal (not equal: VONE)"),
        "{}",
        response.summary
    );
    let link = &response.data["link"];
    assert_eq!(link["equal"], false);
    let root = &link["root"];
    assert_eq!(root["differing"], 2, "{root}");
    assert_eq!(root["first_difference"]["field"], "sp", "{root}");
    assert_eq!(root["header"][0]["field"], "sp", "{root}");
    assert_eq!(root["header"][0]["original"], 0x0100, "{root}");
    assert_eq!(root["header"][0]["rebuilt"], 0x0102, "{root}");
    let o = &link["overlays"][0];
    assert_eq!(o["first_difference"]["offset"], 16, "{o}");
    assert_eq!(o["first_difference"]["region"], "code", "{o}");
    assert_eq!(
        o["first_difference"]["address"], "ovl:VONE:0000:5002",
        "{o}"
    );
    assert_eq!(o["first_difference"]["name"], "vone+0x2", "{o}");
    let hints = response.data["hints"].to_string();
    assert!(
        hints.contains("link T.EXE: 2 bytes differ, first at 0x10 (header field sp)"),
        "{hints}"
    );
    assert!(
        hints.contains(
            "link VONE.OVR: 1 bytes differ, first at 0x10 (code) at ovl:VONE:0000:5002 in vone+0x2"
        ),
        "{hints}"
    );
}

#[test]
fn a_root_that_does_not_link_leaves_the_overlays_unlinked() {
    let python = python_or_skip!();
    let (ws, objects) = workspace(&python, LINK);
    let response = run(ws.path());
    assert!(
        response
            .summary
            .contains("link: root error; overlays 0 of 1 equal"),
        "{}",
        response.summary
    );
    let link = &response.data["link"];
    assert_eq!(link["root"]["result"], "error");
    assert!(
        link["root"]["message"]
            .as_str()
            .unwrap()
            .contains("Undefined symbol"),
        "{link}"
    );
    assert!(
        link["overlays"][0]["message"]
            .as_str()
            .unwrap()
            .contains("T.EXE did not link"),
        "{link}"
    );
    // only the root link ran
    assert_eq!(log(objects.path()).len(), 1);
}

#[test]
fn a_long_object_list_goes_into_a_control_file() {
    let python = python_or_skip!();
    let names: Vec<String> = (0..16).map(|i| format!("vp{i:02}.c")).collect();
    let link = format!(
        "{LINK}objects = [{}]\n",
        names
            .iter()
            .map(|n| quote(n))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let (ws, objects) = workspace(&python, &link);
    for n in &names {
        std::fs::write(ws.path().join("src").join(n), "int x;\n").unwrap();
        let stem = n.trim_end_matches(".c").to_ascii_uppercase();
        std::fs::write(
            objects.path().join(format!("{stem}.OBJ")),
            object("x", &[0x90]),
        )
        .unwrap();
    }
    std::fs::write(objects.path().join("T.EXE"), mz()).unwrap();
    std::fs::write(objects.path().join("VONE.OVR"), overlay(&VONE)).unwrap();
    let response = run(ws.path());
    assert!(
        response.summary.contains("overlays 1 of 1 equal"),
        "{}",
        response.summary
    );
    let lines = log(objects.path());
    assert_eq!(
        lines[1],
        r"LN -o VONE.OVR -f VONE.LNK D:\LIB\OVBGN.O T.RSM -lc"
    );
    let listed: Vec<String> = names
        .iter()
        .map(|n| n.trim_end_matches(".c").to_ascii_uppercase() + ".O")
        .collect();
    assert_eq!(lines[2], format!("  -f {}", listed.join(" ")));
}
