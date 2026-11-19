//! `build` on an assembler source of an Aztec C86 workspace (synthetic MZ, fake runner serving a hand-built `.O`):
//! the profile's assembler (AS) goes before the built-in one, a function spans its local labels, and AS errors are
//! reported with their line.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use decovery_core::{Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash};
use decovery_facade::{BuildRequest, Control, Response, build};
use decovery_objects::{
    AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget, write_aztec,
};

const KEY_AT: u16 = 0x20;
const NEXT_AT: u16 = 0x27;

/// `key_`: `jmp short l1` (left to the linker, BREL), `l1: call next_` (WREL), `l2: db 55h` (data in the code
/// segment), `ret`; `next_`: `ret`. `l1` and `l2` are named but not public, as AS writes local labels.
fn asm_object() -> Vec<u8> {
    let label = |name: &str, value: u16, public: bool| AztecSymbolSpec {
        name: name.into(),
        section: AztecSection::Code,
        value,
        public,
    };
    write_aztec(&AztecModuleSpec {
        name: "DSASM".into(),
        code: vec![0xEB, 0x00, 0xE8, 0x00, 0x00, 0x55, 0xC3, 0xC3],
        named: vec![
            label("key_", 0, true),
            label("l1", 2, false),
            label("l2", 5, false),
            label("next_", 7, true),
        ],
        refs: vec![
            AztecRefSpec {
                section: AztecSection::Code,
                offset: 1,
                width: 1,
                relative: true,
                target: AztecTarget::Section(AztecSection::Code, 2),
                addend: 0,
            },
            AztecRefSpec {
                section: AztecSection::Code,
                offset: 3,
                width: 2,
                relative: true,
                target: AztecTarget::Section(AztecSection::Code, 7),
                addend: 0,
            },
        ],
        ..AztecModuleSpec::default()
    })
}

/// MZ file with the linked bytes of the object at 0020.
fn mz() -> Vec<u8> {
    let mut image = vec![0u8; 0x100];
    let at = usize::from(KEY_AT);
    image[at..at + 8].copy_from_slice(&[0xEB, 0x00, 0xE8, 0x02, 0x00, 0x55, 0xC3, 0xC3]);
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

/// A byte listing the built-in assembler takes too: the profile's assembler must still go first.
const SOURCE: &str = "codeseg segment byte public 'code'\npublic key_\npublic next_\n\
                      key_:\ndb 0EBh,0,0E8h,2,0,55h,0C3h\nnext_:\ndb 0C3h\ncodeseg ends\nend\n";

/// The workspace; `env` is added to the fake runner's environment. Without `compiler`, the toolchain directory
/// lacks CC.EXE (no assembler available).
fn workspace(python: &str, env: &str, compiler: bool) -> (tempfile::TempDir, tempfile::TempDir) {
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
    if compiler {
        std::fs::write(root.join("tools/BIN/CC.EXE"), b"fake compiler").unwrap();
    }
    std::fs::write(root.join("t.exe"), mz()).unwrap();
    std::fs::write(
        root.join("decovery.toml"),
        format!(
            "schema = 1\n\n[target]\nfile = \"t.exe\"\nsha256 = \"aa\"\nformat = \"mz\"\nprocessor = \"x86\"\n\n\
             [rebuild]\ncompiler = \"aztec-c86-4.2b\"\nrunners = [\"fake\"]\ntool_dir = \"tools\"\n\n\
             [plugins.fake]\ncommand = [{}, {}]\nenv = {{ FAKE_OMF_DIR = {}, FAKE_OBJ_EXT = \"O\"{env} }}\n",
            quote(python),
            quote(script.to_str().unwrap()),
            quote(objects.path().to_str().unwrap()),
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("knowledge/symbols.toml"),
        "schema = 1\n\n[[symbol]]\naddress = \"seg:0000:0020\"\nkind = \"function\"\nname = \"key\"\n\
         source = \"human\"\nconfidence = \"confirmed\"\n\n\
         [[symbol]]\naddress = \"seg:0000:0027\"\nkind = \"function\"\nname = \"next\"\n\
         source = \"human\"\nconfidence = \"confirmed\"\n",
    )
    .unwrap();
    std::fs::write(root.join("src/dsasm.asm"), SOURCE).unwrap();
    std::fs::write(objects.path().join("DSASM.OBJ"), asm_object()).unwrap();
    let workspace = Workspace::open(root).unwrap();
    let lock = workspace.lock(std::time::Duration::from_secs(5)).unwrap();
    let mut analysis = Analysis::new(
        Provider::new("test", "1"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-19",
    );
    let key = Address::Seg {
        seg: 0,
        off: KEY_AT,
    };
    let next = Address::Seg {
        seg: 0,
        off: NEXT_AT,
    };
    analysis.functions = vec![
        AnalyzedFunction::new(key, key, 7),
        AnalyzedFunction::new(next, next, 1),
    ];
    analysis.save(root, &lock).unwrap();
    drop(lock);
    (ws, objects)
}

fn run(root: &std::path::Path) -> Response {
    let mut request = BuildRequest::default();
    request.files = vec!["dsasm.asm".to_string()];
    build(root, &request, &Control::progress_only(&|_| {})).unwrap()
}

fn function<'a>(response: &'a Response, name: &str) -> &'a serde_json::Value {
    response.data["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("no {name} in {}", response.data))
}

#[test]
fn aztec_assembler_goes_first_and_a_function_spans_its_local_labels() {
    let python = python_or_skip!();
    let (ws, objects) = workspace(&python, "", true);
    let response = run(ws.path());
    let calls = std::fs::read_to_string(objects.path().join("calls.log")).unwrap();
    assert_eq!(calls.trim(), "DSASM.ASM", "AS ran on the source");
    let key = function(&response, "key");
    assert_eq!(key["verdict"], "identical", "{key}");
    assert_eq!(function(&response, "next")["verdict"], "identical");
    let records =
        std::fs::read_to_string(ws.path().join(decovery_core::records::REBUILD_FILE)).unwrap();
    assert!(
        records.contains("compiler = \"aztec-c86-4.2b\""),
        "{records}"
    );
    // key_ was compared over all its 7 bytes, not up to its first local label
    assert_eq!(key["bytes"], 7, "{key}");
    assert_eq!(response.data["functions"].as_array().unwrap().len(), 2);
}

#[test]
fn without_the_assembler_the_built_in_one_is_the_fallback() {
    let python = python_or_skip!();
    let (ws, objects) = workspace(&python, "", false);
    let response = run(ws.path());
    assert!(!objects.path().join("calls.log").exists());
    let records =
        std::fs::read_to_string(ws.path().join(decovery_core::records::REBUILD_FILE)).unwrap();
    assert!(
        records.contains("compiler = \"builtin-asm/1\""),
        "{records}"
    );
    assert_eq!(function(&response, "key")["verdict"], "identical");
}

#[test]
fn assembler_errors_carry_their_line() {
    let python = python_or_skip!();
    let (ws, _objects) = workspace(
        &python,
        ", FAKE_AS_ERROR = \"12:undefined symbol foo_\"",
        true,
    );
    let response = run(ws.path());
    let hints = &response.data["hints"];
    assert!(
        hints
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h == "dsasm.asm: line 12: undefined symbol foo_"),
        "{hints}"
    );
}

/// Three data bytes before `key_` (a mode byte and a word holding `key_`'s address, relocated), then the code of
/// [`asm_object`]; the public names are `key` and `next` (`known`) or names the original lacks.
fn lead_object(known: bool) -> Vec<u8> {
    let (key, next) = if known {
        ("key_", "next_")
    } else {
        ("zzz_", "yyy_")
    };
    let label = |name: &str, value: u16, public: bool| AztecSymbolSpec {
        name: name.into(),
        section: AztecSection::Code,
        value,
        public,
    };
    let code_ref = |offset: u16, width: u8, relative: bool, target: u16| AztecRefSpec {
        section: AztecSection::Code,
        offset,
        width,
        relative,
        target: AztecTarget::Section(AztecSection::Code, target),
        addend: 0,
    };
    write_aztec(&AztecModuleSpec {
        name: "DSASM".into(),
        code: vec![
            0x07, 0x00, 0x00, 0xEB, 0x00, 0xE8, 0x00, 0x00, 0x55, 0xC3, 0xC3,
        ],
        named: vec![
            label(key, 3, true),
            label("l1", 5, false),
            label("l2", 8, false),
            label(next, 10, true),
        ],
        refs: vec![
            code_ref(1, 2, false, 3),
            code_ref(4, 1, true, 5),
            code_ref(6, 2, true, 10),
        ],
        ..AztecModuleSpec::default()
    })
}

/// [`workspace`] with [`lead_object`] served and `lead` linked in front of `key` (at 001D).
fn lead_workspace(
    python: &str,
    lead: [u8; 3],
    known: bool,
) -> (tempfile::TempDir, tempfile::TempDir) {
    let (ws, objects) = workspace(python, "", true);
    let mut exe = mz();
    let at = 32 + usize::from(KEY_AT) - 3;
    exe[at..at + 3].copy_from_slice(&lead);
    std::fs::write(ws.path().join("t.exe"), exe).unwrap();
    std::fs::write(objects.path().join("DSASM.OBJ"), lead_object(known)).unwrap();
    (ws, objects)
}

#[test]
fn bytes_before_the_first_public_label_are_compared_with_link_gaps() {
    let python = python_or_skip!();
    // the relocated word holds the linked address of key (0020): a link gap
    let (ws, _objects) = lead_workspace(&python, [0x07, 0x20, 0x00], true);
    let response = run(ws.path());
    let leading = &response.data["files"][0]["leading"];
    assert_eq!(leading["state"], "equal", "{}", response.data);
    assert_eq!(leading["bytes"], 3);
    assert_eq!(leading["address"], "seg:0000:001D");
    assert!(
        response
            .summary
            .contains("dsasm.asm: 3 bytes before the first public label: equal"),
        "{}",
        response.summary
    );
    assert_eq!(response.data["counts"]["leading_differs"], 0);
    assert_eq!(function(&response, "key")["verdict"], "identical");
}

#[test]
fn differing_bytes_before_the_first_public_label_fail_the_build() {
    let python = python_or_skip!();
    let (ws, _objects) = lead_workspace(&python, [0x08, 0x20, 0x00], true);
    let response = run(ws.path());
    let leading = &response.data["files"][0]["leading"];
    assert_eq!(leading["state"], "differs", "{}", response.data);
    assert_eq!(leading["differing"], 1);
    assert_eq!(response.data["counts"]["leading_differs"], 1);
    assert!(
        response
            .summary
            .contains("dsasm.asm: 3 bytes before the first public label: differs"),
        "{}",
        response.summary
    );
}

#[test]
fn bytes_before_the_first_public_label_without_a_placed_function_are_unchecked() {
    let python = python_or_skip!();
    let (ws, _objects) = lead_workspace(&python, [0x07, 0x20, 0x00], false);
    let response = run(ws.path());
    let leading = &response.data["files"][0]["leading"];
    assert_eq!(leading["state"], "unchecked", "{}", response.data);
    assert!(
        leading["reason"]
            .as_str()
            .unwrap()
            .contains("no public function"),
        "{leading}"
    );
    assert!(
        response
            .summary
            .contains("dsasm.asm: 3 bytes before the first public label: unchecked ("),
        "{}",
        response.summary
    );
}
