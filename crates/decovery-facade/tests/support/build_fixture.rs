//! A synthetic MZ workspace for `build`: three functions in the original, sources in `src/`, Turbo C profile with
//! a fake tool directory and the fake runner `tests/fixtures/omf_runner.py`, which serves OBJs the test writes
//! with [`write_obj`]. Shared by the facade and CLI tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_core::{Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash};

pub const ADD: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x8B, 0x46, 0x04, 0x03, 0x46, 0x06, 0x5D, 0xC3,
];
pub const SUB: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x8B, 0x46, 0x04, 0x2B, 0x46, 0x06, 0x5D, 0xC3,
];
pub const ZED: &[u8] = &[0x55, 0x8B, 0xEC, 0x5D, 0xC3];

pub const ADD_AT: Address = Address::Seg { seg: 0, off: 0x10 };
pub const SUB_AT: Address = Address::Seg { seg: 0, off: 0x20 };
pub const ZED_AT: Address = Address::Seg { seg: 0, off: 0x30 };

pub const A_C: &str = "int add(int a, int b)\n{\n    return a + b;\n}\n\nint sub(int a, int b)\n{\n    return a - b;\n}\n";
pub const Z_C: &str = "void zed(void)\n{\n}\n";

pub fn python() -> Option<String> {
    let candidate = std::env::var("DECOVERY_PYTHON").unwrap_or_else(|_| "python".into());
    let ok = std::process::Command::new(&candidate)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then_some(candidate)
}

#[macro_export]
macro_rules! python_or_skip {
    () => {
        match $crate::build_fixture::python() {
            Some(p) => p,
            None => {
                eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
                return;
            }
        }
    };
}

fn rec(t: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len() + 1;
    let mut v = vec![t, (n & 0xFF) as u8, (n >> 8) as u8];
    v.extend_from_slice(body);
    let sum: u32 = v.iter().map(|&b| u32::from(b)).sum();
    v.push(((256 - sum % 256) % 256) as u8);
    v
}

fn pstr(s: &str) -> Vec<u8> {
    let mut v = vec![s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

/// A 16-bit OMF object with one code section `_TEXT` holding `functions` (public name, bytes) back to back.
pub fn omf(functions: &[(&str, &[u8])]) -> Vec<u8> {
    let code: Vec<u8> = functions
        .iter()
        .flat_map(|(_, b)| b.iter().copied())
        .collect();
    let mut out = rec(0x80, &pstr("T.C"));
    out.extend(rec(
        0x96,
        &["_TEXT", "CODE"]
            .iter()
            .flat_map(|n| pstr(n))
            .collect::<Vec<_>>(),
    ));
    let mut segdef = vec![0x48];
    segdef.extend_from_slice(&(code.len() as u16).to_le_bytes());
    segdef.extend_from_slice(&[1, 2, 1]);
    out.extend(rec(0x98, &segdef));
    let mut pubdef = vec![0, 1];
    let mut offset = 0u16;
    for (name, bytes) in functions {
        pubdef.extend(pstr(name));
        pubdef.extend_from_slice(&offset.to_le_bytes());
        pubdef.push(0);
        offset += bytes.len() as u16;
    }
    out.extend(rec(0x90, &pubdef));
    let mut ledata = vec![1, 0, 0];
    ledata.extend_from_slice(&code);
    out.extend(rec(0xA0, &ledata));
    out.extend(rec(0x8A, &[0]));
    out
}

/// Like [`omf`], for functions that each load a word from a variable (`mov ax,[var]`, the offset field at byte 1):
/// `(public name, bytes, variable)`. `_DATA` is in `DGROUP`; each field is a 16-bit offset fixup with frame `DGROUP`
/// against the external symbol `variable` (`_g1`).
pub fn omf_with_refs(functions: &[(&str, &[u8], &str)]) -> Vec<u8> {
    let code: Vec<u8> = functions
        .iter()
        .flat_map(|(_, b, _)| b.iter().copied())
        .collect();
    let mut out = rec(0x80, &pstr("T.C"));
    let names = ["_TEXT", "CODE", "_DATA", "DATA", "DGROUP"];
    out.extend(rec(
        0x96,
        &names.iter().flat_map(|n| pstr(n)).collect::<Vec<_>>(),
    ));
    let mut text = vec![0x48];
    text.extend_from_slice(&(code.len() as u16).to_le_bytes());
    text.extend_from_slice(&[1, 2, 1]);
    out.extend(rec(0x98, &text));
    out.extend(rec(0x98, &[0x48, 4, 0, 3, 4, 1]));
    out.extend(rec(0x9A, &[5, 0xFF, 2]));
    let mut externals: Vec<&str> = Vec::new();
    for (_, _, variable) in functions {
        if !externals.contains(variable) {
            externals.push(variable);
        }
    }
    let mut extdef = Vec::new();
    for name in &externals {
        extdef.extend(pstr(name));
        extdef.push(0);
    }
    out.extend(rec(0x8C, &extdef));
    let mut pubdef = vec![0, 1];
    let mut offset = 0u16;
    for (name, bytes, _) in functions {
        pubdef.extend(pstr(name));
        pubdef.extend_from_slice(&offset.to_le_bytes());
        pubdef.push(0);
        offset += bytes.len() as u16;
    }
    out.extend(rec(0x90, &pubdef));
    let mut ledata = vec![1, 0, 0];
    ledata.extend_from_slice(&code);
    out.extend(rec(0xA0, &ledata));
    let mut fixups = Vec::new();
    let mut at = 0u16;
    for (_, bytes, variable) in functions {
        let locat = 0xC400 | (at + 1); // segment-relative, 16-bit offset
        fixups.extend_from_slice(&locat.to_be_bytes());
        // frame method 1 (group), target method 2 (external) with displacement
        fixups.extend_from_slice(&[0x12, 1]);
        let external = externals.iter().position(|e| e == variable).unwrap_or(0) + 1;
        fixups.push(external as u8);
        fixups.extend_from_slice(&0u16.to_le_bytes());
        at += bytes.len() as u16;
    }
    out.extend(rec(0x9C, &fixups));
    out.extend(rec(0x8A, &[0]));
    out
}

/// MZ file with a 32-byte header and a 0x100-byte image holding ADD, SUB and ZED at their addresses.
fn mz() -> Vec<u8> {
    let mut image = vec![0x90u8; 0x100];
    for (at, bytes) in [(0x10, ADD), (0x20, SUB), (0x30, ZED)] {
        image[at..at + bytes.len()].copy_from_slice(bytes);
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
        0x10,
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

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

const SYMBOLS: &str = r#"schema = 1

[[symbol]]
address = "seg:0000:0010"
kind = "function"
name = "add"
source = "human"
confidence = "confirmed"

[[symbol]]
address = "seg:0000:0020"
kind = "function"
name = "sub"
source = "human"
confidence = "confirmed"

[[symbol]]
address = "seg:0000:0030"
kind = "function"
name = "zed"
source = "human"
confidence = "confirmed"
"#;

/// The workspace and the directory the fake runner serves objects from.
pub struct Fixture {
    pub ws: tempfile::TempDir,
    pub objects: tempfile::TempDir,
}

impl Fixture {
    pub fn root(&self) -> &Path {
        self.ws.path()
    }

    /// Writes `<stem>.OBJ` for the fake runner.
    pub fn write_obj(&self, stem: &str, functions: &[(&str, &[u8])]) {
        std::fs::write(
            self.objects.path().join(format!("{stem}.OBJ")),
            omf(functions),
        )
        .unwrap();
    }

    /// Writes `<stem>.OBJ` from bytes (see [`omf_with_refs`]).
    pub fn write_raw_obj(&self, stem: &str, bytes: &[u8]) {
        std::fs::write(self.objects.path().join(format!("{stem}.OBJ")), bytes).unwrap();
    }

    /// Replaces the bytes of the original at `offset` of the image of `t.exe` (the image starts at file offset 32).
    pub fn patch_original(&self, offset: usize, bytes: &[u8]) {
        let path = self.root().join("t.exe");
        let mut file = std::fs::read(&path).unwrap();
        file[32 + offset..32 + offset + bytes.len()].copy_from_slice(bytes);
        std::fs::write(path, file).unwrap();
    }

    pub fn write_source(&self, name: &str, text: &str) {
        std::fs::write(self.root().join("src").join(name), text).unwrap();
    }

    /// Lines of a log the fake runner writes (`calls.log`, `requests.log`).
    pub fn log(&self, name: &str) -> Vec<String> {
        std::fs::read_to_string(self.objects.path().join(name))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    pub fn rebuild_path(&self) -> PathBuf {
        self.root().join("knowledge/rebuild.toml")
    }
}

/// The workspace with `a.c` (add, sub) and `z.c` (zed) in `src/` and objects for both; `runner_env` is added to
/// the fake runner's environment table.
pub fn fixture(python: &str, runner_env: &str) -> Fixture {
    let ws = tempfile::tempdir().unwrap();
    let objects = tempfile::tempdir().unwrap();
    let root = ws.path();
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../decovery-facade/tests/fixtures/omf_runner.py");
    let script = std::path::absolute(script).unwrap();
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tools")).unwrap();
    std::fs::write(root.join("tools/TCC.EXE"), b"fake compiler").unwrap();
    std::fs::write(root.join("t.exe"), mz()).unwrap();
    let config = format!(
        r#"schema = 1

[target]
file = "t.exe"
sha256 = "aa"
format = "mz"
processor = "x86"

[rebuild]
compiler = "turbo-c-2.0"
flags = "-ms -O"
runners = ["fake"]
tool_dir = "tools"

[plugins.fake]
command = [{}, {}]
env = {{ FAKE_OMF_DIR = {}{runner_env} }}
"#,
        toml_string(python),
        toml_string(script.to_str().unwrap()),
        toml_string(objects.path().to_str().unwrap()),
    );
    std::fs::write(root.join("decovery.toml"), config).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), SYMBOLS).unwrap();
    std::fs::write(root.join("src/a.c"), A_C).unwrap();
    std::fs::write(root.join("src/z.c"), Z_C).unwrap();

    let workspace = Workspace::open(root).unwrap();
    let lock = workspace.lock(Duration::from_secs(5)).unwrap();
    let mut analysis = Analysis::new(
        Provider::new("test", "1"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-06",
    );
    let seg = |off: u16| Address::Seg { seg: 0, off };
    analysis.functions = vec![
        AnalyzedFunction::new(seg(0x10), seg(0x1A), 11),
        AnalyzedFunction::new(seg(0x20), seg(0x2A), 11),
        AnalyzedFunction::new(seg(0x30), seg(0x34), 5),
    ];
    analysis.save(root, &lock).unwrap();
    for at in [0x10, 0x20, 0x30] {
        Analysis::save_decompiled(root, seg(at), "\nvoid f(void) {}\n", &lock).unwrap();
    }
    drop(lock);

    let fixture = Fixture { ws, objects };
    fixture.write_obj("A", &[("_add", ADD), ("_sub", SUB)]);
    fixture.write_obj("Z", &[("_zed", ZED)]);
    fixture
}
