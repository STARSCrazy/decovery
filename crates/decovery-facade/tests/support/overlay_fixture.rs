//! A synthetic Aztec C86 overlay workspace for `diagnose` and `compare`: a one-byte COM main program and two
//! overlays `A` and `B`, each with its own `ovmain` at `ovl:X:0000:5000` (`mov ax, N; ret`). The knowledge names
//! them `A_ovmain` and `B_ovmain` (as Decomp's analysis does); the rebuild records name both `ovmain` (the C name,
//! as `build` records them), with rebuilt objects in `cache/rebuild/obj/`. A's rebuild loads 5 instead of 1, B's
//! is identical. Shared by the facade and CLI tests.

#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use decovery_core::{Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash};
use decovery_objects::{AztecModuleSpec, AztecSection, AztecSymbolSpec, write_aztec};

pub const A_AT: &str = "ovl:A:0000:5000";
pub const B_AT: &str = "ovl:B:0000:5000";

/// An Aztec overlay file: header (magic, code base, code size, data base, data size, BSS, entry), then code.
fn overlay_file(code: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for w in [0xF2u16, 0x5000, code.len() as u16, 0x9000, 0, 0, 0x5000] {
        out.extend(w.to_le_bytes());
    }
    out.extend(code);
    out
}

/// An Aztec object with the public function `ovmain_` = `code`.
pub fn object(code: &[u8]) -> Vec<u8> {
    write_aztec(&AztecModuleSpec {
        name: "M".into(),
        code: code.to_vec(),
        named: vec![AztecSymbolSpec {
            name: "ovmain_".into(),
            section: AztecSection::Code,
            value: 0,
            public: true,
        }],
        ..AztecModuleSpec::default()
    })
}

/// Writes the workspace into `root`; with `main_ovmain`, the main program has a function named `ovmain` too.
pub fn write(root: &Path, main_ovmain: bool) {
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::create_dir_all(root.join("cache/rebuild/obj")).unwrap();
    std::fs::write(root.join("t.com"), [0xC3u8, 0xC3]).unwrap();
    std::fs::write(root.join("A.OVR"), overlay_file(&[0xB8, 1, 0, 0xC3])).unwrap();
    std::fs::write(root.join("B.OVR"), overlay_file(&[0xB8, 2, 0, 0xC3])).unwrap();
    let mut config = String::from(
        "schema = 1

[target]
file = \"t.com\"
sha256 = \"aa\"
format = \"com\"
processor = \"x86\"

[[target.segment]]
name = \"code\"
start = \"seg:0000:0100\"
length = 2
file_offset = 0
permissions = \"rx\"

[rebuild]
compiler = \"aztec-c86-4.2b\"
",
    );
    for o in ["A", "B"] {
        config.push_str(&format!(
            "
[[target.segment]]
name = \"{o}.code\"
start = \"ovl:{o}:0000:5000\"
length = 4
file_offset = 14
permissions = \"rx\"

[[overlay]]
name = \"{o}\"
file = \"{o}.OVR\"
sha256 = \"bb\"
format = \"aztec-c86\"
size = 18
"
        ));
    }
    std::fs::write(root.join("decovery.toml"), config).unwrap();
    let mut symbols = String::from("schema = 1\n\n");
    let mut named = vec![(A_AT, "A_ovmain", 4), (B_AT, "B_ovmain", 4)];
    if main_ovmain {
        named.push(("seg:0000:0100", "ovmain", 1));
    }
    for (address, name, size) in &named {
        symbols.push_str(&format!(
            "[[symbol]]\naddress = \"{address}\"\nkind = \"function\"\nname = \"{name}\"\nsize = {size}\nsource = \"human\"\nconfidence = \"confirmed\"\n\n"
        ));
    }
    std::fs::write(root.join("knowledge/symbols.toml"), symbols).unwrap();
    std::fs::write(
        root.join("knowledge/rebuild.toml"),
        format!(
            "schema = 1

[[function]]
address = \"{A_AT}\"
name = \"ovmain\"
file = \"a.c\"
result = \"differs\"

[[function]]
address = \"{B_AT}\"
name = \"ovmain\"
file = \"b.c\"
result = \"identical\"
"
        ),
    )
    .unwrap();
    let obj = root.join("cache/rebuild/obj");
    std::fs::write(obj.join("a.obj"), object(&[0xB8, 5, 0, 0xC3])).unwrap();
    std::fs::write(obj.join("b.obj"), object(&[0xB8, 2, 0, 0xC3])).unwrap();

    let ws = Workspace::open(root).unwrap();
    let lock = ws.lock(Duration::ZERO).unwrap();
    let mut a = Analysis::new(
        Provider::new("ghidra", "11.3"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-19",
    );
    let at = |s: &str| s.parse::<Address>().unwrap();
    a.functions = vec![
        AnalyzedFunction::new(at("seg:0000:0100"), at("seg:0000:0100"), 1),
        AnalyzedFunction::new(at(A_AT), at("ovl:A:0000:5003"), 4),
        AnalyzedFunction::new(at(B_AT), at("ovl:B:0000:5003"), 4),
    ];
    a.save(root, &lock).unwrap();
}
