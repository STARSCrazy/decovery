//! Parity with Decomp on a private executable. Run with `cargo test -p decovery-loaders -- --ignored`.
//!
//! Needs `DECOVERY_LOCAL_WORKSPACE` (a Decomp workspace; the target comes from its `decomp.toml`) and
//! `DECOVERY_GOLDEN_DIR` (`le.json` from `tools/golden/le_golden.py`).

use std::path::PathBuf;

use decovery_core::{Address, RelocKind};
use decovery_loaders::load_le;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn num(v: &Value) -> i64 {
    v.as_i64().expect("number in golden data")
}

fn kind_name(kind: RelocKind, width: u8) -> &'static str {
    match (kind, width) {
        (RelocKind::Absolute, 4) => "off32",
        (RelocKind::Absolute, 2) => "off16",
        (RelocKind::Selector, 2) => "sel16",
        (RelocKind::FarPointer, 4) => "ptr16:16",
        (RelocKind::FarPointer, 6) => "ptr16:32",
        (RelocKind::Relative, 4) => "rel32",
        other => panic!("unexpected relocation shape {other:?}"),
    }
}

#[test]
#[ignore = "local: private Decomp workspace"]
fn matches_decomp() {
    let workspace = env_path("DECOVERY_LOCAL_WORKSPACE");
    let config: toml::Table = std::fs::read_to_string(workspace.join("decomp.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let exe = workspace.join(config["ziel"]["datei"].as_str().unwrap());
    let golden_path = env_path("DECOVERY_GOLDEN_DIR").join("le.json");
    let bytes = std::fs::read(&exe).unwrap();
    let golden: Value = serde_json::from_slice(&std::fs::read(golden_path).unwrap()).unwrap();
    let image = load_le(&bytes).unwrap();
    let program = &image.program;

    assert_eq!(
        image.header.entry,
        Address::Flat(num(&golden["entry"]) as u32)
    );
    assert_eq!(
        image.header.stack,
        Address::Flat(num(&golden["stack"]) as u32)
    );
    assert_eq!(
        image.warnings,
        golden["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    );

    let objects = golden["objects"].as_array().unwrap();
    assert_eq!(program.regions.len(), objects.len());
    for (region, o) in program.regions.iter().zip(objects) {
        let number = num(&o["number"]);
        assert_eq!(region.name, format!("obj{number}"));
        assert_eq!(
            region.start,
            Address::Flat(num(&o["base"]) as u32),
            "obj{number} base"
        );
        assert_eq!(
            region.virtual_size as i64,
            num(&o["size"]),
            "obj{number} size"
        );
        let flags = num(&o["flags"]);
        let permissions = (
            region.permissions.read,
            region.permissions.write,
            region.permissions.execute,
        );
        assert_eq!(
            permissions,
            (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0),
            "obj{number} flags {flags:#x}"
        );
        assert_eq!(
            region.data.len() as i64,
            num(&o["data_len"]),
            "obj{number} data length"
        );
        let digest: String = Sha256::digest(&region.data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            o["data_sha256"].as_str().unwrap(),
            "obj{number} data"
        );
        assert_eq!(
            region.file_offset.map(|v| v as i64),
            o["file_offset"].as_i64(),
            "obj{number} file offset"
        );
    }

    // Applied fixups: [address, kind, value]; the value is read back from the patched bytes.
    let fixups = golden["fixups"].as_array().unwrap();
    assert!(!fixups.is_empty());
    assert_eq!(program.relocations.len(), fixups.len());
    for (r, f) in program.relocations.iter().zip(fixups) {
        let Address::Flat(at) = r.at else { panic!() };
        assert_eq!(i64::from(at), num(&f[0]));
        let name = kind_name(r.kind, r.width);
        assert_eq!(name, f[1].as_str().unwrap(), "kind at {at:#x}");
        let field = program.read(r.at, r.width.into()).unwrap();
        let word = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let half = |b: &[u8]| i64::from(u16::from_le_bytes([b[0], b[1]]));
        let value = match name {
            "off32" | "ptr16:32" => i64::from(word(field)),
            "rel32" => i64::from(word(field) as i32),
            _ => half(field),
        };
        assert_eq!(value, num(&f[2]), "value at {at:#x} ({name})");
    }

    let raw = golden["raw_fixups"].as_array().unwrap();
    assert!(!raw.is_empty());
    assert_eq!(image.raw_fixups.len(), raw.len());
    for (r, g) in image.raw_fixups.iter().zip(raw) {
        let ours = (
            i64::from(r.page),
            i64::from(r.object),
            i64::from(r.offset),
            i64::from(r.source_type),
            i64::from(r.target_object),
            i64::from(r.target_offset),
            r.short_target,
            i64::from(r.length),
        );
        let theirs = (
            num(&g["seite"]),
            num(&g["objekt"]),
            num(&g["offset"]),
            num(&g["art"]),
            num(&g["ziel_objekt"]),
            num(&g["ziel_offset"]),
            g["kurz"].as_bool().unwrap(),
            num(&g["laenge"]),
        );
        assert_eq!(ours, theirs);
    }
}
