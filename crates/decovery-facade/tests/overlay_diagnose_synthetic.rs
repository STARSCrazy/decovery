//! `diagnose` (and `diagnose` with `deep`) on overlay functions of a synthetic Aztec C86 overlay workspace.

#[path = "support/overlay_fixture.rs"]
mod overlay_fixture;

use decovery_facade::{Budget, Control, LegacyCall, LegacyOperation, Session, diagnose_deep};
use overlay_fixture::{A_AT, B_AT};

fn workspace(main_ovmain: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), main_ovmain);
    dir
}

#[test]
fn overlay_function_is_diagnosed_from_the_overlay_bytes() {
    let dir = workspace(false);
    let session = Session::open(dir.path()).unwrap();
    for target in ["A_ovmain", A_AT, "fun_A_0000_5000"] {
        let r = decovery_facade::diagnose(&session, target, Budget::default()).unwrap();
        assert!(
            !r.summary.contains("no instructions compared"),
            "{target}: {}",
            r.summary
        );
        assert_eq!(r.data["function"]["address"], A_AT, "{target}");
        assert_eq!(r.data["function"]["name"], "A_ovmain", "{target}");
        assert_eq!(r.data["function"]["file"], "a.c", "{target}");
        assert_eq!(r.data["function"]["instructions_differing"], 1, "{target}");
        let text = r.data["pairs_text"].as_str().unwrap();
        assert!(text.contains("mov ax,1"), "{text}");
    }
    let b = decovery_facade::diagnose(&session, "B_ovmain", Budget::default()).unwrap();
    assert_eq!(b.data["function"]["address"], B_AT);
    assert_eq!(b.summary, "B_ovmain: no differing instructions");
}

#[test]
fn ambiguous_overlay_name_lists_candidates() {
    let dir = workspace(false);
    let session = Session::open(dir.path()).unwrap();
    let e = decovery_facade::diagnose(&session, "ovmain", Budget::default())
        .unwrap_err()
        .to_string();
    assert!(e.contains("ambiguous"), "{e}");
    assert!(e.contains("A_ovmain") && e.contains(A_AT), "{e}");
    assert!(e.contains("B_ovmain") && e.contains(B_AT), "{e}");
}

#[test]
fn exact_name_wins_over_overlay_qualified_names() {
    let dir = workspace(true);
    let session = Session::open(dir.path()).unwrap();
    // the main program's own `ovmain` has no rebuild record: the exact name is found, not an overlay's copy
    let e = decovery_facade::diagnose(&session, "ovmain", Budget::default())
        .unwrap_err()
        .to_string();
    assert_eq!(
        e,
        "no rebuilt object for ovmain; run `decovery build <file>`"
    );
}

#[test]
fn deep_diagnosis_of_an_overlay_function_is_refused_clearly() {
    let dir = workspace(false);
    for target in [A_AT, "A_ovmain"] {
        let call = LegacyCall::new(target, LegacyOperation::Context);
        let e = diagnose_deep(dir.path(), &call, &Control::progress_only(&|_| {}))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("not available for overlay functions"),
            "{target}: {e}"
        );
        assert!(!e.contains("not a decovery address"), "{e}");
        assert!(!e.contains("  "), "no indentation inside the message: {e}");
    }
}

/// Overlay `C`: `pre_` (`mov ax, 1; ret`) at 5000 and `g_` at 5004 with short jumps and a call of `pre_`. The rebuilt object is the same module: `g_` lies at offset 4 of it.
fn add_overlay_c(root: &std::path::Path) {
    use decovery_objects::{
        AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget,
    };
    let sym = |name: &str, value| AztecSymbolSpec {
        name: name.into(),
        section: AztecSection::Code,
        value,
        public: true,
    };
    // a short jump inside the function and a call to another function of the module, both relocated
    let body = |jl: u8, call: [u8; 2]| {
        vec![
            0xB8, 1, 0, 0xC3, // pre_
            0x90, 0x90, // 5004
            0x7C, jl, // 5006: jl short 500E
            0xEB, 0x04, // 5008: jmp short 500E (no relocation)
            0xE8, call[0], call[1], // 500A: call pre_
            0x90, 0xC3, // 500D, 500E: .L
        ]
    };
    // as the assembler leaves them: relocated fields hold 0
    let object = decovery_objects::write_aztec(&AztecModuleSpec {
        name: "C".into(),
        code: body(0, [0, 0]),
        named: vec![sym("pre_", 0), sym("g_", 4)],
        unnamed: vec![(AztecSection::Code, 14)],
        refs: vec![
            AztecRefSpec {
                section: AztecSection::Code,
                offset: 7,
                width: 1,
                relative: true,
                target: AztecTarget::Unnamed(0),
                addend: 0,
            },
            AztecRefSpec {
                section: AztecSection::Code,
                offset: 11,
                width: 2,
                relative: true,
                target: AztecTarget::Named(0),
                addend: 0,
            },
        ],
        ..AztecModuleSpec::default()
    });
    std::fs::write(root.join("cache/rebuild/obj/c.obj"), object).unwrap();
    let code = body(0x06, 0x5000u16.wrapping_sub(0x500D).to_le_bytes());
    let mut file = Vec::new();
    for w in [
        0xF2u16,
        0x5000,
        code.len() as u16,
        0x9000,
        0,
        0,
        0x5000 + code.len() as u16,
    ] {
        file.extend(w.to_le_bytes());
    }
    file.extend(&code);
    std::fs::write(root.join("C.OVR"), &file).unwrap();
    let mut config = std::fs::read_to_string(root.join("decovery.toml")).unwrap();
    config.push_str(&format!(
        "
[[target.segment]]
name = \"C.code\"
start = \"ovl:C:0000:5000\"
length = {}
file_offset = 14
permissions = \"rx\"

[[overlay]]
name = \"C\"
file = \"C.OVR\"
sha256 = \"bb\"
format = \"aztec-c86\"
size = {}
",
        code.len(),
        file.len()
    ));
    std::fs::write(root.join("decovery.toml"), config).unwrap();
    let mut records = std::fs::read_to_string(root.join("knowledge/rebuild.toml")).unwrap();
    records.push_str(
        "
[[function]]
address = \"ovl:C:0000:5004\"
name = \"g\"
file = \"c.c\"
result = \"identical\"
",
    );
    std::fs::write(root.join("knowledge/rebuild.toml"), records).unwrap();
    // the analysis names `pre_` differently than the source does
    let mut symbols = std::fs::read_to_string(root.join("knowledge/symbols.toml")).unwrap();
    symbols.push_str(
        "[[symbol]]
address = \"ovl:C:0000:5000\"
kind = \"function\"
name = \"prelude\"
size = 4
source = \"human\"
confidence = \"confirmed\"

",
    );
    std::fs::write(root.join("knowledge/symbols.toml"), symbols).unwrap();
}

#[test]
fn overlay_function_inside_its_module_compares_branch_targets_at_its_address() {
    let dir = workspace(false);
    add_overlay_c(dir.path());
    let session = Session::open(dir.path()).unwrap();
    let r = decovery_facade::diagnose(&session, "ovl:C:0000:5004", Budget::default()).unwrap();
    assert_eq!(
        r.data["function"]["instructions_differing"], 0,
        "{}",
        r.data["pairs_text"]
    );
    assert!(
        r.summary.ends_with(": no differing instructions"),
        "{}",
        r.data["pairs_text"]
    );
}

#[test]
fn stale_analysis_is_one_warning_of_diagnose() {
    let dir = workspace(false);
    std::fs::write(dir.path().join("knowledge/types.h"), "struct x;\n").unwrap();
    let session = Session::open(dir.path()).unwrap();
    let r = decovery_facade::diagnose(&session, "A_ovmain", Budget::default()).unwrap();
    assert_eq!(
        r.data["warnings"],
        serde_json::json!([decovery_facade::output::STALE_ANALYSIS])
    );
    assert!(!r.summary.contains("older than"), "{}", r.summary);
}
