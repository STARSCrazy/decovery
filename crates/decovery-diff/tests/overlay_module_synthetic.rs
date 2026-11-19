//! Whole overlay modules (phase 4, Task 8): code, data, relocations and BSS, objects from the Aztec test writer
//! and hand-built overlay files.

use decovery_diff::{Blocker, Verdict, compare_overlay_module};
use decovery_loaders::read_overlay;
use decovery_objects::{
    AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget, ObjectFile,
    read_aztec, write_aztec,
};

const CORG: u16 = 0x1000;
const DORG: u16 = 0x2000;

fn sym(name: &str, section: AztecSection, value: u16) -> AztecSymbolSpec {
    AztecSymbolSpec {
        name: name.into(),
        section,
        value,
        public: true,
    }
}

fn r(section: AztecSection, offset: u16, relative: bool, target: AztecTarget) -> AztecRefSpec {
    AztecRefSpec {
        section,
        offset,
        width: 2,
        relative,
        target,
        addend: 0,
    }
}

/// A: `f_` = `call g_` (extern, defined in B), `mov ax, [ext_]` (extern data), `mov ax, offset msg` (own data),
/// `ret`; data "hi\0" plus a word pointing at `ext_`; BSS 2.
fn a() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "A".into(),
        code: vec![
            0xE8, 0, 0, // 0: call g_
            0xA1, 0, 0, // 3: mov ax, [ext_]
            0xB8, 0, 0,    // 6: mov ax, offset msg
            0xC3, // 9
        ],
        data: vec![b'h', b'i', 0, 0, 0],
        bss: 2,
        named: vec![
            sym("f_", AztecSection::Code, 0),
            sym("g_", AztecSection::Extern, 0),
            sym("ext_", AztecSection::Extern, 0),
        ],
        unnamed: vec![(AztecSection::Data, 0)],
        refs: vec![
            r(AztecSection::Code, 1, true, AztecTarget::Named(1)),
            r(AztecSection::Code, 4, false, AztecTarget::Named(2)),
            r(AztecSection::Code, 7, false, AztecTarget::Unnamed(0)),
            r(AztecSection::Data, 3, false, AztecTarget::Named(2)),
        ],
        ..AztecModuleSpec::default()
    }
}

/// B: `g_` = `mov ax, [buf_]` (own BSS), `ret`; data 1 byte; BSS 4.
fn b() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "B".into(),
        code: vec![0xA1, 0, 0, 0xC3],
        data: vec![7],
        bss: 4,
        named: vec![
            sym("g_", AztecSection::Code, 0),
            sym("buf_", AztecSection::Bss, 2),
        ],
        refs: vec![r(AztecSection::Code, 1, false, AztecTarget::Named(1))],
        ..AztecModuleSpec::default()
    }
}

fn object(spec: &AztecModuleSpec) -> ObjectFile {
    read_aztec(&write_aztec(spec), &format!("{}.O", spec.name)).expect("object")
}

/// The linked overlay: A code at 1000, B code at 100A, entry ($ovbgn, one `ret`) at 100E; A data at 2000, B data
/// at 2005, one library data byte; BSS from 2007: A 2007..2008, B 2009..200C. `ext_` lives at DS:0050.
fn overlay(bss: u16) -> Vec<u8> {
    let call_g = 0x100Au16.wrapping_sub(0x1003);
    let mut code = vec![0xE8];
    code.extend(call_g.to_le_bytes());
    code.extend([0xA1, 0x50, 0x00, 0xB8, 0x00, 0x20, 0xC3]);
    code.extend([0xA1]);
    code.extend((0x2007u16 + 2 + 2).to_le_bytes()); // buf_ = B's BSS + 2
    code.extend([0xC3]);
    code.push(0xC3); // $ovbgn
    let data = vec![b'h', b'i', 0, 0x50, 0x00, 7, 0xEE];
    let mut file = Vec::new();
    for w in [
        0xF2,
        CORG,
        code.len() as u16,
        DORG,
        data.len() as u16,
        bss,
        CORG + 14,
    ] {
        file.extend(u16::to_le_bytes(w));
    }
    file.extend(code);
    file.extend(data);
    file
}

#[test]
fn module_of_two_objects_places_in_order() {
    let ovl = read_overlay(&overlay(6), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&a()), &object(&b())], &ovl);
    assert!(v.identical, "{v:#?}");
    assert_eq!(v.code.verdict, Verdict::Identical);
    assert_eq!(v.code_size, (14, 14));
    assert_eq!(v.data_size, (7, 6));
    assert_eq!(v.bss, (6, 6));
    assert_eq!(v.code.metrics.refs_ok, 5);
    assert_eq!(v.code.metrics.differing, 0);
    assert_eq!(v.externals.get("ext_"), Some(&0x0050));
    assert!(!v.externals.contains_key("g_"), "g_ is defined in B");
    // the other order puts g_ first: the module no longer matches
    let swapped = compare_overlay_module(&[&object(&b()), &object(&a())], &ovl);
    assert!(!swapped.identical);
}

#[test]
fn data_difference_is_reported_with_offset() {
    let mut spec = a();
    spec.data[1] = b'o';
    let ovl = read_overlay(&overlay(6), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&spec), &object(&b())], &ovl);
    assert!(!v.identical);
    assert!(!v.data_equal);
    assert_eq!(v.data_diffs, [1]);
    assert_eq!(v.code.verdict, Verdict::Identical);
}

#[test]
fn module_with_different_bss_is_not_identical() {
    let ovl = read_overlay(&overlay(8), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&a()), &object(&b())], &ovl);
    assert_eq!(v.code.verdict, Verdict::Identical);
    assert!(v.data_equal);
    assert_eq!(v.bss, (8, 6));
    assert!(!v.identical);
}

#[test]
fn relocated_data_word_is_a_gap() {
    // the data word at A+3 refers to ext_: its bytes come from the original, the binding must agree with the
    // code's use of ext_ (DS:0050)
    let ovl = read_overlay(&overlay(6), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&a()), &object(&b())], &ovl);
    assert!(v.data_equal);
    assert!(v.ambiguous.is_empty());
    // the same name bound elsewhere in the data: ambiguous, not identical
    let mut file = overlay(6);
    let data_at = 14 + 15 + 3;
    file[data_at] = 0x52;
    let ovl = read_overlay(&file, "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&a()), &object(&b())], &ovl);
    assert_eq!(v.ambiguous.len(), 1, "{v:#?}");
    assert!(!v.identical);
}

#[test]
fn wrong_internal_reference_is_reported() {
    let mut file = overlay(6);
    file[14 + 7] = 0x01; // mov ax, offset msg: 2001 instead of 2000
    let ovl = read_overlay(&file, "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&a()), &object(&b())], &ovl);
    assert!(!v.identical);
    assert_eq!(v.code.metrics.refs_wrong, 1);
    assert!(
        v.code
            .blockers
            .contains(&Blocker::WrongAbsoluteRef { at: 7 })
    );
}

#[test]
fn code_that_does_not_end_at_the_entry_is_not_identical() {
    let ovl = read_overlay(&overlay(6), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&a())], &ovl);
    assert_eq!(v.code_size, (14, 10));
    assert!(!v.identical);
    assert_eq!(v.code.verdict, Verdict::Differs);
}

#[test]
fn partial_module_names_the_covered_range() {
    let ovl = read_overlay(&overlay(6), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&a())], &ovl);
    assert!(
        v.findings
            .iter()
            .any(|f| f.contains("module covers only 0x0000..0x000A of 0x0000..0x000E")),
        "{:?}",
        v.findings
    );
}

#[test]
fn shifted_code_reports_size_and_first_real_difference() {
    // one extra `nop` before A's `ret`: the module is one byte longer, B and every reference behind it shift
    let mut spec = a();
    spec.code.insert(9, 0x90);
    let ovl = read_overlay(&overlay(6), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&spec), &object(&b())], &ovl);
    assert!(!v.identical);
    assert_eq!(v.code_size, (14, 15));
    // the call field at 1 is a relocated field (wrong reference, not a byte difference)
    assert_eq!(v.code.metrics.first_difference, Some(9), "{v:#?}");
    assert!(v.code.metrics.instructions_differing > 0, "{v:#?}");
    assert!(v.findings[0].contains("1 byte longer"), "{:?}", v.findings);
    assert!(
        v.findings
            .iter()
            .any(|f| f.contains("after offset 0x0009 are likely consequences")),
        "{:?}",
        v.findings
    );
}
