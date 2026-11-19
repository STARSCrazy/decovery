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

/// The linked overlay: A code at 1000, B code at 100A, entry ($ovbgn, one `ret`) at 100E; A data at 2000 (5 bytes),
/// B data at 2006 (the linker starts every object's data on a word), one library data byte; BSS from 2008:
/// A 2008..2009, B 200A..200D. `ext_` lives at DS:0050.
fn overlay(bss: u16) -> Vec<u8> {
    let call_g = 0x100Au16.wrapping_sub(0x1003);
    let mut code = vec![0xE8];
    code.extend(call_g.to_le_bytes());
    code.extend([0xA1, 0x50, 0x00, 0xB8, 0x00, 0x20, 0xC3]);
    code.extend([0xA1]);
    code.extend((0x2008u16 + 2 + 2).to_le_bytes()); // buf_ = B's BSS + 2
    code.extend([0xC3]);
    code.push(0xC3); // $ovbgn
    let data = vec![b'h', b'i', 0, 0x50, 0x00, 0, 7, 0xEE];
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
    assert_eq!(v.data_size, (8, 7));
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
    let texts: Vec<String> = v.wrong_refs.iter().map(|w| w.text()).collect();
    assert_eq!(texts, ["A DATA: original 2001, rebuilt 2000"], "{v:#?}");
    assert_eq!(v.wrong_refs[0].place, 0x1007);
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

#[test]
fn findings_have_no_indentation_inside() {
    let ovl = read_overlay(&overlay(6), "T").expect("overlay");
    let partial = compare_overlay_module(&[&object(&a())], &ovl);
    let mut spec = a();
    spec.code.insert(9, 0x90);
    let shifted = compare_overlay_module(&[&object(&spec), &object(&b())], &ovl);
    for f in partial.findings.iter().chain(&shifted.findings) {
        assert!(!f.contains("  "), "{f:?}");
    }
}

/// C declares the commons `cnt_` (2) and `tbl_` (4) and reads `tbl_`; D declares `cnt_` and `z_` (2) and reads both.
fn commons() -> (AztecModuleSpec, AztecModuleSpec) {
    let c = AztecModuleSpec {
        name: "C".into(),
        code: vec![0xA1, 0, 0, 0xC3],
        named: vec![
            sym("cnt_", AztecSection::Extern, 2),
            sym("tbl_", AztecSection::Extern, 4),
        ],
        refs: vec![r(AztecSection::Code, 1, false, AztecTarget::Named(1))],
        ..AztecModuleSpec::default()
    };
    let d = AztecModuleSpec {
        name: "D".into(),
        code: vec![0xA1, 0, 0, 0xA1, 0, 0, 0xC3],
        named: vec![
            sym("z_", AztecSection::Extern, 2),
            sym("cnt_", AztecSection::Extern, 2),
        ],
        refs: vec![
            r(AztecSection::Code, 1, false, AztecTarget::Named(0)),
            r(AztecSection::Code, 4, false, AztecTarget::Named(1)),
        ],
        ..AztecModuleSpec::default()
    };
    (c, d)
}

/// Overlay of C and D with `cnt_`, `tbl_`, `z_` at the given addresses and no data.
fn commons_overlay(tbl: u16, z: u16, cnt: u16, bss: u16) -> Vec<u8> {
    let mut code = vec![0xA1];
    code.extend(tbl.to_le_bytes());
    code.push(0xC3);
    code.push(0xA1);
    code.extend(z.to_le_bytes());
    code.push(0xA1);
    code.extend(cnt.to_le_bytes());
    code.extend([0xC3, 0xC3]);
    let mut file = Vec::new();
    for w in [0xF2, CORG, code.len() as u16, DORG, 0, bss, CORG + 11] {
        file.extend(u16::to_le_bytes(w));
    }
    file.extend(code);
    file
}

#[test]
fn common_symbols_are_placed_in_bss_in_order_of_first_appearance() {
    let (c, d) = commons();
    let ovl = read_overlay(&commons_overlay(0x2002, 0x2006, 0x2000, 8), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&c), &object(&d)], &ovl);
    assert!(v.identical, "{v:#?}");
    assert_eq!(v.bss, (8, 8));
    assert_eq!(v.code.metrics.refs_ok, 3);
    assert!(v.externals.is_empty(), "commons are bound by the layout");
    // a common placed elsewhere in the original is a wrong reference
    let ovl = read_overlay(&commons_overlay(0x2004, 0x2006, 0x2000, 8), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&c), &object(&d)], &ovl);
    assert!(!v.identical);
    assert_eq!(v.code.metrics.refs_wrong, 1);
}

/// E reads the extern `tbl_` at a fixed offset on both sides (`tbl_ - 2`, `tbl_ + 2`); F defines nothing of it.
fn extern_with_addends(defined_common: bool) -> (AztecModuleSpec, AztecModuleSpec) {
    let e = AztecModuleSpec {
        name: "E".into(),
        code: vec![0xA1, 0, 0, 0xA1, 0, 0, 0xC3],
        named: vec![sym("tbl_", AztecSection::Extern, 0)],
        refs: vec![
            AztecRefSpec {
                addend: -2,
                ..r(AztecSection::Code, 1, false, AztecTarget::Named(0))
            },
            AztecRefSpec {
                addend: 2,
                ..r(AztecSection::Code, 4, false, AztecTarget::Named(0))
            },
        ],
        ..AztecModuleSpec::default()
    };
    let f = AztecModuleSpec {
        name: "F".into(),
        code: vec![0xA1, 0, 0, 0xC3],
        named: vec![sym(
            "tbl_",
            AztecSection::Extern,
            if defined_common { 4 } else { 0 },
        )],
        refs: vec![r(AztecSection::Code, 1, false, AztecTarget::Named(0))],
        ..AztecModuleSpec::default()
    };
    (e, f)
}

/// Overlay of E and F: `tbl_` at `tbl` (E reads tbl-2 and tbl+2, F reads tbl), BSS `bss`.
fn addend_overlay(tbl: u16, bss: u16) -> Vec<u8> {
    let mut code = vec![0xA1];
    code.extend((tbl - 2).to_le_bytes());
    code.push(0xA1);
    code.extend((tbl + 2).to_le_bytes());
    code.push(0xC3);
    code.push(0xA1);
    code.extend(tbl.to_le_bytes());
    code.extend([0xC3, 0xC3]);
    let mut file = Vec::new();
    for w in [0xF2, CORG, code.len() as u16, DORG, 0, bss, CORG + 11] {
        file.extend(u16::to_le_bytes(w));
    }
    file.extend(code);
    file
}

#[test]
fn extern_at_a_fixed_offset_binds_once() {
    let (e, f) = extern_with_addends(false);
    let ovl = read_overlay(&addend_overlay(0x84AA, 0), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert!(v.ambiguous.is_empty(), "{v:#?}");
    assert_eq!(v.code.metrics.refs_wrong, 0, "{v:#?}");
    assert_eq!(v.externals.get("tbl_"), Some(&0x84AA));
    assert!(v.identical, "{v:#?}");
}

#[test]
fn disagreeing_extern_use_names_its_addend_and_field() {
    // the original reads tbl_+0 where E reads tbl_-2 (a source error): the message says what the field holds
    let (e, f) = extern_with_addends(false);
    let mut file = addend_overlay(0x84AA, 0);
    file[14 + 1..14 + 3].copy_from_slice(&0x84AAu16.to_le_bytes());
    let ovl = read_overlay(&file, "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert_eq!(v.code.metrics.refs_wrong, 1, "{v:#?}");
    assert_eq!(
        v.ambiguous,
        [
            "tbl_: bound at 84AA by its other uses; the field at 1001 (tbl_-2) holds 84AA, as if tbl_ were at 84AC"
        ]
    );
    // the majority of the uses binds the name: the one disagreeing use is the wrong reference
    assert_eq!(v.code.blockers, [Blocker::WrongAbsoluteRef { at: 1 }]);
    assert_eq!(v.externals.get("tbl_"), Some(&0x84AA));
    let texts: Vec<String> = v.wrong_refs.iter().map(|w| w.text()).collect();
    assert_eq!(texts, ["tbl_-2: original 84AA, rebuilt 84A8"]);
}

#[test]
fn common_at_a_fixed_offset_uses_the_addend() {
    // F declares tbl_ as a common of 4 bytes: placed at the BSS start (2000), E's uses at 1FFE and 2002
    let (e, f) = extern_with_addends(true);
    let ovl = read_overlay(&addend_overlay(0x2000, 4), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert!(v.ambiguous.is_empty(), "{v:#?}");
    assert_eq!(v.code.metrics.refs_wrong, 0, "{v:#?}");
    assert!(v.identical, "{v:#?}");
}

#[test]
fn bss_missing_from_the_files_names_the_externs_bound_inside_it() {
    // the original's BSS holds tbl_ (2002); the files only declare it extern: no BSS of their own
    let (e, f) = extern_with_addends(false);
    let ovl = read_overlay(&addend_overlay(0x2002, 8), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert_eq!(v.bss, (8, 0));
    assert!(
        v.findings.contains(
            &"BSS: 8 bytes in the original, 0 from the module's files; 1 external name bound inside the \
              original BSS (2000..2008), defined in none of the files: tbl_"
                .to_string()
        ),
        "{:?}",
        v.findings
    );
    // an extern outside the BSS is not named
    let ovl = read_overlay(&addend_overlay(0x84AA, 8), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert!(
        v.findings
            .contains(&"BSS: 8 bytes in the original, 0 from the module's files; no external name is bound inside the original BSS (2000..2008)".to_string()),
        "{:?}",
        v.findings
    );
}

#[test]
fn extern_whose_name_says_another_address_is_a_finding() {
    let (mut e, mut f) = extern_with_addends(false);
    for spec in [&mut e, &mut f] {
        spec.named[0].name = "word_84a0_".into();
    }
    let ovl = read_overlay(&addend_overlay(0x84AA, 0), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert_eq!(v.externals.get("word_84a0_"), Some(&0x84AA), "{v:#?}");
    assert!(
        v.findings
            .iter()
            .any(|x| x.starts_with("word_84a0_: bound at 84AA, but its name says 84A0")),
        "{:?}",
        v.findings
    );
    // a name that says its address is no finding
    for spec in [&mut e, &mut f] {
        spec.named[0].name = "word_84aa_".into();
    }
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert!(v.findings.is_empty(), "{:?}", v.findings);
}

#[test]
fn bss_externals_lists_every_name_with_its_address() {
    let (e, f) = extern_with_addends(false);
    let ovl = read_overlay(&addend_overlay(0x2002, 8), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&e), &object(&f)], &ovl);
    assert_eq!(v.bss_externals, [("tbl_".to_string(), 0x2002)]);
}

#[test]
fn commons_counted_into_a_differing_bss_are_named() {
    // C and D declare commons (cnt_ 2, tbl_ 4, z_ 2): 8 bytes; the original has 10
    let (c, d) = commons();
    let ovl = read_overlay(&commons_overlay(0x2002, 0x2006, 0x2000, 10), "T").expect("overlay");
    let v = compare_overlay_module(&[&object(&c), &object(&d)], &ovl);
    assert_eq!(v.commons.len(), 3, "{v:#?}");
    assert!(
        v.findings
            .iter()
            .any(|f| f.starts_with("BSS counts 8 bytes of commons")
                && f.contains("cnt_ 2 bytes at 2000 (C, D)")),
        "{:?}",
        v.findings
    );
}
