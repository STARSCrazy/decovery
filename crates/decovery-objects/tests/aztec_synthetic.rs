//! Aztec C86 reader on objects and libraries built by the test-only writer (no compiler output).

use decovery_core::RelocKind;
use decovery_objects::{
    AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget, Frame, ObjectError,
    ObjectFormat, RefTarget, SectionKind, functions, read_aztec, read_object, write_aztec,
    write_aztec_library,
};

fn sym(name: &str, section: AztecSection, value: u16, public: bool) -> AztecSymbolSpec {
    AztecSymbolSpec {
        name: name.into(),
        section,
        value,
        public,
    }
}

fn reference(
    offset: u16,
    width: u8,
    relative: bool,
    target: AztecTarget,
    addend: i32,
) -> AztecRefSpec {
    AztecRefSpec {
        section: AztecSection::Code,
        offset,
        width,
        relative,
        target,
        addend,
    }
}

/// Two functions: `f_` calls `g_` and jumps short to an unnamed label; static `s_` loads `buf_+3` and a string.
fn sample() -> AztecModuleSpec {
    let mut code = vec![
        0xE8, 0, 0, // 0: call g_
        0xEB, 0, // 3: jmp short .L (unnamed 0 = 7)
        0x90, 0x90, // 5
        0xC3, // 7: .L ret
        0xB8, 0, 0, // 8: s_: mov ax, buf_+3
        0xBA, 0, 0, // 11: mov dx, offset string (data 0)
        0xB9, 0, 0,    // 14: mov cx, seg data
        0xC3, // 17
    ];
    code.extend([0u8; 10]); // padding as SPACE item
    AztecModuleSpec {
        name: "T".into(),
        code,
        data: b"hi\0\0".to_vec(),
        bss: 0x20,
        named: vec![
            sym("f_", AztecSection::Code, 0, true),
            sym("g_", AztecSection::Extern, 0, true),
            sym("s_", AztecSection::Code, 8, false),
            sym("buf_", AztecSection::Bss, 0, true),
            sym("v_", AztecSection::Data, 2, true),
        ],
        unnamed: vec![(AztecSection::Code, 7), (AztecSection::Data, 0)],
        refs: vec![
            reference(1, 2, true, AztecTarget::Named(1), 0),
            reference(4, 1, true, AztecTarget::Unnamed(0), 0),
            reference(9, 2, false, AztecTarget::Named(3), 3),
            reference(12, 2, false, AztecTarget::Unnamed(1), 0),
            reference(15, 2, false, AztecTarget::Paragraph(AztecSection::Data), 0),
        ],
        debug: true,
        start: None,
    }
}

#[test]
fn header_magic_is_checked() {
    let mut bytes = write_aztec(&sample());
    assert!(read_aztec(&bytes, "T.O").is_ok());
    bytes[0] = 0x80;
    let e = read_aztec(&bytes, "T.O").unwrap_err();
    assert!(
        matches!(e, ObjectError::Malformed { offset: 0, .. }),
        "{e:?}"
    );
    assert!(read_aztec(&[], "T.O").is_err());
    assert!(read_aztec(&[0x66], "T.O").is_err());
}

#[test]
fn code_data_bss_sections() {
    let spec = sample();
    let f = read_aztec(&write_aztec(&spec), "T.O").unwrap();
    assert!(f.unknown_records.is_empty());
    let [m] = f.modules.as_slice() else {
        panic!("one module")
    };
    assert_eq!(m.name, "T");
    let kinds: Vec<_> = m
        .sections
        .iter()
        .map(|s| (s.name.as_str(), s.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            ("CODE", SectionKind::Code),
            ("DATA", SectionKind::Data),
            ("BSS", SectionKind::Bss)
        ]
    );
    assert_eq!(m.sections[0].data.len(), spec.code.len());
    assert_eq!(m.sections[1].data, spec.data);
    assert!(m.sections[2].data.is_empty());
    assert_eq!(m.sections[2].size, 0x20);
    assert_eq!(m.sections[0].size, spec.code.len() as u32);
    assert!(m.sections.iter().all(|s| s.bits == 16));
    // bytes outside the fixup fields as written; fixup fields hold the integer part
    let code = &m.sections[0].data;
    assert_eq!(code[0], 0xE8);
    assert_eq!(&code[5..9], &[0x90, 0x90, 0xC3, 0xB8]);
    assert_eq!(&code[9..11], &3u16.to_le_bytes());
    assert_eq!(&code[18..], &[0u8; 10]);
}

#[test]
fn named_symbols_become_publics() {
    let f = read_aztec(&write_aztec(&sample()), "T.O").unwrap();
    let m = &f.modules[0];
    let syms: Vec<_> = m
        .symbols
        .iter()
        .map(|s| (s.name.as_str(), s.section, s.offset, s.public))
        .collect();
    // externals are not symbols of the module; the static function keeps its name
    assert_eq!(
        syms,
        [
            ("f_", 0, 0, true),
            ("s_", 0, 8, false),
            ("buf_", 2, 0, true),
            ("v_", 1, 2, true)
        ]
    );
    let names: Vec<_> = functions(m)
        .iter()
        .map(|f| (f.name, f.start, f.len))
        .collect();
    assert_eq!(names, [("f_", 0, 8), ("s_", 8, 20)]);
}

#[test]
fn unnamed_symbols_are_local() {
    let f = read_aztec(&write_aztec(&sample()), "T.O").unwrap();
    let m = &f.modules[0];
    // no symbol for the label at 7 or the string: functions are not split at labels
    assert!(m.symbols.iter().all(|s| !(s.section == 0 && s.offset == 7)));
    let r = m.sections[0]
        .relocs
        .iter()
        .find(|r| r.offset == 12)
        .unwrap();
    assert_eq!(r.kind, RelocKind::Absolute);
    assert_eq!(r.width, 2);
    assert_eq!(
        r.target,
        RefTarget::Section {
            index: 1,
            offset: 0
        }
    );
    assert_eq!(r.frame, Frame::Target);
}

#[test]
fn short_jump_to_unnamed_is_self_relative_reloc() {
    let f = read_aztec(&write_aztec(&sample()), "T.O").unwrap();
    let relocs = &f.modules[0].sections[0].relocs;
    let jump = relocs.iter().find(|r| r.offset == 4).unwrap();
    assert_eq!(
        (jump.kind, jump.width, &jump.target, jump.addend),
        (
            RelocKind::Relative,
            1,
            &RefTarget::Section {
                index: 0,
                offset: 7
            },
            0
        )
    );
    let call = relocs.iter().find(|r| r.offset == 1).unwrap();
    assert_eq!(
        (call.kind, call.width, &call.target),
        (RelocKind::Relative, 2, &RefTarget::Symbol("g_".into()))
    );
    let data = relocs.iter().find(|r| r.offset == 9).unwrap();
    assert_eq!(
        (data.kind, &data.target, data.addend),
        (RelocKind::Absolute, &RefTarget::Symbol("buf_".into()), 0)
    );
    let seg = relocs.iter().find(|r| r.offset == 15).unwrap();
    assert_eq!(
        (seg.kind, &seg.target),
        (
            RelocKind::Selector,
            &RefTarget::Section {
                index: 1,
                offset: 0
            }
        )
    );
    assert_eq!(relocs.len(), 5);
}

#[test]
fn integer_encodings_and_section_references() {
    let mut spec = AztecModuleSpec {
        name: "N".into(),
        code: vec![0; 40],
        ..Default::default()
    };
    spec.named = vec![sym("x_", AztecSection::Extern, 0, true)];
    let values = [5, -7, 400, -1000, 30000, 70000];
    for (k, v) in values.iter().enumerate() {
        let width = if k == 5 { 4 } else { 2 };
        spec.refs.push(reference(
            (k * 4) as u16,
            width,
            false,
            AztecTarget::Number,
            *v,
        ));
    }
    spec.refs.push(reference(
        24,
        2,
        false,
        AztecTarget::Section(AztecSection::Data, 0x1234),
        0,
    ));
    spec.refs.push(reference(
        26,
        2,
        true,
        AztecTarget::Section(AztecSection::Code, 2),
        0,
    ));
    spec.refs
        .push(reference(28, 4, false, AztecTarget::Named(0), -2));
    spec.start = Some((AztecSection::Code, 6));
    let f = read_aztec(&write_aztec(&spec), "N.O").unwrap();
    let m = &f.modules[0];
    let code = &m.sections[0].data;
    for (k, v) in values.iter().enumerate() {
        let w = if k == 5 { 4 } else { 2 };
        let got = &code[k * 4..k * 4 + w];
        assert_eq!(got, &v.to_le_bytes()[..w], "value {v}");
    }
    let relocs = &m.sections[0].relocs;
    // plain numbers carry no relocation
    assert_eq!(relocs.len(), 3);
    assert_eq!(&code[24..26], &0x1234u16.to_le_bytes());
    assert_eq!(
        relocs[0].target,
        RefTarget::Section {
            index: 1,
            offset: 0
        }
    );
    assert_eq!(
        (relocs[1].kind, &relocs[1].target),
        (
            RelocKind::Relative,
            &RefTarget::Section {
                index: 0,
                offset: 2
            }
        )
    );
    assert_eq!(
        (relocs[2].kind, relocs[2].width),
        (RelocKind::FarPointer, 4)
    );
    assert_eq!(&code[28..32], &(-2i32).to_le_bytes());
    assert_eq!(m.start, Some((0, 6)));
}

#[test]
fn library_lists_modules() {
    let mut second = sample();
    second.name = "U".into();
    second.named[0].name = "h_".into();
    second.debug = false;
    let lib = write_aztec_library(&[sample(), second]);
    let f = read_aztec(&lib, "T.LIB").unwrap();
    let names: Vec<_> = f.modules.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["T", "U"]);
    let single = read_aztec(&write_aztec(&sample()), "T.O").unwrap();
    assert_eq!(f.modules[0], single.modules[0]);
    let fns: Vec<_> = f
        .modules
        .iter()
        .flat_map(functions)
        .map(|v| v.name)
        .collect();
    assert_eq!(fns, ["f_", "s_", "h_", "s_"]);
}

#[test]
fn library_block_past_end_is_error() {
    let mut lib = write_aztec_library(&[sample()]);
    // a next dictionary block beyond the file
    lib[2..4].copy_from_slice(&0x0400u16.to_le_bytes());
    let e = read_aztec(&lib, "T.LIB").unwrap_err();
    assert!(matches!(e, ObjectError::Malformed { .. }), "{e:?}");
    // a module position beyond the file
    let mut lib = write_aztec_library(&[sample()]);
    lib[4..6].copy_from_slice(&0x0400u16.to_le_bytes());
    let e = read_aztec(&lib, "T.LIB").unwrap_err();
    assert!(
        matches!(e, ObjectError::Malformed { offset: 4, .. }),
        "{e:?}"
    );
}

#[test]
fn symbol_index_out_of_range_is_error() {
    let mut spec = sample();
    spec.refs
        .push(reference(19, 2, false, AztecTarget::Named(9), 0));
    let e = read_aztec(&write_aztec(&spec), "T.O").unwrap_err();
    let ObjectError::Malformed { offset, what } = e else {
        panic!("{e:?}")
    };
    assert!(what.contains("symbol 9"), "{what}");
    assert!(offset >= 30, "offset {offset}");
    let mut spec = sample();
    spec.refs
        .push(reference(19, 2, false, AztecTarget::Unnamed(2), 0));
    assert!(read_aztec(&write_aztec(&spec), "T.O").is_err());
}

#[test]
fn items_past_header_size_are_error() {
    let mut bytes = write_aztec(&sample());
    bytes[10] -= 1; // code size one smaller than the items write
    let e = read_aztec(&bytes, "T.O").unwrap_err();
    assert!(
        matches!(&e, ObjectError::Malformed { what, .. } if what.contains("header")),
        "{e:?}"
    );
}

#[test]
fn truncated_object_names_offset() {
    let bytes = write_aztec(&sample());
    assert!(read_aztec(&bytes, "T.O").is_ok());
    for n in 0..bytes.len() {
        let e = read_aztec(&bytes[..n], "T.O").expect_err(&format!("prefix {n} must fail"));
        match e {
            ObjectError::Truncated { offset } | ObjectError::Malformed { offset, .. } => {
                assert!(offset <= n as u64, "offset {offset} at prefix {n}");
            }
            other => panic!("unexpected {other:?} at prefix {n}"),
        }
    }
}

#[test]
fn truncated_library_never_panics() {
    let lib = write_aztec_library(&[sample(), sample()]);
    for n in 0..=lib.len() {
        let _ = read_aztec(&lib[..n], "T.LIB");
    }
}

#[test]
fn corrupt_bytes_never_panic() {
    let bytes = write_aztec(&sample());
    for i in 0..bytes.len() {
        for v in [0x00, 0x0F, 0x20, 0x7F, 0x8F, 0xF6, 0xFF] {
            let mut b = bytes.clone();
            b[i] = v;
            let _ = read_aztec(&b, "T.O");
        }
    }
}

#[test]
fn deeply_nested_expression_is_error() {
    let mut bytes = write_aztec(&sample());
    // overwrite the start of the load items with 70 nested ADD operators
    bytes[30] = 0xF4;
    bytes[31..101].fill(0x21);
    let e = read_aztec(&bytes, "T.O").unwrap_err();
    assert!(
        matches!(&e, ObjectError::Malformed { what, .. } if what.contains("nested")),
        "{e:?}"
    );
}

#[test]
fn read_object_dispatches_by_format() {
    let aztec = write_aztec(&sample());
    assert_eq!(
        read_object(ObjectFormat::Aztec, &aztec, "T.O").unwrap(),
        read_aztec(&aztec, "T.O").unwrap()
    );
    assert!(read_object(ObjectFormat::Omf, &aztec, "T.O").is_err());
    // THEADR "M" and MODEND, checksums not computed
    let omf = [0x80, 3, 0, 1, b'M', 0, 0x8A, 2, 0, 0, 0];
    assert!(read_object(ObjectFormat::Omf, &omf, "M.OBJ").is_ok());
    assert!(read_object(ObjectFormat::Aztec, &omf, "M.OBJ").is_err());
}
