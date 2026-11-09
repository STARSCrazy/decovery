//! The built-in assembler for byte-listing MASM sources: every object goes back through `read_omf`.

use decovery_core::RelocKind;
use decovery_objects::{ObjReloc, ObjectModule, RefTarget, SectionKind, read_omf};
use decovery_toolchain::{AssembleError, assemble_listing};

fn assemble(text: &str) -> ObjectModule {
    let bytes = assemble_listing("T.ASM", text).unwrap();
    let mut file = read_omf(&bytes, "T.OBJ").unwrap();
    assert!(
        file.unknown_records.is_empty(),
        "{:?}",
        file.unknown_records
    );
    assert_eq!(file.modules.len(), 1);
    file.modules.remove(0)
}

fn symbols(m: &ObjectModule) -> Vec<(&str, u32, u32, bool)> {
    m.symbols
        .iter()
        .map(|s| (s.name.as_str(), s.section, s.offset, s.public))
        .collect()
}

fn shape(r: &ObjReloc) -> (u32, u8, RelocKind, RefTarget, i64) {
    (r.offset, r.width, r.kind, r.target.clone(), r.addend)
}

fn symbol(name: &str) -> RefTarget {
    RefTarget::Symbol(name.to_string())
}

#[test]
fn db_bytes_and_labels_round_trip() {
    let m = assemble(
        "; a listing\n\
         \t.386p\n\
         _TEXT0001\tsegment byte public use32 'CODE'\n\
         \tpublic first_\n\
         first_:\n\
         \tdb 055h,08Bh,0ECh\t; +0000 push ebp\n\
         \tdb 0x5d, 195\n\
         _TEXT0001\tends\n\
         _TEXT0002 SEGMENT BYTE PUBLIC USE32 'CODE'\n\
         \tPUBLIC second_, third_\n\
         second_: db 090h\n\
         third_:\n\
         \tdb -1\n\
         _TEXT0002 ENDS\n\
         \tend\n\
         this line is after end and ignored\n",
    );
    assert_eq!(m.name, "T.ASM");
    let sections: Vec<(&str, &str, SectionKind, u8, &[u8])> = m
        .sections
        .iter()
        .map(|s| {
            (
                s.name.as_str(),
                s.class.as_str(),
                s.kind,
                s.bits,
                s.data.as_slice(),
            )
        })
        .collect();
    assert_eq!(
        sections,
        [
            (
                "_TEXT0001",
                "CODE",
                SectionKind::Code,
                32,
                &[0x55, 0x8B, 0xEC, 0x5D, 0xC3][..]
            ),
            (
                "_TEXT0002",
                "CODE",
                SectionKind::Code,
                32,
                &[0x90, 0xFF][..]
            ),
        ]
    );
    assert_eq!(
        symbols(&m),
        [
            ("first_", 0, 0, true),
            ("second_", 1, 0, true),
            ("third_", 1, 1, true)
        ]
    );
    assert!(m.sections.iter().all(|s| s.relocs.is_empty()));
    assert!(m.groups.is_empty() && m.start.is_none());
}

#[test]
fn call_and_jmp_to_extern_are_rel32_fixups() {
    let m = assemble(
        "\t.386p\n\
         \textrn helper_:near, _table:dword\n\
         \textrn other_:NEAR\n\
         _TEXT0001 segment byte public use32 'CODE'\n\
         \tpublic f_\n\
         f_:\n\
         \tdb 090h\n\
         \tcall helper_\t; +0001 call 0x1234\n\
         \tjmp near ptr other_\n\
         _TEXT0001 ends\n\
         \tend\n",
    );
    let s = &m.sections[0];
    assert_eq!(s.data, [0x90, 0xE8, 0, 0, 0, 0, 0xE9, 0, 0, 0, 0]);
    let relocs: Vec<_> = s.relocs.iter().map(shape).collect();
    assert_eq!(
        relocs,
        [
            (2, 4, RelocKind::Relative, symbol("helper_"), 0),
            (7, 4, RelocKind::Relative, symbol("other_"), 0),
        ]
    );
}

#[test]
fn call_to_label_in_other_segment_is_fixup() {
    let m = assemble(
        "\t.386p\n\
         _TEXT0001 segment byte public use32 'CODE'\n\
         \tpublic a_\n\
         a_:\n\
         \tdb 090h\n\
         \tcall b_\n\
         \tcall a_\n\
         \tjmp near ptr inner\n\
         inner:\n\
         \tdb 0C3h\n\
         _TEXT0001 ends\n\
         _TEXT0002 segment byte public use32 'CODE'\n\
         \tpublic b_\n\
         \tdb 0CCh\n\
         b_:\n\
         \tdb 0C3h\n\
         _TEXT0002 ends\n\
         \tend\n",
    );
    let a = &m.sections[0];
    // the calls inside the segment are resolved here: call a_ at +6 lands at 0 (0 - 11), the jmp at +11 at +16
    assert_eq!(
        a.data,
        [
            0x90, 0xE8, 0, 0, 0, 0, 0xE8, 0xF5, 0xFF, 0xFF, 0xFF, 0xE9, 0, 0, 0, 0, 0xC3
        ]
    );
    let relocs: Vec<_> = a.relocs.iter().map(shape).collect();
    assert_eq!(
        relocs,
        [(
            2,
            4,
            RelocKind::Relative,
            RefTarget::Section {
                index: 1,
                offset: 1
            },
            0
        )]
    );
    // a label that is not public is no symbol of the object
    assert_eq!(symbols(&m), [("a_", 0, 0, true), ("b_", 1, 1, true)]);
}

#[test]
fn dd_name_plus_offset_keeps_addend() {
    let m = assemble(
        "\t.386p\n\
         \textrn _data:dword\n\
         _TEXT0001 segment byte public use32 'CODE'\n\
         \tpublic f_\n\
         f_:\n\
         \tdb 0A1h\n\
         \tdd _data\n\
         \tdd _data+0x1c4\n\
         \tdd _data - 4\n\
         \tdd f_+012h, g_\n\
         _TEXT0001 ends\n\
         _TEXT0002 segment byte public use32 'CODE'\n\
         \tdb 0, 0\n\
         g_:\n\
         _TEXT0002 ends\n\
         \tend\n",
    );
    let s = &m.sections[0];
    let relocs: Vec<_> = s.relocs.iter().map(shape).collect();
    let section = |index, offset| RefTarget::Section { index, offset };
    assert_eq!(
        relocs,
        [
            (1, 4, RelocKind::Absolute, symbol("_data"), 0),
            (5, 4, RelocKind::Absolute, symbol("_data"), 0x1C4),
            // a negative displacement stays in the field
            (9, 4, RelocKind::Absolute, symbol("_data"), 0),
            (13, 4, RelocKind::Absolute, section(0, 0x12), 0),
            (17, 4, RelocKind::Absolute, section(1, 2), 0),
        ]
    );
    assert_eq!(&s.data[1..9], &[0; 8]);
    assert_eq!(&s.data[9..13], &(-4i32).to_le_bytes());
    assert_eq!(&s.data[13..21], &[0; 8]);
}

#[test]
fn use16_dw_and_call_rel16() {
    let m = assemble(
        "\textrn _var:word, _near:near\n\
         _TEXT segment word public 'CODE'\n\
         \tpublic _f\n\
         _f:\n\
         \tdb 0A1h\n\
         \tdw _var+2\n\
         \tcall _near\n\
         \tcall _f\n\
         \tdw 0FFFFh, -2\n\
         _TEXT ends\n\
         \tend _f\n",
    );
    let s = &m.sections[0];
    assert_eq!(s.bits, 16);
    assert_eq!(
        s.data,
        [
            0xA1, 0, 0, 0xE8, 0, 0, 0xE8, 0xF7, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF
        ]
    );
    let relocs: Vec<_> = s.relocs.iter().map(shape).collect();
    assert_eq!(
        relocs,
        [
            (1, 2, RelocKind::Absolute, symbol("_var"), 2),
            (4, 2, RelocKind::Relative, symbol("_near"), 0),
        ]
    );
    assert_eq!(m.start, Some((0, 0)));
    // 16-bit offsets only in 16-bit segments, 32-bit ones only in 32-bit segments
    let err = assemble_listing(
        "T.ASM",
        "\textrn _v:word\n_TEXT segment use16\n\tdd _v\n_TEXT ends\n\tend\n",
    )
    .unwrap_err();
    assert_eq!(
        err,
        AssembleError::Unsupported {
            line: 3,
            text: "dd _v".into()
        }
    );
    let err = assemble_listing(
        "T.ASM",
        "\t.386\n\textrn _v:word\n_TEXT segment\n\tdw _v\n_TEXT ends\n\tend\n",
    )
    .unwrap_err();
    assert!(
        matches!(err, AssembleError::Unsupported { line: 4, .. }),
        "{err:?}"
    );
}

#[test]
fn call_and_jmp_only_to_labels_and_near_externals() {
    // proc and abs externals are near targets too
    let m = assemble(
        "\t.386p\n\textrn p_:proc, a_:abs\n_TEXT segment use32\n\tcall p_\n\tjmp near ptr a_\n_TEXT ends\n",
    );
    assert_eq!(m.sections[0].relocs.len(), 2);
    // a far external is a far call to MASM, a data external an indirect one: not E8/E9, so not built here
    for (kind, statement) in [
        ("far", "call x"),
        ("dword", "call x"),
        ("byte", "jmp near ptr x"),
        ("fword", "call x"),
    ] {
        let text =
            format!("\t.386p\n\textrn x:{kind}\n_TEXT segment use32\n\t{statement}\n_TEXT ends\n");
        assert_eq!(
            assemble_listing("T.ASM", &text).unwrap_err(),
            AssembleError::Unsupported {
                line: 4,
                text: statement.into()
            },
            "{kind}"
        );
    }
    // the same name declared with two types
    let err = assemble_listing("T.ASM", "\textrn x:near\n\textrn x:dword\n").unwrap_err();
    assert!(
        matches!(err, AssembleError::Invalid { line: 2, .. }),
        "{err:?}"
    );
}

#[test]
fn public_without_label_is_invalid() {
    let err = assemble_listing(
        "T.ASM",
        "\t.386p\n\textrn x_:near\n_TEXT segment use32\n\tpublic f_, x_\nf_:\n\tdb 0C3h\n_TEXT ends\n\tend\n",
    )
    .unwrap_err();
    assert_eq!(
        err,
        AssembleError::Invalid {
            line: 4,
            reason: "public x_ is not a label of this file".into()
        }
    );
    // an unknown name, a label twice, a value out of range, an open segment
    let invalid = |text: &str| match assemble_listing("T.ASM", text) {
        Err(AssembleError::Invalid { line, .. }) => line,
        other => panic!("{text:?}: {other:?}"),
    };
    assert_eq!(
        invalid("_TEXT segment use32\n\tdd nowhere\n_TEXT ends\n"),
        2
    );
    assert_eq!(invalid("_TEXT segment\na:\na:\n_TEXT ends\n"), 3);
    assert_eq!(invalid("_TEXT segment\n\tdb 256\n_TEXT ends\n"), 2);
    assert_eq!(invalid("_TEXT segment\n\tdb 1\n"), 1);
    assert_eq!(invalid("\tdb 1\n"), 1);
    assert_eq!(invalid("_TEXT segment\n_DATA ends\n"), 2);
}

#[test]
fn unknown_mnemonic_is_unsupported_with_line() {
    let err = assemble_listing(
        "T.ASM",
        "\t.386p\n_TEXT segment use32\nf_:\tmov eax, 1\t; a real instruction\n_TEXT ends\n\tend\n",
    )
    .unwrap_err();
    assert_eq!(
        err,
        AssembleError::Unsupported {
            line: 3,
            text: "mov eax, 1".into()
        }
    );
    assert_eq!(
        err.to_string(),
        "line 3 is outside the built-in assembler subset (mov eax, 1)"
    );
    let unsupported = |text: &str| match assemble_listing("T.ASM", text) {
        Err(AssembleError::Unsupported { line, .. }) => line,
        other => panic!("{text:?}: {other:?}"),
    };
    for line in [
        "\tjmp short x",
        "\tjmp x",
        "\tcall dword ptr [eax]",
        "\tdb 3 dup (0)",
        "\tdb ?",
        "\tdd offset x",
        "\tdb x",
        "\tdd x*2",
        "\t.model small",
        "\tinclude x.inc",
    ] {
        let text = format!("\textrn x:near\n_TEXT segment use32\n{line}\n_TEXT ends\n");
        assert_eq!(unsupported(&text), 3, "{line}");
    }
    assert_eq!(
        unsupported("_TEXT segment at 0B800h\n_TEXT ends\n"),
        1,
        "segment at"
    );
    assert_eq!(
        unsupported("A segment\nB segment\nB ends\nA ends\n"),
        2,
        "nested"
    );
}

#[test]
fn string_in_db() {
    let m = assemble(
        "_DATA segment byte public 'DATA'\n\
         \tdb 'it''s', 0, \"a;b\", 0Dh,0Ah\t; comment\n\
         \tdb 'ä─'\n\
         _DATA ends\n\
         \tend\n",
    );
    // code page 437, as the staged source: a-umlaut 0x84, box drawing 0xC4
    assert_eq!(m.sections[0].data, b"it's\0a;b\r\n\x84\xC4");
    // a character code page 437 does not have
    let err = assemble_listing("T.ASM", "_DATA segment\n\tdb '€'\n_DATA ends\n").unwrap_err();
    assert!(
        matches!(err, AssembleError::Invalid { line: 2, .. }),
        "{err:?}"
    );
    assert_eq!(m.sections[0].kind, SectionKind::Data);
}
