//! The data of an Aztec main-program object against the original image (synthetic objects and images).

use decovery_core::{
    Address, ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
use decovery_diff::{DataState, Placement, aztec_data_segment, compare_main_data};
use decovery_objects::{
    Frame, ObjReloc, ObjSymbol, ObjectModule, RefTarget, Section, SectionKind, functions,
};

const DS: u16 = 0x0100;
const CODE_AT: u16 = 0x0020;

fn word(offset: u32, target: RefTarget) -> ObjReloc {
    ObjReloc::new(offset, 2, RelocKind::Absolute, target, 0, Frame::Target)
}

/// `f_`: `mov ax,[data+0]; mov ax,[data+2]; ret`, data `11 22 33 44` plus a pointer to data+2 at offset 4.
fn module(code_targets: [u32; 2], data: Vec<u8>) -> ObjectModule {
    let code = vec![0xA1, 0, 0, 0xA1, 0, 0, 0xC3];
    let code_relocs = vec![
        word(
            1,
            RefTarget::Section {
                index: 1,
                offset: code_targets[0],
            },
        ),
        word(
            4,
            RefTarget::Section {
                index: 1,
                offset: code_targets[1],
            },
        ),
    ];
    let data_relocs = vec![word(
        4,
        RefTarget::Section {
            index: 1,
            offset: 2,
        },
    )];
    ObjectModule::new(
        "M",
        vec![
            Section::new("CODE", "CODE", SectionKind::Code, 16, code, code_relocs),
            Section::new("DATA", "DATA", SectionKind::Data, 16, data, data_relocs),
            Section::new("BSS", "BSS", SectionKind::Bss, 16, vec![], vec![]),
        ],
        vec![ObjSymbol::new("f_", 0, 0, true)],
    )
}

/// An image with the function at 0000:0020 naming data at `start`, and `data` at DS:start. The entry loads DS.
fn program(start: u16, fields: [u16; 2], data: &[u8]) -> Program {
    let mut image = vec![0u8; 0x1000 + 0x400];
    image[0..3].copy_from_slice(&[0xBD, DS as u8, (DS >> 8) as u8]);
    let c = usize::from(CODE_AT);
    image[c] = 0xA1;
    image[c + 1..c + 3].copy_from_slice(&fields[0].to_le_bytes());
    image[c + 3] = 0xA1;
    image[c + 4..c + 6].copy_from_slice(&fields[1].to_le_bytes());
    image[c + 6] = 0xC3;
    let d = usize::from(DS) * 16 + usize::from(start);
    image[d..d + data.len()].copy_from_slice(data);
    let region = Region::new(
        "image",
        Address::Seg { seg: 0, off: 0 },
        image.len() as u64,
        image,
        Permissions::default(),
        ArchMode::X86Real16,
    );
    let reloc = Relocation::new(
        Address::Seg { seg: 0, off: 1 },
        RelocKind::Selector,
        2,
        Address::Seg { seg: DS, off: 0 },
        0,
    );
    Program::new(
        ExecutableFormat::Mz,
        vec![region],
        vec![Address::Seg { seg: 0, off: 0 }],
        vec![reloc],
    )
}

fn run(m: &ObjectModule, p: &Program) -> decovery_diff::MainData {
    let view = functions(m).remove(0);
    let placements = [Placement::new(
        view,
        Address::Seg {
            seg: 0,
            off: CODE_AT,
        },
        Some(7),
    )];
    compare_main_data(m, &placements, p, DS).unwrap()
}

#[test]
fn startup_names_the_data_segment() {
    assert_eq!(aztec_data_segment(&program(0, [0, 0], &[])), Some(DS));
}

#[test]
fn data_anchored_by_code_fields_is_equal() {
    let m = module([0, 2], vec![0x11, 0x22, 0, 0, 0, 0]);
    // data at DS:0040; the pointer field holds 0040 + 2
    let p = program(0x40, [0x40, 0x42], &[0x11, 0x22, 0, 0, 0x42, 0]);
    let d = run(&m, &p);
    assert_eq!(d.start, Some(0x40));
    assert_eq!((d.votes, d.dissent), (2, 0));
    assert_eq!(d.refs_ok, 1);
    assert_eq!(d.state, DataState::Equal, "{d:?}");
}

#[test]
fn differing_data_byte_and_wrong_pointer_are_found() {
    let m = module([0, 2], vec![0x11, 0x22, 0, 0, 0, 0]);
    let p = program(0x40, [0x40, 0x42], &[0x11, 0x99, 0, 0, 0x44, 0]);
    let d = run(&m, &p);
    assert_eq!(d.state, DataState::Differs);
    assert_eq!(d.refs_wrong, 1);
    assert_eq!(d.diffs, vec![1, 4, 5]);
    assert!(
        d.findings[0].starts_with("data differs in 3 bytes of 6, first at 0100:0041"),
        "{:?}",
        d.findings
    );
    assert!(
        d.findings
            .iter()
            .any(|f| f.contains("field at +0x4 should hold 0042, the original holds 0044"))
    );
}

#[test]
fn disagreeing_code_fields_leave_the_data_unchecked() {
    let m = module([0, 2], vec![0x11, 0x22, 0, 0, 0, 0]);
    // the two fields name starts 0040 and 0050: a tie
    let p = program(0x40, [0x40, 0x52], &[0x11, 0x22, 0, 0, 0x42, 0]);
    let d = run(&m, &p);
    assert_eq!(d.start, None);
    assert_eq!(d.state, DataState::Unchecked);
    assert!(
        d.findings[0].contains("2 different starts"),
        "{:?}",
        d.findings
    );
}

#[test]
fn an_odd_start_is_reported() {
    let m = module([0, 2], vec![0x11, 0x22, 0, 0, 0, 0]);
    let p = program(0x41, [0x41, 0x43], &[0x11, 0x22, 0, 0, 0x43, 0]);
    let d = run(&m, &p);
    assert_eq!(d.state, DataState::Equal);
    assert!(
        d.findings.iter().any(|f| f.contains("is odd")),
        "{:?}",
        d.findings
    );
}

#[test]
fn a_module_without_data_gives_nothing() {
    let m = module([0, 2], vec![]);
    let view = functions(&m).remove(0);
    let placements = [Placement::new(
        view,
        Address::Seg {
            seg: 0,
            off: CODE_AT,
        },
        Some(7),
    )];
    assert!(compare_main_data(&m, &placements, &program(0x40, [0, 0], &[]), DS).is_none());
}
