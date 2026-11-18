//! Object-against-image comparison with link gaps (phase 4, Task 4) on objects from the Aztec test writer.

use decovery_core::Address;
use decovery_diff::{Blocker, Verdict, compare_with_gaps};
use decovery_objects::{
    AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget, functions,
    read_aztec, write_aztec,
};

fn sym(name: &str, section: AztecSection, value: u16) -> AztecSymbolSpec {
    AztecSymbolSpec {
        name: name.into(),
        section,
        value,
        public: true,
    }
}

fn code_ref(offset: u16, relative: bool, target: AztecTarget) -> AztecRefSpec {
    AztecRefSpec {
        section: AztecSection::Code,
        offset,
        width: 2,
        relative,
        target,
        addend: 0,
    }
}

/// `f_` at code 0: `mov ax, [buf_]` (absolute word), `call ext_` (relative), `call .L` (relative to an unnamed
/// label at 10), `ret`, `.L: ret`.
fn module() -> AztecModuleSpec {
    AztecModuleSpec {
        name: "T".into(),
        code: vec![
            0xA1, 0, 0, // 0: mov ax, [buf_]
            0xE8, 0, 0, // 3: call ext_
            0xE8, 0, 0,    // 6: call .L
            0xC3, // 9
            0xC3, // 10: .L
        ],
        bss: 4,
        named: vec![
            sym("f_", AztecSection::Code, 0),
            sym("ext_", AztecSection::Extern, 0),
            sym("buf_", AztecSection::Bss, 0),
        ],
        unnamed: vec![(AztecSection::Code, 10)],
        refs: vec![
            code_ref(1, false, AztecTarget::Named(2)),
            code_ref(4, true, AztecTarget::Named(1)),
            code_ref(7, true, AztecTarget::Unnamed(0)),
        ],
        ..AztecModuleSpec::default()
    }
}

/// The linked original at 0000:1000: buf_ at 0x2040, ext_ at 0x0100, .L at 0x100A.
fn image() -> Vec<u8> {
    let call_ext = (0x0100i32 - 0x1006) as u16;
    vec![
        0xA1,
        0x40,
        0x20,
        0xE8,
        call_ext as u8,
        (call_ext >> 8) as u8,
        0xE8,
        0x01,
        0x00, // 0x1009 + 1 = 0x100A
        0xC3,
        0xC3,
    ]
}

const AT: Address = Address::Seg {
    seg: 0,
    off: 0x1000,
};

#[test]
fn relocated_word_is_a_gap() {
    let object = read_aztec(&write_aztec(&module()), "T.O").unwrap();
    let f = &functions(&object.modules[0])[0];
    let c = compare_with_gaps(f, &image(), AT);
    assert_eq!(c.verdict, Verdict::Identical, "{c:?}");
    assert_eq!(c.metrics.gaps, 6);
    assert_eq!(c.metrics.equal, 5);
    assert_eq!(c.metrics.differing, 0);
    assert_eq!(c.metrics.refs_unchecked, 2);
}

#[test]
fn self_relative_call_to_unnamed_symbol_compares() {
    let object = read_aztec(&write_aztec(&module()), "T.O").unwrap();
    let f = &functions(&object.modules[0])[0];
    assert_eq!(compare_with_gaps(f, &image(), AT).metrics.refs_ok, 1);
    let mut wrong = image();
    wrong[7] = 0x02; // the original calls 0x100B, not .L
    let c = compare_with_gaps(f, &wrong, AT);
    assert_eq!(c.verdict, Verdict::Differs);
    assert_eq!(c.blockers, vec![Blocker::WrongRelativeRef { at: 7 }]);
    assert_eq!(c.metrics.differing, 0);
}

#[test]
fn gap_does_not_hide_opcode_difference() {
    let object = read_aztec(&write_aztec(&module()), "T.O").unwrap();
    let f = &functions(&object.modules[0])[0];
    let mut other = image();
    other[3] = 0xE9; // jmp instead of call: the opcode is outside the gap
    let c = compare_with_gaps(f, &other, AT);
    assert_eq!(c.verdict, Verdict::Differs);
    assert_eq!(c.blockers, vec![Blocker::BytesDiffer { count: 1 }]);
    assert_eq!(c.metrics.first_difference, Some(3));
}

#[test]
fn short_image_is_unavailable() {
    let object = read_aztec(&write_aztec(&module()), "T.O").unwrap();
    let f = &functions(&object.modules[0])[0];
    let c = compare_with_gaps(f, &image()[..4], AT);
    assert_eq!(c.verdict, Verdict::Unchecked);
    assert_eq!(c.blockers, vec![Blocker::OriginalUnavailable]);
}
