//! Synthetic rebuilt functions compared against synthetic originals (no private data).

use std::collections::BTreeMap;

use decovery_core::{
    Address, ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
use decovery_diff::{
    Blocker, CompareOptions, Comparison, Decoration, NameAt, SymbolView, Verdict, compare,
};
use decovery_objects::{
    Frame, ObjReloc, ObjSymbol, ObjectModule, RefTarget, Section, SectionKind, functions,
};

const AT: u32 = 0x10000;

#[derive(Default)]
struct Symbols {
    names: BTreeMap<u32, String>,
}

impl Symbols {
    fn with(pairs: &[(u32, &str)]) -> Self {
        Symbols {
            names: pairs.iter().map(|&(a, n)| (a, n.to_string())).collect(),
        }
    }
}

impl SymbolView for Symbols {
    fn name_at(&self, at: Address) -> Option<NameAt> {
        let Address::Flat(a) = at else { return None };
        Some(match self.names.get(&a) {
            Some(n) => NameAt::new(n.clone(), false),
            None => NameAt::new(format!("fun_{a:08X}"), true),
        })
    }

    fn address_of(&self, name: &str) -> Option<Address> {
        self.names
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(&a, _)| Address::Flat(a))
    }
}

fn module(code: &[u8], relocs: Vec<ObjReloc>) -> ObjectModule {
    ObjectModule::new(
        "t.c",
        vec![Section::new(
            "_TEXT",
            "CODE",
            SectionKind::Code,
            32,
            code.to_vec(),
            relocs,
        )],
        vec![ObjSymbol::new("f_", 0, 0, true)],
    )
}

fn program(original: &[u8], relocations: Vec<Relocation>) -> Program {
    let mut data = original.to_vec();
    data.resize(0x400, 0xCC);
    let code = Region::new(
        "obj1",
        Address::Flat(AT),
        0x400,
        data,
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
        ArchMode::X86Flat32,
    );
    Program::new(ExecutableFormat::Le, vec![code], vec![], relocations)
}

fn run(m: &ObjectModule, p: &Program, symbols: &Symbols, original_len: Option<u32>) -> Comparison {
    let fs = functions(m);
    let f = fs.iter().find(|f| f.name == "f_").unwrap();
    compare(
        f,
        Address::Flat(AT),
        p,
        symbols,
        &Decoration::watcom(),
        &CompareOptions::new(false, original_len),
    )
}

fn rel(offset: u32, name: &str) -> ObjReloc {
    ObjReloc::new(
        offset,
        4,
        RelocKind::Relative,
        RefTarget::Symbol(name.to_string()),
        0,
        Frame::Unknown,
    )
}

fn abs(offset: u32, name: &str) -> ObjReloc {
    ObjReloc::new(
        offset,
        4,
        RelocKind::Absolute,
        RefTarget::Symbol(name.to_string()),
        0,
        Frame::Unknown,
    )
}

/// `call` at `AT` to `target` followed by `ret`.
fn call_to(target: u32) -> Vec<u8> {
    let mut v = vec![0xE8];
    v.extend_from_slice(&(target.wrapping_sub(AT + 5)).to_le_bytes());
    v.push(0xC3);
    v
}

#[test]
fn identical_without_relocations() {
    let code = [0x55, 0x8B, 0xEC, 0x5D, 0xC3];
    let c = run(
        &module(&code, vec![]),
        &program(&code, vec![]),
        &Symbols::default(),
        None,
    );
    assert_eq!(c.verdict, Verdict::Identical);
    assert!(c.blockers.is_empty());
    assert_eq!(c.metrics.bytes, 5);
    assert_eq!(c.metrics.equal, 5);
    assert_eq!(c.metrics.instructions_differing, 0);
}

#[test]
fn relative_ref_same_target_is_identical() {
    let m = module(&[0xE8, 0, 0, 0, 0, 0xC3], vec![rel(1, "g_")]);
    let p = program(&call_to(0x10100), vec![]);
    let c = run(&m, &p, &Symbols::with(&[(0x10100, "g")]), None);
    assert_eq!(c.verdict, Verdict::Identical, "{:?}", c.blockers);
    assert_eq!(c.metrics.refs_ok, 1);
    assert_eq!(c.metrics.gaps, 4);
    assert_eq!(c.metrics.equal, 2);
}

#[test]
fn relative_ref_other_target_blocks() {
    let m = module(&[0xE8, 0, 0, 0, 0, 0xC3], vec![rel(1, "g_")]);
    let p = program(&call_to(0x10200), vec![]);
    let c = run(
        &m,
        &p,
        &Symbols::with(&[(0x10100, "g"), (0x10200, "h")]),
        None,
    );
    assert_eq!(c.verdict, Verdict::Differs);
    assert!(c.blockers.contains(&Blocker::WrongRelativeRef { at: 1 }));
    assert_eq!(c.metrics.refs_wrong, 1);
}

#[test]
fn absolute_ref_other_target_blocks() {
    // mov eax,[var]: the rebuild means `var`, the original reads var + 0x10.
    let m = module(&[0xA1, 0, 0, 0, 0, 0xC3], vec![abs(1, "_var")]);
    let p = program(
        &[0xA1, 0x10, 0x00, 0x05, 0x00, 0xC3],
        vec![Relocation::new(
            Address::Flat(AT + 1),
            RelocKind::Absolute,
            4,
            Address::Flat(0x50010),
            0,
        )],
    );
    let c = run(&m, &p, &Symbols::with(&[(0x50000, "var")]), None);
    // Decomp's byte comparison passes it: the field is a linker gap and no relative reference is involved.
    assert_eq!(c.metrics.differing, 0);
    assert_eq!(c.metrics.refs_wrong, 0);
    assert_eq!(c.metrics.gaps, 4);
    assert_eq!(c.verdict, Verdict::Differs);
    assert!(c.blockers.contains(&Blocker::WrongAbsoluteRef { at: 1 }));
}

#[test]
fn unnamed_ref_is_unchecked_blocker() {
    let m = module(
        &[0xE8, 0, 0, 0, 0, 0xC3],
        vec![ObjReloc::new(
            1,
            4,
            RelocKind::Relative,
            RefTarget::Unknown,
            0,
            Frame::Unknown,
        )],
    );
    let p = program(&call_to(0x10100), vec![]);
    let c = run(&m, &p, &Symbols::with(&[(0x10100, "g")]), None);
    assert_eq!(c.metrics.refs_unchecked, 1);
    assert_eq!(c.verdict, Verdict::Differs);
    assert_eq!(c.blockers, vec![Blocker::UncheckedRef { at: 1 }]);
}

#[test]
fn nop_padding_after_ret_counts_as_padding() {
    let m = module(&[0xC3, 0x90, 0x90, 0x90], vec![]);
    let p = program(&[0xC3, 0x00, 0x00, 0x00], vec![]);
    let c = run(&m, &p, &Symbols::default(), Some(1));
    assert_eq!(c.metrics.padding, 3);
    assert_eq!(c.metrics.equal, 1);
    assert_eq!(c.metrics.differing, 0);
    assert_eq!(c.metrics.instructions_differing, 0);
    assert_eq!(c.verdict, Verdict::Identical, "{:?}", c.blockers);
}

#[test]
fn one_byte_difference_counts_one_instruction() {
    let m = module(&[0xB8, 1, 0, 0, 0, 0xC3], vec![]);
    let p = program(&[0xB8, 2, 0, 0, 0, 0xC3], vec![]);
    let c = run(&m, &p, &Symbols::default(), None);
    assert_eq!(c.metrics.differing, 1);
    assert_eq!(c.metrics.first_difference, Some(1));
    assert_eq!(c.metrics.instructions_differing, 1);
    assert_eq!(c.verdict, Verdict::Differs);
    assert_eq!(
        c.blockers,
        vec![
            Blocker::BytesDiffer { count: 1 },
            Blocker::InstructionsDiffer { count: 1 }
        ]
    );
}

#[test]
fn metrics_match_decomp_fields() {
    // 0: call g_ (fixup)      E8 xx xx xx xx
    // 5: mov eax,[var] (fixup) A1 xx xx xx xx
    // A: call ? (no name)     E8 xx xx xx xx
    // F: mov ecx,1 / 2        B9 01 00 00 00
    // 14: call h_ (fixup, original calls k) E8 xx xx xx xx
    // 19: ret                 C3
    let mut rebuild = vec![0xE8, 0, 0, 0, 0, 0xA1, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0];
    rebuild.extend_from_slice(&[0xB9, 1, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xC3]);
    let relocs = vec![
        rel(1, "g_"),
        abs(6, "_var"),
        ObjReloc::new(
            0xB,
            4,
            RelocKind::Relative,
            RefTarget::Unknown,
            0,
            Frame::Unknown,
        ),
        rel(0x15, "h_"),
    ];
    let m = module(&rebuild, relocs);
    let call = |at: u32, target: u32| {
        let mut v = vec![0xE8];
        v.extend_from_slice(&target.wrapping_sub(AT + at + 5).to_le_bytes());
        v
    };
    let mut original = call(0, 0x10100);
    original.extend_from_slice(&[0xA1, 0x00, 0x00, 0x05, 0x00]);
    original.extend(call(0xA, 0x10300));
    original.extend_from_slice(&[0xB9, 2, 0, 0, 0]);
    original.extend(call(0x14, 0x10200));
    original.push(0xC3);
    let p = program(
        &original,
        vec![Relocation::new(
            Address::Flat(AT + 6),
            RelocKind::Absolute,
            4,
            Address::Flat(0x50000),
            0,
        )],
    );
    let symbols = Symbols::with(&[
        (0x10100, "g"),
        (0x10200, "k"),
        (0x10280, "h"),
        (0x50000, "var"),
    ]);
    let c = run(&m, &p, &symbols, None);
    let x = &c.metrics;
    assert_eq!(x.bytes, 26);
    assert_eq!(x.gaps, 16);
    assert_eq!(x.equal, 9);
    assert_eq!(x.differing, 1);
    assert_eq!(x.padding, 0);
    assert_eq!(x.first_difference, Some(0x10));
    assert_eq!(x.refs_ok, 1);
    assert_eq!(x.refs_wrong, 1);
    assert_eq!(x.refs_unchecked, 1);
    // mov ecx differs in its bytes; call h_ against k differs by name.
    assert_eq!(x.instructions_differing, 2);
    assert_eq!(
        c.blockers,
        vec![
            Blocker::BytesDiffer { count: 1 },
            Blocker::UncheckedRef { at: 0xB },
            Blocker::WrongRelativeRef { at: 0x15 },
            Blocker::InstructionsDiffer { count: 2 },
        ]
    );
}

#[test]
fn own_section_jump_table_resolves_through_function_address() {
    // 0: jmp [eax*4 + table]; 7: nop; 8: table (one entry -> C); C: ret
    let own = |offset: u32| {
        ObjReloc::new(
            offset,
            4,
            RelocKind::Absolute,
            RefTarget::Section {
                index: 0,
                offset: 0,
            },
            0,
            Frame::Unknown,
        )
    };
    let mut rebuild = vec![0xFF, 0x24, 0x85, 0x08, 0, 0, 0, 0x90, 0x0C, 0, 0, 0, 0xC3];
    let m = module(&rebuild, vec![own(3), own(8)]);
    rebuild[3..7].copy_from_slice(&(AT + 8).to_le_bytes());
    rebuild[8..12].copy_from_slice(&(AT + 0xC).to_le_bytes());
    let table = |at: u32, target: u32| {
        Relocation::new(
            Address::Flat(AT + at),
            RelocKind::Absolute,
            4,
            Address::Flat(AT + target),
            0,
        )
    };
    let p = program(&rebuild, vec![table(3, 8), table(8, 0xC)]);
    let c = run(&m, &p, &Symbols::default(), None);
    assert_eq!(c.verdict, Verdict::Identical, "{:?}", c.blockers);
    assert_eq!(c.metrics.gaps, 8);

    // The original's table sits 4 bytes further on: Decomp passes it, decovery does not.
    let p = program(&rebuild, vec![table(3, 0xC), table(8, 0xC)]);
    let c = run(&m, &p, &Symbols::default(), None);
    assert_eq!(c.blockers, vec![Blocker::WrongAbsoluteRef { at: 3 }]);
}

#[test]
fn unreadable_original_is_unchecked() {
    let m = module(&[0xC3], vec![]);
    let p = program(&[0xC3], vec![]);
    let fs = functions(&m);
    let c = compare(
        &fs[0],
        Address::Flat(0x90000),
        &p,
        &Symbols::default(),
        &Decoration::watcom(),
        &CompareOptions::default(),
    );
    assert_eq!(c.verdict, Verdict::Unchecked);
}

#[test]
fn decoration_strips_watcom_affixes() {
    let d = Decoration::watcom();
    assert_eq!(d.undecorate("play_"), "play");
    assert_eq!(d.undecorate("_timer"), "timer");
    assert_eq!(d.undecorate("_"), "_");
    assert_eq!(d.undecorate("plain"), "plain");
}
