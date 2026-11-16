//! Module comparison of what assembler listings and Watcom's literal sections produce (phase-2 refresh), on
//! synthetic programs (no private data): pointer tables in segments of their own, references to labels of other
//! code segments, functions the analysis split, and alignment fill between string literals.

use std::collections::{BTreeMap, BTreeSet};

use decovery_core::{
    Address, ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
use decovery_diff::{
    Blocker, Decoration, LiteralSections, ModuleComparison, ModuleOptions, NameAt, Placement,
    SymbolView, Verdict, compare_module,
};
use decovery_objects::{
    Frame, ObjReloc, ObjSymbol, ObjectModule, RefTarget, Section, SectionKind, functions,
};

const AT: u32 = 0x10000;
const DATA: u32 = 0x20000;

#[derive(Default)]
struct Symbols {
    names: BTreeMap<Address, String>,
}

impl Symbols {
    fn with(pairs: &[(u32, &str)]) -> Self {
        Symbols {
            names: pairs
                .iter()
                .map(|&(a, n)| (Address::Flat(a), n.to_string()))
                .collect(),
        }
    }
}

impl SymbolView for Symbols {
    fn name_at(&self, at: Address) -> Option<NameAt> {
        Some(match self.names.get(&at) {
            Some(n) => NameAt::new(n.clone(), false),
            None => NameAt::new(format!("fun_{at}"), true),
        })
    }

    fn address_of(&self, name: &str) -> Option<Address> {
        self.names
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(&a, _)| a)
    }
}

fn program(code: &[u8], data: &[u8], relocations: Vec<Relocation>) -> Program {
    let region = |name: &str, start: u32, bytes: &[u8]| {
        let mut v = bytes.to_vec();
        v.resize(0x400, 0xCC);
        Region::new(
            name,
            Address::Flat(start),
            0x400,
            v,
            Permissions {
                read: true,
                write: false,
                execute: true,
            },
            ArchMode::X86Flat32,
        )
    };
    Program::new(
        ExecutableFormat::Le,
        vec![region("obj1", AT, code), region("obj2", DATA, data)],
        vec![],
        relocations,
    )
}

fn absolute(at: u32, target: u32) -> Relocation {
    Relocation::new(
        Address::Flat(at),
        RelocKind::Absolute,
        4,
        Address::Flat(target),
        0,
    )
}

fn section_field(offset: u32, index: u32, base: u32) -> ObjReloc {
    ObjReloc::new(
        offset,
        4,
        RelocKind::Absolute,
        RefTarget::Section {
            index,
            offset: base,
        },
        0,
        Frame::Unknown,
    )
}

fn code(name: &str, bytes: Vec<u8>, relocs: Vec<ObjReloc>) -> Section {
    Section::new(name, "CODE", SectionKind::Code, 32, bytes, relocs)
}

/// Every public function of `m` at its address in `symbols`.
fn run(
    m: &ObjectModule,
    p: &Program,
    symbols: &Symbols,
    lens: &[Option<u32>],
    options: &ModuleOptions,
) -> ModuleComparison {
    let fs = functions(m);
    let placements: Vec<Placement> = fs
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let at = symbols.address_of(f.name).expect("placed function");
            Placement::new(f.clone(), at, lens.get(i).copied().flatten())
        })
        .collect();
    compare_module(
        &placements,
        p,
        symbols,
        &Decoration::new("{name}", "{name}"),
        options,
    )
}

/// A jump table in a segment of its own (`dd stub+5`, `dd stub+6`, the label's offset in the field) and the stub in
/// the next segment; in the original the table lies at `AT` and its entries lead to `entries`.
fn table_case(entries: [u32; 2]) -> ModuleComparison {
    let m = ObjectModule::new(
        "t.asm",
        vec![
            code(
                "T_0001",
                vec![5, 0, 0, 0, 6, 0, 0, 0],
                vec![section_field(0, 1, 0), section_field(4, 1, 0)],
            ),
            code(
                "T_0002",
                vec![0x90, 0x90, 0x90, 0x90, 0x90, 0xC3, 0xC3],
                vec![],
            ),
        ],
        vec![
            ObjSymbol::new("table", 0, 0, true),
            ObjSymbol::new("stub", 1, 0, true),
        ],
    );
    let stub = AT + 0x10;
    let mut original = vec![0xCCu8; 0x10];
    original[..4].copy_from_slice(&entries[0].to_le_bytes());
    original[4..8].copy_from_slice(&entries[1].to_le_bytes());
    original.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0xC3, 0xC3]);
    let p = program(
        &original,
        &[],
        vec![absolute(AT, entries[0]), absolute(AT + 4, entries[1])],
    );
    let symbols = Symbols::with(&[(AT, "table"), (stub, "stub")]);
    run(&m, &p, &symbols, &[], &ModuleOptions::default())
}

#[test]
fn table_entries_to_labels_of_another_code_segment_are_checked_by_the_label_before_them() {
    let c = table_case([AT + 0x15, AT + 0x16]);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0]
    );
    // a table of addresses has no instructions to compare
    assert_eq!(c.functions[0].metrics.instructions_differing, 0);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert_eq!(c.functions[1].verdict, Verdict::Identical);

    let c = table_case([AT + 0x15, AT + 0x17]);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 4 }]
    );
}

/// `mov eax, 1; ret; mov eax, 2; ret` as one function of the rebuild; the analysis ends the original function
/// after its first `ret` (`original_len` 6). The original holds `second` behind it.
fn split_case(second: u8) -> ModuleComparison {
    let bytes = vec![0xB8, 1, 0, 0, 0, 0xC3, 0xB8, 2, 0, 0, 0, 0xC3];
    let m = ObjectModule::new(
        "t.asm",
        vec![code("T_0001", bytes.clone(), vec![])],
        vec![ObjSymbol::new("f", 0, 0, true)],
    );
    let mut original = bytes;
    original[7] = second;
    let p = program(&original, &[], vec![]);
    run(
        &m,
        &p,
        &Symbols::with(&[(AT, "f")]),
        &[Some(6)],
        &ModuleOptions::default(),
    )
}

#[test]
fn code_beyond_the_analysis_end_with_equal_bytes_is_compared_as_instructions() {
    let c = split_case(2);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0]
    );
    let c = split_case(3);
    assert_eq!(c.functions[0].verdict, Verdict::Differs);
    assert!(
        c.functions[0]
            .blockers
            .contains(&Blocker::BytesDiffer { count: 1 }),
        "{:?}",
        c.functions[0].blockers
    );
}

/// Two `mov eax, offset CONST+n` (n = 0 and 8) over the literals `rebuild`; the original holds `original` at
/// `DATA + 0x10`.
fn literal_case(rebuild: &[u8], original: &[u8], options: &ModuleOptions) -> ModuleComparison {
    let m = ObjectModule::new(
        "T.C",
        vec![
            code(
                "_TEXT",
                vec![0xB8, 0, 0, 0, 0, 0xB8, 8, 0, 0, 0, 0xC3],
                vec![section_field(1, 1, 0), section_field(6, 1, 0)],
            ),
            Section::new(
                "CONST",
                "DATA",
                SectionKind::Data,
                32,
                rebuild.to_vec(),
                vec![],
            ),
        ],
        vec![ObjSymbol::new("f", 0, 0, true)],
    );
    let (first, second) = (DATA + 0x10, DATA + 0x18);
    let mut code = vec![0xB8];
    code.extend_from_slice(&first.to_le_bytes());
    code.push(0xB8);
    code.extend_from_slice(&second.to_le_bytes());
    code.push(0xC3);
    let p = program(
        &code,
        &[&[0u8; 0x10][..], original].concat(),
        vec![absolute(AT + 1, first), absolute(AT + 6, second)],
    );
    run(&m, &p, &Symbols::with(&[(AT, "f")]), &[], options)
}

fn literals(modules: &[&str]) -> ModuleOptions {
    ModuleOptions::default().with_literals(LiteralSections::new(
        BTreeSet::from(["CONST".to_string()]),
        4,
        modules.iter().map(|m| m.to_string()).collect(),
    ))
}

#[test]
fn alignment_fill_between_literals_is_not_compared() {
    // "abcde\0" padded to 8 with fill the compiler left uninitialised ("XY"), then "fg\0"
    let rebuild = b"abcde\0XYfg\0";
    let original = b"abcde\0\0\0fg\0";
    let c = literal_case(rebuild, original, &literals(&["T.C"]));
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0]
    );

    // without the profile's literal sections, or for a module the compiler did not write, the fill counts
    for options in [ModuleOptions::default(), literals(&["OTHER.ASM"])] {
        let c = literal_case(rebuild, original, &options);
        assert_eq!(
            c.functions[0].blockers,
            vec![Blocker::WrongAbsoluteRef { at: 1 }]
        );
    }

    // a different character before the literal's end is still a wrong reference
    let c = literal_case(rebuild, b"abcdx\0\0\0fg\0", &literals(&["T.C"]));
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
    // as is a NUL-free item: no fill without its terminating zero
    let c = literal_case(b"abcdefXYfg\0", b"abcdef\0\0fg\0", &literals(&["T.C"]));
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}
