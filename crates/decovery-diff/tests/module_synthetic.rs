//! Module comparison with 16-bit reference anchors (ADR 0006) on synthetic programs (no private data).

use std::collections::BTreeMap;

use decovery_core::{
    Address, ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
use decovery_diff::{
    Anchor, AnchorSource, Blocker, CompareOptions, Decoration, ModuleComparison, ModuleOptions,
    NameAt, Placement, SymbolView, Verdict, compare, compare_module,
};
use decovery_objects::{
    Frame, Group, ObjReloc, ObjSymbol, ObjectModule, RefTarget, Section, SectionKind, functions,
};

/// Names by address; any other address has a default name.
#[derive(Default)]
struct Symbols {
    names: BTreeMap<Address, String>,
}

impl Symbols {
    fn with(pairs: &[(Address, &str)]) -> Self {
        Symbols {
            names: pairs.iter().map(|&(a, n)| (a, n.to_string())).collect(),
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

fn seg(seg: u16, off: u16) -> Address {
    Address::Seg { seg, off }
}

const DATA: &[u8] = b"ab\0cdef\0";

/// `_TEXT` (code) and `_DATA` (`"ab\0cdef\0"`) in `DGROUP`; one function per entry of `code` at offsets 0, 8, 16, …
fn module16(code: &[&[u8]], relocs: Vec<ObjReloc>) -> ObjectModule {
    let mut text = Vec::new();
    let mut symbols = Vec::new();
    for (i, c) in code.iter().enumerate() {
        let start = 8 * i as u32;
        text.resize(start as usize, 0x90);
        text.extend_from_slice(c);
        symbols.push(ObjSymbol::new(format!("f{i}_"), 0, start, true));
    }
    let mut m = ObjectModule::new(
        "t.c",
        vec![
            Section::new("_TEXT", "CODE", SectionKind::Code, 16, text, relocs),
            Section::new(
                "_DATA",
                "DATA",
                SectionKind::Data,
                16,
                DATA.to_vec(),
                vec![],
            ),
        ],
        symbols,
    );
    m.groups = vec![Group::new("DGROUP", vec![1])];
    m
}

/// Offset fixup (16-bit) of `_TEXT` at `offset`, frame `DGROUP`.
fn off16(offset: u32, target: RefTarget) -> ObjReloc {
    ObjReloc::new(
        offset,
        2,
        RelocKind::Absolute,
        target,
        0,
        Frame::Group("DGROUP".to_string()),
    )
}

fn sym(name: &str) -> RefTarget {
    RefTarget::Symbol(name.to_string())
}

fn data_at(offset: u32) -> RefTarget {
    RefTarget::Section { index: 1, offset }
}

/// An MZ program: the image starts at `seg:0000:0000`, the original code at offset 0 (functions every 8 bytes),
/// `extra` bytes written at their linear addresses.
fn program16(code: &[&[u8]], extra: &[(usize, &[u8])], relocations: Vec<Relocation>) -> Program {
    let mut image = vec![0u8; 0x4000];
    for (i, c) in code.iter().enumerate() {
        let start = 8 * i;
        for b in &mut image[start..start + 8] {
            *b = 0x90;
        }
        image[start..start + c.len()].copy_from_slice(c);
    }
    for &(at, bytes) in extra {
        image[at..at + bytes.len()].copy_from_slice(bytes);
    }
    let region = Region::new(
        "image",
        seg(0, 0),
        image.len() as u64,
        image,
        Permissions {
            read: true,
            write: true,
            execute: true,
        },
        ArchMode::X86Real16,
    );
    Program::new(ExecutableFormat::Mz, vec![region], vec![], relocations)
}

fn known_globals() -> Symbols {
    Symbols::with(&[
        (seg(0x200, 0x10), "g1"),
        (seg(0x200, 0x14), "g2"),
        (seg(0x200, 0x18), "g3"),
    ])
}

fn run16(
    m: &ObjectModule,
    p: &Program,
    symbols: &Symbols,
    options: &ModuleOptions,
) -> ModuleComparison {
    let fs = functions(m);
    let placements: Vec<Placement> = fs
        .iter()
        .map(|f| Placement::new(f.clone(), seg(0, f.start as u16), None))
        .collect();
    compare_module(&placements, p, symbols, &Decoration::watcom(), options)
}

fn anchor<'a>(c: &'a ModuleComparison, frame: &str, section: Option<&str>) -> &'a Anchor {
    c.anchors
        .iter()
        .find(|a| a.frame == frame && a.section.as_deref() == section)
        .unwrap_or_else(|| panic!("no anchor {frame} {section:?} in {:?}", c.anchors))
}

/// `mov ax,[x]; ret` with the rebuild's field zero.
const LOAD: &[u8] = &[0xA1, 0, 0, 0xC3];

fn load(field: u16) -> Vec<u8> {
    let [lo, hi] = field.to_le_bytes();
    vec![0xA1, lo, hi, 0xC3]
}

#[test]
fn dgroup_frame_anchor_by_consensus() {
    let m = module16(
        &[LOAD, LOAD, LOAD],
        vec![
            off16(1, sym("_g1")),
            off16(9, sym("_g2")),
            off16(17, sym("_g1")),
        ],
    );
    let p = program16(&[&load(0x10), &load(0x14), &load(0x10)], &[], vec![]);
    let c = run16(&m, &p, &known_globals(), &ModuleOptions::default());
    for f in &c.functions {
        assert_eq!(f.verdict, Verdict::Identical, "{:?}", f.blockers);
    }
    let a = anchor(&c, "DGROUP", None);
    assert_eq!(a.base, 0x2000);
    assert_eq!(a.votes, 2);
    assert_eq!(a.dissent, 0);
    assert_eq!(a.source, AnchorSource::Consensus);
}

#[test]
fn dissenting_field_is_wrong() {
    let m = module16(
        &[LOAD, LOAD, LOAD],
        vec![
            off16(1, sym("_g1")),
            off16(9, sym("_g2")),
            off16(17, sym("_g2")),
        ],
    );
    let p = program16(&[&load(0x10), &load(0x14), &load(0x18)], &[], vec![]);
    let c = run16(&m, &p, &known_globals(), &ModuleOptions::default());
    assert_eq!(c.functions[0].verdict, Verdict::Identical);
    assert_eq!(c.functions[1].verdict, Verdict::Identical);
    assert_eq!(
        c.functions[2].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
    let a = anchor(&c, "DGROUP", None);
    assert_eq!((a.base, a.votes, a.dissent), (0x2000, 2, 1));
}

/// `mov ax,[_g1]; mov ax,offset _DATA+0; mov dx,offset _DATA+3; ret` (the strings `"ab"` and `"cdef"`); the
/// string fields are 0x40 and 0x43 in the original, `strings` sits at linear 0x2040.
fn strings_case(strings: &[u8], symbols: &Symbols) -> ModuleComparison {
    let code: &[u8] = &[0xA1, 0, 0, 0xB8, 0, 0, 0xBA, 3, 0, 0xC3];
    let m = module16(
        &[code],
        vec![
            off16(1, sym("_g1")),
            off16(4, data_at(0)),
            off16(7, data_at(0)),
        ],
    );
    let original: &[u8] = &[0xA1, 0x10, 0, 0xB8, 0x40, 0, 0xBA, 0x43, 0, 0xC3];
    let p = program16(&[original], &[(0x2040, strings)], vec![]);
    run16(&m, &p, symbols, &ModuleOptions::default())
}

#[test]
fn string_section_anchor_and_bytes() {
    let c = strings_case(DATA, &known_globals());
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    let a = anchor(&c, "DGROUP", Some("_DATA"));
    assert_eq!((a.base, a.votes, a.dissent), (0x40, 2, 0));
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
}

#[test]
fn string_bytes_differ_mark_refs_wrong() {
    // both strings differ
    let c = strings_case(b"aX\0cdeX\0", &known_globals());
    assert_eq!(
        c.functions[0].blockers,
        vec![
            Blocker::WrongAbsoluteRef { at: 4 },
            Blocker::WrongAbsoluteRef { at: 7 }
        ]
    );
}

#[test]
fn unrelated_section_difference_does_not_mark_ref() {
    // only the second string differs: the reference to the first stays matched
    let c = strings_case(b"ab\0cdeX\0", &known_globals());
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 7 }]
    );
}

#[test]
fn no_frame_anchor_warns_and_skips_bytes() {
    // `_g1` unknown: no field names a known address, so DGROUP has no anchor.
    let c = strings_case(b"different", &Symbols::default());
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    assert!(c.anchors.iter().all(|a| a.section.is_some()));
    let a = anchor(&c, "DGROUP", Some("_DATA"));
    assert_eq!((a.base, a.votes), (0x40, 2));
    assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
    assert!(
        c.warnings[0].contains("_DATA") && c.warnings[0].contains("DGROUP"),
        "{:?}",
        c.warnings
    );
}

#[test]
fn config_frame_wins_over_consensus() {
    // `_g1` agrees with 0x2000, `_g2` and `_g3` both propose 0x1FF0.
    let m = module16(
        &[LOAD, LOAD, LOAD],
        vec![
            off16(1, sym("_g1")),
            off16(9, sym("_g2")),
            off16(17, sym("_g3")),
        ],
    );
    let p = program16(&[&load(0x10), &load(0x24), &load(0x28)], &[], vec![]);
    let consensus = run16(&m, &p, &known_globals(), &ModuleOptions::default());
    assert_eq!(anchor(&consensus, "DGROUP", None).base, 0x1FF0);
    assert_eq!(
        consensus.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );

    let mut options = ModuleOptions::default();
    options.frames.insert("DGROUP".to_string(), seg(0x200, 0));
    let c = run16(&m, &p, &known_globals(), &options);
    let a = anchor(&c, "DGROUP", None);
    assert_eq!(a.source, AnchorSource::Config);
    assert_eq!((a.base, a.votes, a.dissent), (0x2000, 1, 2));
    assert_eq!(c.functions[0].verdict, Verdict::Identical);
    assert_eq!(
        c.functions[1].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
    assert_eq!(
        c.functions[2].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}

/// `mov ax,[_g1]; mov ax,seg DGROUP; ret` with the original's segment word `segment` and its MZ relocation.
fn selector_case(segment: u16) -> ModuleComparison {
    let code: &[u8] = &[0xA1, 0, 0, 0xB8, 0, 0, 0xC3];
    let selector = ObjReloc::new(
        4,
        2,
        RelocKind::Selector,
        data_at(0),
        0,
        Frame::Group("DGROUP".to_string()),
    );
    let m = module16(&[code], vec![off16(1, sym("_g1")), selector]);
    let [lo, hi] = segment.to_le_bytes();
    let original: &[u8] = &[0xA1, 0x10, 0, 0xB8, lo, hi, 0xC3];
    let p = program16(
        &[original],
        &[],
        vec![Relocation::new(
            seg(0, 4),
            RelocKind::Selector,
            2,
            seg(segment, 0),
            0,
        )],
    );
    run16(&m, &p, &known_globals(), &ModuleOptions::default())
}

#[test]
fn selector_field_matches_mz_relocation() {
    let c = selector_case(0x200);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
}

#[test]
fn selector_with_wrong_segment_is_wrong() {
    let c = selector_case(0x300);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 4 }]
    );
}

// --- 32-bit ---

const AT: u32 = 0x10000;

fn flat_program(code: &[u8], data: &[u8], relocations: Vec<Relocation>) -> Program {
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
        vec![region("obj1", AT, code), region("obj2", 0x20000, data)],
        vec![],
        relocations,
    )
}

fn flat_reloc(offset: u32, kind: RelocKind, target: RefTarget) -> ObjReloc {
    ObjReloc::new(offset, 4, kind, target, 0, Frame::Unknown)
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

/// Three 8-byte functions: `call g_`, `mov eax,[var]`, `call ?` (no name).
#[test]
fn flat_results_unchanged() {
    let mut code = vec![0xE8, 0, 0, 0, 0, 0xC3, 0x90, 0x90];
    code.extend_from_slice(&[0xA1, 0, 0, 0, 0, 0xC3, 0x90, 0x90]);
    code.extend_from_slice(&[0xE8, 0, 0, 0, 0, 0xC3, 0x90, 0x90]);
    let relocs = vec![
        flat_reloc(1, RelocKind::Relative, sym("g_")),
        flat_reloc(9, RelocKind::Absolute, sym("_var")),
        flat_reloc(17, RelocKind::Relative, RefTarget::Unknown),
    ];
    let m = ObjectModule::new(
        "t.c",
        vec![Section::new(
            "_TEXT",
            "CODE",
            SectionKind::Code,
            32,
            code,
            relocs,
        )],
        vec![
            ObjSymbol::new("f_", 0, 0, true),
            ObjSymbol::new("h_", 0, 8, true),
            ObjSymbol::new("k_", 0, 16, true),
        ],
    );
    let call = |at: u32, target: u32| {
        let mut v = vec![0xE8];
        v.extend_from_slice(&target.wrapping_sub(AT + at + 5).to_le_bytes());
        v.extend_from_slice(&[0xC3, 0x90, 0x90]);
        v
    };
    let mut original = call(0, 0x10100);
    original.extend_from_slice(&[0xA1, 0x00, 0x00, 0x02, 0x00, 0xC3, 0x90, 0x90]);
    original.extend(call(16, 0x10200));
    let p = flat_program(&original, &[], vec![absolute(AT + 9, 0x20000)]);
    let symbols = Symbols::with(&[
        (Address::Flat(0x10100), "g"),
        (Address::Flat(0x20000), "var"),
    ]);
    let fs = functions(&m);
    let placements: Vec<Placement> = fs
        .iter()
        .map(|f| Placement::new(f.clone(), Address::Flat(AT + f.start), None))
        .collect();
    let decoration = Decoration::watcom();
    let module = compare_module(
        &placements,
        &p,
        &symbols,
        &decoration,
        &ModuleOptions::default(),
    );
    for (f, c) in fs.iter().zip(&module.functions) {
        let single = compare(
            f,
            Address::Flat(AT + f.start),
            &p,
            &symbols,
            &decoration,
            &CompareOptions::default(),
        );
        assert_eq!(*c, single, "{}", f.name);
    }
    assert_eq!(module.functions[0].verdict, Verdict::Identical);
    assert_eq!(module.functions[1].verdict, Verdict::Identical);
    assert_eq!(
        module.functions[2].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    assert!(module.anchors.is_empty());
}

/// `mov eax,offset CONST+0; ret` against an original whose relocation points at `strings`.
fn flat_string_case(strings: &[u8]) -> ModuleComparison {
    let m = ObjectModule::new(
        "t.c",
        vec![
            Section::new(
                "_TEXT",
                "CODE",
                SectionKind::Code,
                32,
                vec![0xB8, 0, 0, 0, 0, 0xC3],
                vec![flat_reloc(
                    1,
                    RelocKind::Absolute,
                    RefTarget::Section {
                        index: 1,
                        offset: 0,
                    },
                )],
            ),
            Section::new(
                "CONST",
                "DATA",
                SectionKind::Data,
                32,
                b"hi\0".to_vec(),
                vec![],
            ),
        ],
        vec![ObjSymbol::new("f_", 0, 0, true)],
    );
    let p = flat_program(
        &[0xB8, 0x10, 0x00, 0x02, 0x00, 0xC3],
        &[&[0u8; 0x10][..], strings].concat(),
        vec![absolute(AT + 1, 0x20010)],
    );
    let fs = functions(&m);
    compare_module(
        &[Placement::new(fs[0].clone(), Address::Flat(AT), None)],
        &p,
        &Symbols::default(),
        &Decoration::watcom(),
        &ModuleOptions::default(),
    )
}

#[test]
fn flat_unnamed_section_ref_uses_section_anchor() {
    let c = flat_string_case(b"hi\0");
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    assert_eq!(c.anchors.len(), 1);
    assert_eq!(c.anchors[0].section.as_deref(), Some("CONST"));
    assert_eq!(c.anchors[0].base, 0x20010);

    let c = flat_string_case(b"ho\0");
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}
