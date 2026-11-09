//! Module comparison with 16-bit reference anchors (ADR 0006) on synthetic programs (no private data).

use std::collections::BTreeMap;

use decovery_core::{
    Address, ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
use decovery_diff::{
    Anchor, AnchorSource, Blocker, CompareOptions, Decoration, ModuleComparison, ModuleOptions,
    NameAt, Placement, SymbolView, Verdict, compare, compare_module, startup_frames,
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
    let size = extra
        .iter()
        .map(|&(at, bytes)| at + bytes.len())
        .fold(0x4000, usize::max);
    let mut image = vec![0u8; size];
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

/// `mov ax,[_g1]; mov ax,offset _DATA+0; mov dx,offset _DATA+3; mov bx,[_g2]; ret` (the strings `"ab"` and
/// `"cdef"`); the string fields are 0x40 and 0x43 in the original, `strings` sits at linear 0x2040. `_g1` and `_g2`
/// give DGROUP two votes.
fn strings_case(strings: &[u8], symbols: &Symbols) -> ModuleComparison {
    let code: &[u8] = &[0xA1, 0, 0, 0xB8, 0, 0, 0xBA, 3, 0, 0x8B, 0x1E, 0, 0, 0xC3];
    let m = module16(
        &[code],
        vec![
            off16(1, sym("_g1")),
            off16(4, data_at(0)),
            off16(7, data_at(0)),
            off16(11, sym("_g2")),
        ],
    );
    let original: &[u8] = &[
        0xA1, 0x10, 0, 0xB8, 0x40, 0, 0xBA, 0x43, 0, 0x8B, 0x1E, 0x14, 0, 0xC3,
    ];
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
fn no_frame_anchor_warns_and_leaves_items_unchecked() {
    // `_g1` unknown: no field names a known address, so DGROUP has no anchor. The string fields agree with their
    // section anchor, but their items cannot be compared: unchecked, not identical (item 5, 2026-11-09).
    let c = strings_case(b"different", &Symbols::default());
    assert_eq!(
        c.functions[0].blockers,
        vec![
            Blocker::UncheckedRef { at: 1 },
            Blocker::UncheckedRef { at: 4 },
            Blocker::UncheckedRef { at: 7 },
            Blocker::UncheckedRef { at: 11 }
        ]
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

/// `mov ax,[_g1]; mov ax,seg DGROUP; mov bx,[_g2]; ret` with the original's segment word `segment` and its MZ
/// relocation.
fn selector_case(segment: u16) -> ModuleComparison {
    let code: &[u8] = &[0xA1, 0, 0, 0xB8, 0, 0, 0x8B, 0x1E, 0, 0, 0xC3];
    let selector = ObjReloc::new(
        4,
        2,
        RelocKind::Selector,
        data_at(0),
        0,
        Frame::Group("DGROUP".to_string()),
    );
    let m = module16(
        &[code],
        vec![off16(1, sym("_g1")), selector, off16(8, sym("_g2"))],
    );
    let [lo, hi] = segment.to_le_bytes();
    let original: &[u8] = &[0xA1, 0x10, 0, 0xB8, lo, hi, 0x8B, 0x1E, 0x14, 0, 0xC3];
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

/// `call far _g1; ret` (16:16 pointer at +1) with `frame`; the original's pointer is `offset:segment`, with an MZ
/// relocation of its segment word when `relocated`.
fn far_case(frame: Frame, offset: u16, segment: u16, relocated: bool) -> ModuleComparison {
    let code: &[u8] = &[0x9A, 0, 0, 0, 0, 0xC3];
    let far = ObjReloc::new(1, 4, RelocKind::FarPointer, sym("_g1"), 0, frame);
    let m = module16(&[code], vec![far]);
    let [o0, o1] = offset.to_le_bytes();
    let [s0, s1] = segment.to_le_bytes();
    let original: &[u8] = &[0x9A, o0, o1, s0, s1, 0xC3];
    let relocations = if relocated {
        vec![Relocation::new(
            seg(0, 3),
            RelocKind::Selector,
            2,
            seg(segment, 0),
            0,
        )]
    } else {
        vec![]
    };
    let p = program16(&[original], &[], relocations);
    run16(&m, &p, &known_globals(), &ModuleOptions::default())
}

#[test]
fn far_pointer_offset_and_segment_match() {
    let group = || Frame::Group("DGROUP".to_string());
    let c = far_case(group(), 0x10, 0x200, true);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    // a lone field anchors no frame (item 4); segment and offset still give the linear address
    assert!(c.anchors.is_empty(), "{:?}", c.anchors);

    // the segment word disagrees with the base the offset word proposes
    let c = far_case(group(), 0x10, 0x1F0, true);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}

#[test]
fn far_pointer_without_frame_uses_linear() {
    // an external symbol with a target frame: no frame name, 01F0:0110 is linear 0x2010 = `g1`
    let c = far_case(Frame::Target, 0x110, 0x1F0, true);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    assert!(c.anchors.is_empty(), "{:?}", c.anchors);

    let c = far_case(Frame::Target, 0x114, 0x1F0, true);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}

#[test]
fn far_pointer_missing_selector_relocation_is_wrong() {
    for frame in [Frame::Group("DGROUP".to_string()), Frame::Target] {
        let c = far_case(frame, 0x10, 0x200, false);
        assert_eq!(
            c.functions[0].blockers,
            vec![Blocker::WrongAbsoluteRef { at: 1 }]
        );
    }
}

/// `mov ax,[_g1]` and `mov bx,[_g2]` (frame `DGROUP`) and `mov ax,offset _DATA+0; mov dx,offset _DATA+3` with
/// `frame`; the original's string fields are `string0` and `string0 + 3`, the strings at linear 0x2040.
fn framed_strings_case(frame: Frame, string0: u16, options: &ModuleOptions) -> ModuleComparison {
    let code: &[u8] = &[0xA1, 0, 0, 0xB8, 0, 0, 0xBA, 3, 0, 0x8B, 0x1E, 0, 0, 0xC3];
    let data =
        |offset: u32| ObjReloc::new(offset, 2, RelocKind::Absolute, data_at(0), 0, frame.clone());
    let m = module16(
        &[code],
        vec![
            off16(1, sym("_g1")),
            data(4),
            data(7),
            off16(11, sym("_g2")),
        ],
    );
    let [a0, a1] = string0.to_le_bytes();
    let [b0, b1] = (string0 + 3).to_le_bytes();
    let original: &[u8] = &[
        0xA1, 0x10, 0, 0xB8, a0, a1, 0xBA, b0, b1, 0x8B, 0x1E, 0x14, 0, 0xC3,
    ];
    let p = program16(&[original], &[(0x2040, b"ab\0cdeX\0")], vec![]);
    run16(&m, &p, &known_globals(), options)
}

#[test]
fn target_frame_resolves_to_group() {
    // `_DATA` is a member of DGROUP: target and unknown frames are DGROUP, so the DGROUP anchor from `_g1` enables
    // the item check (the second string differs).
    for frame in [Frame::Target, Frame::Unknown] {
        let c = framed_strings_case(frame, 0x40, &ModuleOptions::default());
        let a = anchor(&c, "DGROUP", Some("_DATA"));
        assert_eq!((a.base, a.votes), (0x40, 2));
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        assert_eq!(
            c.functions[0].blockers,
            vec![Blocker::WrongAbsoluteRef { at: 7 }]
        );
    }
}

#[test]
fn section_frame_is_the_section_itself() {
    // Frame `_DATA` (F0), although `_DATA` is in DGROUP: offsets are relative to `_DATA`, a frame of its own.
    let section = || Frame::Section(1);
    let c = framed_strings_case(section(), 0, &ModuleOptions::default());
    let a = anchor(&c, "_DATA", Some("_DATA"));
    assert_eq!((a.base, a.votes), (0, 2));
    assert!(
        c.anchors
            .iter()
            .all(|a| a.frame != "_DATA" || a.section.is_some())
    );
    assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
    assert!(c.warnings[0].contains("frame _DATA"), "{:?}", c.warnings);
    // `_g1` is checked by DGROUP, the two string items are not comparable without a `_DATA` frame
    assert_eq!(
        c.functions[0].blockers,
        vec![
            Blocker::UncheckedRef { at: 4 },
            Blocker::UncheckedRef { at: 7 }
        ]
    );

    // with the `_DATA` frame configured at linear 0x2040 the items are compared
    let mut options = ModuleOptions::default();
    options.frames.insert("_DATA".to_string(), seg(0x204, 0));
    let c = framed_strings_case(section(), 0, &options);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 7 }]
    );
}

// --- startup frames (ADR 0006 item 10) ---

/// The startup object: `mov dx, DGROUP; ret`, its selector field targets the group (frame of the target), the start
/// address at offset 0 of `_TEXT`.
fn startup16(code: &[u8], selectors: &[u32]) -> ObjectModule {
    let relocs = selectors
        .iter()
        .map(|&at| {
            ObjReloc::new(
                at,
                2,
                RelocKind::Selector,
                RefTarget::Group("DGROUP".to_string()),
                0,
                Frame::Target,
            )
        })
        .collect();
    let mut m = ObjectModule::new(
        "c0.obj",
        vec![Section::new(
            "_TEXT",
            "CODE",
            SectionKind::Code,
            16,
            code.to_vec(),
            relocs,
        )],
        vec![],
    );
    m.groups = vec![Group::new("DGROUP", vec![])];
    m.start = Some((0, 0));
    m
}

const STARTUP: &[u8] = &[0xBA, 0, 0, 0xC3];
/// The original's startup at `seg:0010:0000` (the entry point), loading segment 0x0200 (MZ relocation at the field).
const STARTUP_AT: usize = 0x100;

fn segment_reloc(at: usize, segment: u16) -> Relocation {
    Relocation::new(
        seg(0x10, (at - STARTUP_AT) as u16),
        RelocKind::Selector,
        2,
        seg(segment, 0),
        0,
    )
}

/// `mov ax,offset _DATA+0; mov dx,offset _DATA+3; ret`: only unnamed references, no named global and no selector;
/// the original's fields are 0x40 and 0x43, its `_DATA` bytes `strings` at linear 0x2040, its startup code
/// `startup` at the entry point with the given segment relocations.
fn unnamed_case(
    strings: &[u8],
    startup: &[u8],
    relocations: Vec<Relocation>,
) -> (ObjectModule, Program) {
    let code: &[u8] = &[0xB8, 0, 0, 0xBA, 3, 0, 0xC3];
    let m = module16(&[code], vec![off16(1, data_at(0)), off16(4, data_at(0))]);
    let original: &[u8] = &[0xB8, 0x40, 0, 0xBA, 0x43, 0, 0xC3];
    let mut p = program16(
        &[original],
        &[(0x2040, strings), (STARTUP_AT, startup)],
        relocations,
    );
    p.entry_points = vec![seg(0x10, 0)];
    (m, p)
}

fn with_startup(frames: BTreeMap<String, Address>) -> ModuleOptions {
    ModuleOptions::default().with_startup_frames(frames)
}

#[test]
fn startup_frame_checks_unnamed_references() {
    let (m, p) = unnamed_case(
        DATA,
        &[0xBA, 0x00, 0x02, 0xC3],
        vec![segment_reloc(STARTUP_AT + 1, 0x200)],
    );
    // without a frame base the strings are not compared: unchecked, so not identical
    let before = run16(&m, &p, &Symbols::default(), &ModuleOptions::default());
    assert_eq!(before.warnings.len(), 1, "{:?}", before.warnings);
    assert!(before.warnings[0].contains("frame DGROUP has no anchor"));
    assert_eq!(before.functions[0].verdict, Verdict::Differs);
    assert_eq!(
        before.functions[0].blockers,
        vec![
            Blocker::UncheckedRef { at: 1 },
            Blocker::UncheckedRef { at: 4 }
        ]
    );

    let found = startup_frames(&startup16(STARTUP, &[1]), &p);
    assert!(found.warnings.is_empty(), "{:?}", found.warnings);
    assert_eq!(
        found.frames,
        BTreeMap::from([("DGROUP".to_string(), seg(0x200, 0))])
    );
    let c = run16(&m, &p, &Symbols::default(), &with_startup(found.frames));
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert_eq!(c.functions[0].verdict, Verdict::Identical);
    let a = anchor(&c, "DGROUP", None);
    assert_eq!(
        (a.base, a.votes, a.source),
        (0x2000, 0, AnchorSource::Startup)
    );
    assert_eq!(anchor(&c, "DGROUP", Some("_DATA")).base, 0x40);
}

#[test]
fn wrong_string_differs_under_startup_frame() {
    // the original's second string is "cXef": the rebuild's "cdef" is a wrong item
    let (m, p) = unnamed_case(
        b"ab\0cXef\0",
        &[0xBA, 0x00, 0x02, 0xC3],
        vec![segment_reloc(STARTUP_AT + 1, 0x200)],
    );
    let found = startup_frames(&startup16(STARTUP, &[1]), &p);
    let c = run16(&m, &p, &Symbols::default(), &with_startup(found.frames));
    assert_eq!(c.functions[0].verdict, Verdict::Differs);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 4 }]
    );
}

#[test]
fn startup_unlike_the_original_gives_no_frame() {
    // another startup (`mov cx, …`) at the entry: its selector proves nothing, the strings stay uncompared
    let (m, p) = unnamed_case(
        b"ab\0cXef\0",
        &[0xB9, 0x00, 0x02, 0xC3],
        vec![segment_reloc(STARTUP_AT + 1, 0x200)],
    );
    let found = startup_frames(&startup16(STARTUP, &[1]), &p);
    assert!(found.frames.is_empty());
    assert!(
        found.warnings[0].contains("1 bytes differ"),
        "{:?}",
        found.warnings
    );
    let c = run16(&m, &p, &Symbols::default(), &with_startup(found.frames));
    assert!(
        c.anchors.iter().all(|a| a.section.is_some()),
        "{:?}",
        c.anchors
    );
    assert!(c.warnings[0].contains("frame DGROUP has no anchor"));
    // the wrong string is not identical either: its field is unchecked
    assert_eq!(
        c.functions[0].blockers,
        vec![
            Blocker::UncheckedRef { at: 1 },
            Blocker::UncheckedRef { at: 4 }
        ]
    );
}

#[test]
fn startup_selector_without_segment_relocation_gives_no_frame() {
    let (_, p) = unnamed_case(DATA, &[0xBA, 0x00, 0x02, 0xC3], vec![]);
    let found = startup_frames(&startup16(STARTUP, &[1]), &p);
    assert!(found.frames.is_empty());
    assert!(
        found.warnings[0].contains("no segment relocation"),
        "{:?}",
        found.warnings
    );
}

#[test]
fn startup_selectors_disagreeing_give_no_frame() {
    // `mov dx, DGROUP; mov ax, DGROUP; ret`, the original loads two different segments
    let code: &[u8] = &[0xBA, 0, 0, 0xB8, 0, 0, 0xC3];
    let (_, p) = unnamed_case(
        DATA,
        &[0xBA, 0x00, 0x02, 0xB8, 0x10, 0x02, 0xC3],
        vec![
            segment_reloc(STARTUP_AT + 1, 0x200),
            segment_reloc(STARTUP_AT + 4, 0x210),
        ],
    );
    let found = startup_frames(&startup16(code, &[1, 4]), &p);
    assert!(found.frames.is_empty());
    assert!(
        found.warnings[0].contains("different bases"),
        "{:?}",
        found.warnings
    );
}

#[test]
fn configured_frame_overrides_startup_frame() {
    let (m, p) = unnamed_case(
        DATA,
        &[0xBA, 0x00, 0x02, 0xC3],
        vec![segment_reloc(STARTUP_AT + 1, 0x200)],
    );
    let found = startup_frames(&startup16(STARTUP, &[1]), &p);
    let mut options = with_startup(found.frames);
    options.frames.insert("DGROUP".to_string(), seg(0x201, 0));
    let c = run16(&m, &p, &Symbols::default(), &options);
    let a = anchor(&c, "DGROUP", None);
    assert_eq!((a.base, a.source), (0x2010, AnchorSource::Config));
    assert!(
        c.warnings[0].contains("differs from the startup"),
        "{:?}",
        c.warnings
    );
    // the strings are compared at the configured base, where they are not
    assert_eq!(c.functions[0].verdict, Verdict::Differs);
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
    flat_section_case(b"hi\0", strings)
}

/// `mov eax, offset CONST` with `CONST` holding `section`; the original holds `strings` at 0x20010.
fn flat_section_case(section: &[u8], strings: &[u8]) -> ModuleComparison {
    flat_section_case_in(section, strings, &[])
}

/// [`flat_section_case`] with `code_extra` bytes written into the original's code object at their offsets.
fn flat_section_case_in(
    section: &[u8],
    strings: &[u8],
    code_extra: &[(usize, &[u8])],
) -> ModuleComparison {
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
                section.to_vec(),
                vec![],
            ),
        ],
        vec![ObjSymbol::new("f_", 0, 0, true)],
    );
    let mut code = vec![0xCC; 0x400];
    code[..6].copy_from_slice(&[0xB8, 0x10, 0x00, 0x02, 0x00, 0xC3]);
    for &(at, bytes) in code_extra {
        code[at..at + bytes.len()].copy_from_slice(bytes);
    }
    let p = flat_program(
        &code,
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
fn flat_unnamed_section_ref_needs_an_agreed_section_anchor() {
    // one vote anchors no section (item 4, 2026-11-09): equal bytes could be another item with the same value
    let c = flat_string_case(b"hi\0");
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    assert!(c.anchors.is_empty(), "{:?}", c.anchors);
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("section CONST has no anchor")),
        "{:?}",
        c.warnings
    );

    // the bytes at the position the field names differ: wrong whatever the section's position
    let c = flat_string_case(b"ho\0");
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}

/// A function at section offset 0x10 loading its own jump table at offset 0 (two entries: +5 and +0 of the
/// function); in the original the table lies 0x14 bytes before the function, its second entry going to `second`.
fn own_table_case(second: u32) -> ModuleComparison {
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
    let mut text = vec![0x15, 0, 0, 0, 0x10, 0, 0, 0];
    text.resize(0x10, 0x90);
    text.extend_from_slice(&[0xB8, 0, 0, 0, 0, 0xC3, 0x90, 0x90]);
    let m = ObjectModule::new(
        "t.c",
        vec![Section::new(
            "_TEXT",
            "CODE",
            SectionKind::Code,
            32,
            text,
            vec![own(0), own(4), own(0x11)],
        )],
        vec![ObjSymbol::new("f_", 0, 0x10, true)],
    );
    let (table, start) = (AT + 0x0C, AT + 0x20);
    let mut original = vec![0xCCu8; 0x20];
    original[0x0C..0x10].copy_from_slice(&(start + 5).to_le_bytes());
    original[0x10..0x14].copy_from_slice(&second.to_le_bytes());
    original.extend_from_slice(&[0xB8]);
    original.extend_from_slice(&table.to_le_bytes());
    original.extend_from_slice(&[0xC3, 0x90, 0x90]);
    let p = flat_program(
        &original,
        &[],
        vec![
            absolute(table, start + 5),
            absolute(table + 4, second),
            absolute(start + 1, table),
        ],
    );
    let fs = functions(&m);
    compare_module(
        &[Placement::new(fs[0].clone(), Address::Flat(start), None)],
        &p,
        &Symbols::default(),
        &Decoration::watcom(),
        &ModuleOptions::default(),
    )
}

#[test]
fn own_jump_table_is_matched_by_its_entries() {
    let c = own_table_case(AT + 0x20);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    let c = own_table_case(AT + 0x21);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}

/// Three `mov eax, offset CONST+n` (n = 0, 3, 6 over `"hi\0yo\0ab\0"`); in the original `"hi"` and `"ab"` keep
/// their places relative to 0x20010, the second item lies at 0x20020 with the bytes `moved`.
fn layout_case(moved: &[u8]) -> ModuleComparison {
    let field = |offset: u32, rel: u32| {
        ObjReloc::new(
            offset,
            4,
            RelocKind::Absolute,
            RefTarget::Section {
                index: 1,
                offset: rel,
            },
            0,
            Frame::Unknown,
        )
    };
    let mut code = Vec::new();
    for _ in 0..3 {
        code.extend_from_slice(&[0xB8, 0, 0, 0, 0]);
    }
    code.push(0xC3);
    let m = ObjectModule::new(
        "t.c",
        vec![
            Section::new(
                "_TEXT",
                "CODE",
                SectionKind::Code,
                32,
                code,
                vec![field(1, 0), field(6, 3), field(11, 6)],
            ),
            Section::new(
                "CONST",
                "DATA",
                SectionKind::Data,
                32,
                b"hi\0yo\0ab\0".to_vec(),
                vec![],
            ),
        ],
        vec![ObjSymbol::new("f_", 0, 0, true)],
    );
    let targets = [0x20010u32, 0x20020, 0x20016];
    let mut original = Vec::new();
    for t in targets {
        original.push(0xB8);
        original.extend_from_slice(&t.to_le_bytes());
    }
    original.push(0xC3);
    let mut data = vec![0u8; 0x20];
    data[0x10..0x13].copy_from_slice(b"hi\0");
    data[0x16..0x19].copy_from_slice(b"ab\0");
    data.extend_from_slice(moved);
    let p = flat_program(
        &original,
        &data,
        vec![
            absolute(AT + 1, targets[0]),
            absolute(AT + 6, targets[1]),
            absolute(AT + 11, targets[2]),
        ],
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
fn moved_unchanged_item_is_data_layout() {
    let c = layout_case(b"yo\0");
    assert_eq!(c.functions[0].verdict, Verdict::Differs);
    assert_eq!(c.functions[0].blockers, vec![Blocker::DataLayout { at: 6 }]);
    let c = layout_case(b"yx\0");
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 6 }]
    );
}

#[test]
fn moved_string_with_other_trailing_items_is_data_layout() {
    // CONST "hi\0yo\0zz\0ab\0", references to +0, +3 and +9; "zz" is unreferenced, so the item at +3 reaches to +9.
    // In the original "yo\0" moved and is followed by other bytes.
    let field = |offset: u32, rel: u32| {
        ObjReloc::new(
            offset,
            4,
            RelocKind::Absolute,
            RefTarget::Section {
                index: 1,
                offset: rel,
            },
            0,
            Frame::Unknown,
        )
    };
    let mut code = Vec::new();
    for _ in 0..3 {
        code.extend_from_slice(&[0xB8, 0, 0, 0, 0]);
    }
    code.push(0xC3);
    let m = ObjectModule::new(
        "t.c",
        vec![
            Section::new(
                "_TEXT",
                "CODE",
                SectionKind::Code,
                32,
                code,
                vec![field(1, 0), field(6, 3), field(11, 9)],
            ),
            Section::new(
                "CONST",
                "DATA",
                SectionKind::Data,
                32,
                b"hi\0yo\0zz\0ab\0".to_vec(),
                vec![],
            ),
        ],
        vec![ObjSymbol::new("f_", 0, 0, true)],
    );
    let targets = [0x20010u32, 0x20030, 0x20019];
    let mut original = Vec::new();
    for t in targets {
        original.push(0xB8);
        original.extend_from_slice(&t.to_le_bytes());
    }
    original.push(0xC3);
    let mut data = vec![0u8; 0x30];
    data[0x10..0x13].copy_from_slice(b"hi\0");
    data[0x19..0x1C].copy_from_slice(b"ab\0");
    data.extend_from_slice(b"yo\0qq\0");
    let p = flat_program(
        &original,
        &data,
        targets
            .iter()
            .zip([1, 6, 11])
            .map(|(&t, o)| absolute(AT + o, t))
            .collect(),
    );
    let fs = functions(&m);
    let c = compare_module(
        &[Placement::new(fs[0].clone(), Address::Flat(AT), None)],
        &p,
        &Symbols::default(),
        &Decoration::watcom(),
        &ModuleOptions::default(),
    );
    assert_eq!(c.functions[0].blockers, vec![Blocker::DataLayout { at: 6 }]);
}

#[test]
fn unnamed_static_before_function_at_same_distance() {
    // `mov eax, offset _TEXT+0` from a function at offset 0x10; offset 0 is an unnamed static, not a jump table
    let mut text = vec![0x90u8; 0x10];
    text.extend_from_slice(&[0xB8, 0, 0, 0, 0, 0xC3]);
    let m = ObjectModule::new(
        "t.c",
        vec![Section::new(
            "_TEXT",
            "CODE",
            SectionKind::Code,
            32,
            text,
            vec![flat_reloc(
                0x11,
                RelocKind::Absolute,
                RefTarget::Section {
                    index: 0,
                    offset: 0,
                },
            )],
        )],
        vec![ObjSymbol::new("f_", 0, 0x10, true)],
    );
    let case = |target: u32| {
        let mut original = vec![0x90u8; 0x20];
        original.push(0xB8);
        original.extend_from_slice(&target.to_le_bytes());
        original.push(0xC3);
        let p = flat_program(&original, &[], vec![absolute(AT + 0x21, target)]);
        let fs = functions(&m);
        compare_module(
            &[Placement::new(
                fs[0].clone(),
                Address::Flat(AT + 0x20),
                None,
            )],
            &p,
            &Symbols::default(),
            &Decoration::watcom(),
            &ModuleOptions::default(),
        )
    };
    let c = case(AT + 0x10);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    let c = case(AT + 0x0C);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}

/// Own variants judged against prepared shared functions give what one module comparison over all of them gives.
#[test]
fn shared_functions_give_the_results_of_one_module_comparison() {
    use decovery_diff::{SharedFunctions, compare_module_with};

    // shared: `f0 = mov ax,[g2]` at 0, `f1` (g1 and two strings) at 8; the original has the same
    let strings_code: &[u8] = &[0xA1, 0, 0, 0xB8, 0, 0, 0xBA, 3, 0, 0xC3];
    let strings_original: &[u8] = &[0xA1, 0x10, 0, 0xB8, 0x40, 0, 0xBA, 0x43, 0, 0xC3];
    let shared_module = module16(
        &[LOAD, strings_code],
        vec![
            off16(1, sym("_g2")),
            off16(9, sym("_g1")),
            off16(12, data_at(0)),
            off16(15, data_at(3)),
        ],
    );
    let symbols = known_globals();
    let own_at = seg(0, 0x20);
    let decoration = Decoration::watcom();
    let options = ModuleOptions::default();
    let shared_fs = functions(&shared_module);
    let shared_placements: Vec<Placement> = shared_fs
        .iter()
        .map(|f| Placement::new(f.clone(), seg(0, f.start as u16), None))
        .collect();
    let shared_cache_program = |own_original: &[u8], strings: &[u8]| {
        program16(
            &[&load(0x14), strings_original],
            &[(0x20, own_original), (0x2040, strings)],
            vec![],
        )
    };

    // (the variant's own function, its fields) against the original bytes of that function
    let cases: Vec<(&str, ObjectModule, Vec<u8>, &[u8])> = vec![
        (
            "agrees",
            module16(&[LOAD], vec![off16(1, sym("_g1"))]),
            load(0x10),
            DATA,
        ),
        (
            "dissents",
            module16(&[LOAD], vec![off16(1, sym("_g2"))]),
            load(0x10),
            DATA,
        ),
        (
            "string",
            module16(&[LOAD], vec![off16(1, data_at(0))]),
            load(0x40),
            DATA,
        ),
        (
            "string differs",
            module16(&[LOAD], vec![off16(1, data_at(0))]),
            load(0x40),
            b"aX\0cdeX\0",
        ),
        (
            "unknown",
            module16(&[LOAD], vec![off16(1, sym("_nowhere"))]),
            load(0x10),
            DATA,
        ),
    ];
    let mut verdicts = std::collections::BTreeSet::new();
    for (name, own_module, original, strings) in &cases {
        let program = shared_cache_program(original, strings);
        let own_fs = functions(own_module);
        let own: Vec<Placement> = own_fs
            .iter()
            .map(|f| Placement::new(f.clone(), own_at, None))
            .collect();
        // one module comparison over the own function and the shared ones
        let all: Vec<Placement> = own.iter().chain(&shared_placements).cloned().collect();
        let whole = compare_module(&all, &program, &symbols, &decoration, &options);
        let prepared = SharedFunctions::new(
            &shared_placements,
            &program,
            &symbols,
            &decoration,
            &options,
        );
        let split = compare_module_with(&own, &prepared, &program, &symbols, &decoration, &options);
        assert_eq!(split.functions.len(), own.len(), "{name}");
        assert_eq!(split.functions[0], whole.functions[0], "{name}");
        let sorted = |w: &[String]| {
            let mut v = w.to_vec();
            v.sort();
            v
        };
        assert_eq!(sorted(&split.warnings), sorted(&whole.warnings), "{name}");
        let frame = |c: &ModuleComparison| {
            c.anchors
                .iter()
                .filter(|a| a.section.is_none())
                .map(|a| (a.frame.clone(), a.base, a.votes, a.dissent))
                .collect::<Vec<_>>()
        };
        assert_eq!(frame(&split), frame(&whole), "{name}");
        verdicts.insert(format!("{:?}", split.functions[0].verdict));
    }
    // the cases cover both outcomes
    assert!(verdicts.len() >= 2, "{verdicts:?}");

    // a shared function at the address of an own placement is left out, as one comparison places only the first
    let own_module = module16(&[LOAD], vec![off16(1, sym("_g1"))]);
    let own_fs = functions(&own_module);
    let program = shared_cache_program(&load(0x10), DATA);
    let own: Vec<Placement> = own_fs
        .iter()
        .map(|f| Placement::new(f.clone(), seg(0, 0), None))
        .collect();
    let prepared = SharedFunctions::new(
        &shared_placements,
        &program,
        &symbols,
        &decoration,
        &options,
    );
    let split = compare_module_with(&own, &prepared, &program, &symbols, &decoration, &options);
    let mut first_wins: Vec<Placement> = own.clone();
    first_wins.extend(shared_placements.iter().skip(1).cloned());
    let whole = compare_module(&first_wins, &program, &symbols, &decoration, &options);
    assert_eq!(split.functions[0], whole.functions[0]);
}

// --- consensus needs evidence beyond the field itself (ADR 0006 item 4, amendment 2026-11-09) ---

#[test]
fn single_wrong_reference_is_not_identical() {
    // `mov ax,[_g2]` where the original loads g1's 0x10: a lone field would vote for the base that makes it right
    let m = module16(&[LOAD], vec![off16(1, sym("_g2"))]);
    let p = program16(&[&load(0x10)], &[], vec![]);
    let c = run16(&m, &p, &known_globals(), &ModuleOptions::default());
    assert_ne!(c.functions[0].verdict, Verdict::Identical);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    assert!(
        c.anchors.iter().all(|a| a.frame != "DGROUP"),
        "{:?}",
        c.anchors
    );
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("DGROUP") && w.contains("1 vote")),
        "{:?}",
        c.warnings
    );
}

#[test]
fn tied_frame_votes_leave_both_fields_unchecked() {
    // f0 `_g2` is right (0x14), f1 `_g1` is wrong (the original has g3's 0x18): 1:1, no base wins
    let m = module16(
        &[LOAD, LOAD],
        vec![off16(1, sym("_g2")), off16(9, sym("_g1"))],
    );
    let p = program16(&[&load(0x14), &load(0x18)], &[], vec![]);
    let c = run16(&m, &p, &known_globals(), &ModuleOptions::default());
    for f in &c.functions {
        assert_ne!(f.verdict, Verdict::Identical, "{:?}", f.blockers);
        assert_eq!(f.blockers, vec![Blocker::UncheckedRef { at: 1 }]);
    }
    assert!(c.anchors.iter().all(|a| a.frame != "DGROUP"));
}

#[test]
fn tied_frame_votes_are_decided_by_a_configured_base() {
    let m = module16(
        &[LOAD, LOAD],
        vec![off16(1, sym("_g2")), off16(9, sym("_g1"))],
    );
    let p = program16(&[&load(0x14), &load(0x18)], &[], vec![]);
    let mut options = ModuleOptions::default();
    options.frames.insert("DGROUP".to_string(), seg(0x200, 0));
    let c = run16(&m, &p, &known_globals(), &options);
    assert_eq!(c.functions[0].verdict, Verdict::Identical);
    assert_eq!(
        c.functions[1].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
}

#[test]
fn majority_with_equal_dissent_gives_no_anchor() {
    // two votes for 0x2000 (g1, g2), two for 0x1FF0 (g3 twice wrong-shaped): 2:2 is no majority
    let m = module16(
        &[LOAD, LOAD, LOAD, LOAD],
        vec![
            off16(1, sym("_g1")),
            off16(9, sym("_g2")),
            off16(17, sym("_g3")),
            off16(25, sym("_g4")),
        ],
    );
    let p = program16(
        &[&load(0x10), &load(0x14), &load(0x28), &load(0x2C)],
        &[],
        vec![],
    );
    let symbols = Symbols::with(&[
        (seg(0x200, 0x10), "g1"),
        (seg(0x200, 0x14), "g2"),
        (seg(0x200, 0x18), "g3"),
        (seg(0x200, 0x1C), "g4"),
    ]);
    let c = run16(&m, &p, &symbols, &ModuleOptions::default());
    for f in &c.functions {
        assert_eq!(f.blockers, vec![Blocker::UncheckedRef { at: 1 }]);
    }
}

/// `mov ax,offset _BSS+rel` per entry of `rels` (one function each) against original words `words`; `_BSS` (no
/// initialised bytes) is a member of DGROUP, whose base is configured at linear 0x2000.
fn bss16_case(rels: &[u32], words: &[u16]) -> ModuleComparison {
    let codes: Vec<Vec<u8>> = rels
        .iter()
        .map(|&r| {
            let [lo, hi] = (r as u16).to_le_bytes();
            vec![0xB8, lo, hi, 0xC3]
        })
        .collect();
    let code_refs: Vec<&[u8]> = codes.iter().map(Vec::as_slice).collect();
    let relocs = (0..rels.len() as u32)
        .map(|i| {
            off16(
                8 * i + 1,
                RefTarget::Section {
                    index: 2,
                    offset: 0,
                },
            )
        })
        .collect();
    let mut m = module16(&code_refs, relocs);
    m.sections.push(Section::new(
        "_BSS",
        "BSS",
        SectionKind::Bss,
        16,
        vec![],
        vec![],
    ));
    m.groups = vec![Group::new("DGROUP", vec![1, 2])];
    let originals: Vec<Vec<u8>> = words
        .iter()
        .map(|&w| {
            let [lo, hi] = w.to_le_bytes();
            vec![0xB8, lo, hi, 0xC3]
        })
        .collect();
    let original_refs: Vec<&[u8]> = originals.iter().map(Vec::as_slice).collect();
    let p = program16(&original_refs, &[], vec![]);
    let mut options = ModuleOptions::default();
    options.frames.insert("DGROUP".to_string(), seg(0x200, 0));
    run16(&m, &p, &Symbols::default(), &options)
}

#[test]
fn lone_reference_into_bss_is_unchecked() {
    // no bytes to compare: a lone field would anchor `_BSS` wherever it points
    let c = bss16_case(&[0], &[0x1234]);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
}

#[test]
fn consistent_references_into_bss_anchor_it() {
    let c = bss16_case(&[0, 4], &[0x80, 0x84]);
    for f in &c.functions {
        assert_eq!(f.verdict, Verdict::Identical, "{:?}", f.blockers);
    }
    let a = anchor(&c, "DGROUP", Some("_BSS"));
    assert_eq!((a.base, a.votes, a.dissent), (0x80, 2, 0));

    // 1:1 in `_BSS`: neither is identical
    let c = bss16_case(&[0, 4], &[0x80, 0x90]);
    for f in &c.functions {
        assert_ne!(f.verdict, Verdict::Identical, "{:?}", f.blockers);
    }
}

#[test]
fn lone_flat_reference_into_bss_is_unchecked() {
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
            Section::new("_BSS", "BSS", SectionKind::Bss, 32, vec![], vec![]),
        ],
        vec![ObjSymbol::new("f_", 0, 0, true)],
    );
    // the original points into its code: no data can confirm the rebuild's `_BSS`
    let p = flat_program(
        &[0xB8, 0x00, 0x01, 0x01, 0x00, 0xC3],
        &[],
        vec![absolute(AT + 1, 0x10100)],
    );
    let fs = functions(&m);
    let c = compare_module(
        &[Placement::new(fs[0].clone(), Address::Flat(AT), None)],
        &p,
        &Symbols::default(),
        &Decoration::watcom(),
        &ModuleOptions::default(),
    );
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
}

// --- section ties (ADR 0006 item 3/4, amendment 2026-11-09, round 2) ---

#[test]
fn tied_section_votes_with_equal_items_are_not_identical() {
    // `_DATA` holds two words, both 1. f0 reads a (+0, right: the original reads 0x40), f1 reads b (+2) where the
    // original also reads a: 1:1, and the lower base (0x3E) would make f1 identical by equal bytes. A second copy of
    // the section's bytes at 0x100 keeps its content from naming the position.
    let mut m = module16(
        &[&load(0), &load(2)],
        vec![off16(1, data_at(0)), off16(9, data_at(0))],
    );
    m.sections[1].data = vec![1, 0, 1, 0];
    let p = program16(
        &[&load(0x40), &load(0x40)],
        &[(0x2040, &[1, 0, 1, 0]), (0x2100, &[1, 0, 1, 0])],
        vec![],
    );
    let mut options = ModuleOptions::default();
    options.frames.insert("DGROUP".to_string(), seg(0x200, 0));
    let c = run16(&m, &p, &Symbols::default(), &options);
    for f in &c.functions {
        assert_eq!(
            f.blockers,
            vec![Blocker::UncheckedRef { at: 1 }],
            "{:?}",
            c.anchors
        );
    }
    assert!(
        c.anchors.iter().all(|a| a.section.is_none()),
        "{:?}",
        c.anchors
    );
}

#[test]
fn tied_flat_section_votes_with_equal_items_are_not_identical() {
    let code = vec![
        0xA1, 0, 0, 0, 0, 0xC3, 0x90, 0x90, //
        0xA1, 4, 0, 0, 0, 0xC3, 0x90, 0x90,
    ];
    let to_data = || RefTarget::Section {
        index: 1,
        offset: 0,
    };
    let m = ObjectModule::new(
        "t.c",
        vec![
            Section::new(
                "_TEXT",
                "CODE",
                SectionKind::Code,
                32,
                code,
                vec![
                    flat_reloc(1, RelocKind::Absolute, to_data()),
                    flat_reloc(9, RelocKind::Absolute, to_data()),
                ],
            ),
            Section::new(
                "_DATA",
                "DATA",
                SectionKind::Data,
                32,
                vec![1, 0, 0, 0, 1, 0, 0, 0],
                vec![],
            ),
        ],
        vec![
            ObjSymbol::new("f_", 0, 0, true),
            ObjSymbol::new("g_", 0, 8, true),
        ],
    );
    let original = [
        0xA1, 0, 0, 2, 0, 0xC3, 0x90, 0x90, //
        0xA1, 0, 0, 2, 0, 0xC3, 0x90, 0x90,
    ];
    let p = flat_program(
        &original,
        // a second copy of the section's bytes keeps its content from naming the position
        &[
            [1, 0, 0, 0, 1, 0, 0, 0],
            [0xCC; 8],
            [1, 0, 0, 0, 1, 0, 0, 0],
        ]
        .concat(),
        vec![absolute(AT + 1, 0x20000), absolute(AT + 9, 0x20000)],
    );
    let placements: Vec<Placement> = functions(&m)
        .iter()
        .map(|f| Placement::new(f.clone(), Address::Flat(AT + f.start), None))
        .collect();
    let c = compare_module(
        &placements,
        &p,
        &Symbols::default(),
        &Decoration::watcom(),
        &ModuleOptions::default(),
    );
    for f in &c.functions {
        assert_eq!(f.blockers, vec![Blocker::UncheckedRef { at: 1 }]);
    }
    assert!(c.anchors.is_empty(), "{:?}", c.anchors);
}

// --- section anchor by unique content (ADR 0006 item 4, amendment 2026-11-09, content anchor) ---

/// `_DATA` holds `section` (its own fixups `section_relocs`, extra symbols at `data_symbols`); function `i` loads
/// `_DATA + rels[i].0`, its original field is `rels[i].1`. DGROUP is configured at 0x2000; `extra` bytes are
/// written into the original image at their linear addresses.
fn content16_case(
    section: &[u8],
    section_relocs: Vec<ObjReloc>,
    data_symbols: &[u32],
    rels: &[(u16, u16)],
    extra: &[(usize, &[u8])],
) -> ModuleComparison {
    let codes: Vec<Vec<u8>> = rels.iter().map(|&(rel, _)| load(rel)).collect();
    let code_refs: Vec<&[u8]> = codes.iter().map(Vec::as_slice).collect();
    let relocs = (0..rels.len() as u32)
        .map(|i| off16(8 * i + 1, data_at(0)))
        .collect();
    let mut m = module16(&code_refs, relocs);
    m.sections[1].data = section.to_vec();
    m.sections[1].relocs = section_relocs;
    for (i, &offset) in data_symbols.iter().enumerate() {
        m.symbols
            .push(ObjSymbol::new(format!("d{i}_"), 1, offset, false));
    }
    let originals: Vec<Vec<u8>> = rels.iter().map(|&(_, field)| load(field)).collect();
    let original_refs: Vec<&[u8]> = originals.iter().map(Vec::as_slice).collect();
    let p = program16(&original_refs, extra, vec![]);
    let mut options = ModuleOptions::default();
    options.frames.insert("DGROUP".to_string(), seg(0x200, 0));
    run16(&m, &p, &Symbols::default(), &options)
}

const HELLO: &[u8] = b"hello\0";

fn no_section_anchor(c: &ModuleComparison) {
    assert!(
        c.anchors.iter().all(|a| a.section.is_none()),
        "{:?}",
        c.anchors
    );
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("section _DATA has no anchor")),
        "{:?}",
        c.warnings
    );
}

#[test]
fn lone_vote_with_unique_section_content_is_anchored() {
    // 16-bit: the whole of `_DATA` occurs once in DGROUP, at the position the lone field names
    let c = content16_case(HELLO, vec![], &[], &[(0, 0x40)], &[(0x2040, HELLO)]);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    let a = anchor(&c, "DGROUP", Some("_DATA"));
    assert_eq!(
        (a.base, a.votes, a.dissent, a.source),
        (0x40, 1, 0, AnchorSource::Content)
    );
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);

    // flat: the same with the frame base 0
    let c = flat_section_case(HELLO, HELLO);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    let a = anchor(&c, "FLAT", Some("CONST"));
    assert_eq!(
        (a.base, a.votes, a.dissent, a.source),
        (0x20010, 1, 0, AnchorSource::Content)
    );
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
}

#[test]
fn lone_vote_with_repeated_section_content_stays_unchecked() {
    // a second copy of the section's bytes in DGROUP: the content names no position
    let c = content16_case(
        HELLO,
        vec![],
        &[],
        &[(0, 0x40)],
        &[(0x2040, HELLO), (0x2100, HELLO)],
    );
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    no_section_anchor(&c);

    // flat: a second copy further on in the program
    let mut strings = HELLO.to_vec();
    strings.resize(0x40, 0xCC);
    strings.extend_from_slice(HELLO);
    let c = flat_section_case(HELLO, &strings);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    assert!(c.anchors.is_empty(), "{:?}", c.anchors);
}

#[test]
fn short_section_content_stays_unchecked() {
    // fewer than 4 bytes
    let c = content16_case(b"hi\0", vec![], &[], &[(0, 0x40)], &[(0x2040, b"hi\0")]);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    no_section_anchor(&c);

    // 5 bytes, 2 of them a fixup field: fewer than 4 bytes that are not wildcards
    let section_relocs = vec![ObjReloc::new(
        1,
        2,
        RelocKind::Absolute,
        sym("_x"),
        0,
        Frame::Group("DGROUP".to_string()),
    )];
    let c = content16_case(
        &[1, 0, 0, 2, 3],
        section_relocs,
        &[],
        &[(0, 0x40)],
        &[(0x2040, &[1, 0xAB, 0xCD, 2, 3])],
    );
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    no_section_anchor(&c);

    // all bytes equal: a fill pattern, not content
    let c = content16_case(&[7; 8], vec![], &[], &[(0, 0x40)], &[(0x2040, &[7; 8])]);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    no_section_anchor(&c);
}

#[test]
fn content_found_elsewhere_than_the_vote_stays_unchecked() {
    // `_DATA` is "he" (referenced) and "llo\0" (a symbol of its own). The field names 0x40, where the original
    // holds "he" but then other bytes; the whole section lies once at 0x80. The content names a position no vote
    // proposes: no anchor.
    let c = content16_case(
        HELLO,
        vec![],
        &[2],
        &[(0, 0x40)],
        &[(0x2040, b"heXYZ\0"), (0x2080, HELLO)],
    );
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    no_section_anchor(&c);
}

#[test]
fn tie_with_unique_content_picks_the_matching_candidate() {
    // f0 reads +0 and proposes 0x40, f1 reads +2 and proposes 0x30: 1:1. The section lies at 0x40, so f0 is right
    // and f1 is wrong, although a tie-break would have taken the lower 0x30.
    const SECTION: &[u8] = &[0x11, 0x22, 0x33, 0x44];
    let c = content16_case(
        SECTION,
        vec![],
        &[],
        &[(0, 0x40), (2, 0x32)],
        &[(0x2040, SECTION)],
    );
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    assert_eq!(
        c.functions[1].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
    let a = anchor(&c, "DGROUP", Some("_DATA"));
    assert_eq!(
        (a.base, a.votes, a.dissent, a.source),
        (0x40, 1, 1, AnchorSource::Content)
    );
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);

    // the section at 0x30: now f1 is right and f0 wrong
    let c = content16_case(
        SECTION,
        vec![],
        &[],
        &[(0, 0x40), (2, 0x32)],
        &[(0x2030, SECTION)],
    );
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::WrongAbsoluteRef { at: 1 }]
    );
    assert_eq!(
        c.functions[1].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[1].blockers
    );
    assert_eq!(anchor(&c, "DGROUP", Some("_DATA")).base, 0x30);
}

#[test]
fn fixup_bytes_in_section_are_wildcards() {
    // `_DATA` holds a pointer at offset 2; the original's bytes there are its loaded value
    let section_relocs = vec![ObjReloc::new(
        2,
        2,
        RelocKind::Absolute,
        sym("_x"),
        0,
        Frame::Group("DGROUP".to_string()),
    )];
    let c = content16_case(
        &[0x11, 0x22, 0, 0, 0x33, 0x44],
        section_relocs,
        &[],
        &[(0, 0x40)],
        &[(0x2040, &[0x11, 0x22, 0xAB, 0xCD, 0x33, 0x44])],
    );
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    assert_eq!(
        anchor(&c, "DGROUP", Some("_DATA")).source,
        AnchorSource::Content
    );
}

// --- content anchor, review round 1 ---

#[test]
fn content_outside_the_referenced_items_does_not_anchor() {
    // `_DATA` is a table of two pointers (all fixup bytes, referenced) and a constant of its own (a symbol at 4). The
    // section is unique at the vote's position, but only through the constant: the referenced item has no byte to
    // compare, so nothing confirms the field itself.
    let pointer = |offset: u32| {
        ObjReloc::new(
            offset,
            2,
            RelocKind::Absolute,
            sym("_x"),
            0,
            Frame::Group("DGROUP".to_string()),
        )
    };
    let c = content16_case(
        &[0, 0, 0, 0, 1, 2, 3, 4],
        vec![pointer(0), pointer(2)],
        &[4],
        &[(0, 0x40)],
        &[(0x2040, &[0xAB, 0xCD, 0xEF, 0x01, 1, 2, 3, 4])],
    );
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    no_section_anchor(&c);
}

#[test]
fn content_anchor_dissent_with_equal_item_is_data_layout() {
    // `_DATA` holds two words, both 1, once in the original at 0x40. f0 reads +0 (0x40, right); f1 reads +2 where
    // the original reads +0: its item equals the original at its own position, so it is a layout difference
    let c = content16_case(
        &[1, 0, 1, 0],
        vec![],
        &[],
        &[(0, 0x40), (2, 0x40)],
        &[(0x2040, &[1, 0, 1, 0])],
    );
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    assert!(
        matches!(
            c.functions[1].blockers.as_slice(),
            [Blocker::DataLayout { .. }]
        ),
        "{:?}",
        c.functions[1].blockers
    );
    let a = anchor(&c, "DGROUP", Some("_DATA"));
    assert_eq!(
        (a.base, a.votes, a.dissent, a.source),
        (0x40, 1, 1, AnchorSource::Content)
    );
}

#[test]
fn flat_copy_in_the_code_object_blocks_the_content_anchor() {
    let c = flat_section_case_in(HELLO, HELLO, &[(0x100, HELLO)]);
    assert_eq!(
        c.functions[0].blockers,
        vec![Blocker::UncheckedRef { at: 1 }]
    );
    assert!(c.anchors.is_empty(), "{:?}", c.anchors);
}

#[test]
fn copies_outside_the_16_bit_frame_window_do_not_count() {
    // copies starting before DGROUP's base and at base + 64 KiB lie outside the frame
    let c = content16_case(
        HELLO,
        vec![],
        &[],
        &[(0, 0x40)],
        &[(0x1FFC, HELLO), (0x2040, HELLO), (0x12000, HELLO)],
    );
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    assert_eq!(
        anchor(&c, "DGROUP", Some("_DATA")).source,
        AnchorSource::Content
    );
}

#[test]
fn partial_copy_at_a_region_end_is_not_an_occurrence() {
    // the code object ends with the first 3 bytes of the section: the scan stops at the region's end
    let c = flat_section_case_in(HELLO, HELLO, &[(0x3FD, &HELLO[..3])]);
    assert_eq!(
        c.functions[0].verdict,
        Verdict::Identical,
        "{:?}",
        c.functions[0].blockers
    );
    assert_eq!(anchor(&c, "FLAT", Some("CONST")).base, 0x20010);
}
