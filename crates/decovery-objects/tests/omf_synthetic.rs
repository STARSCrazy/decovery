//! Synthetic OMF objects built byte by byte.

use decovery_core::RelocKind;
use decovery_objects::{Frame, ObjectError, RefTarget, SectionKind, functions, read_omf};

fn rec(t: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len() + 1;
    let mut v = vec![t, (n & 0xFF) as u8, (n >> 8) as u8];
    v.extend_from_slice(body);
    // the checksum byte makes the record sum 0 mod 256
    let sum: u32 = v.iter().map(|&b| u32::from(b)).sum();
    v.push(((256 - sum % 256) % 256) as u8);
    v
}

fn pstr(s: &str) -> Vec<u8> {
    let mut v = vec![s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

fn theadr(name: &str) -> Vec<u8> {
    rec(0x80, &pstr(name))
}

fn lnames(names: &[&str]) -> Vec<u8> {
    rec(
        0x96,
        &names.iter().flat_map(|n| pstr(n)).collect::<Vec<_>>(),
    )
}

/// 16-bit SEGDEF: attribute, length, segment name index, class name index, overlay.
fn segdef16(attr: u8, len: u16, name: u8, class: u8) -> Vec<u8> {
    let mut b = vec![attr];
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&[name, class, 1]);
    rec(0x98, &b)
}

fn segdef32(attr: u8, len: u32, name: u8, class: u8) -> Vec<u8> {
    let mut b = vec![attr];
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&[name, class, 1]);
    rec(0x99, &b)
}

fn pubdef(t: u8, seg: u8, syms: &[(&str, u16)]) -> Vec<u8> {
    let mut b = vec![0, seg];
    for (n, off) in syms {
        b.extend(pstr(n));
        b.extend_from_slice(&off.to_le_bytes());
        b.push(0);
    }
    rec(t, &b)
}

fn extdef(names: &[&str]) -> Vec<u8> {
    let mut b = Vec::new();
    for n in names {
        b.extend(pstr(n));
        b.push(0);
    }
    rec(0x8C, &b)
}

fn ledata(seg: u8, off: u16, data: &[u8]) -> Vec<u8> {
    let mut b = vec![seg];
    b.extend_from_slice(&off.to_le_bytes());
    b.extend_from_slice(data);
    rec(0xA0, &b)
}

/// GRPDEF: group name index, then the member segment indices (component type 0xFF).
fn grpdef(name: u8, segs: &[u8]) -> Vec<u8> {
    let mut b = vec![name];
    for s in segs {
        b.extend_from_slice(&[0xFF, *s]);
    }
    rec(0x9A, &b)
}

/// FIXUPP with one explicit fixup: segment-relative 16-bit offset (loc 1) at `dro`, frame method/datum
/// `frame` (`None` = method >= 3, no datum), target method 0 (SEGDEF `seg`) with displacement `disp`.
fn fixup_offset(dro: u16, frame: Option<(u8, u8)>, seg: u8, disp: u16) -> Vec<u8> {
    let lo = 0xC400 | dro; // M=1 (segment-relative), loc 1
    let mut b = lo.to_be_bytes().to_vec();
    match frame {
        Some((m, idx)) => {
            b.push(m << 4);
            b.push(idx);
        }
        None => b.push(5 << 4),
    }
    b.push(seg);
    b.extend_from_slice(&disp.to_le_bytes());
    rec(0x9C, &b)
}

fn modend() -> Vec<u8> {
    rec(0x8A, &[0])
}

const CODE: u8 = 0x48;

/// THEADR, LNAMES [_TEXT CODE _DATA DATA], SEGDEF 1 = code (len), SEGDEF 2 = data.
fn prologue(code_len: u16) -> Vec<u8> {
    [
        theadr("T.C"),
        lnames(&["_TEXT", "CODE", "_DATA", "DATA"]),
        segdef16(CODE, code_len, 1, 2),
        segdef16(CODE, 4, 3, 4),
    ]
    .concat()
}

fn obj(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = parts.concat();
    v.extend(modend());
    v
}

#[test]
fn reads_segdef_pubdef_ledata() {
    let bytes = obj(&[
        prologue(4),
        pubdef(0x90, 1, &[("_f", 0)]),
        ledata(1, 0, &[0x90, 0x90, 0xC3, 0x00]),
        ledata(2, 0, &[1, 2, 3, 4]),
    ]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    assert_eq!(f.modules.len(), 1);
    let m = &f.modules[0];
    assert_eq!(m.name, "T.C");
    assert_eq!(m.sections.len(), 2);
    assert_eq!(m.sections[0].name, "_TEXT");
    assert_eq!(m.sections[0].class, "CODE");
    assert_eq!(m.sections[0].kind, SectionKind::Code);
    assert_eq!(m.sections[0].bits, 16);
    assert_eq!(m.sections[0].data, [0x90, 0x90, 0xC3, 0]);
    assert_eq!(m.sections[1].kind, SectionKind::Data);
    assert_eq!(m.symbols.len(), 1);
    assert_eq!(m.symbols[0].name, "_f");
    assert_eq!(m.symbols[0].section, 0);
    assert!(m.symbols[0].public);
}

#[test]
fn expands_lidata() {
    // repeat 3 of [1,2]; repeat 2 of (one nested block: repeat 2 of [9])
    let mut b = vec![1, 0, 0];
    b.extend_from_slice(&[3, 0, 0, 0, 2, 1, 2]);
    b.extend_from_slice(&[2, 0, 1, 0, 2, 0, 0, 0, 1, 9]);
    let bytes = obj(&[prologue(16), rec(0xA2, &b)]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    assert_eq!(
        f.modules[0].sections[0].data,
        [1, 2, 1, 2, 1, 2, 9, 9, 9, 9]
    );
}

#[test]
fn fixupp_with_threads_resolves_targets() {
    // target thread 0 = method T2 (EXTDEF) index 1; fixup self-relative, loc 1, offset 1, frame+target by thread
    let fixupp = rec(0x9C, &[0x08, 0x01, 0x84, 0x01, 0x8C]);
    let bytes = obj(&[
        prologue(4),
        extdef(&["_ext"]),
        pubdef(0x90, 1, &[("_f", 0)]),
        ledata(1, 0, &[0xE8, 0xFD, 0xFF, 0xC3]),
        fixupp,
    ]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    let r = &f.modules[0].sections[0].relocs;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].offset, 1);
    assert_eq!(r[0].width, 2);
    assert_eq!(r[0].kind, RelocKind::Relative);
    assert_eq!(r[0].target, RefTarget::Symbol("_ext".into()));
    assert_eq!(r[0].addend, 0);
    let m = &f.modules[0];
    let fv = functions(m);
    assert_eq!(fv.len(), 1);
    assert_eq!(fv[0].references(), [(1, "_ext")]);
    assert_eq!(
        fv[0].relative_offsets().into_iter().collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(fv[0].gaps().into_iter().collect::<Vec<_>>(), [1, 2]);
}

#[test]
fn fixup_to_own_segment_is_section_target() {
    // segment-relative (M=1), loc 1, offset 2; frame SEGDEF 1, target SEGDEF 1 + displacement 8
    let fixupp = rec(0x9C, &[0xC4, 0x02, 0x00, 0x01, 0x01, 0x08, 0x00]);
    let bytes = obj(&[prologue(16), ledata(1, 0, &[0; 16]), fixupp]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    let r = &f.modules[0].sections[0].relocs;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].kind, RelocKind::Absolute);
    assert_eq!(r[0].offset, 2);
    assert_eq!(
        r[0].target,
        RefTarget::Section {
            index: 0,
            offset: 8
        }
    );
}

#[test]
fn two_publics_split_code() {
    let bytes = obj(&[
        prologue(8),
        pubdef(0x90, 1, &[("_b", 4), ("_a", 0)]),
        ledata(1, 0, &[1, 2, 3, 4, 5, 6, 7, 8]),
    ]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    let fv = functions(&f.modules[0]);
    assert_eq!(fv.len(), 2);
    assert_eq!((fv[0].name, fv[0].start, fv[0].len), ("_a", 0, 4));
    assert_eq!(fv[0].code(), [1, 2, 3, 4]);
    assert_eq!((fv[1].name, fv[1].start, fv[1].len), ("_b", 4, 4));
    assert_eq!(fv[1].code(), [5, 6, 7, 8]);
}

#[test]
fn last_public_takes_rest_of_section() {
    let bytes = obj(&[
        prologue(6),
        pubdef(0x90, 1, &[("_a", 2)]),
        ledata(1, 0, &[1, 2, 3, 4, 5, 6]),
    ]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    let fv = functions(&f.modules[0]);
    assert_eq!(fv.len(), 1);
    assert_eq!((fv[0].start, fv[0].len), (2, 4));
    assert_eq!(fv[0].code(), [3, 4, 5, 6]);
}

#[test]
fn use16_and_use32_sections_keep_bits() {
    let bytes = obj(&[
        theadr("T.C"),
        lnames(&["_TEXT", "CODE", "_TEXT32"]),
        segdef16(CODE, 2, 1, 2),
        segdef32(CODE, 2, 3, 2),
        ledata(1, 0, &[1, 2]),
        // 32-bit LEDATA has a 4-byte offset
        rec(0xA1, &[2, 0, 0, 0, 0, 7, 8]),
    ]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    let s = &f.modules[0].sections;
    assert_eq!((s[0].bits, s[1].bits), (16, 32));
    assert_eq!(s[1].data, [7, 8]);
}

#[test]
fn splits_library_modules() {
    let page = 32usize;
    let m1 = obj(&[prologue(1), ledata(1, 0, &[1])]);
    let m2 = obj(&[prologue(1), ledata(1, 0, &[2])]);
    let mut lib = rec(0xF0, &vec![0; page - 4]);
    assert_eq!(lib.len(), page);
    for m in [m1, m2] {
        lib.extend(m);
        while !lib.len().is_multiple_of(page) {
            lib.push(0);
        }
    }
    lib.push(0xF1);
    let f = read_omf(&lib, "t.lib").unwrap();
    assert_eq!(f.modules.len(), 2);
    assert_eq!(f.modules[0].sections[0].data, [1]);
    assert_eq!(f.modules[1].sections[0].data, [2]);
}

#[test]
fn truncated_at_every_offset_errors() {
    let bytes = obj(&[
        prologue(4),
        extdef(&["_ext"]),
        pubdef(0x90, 1, &[("_f", 0)]),
        ledata(1, 0, &[0xE8, 0xFD, 0xFF, 0xC3]),
        rec(0x9C, &[0x08, 0x01, 0x84, 0x01, 0x8C]),
    ]);
    assert!(read_omf(&bytes, "t.obj").is_ok());
    for n in 0..bytes.len() {
        let e = read_omf(&bytes[..n], "t.obj").expect_err(&format!("prefix {n} must fail"));
        match e {
            ObjectError::Truncated { offset } | ObjectError::Malformed { offset, .. } => {
                assert!(
                    offset <= bytes.len() as u64,
                    "offset {offset} at prefix {n}"
                );
            }
            other => panic!("unexpected {other:?} at prefix {n}"),
        }
    }
}

#[test]
fn truncated_library_never_panics() {
    let page = 32usize;
    let m1 = obj(&[
        prologue(2),
        ledata(1, 0, &[1, 2]),
        pubdef(0x90, 1, &[("_a", 0)]),
    ]);
    let mut lib = rec(0xF0, &vec![0; page - 4]);
    lib.extend(m1);
    while !lib.len().is_multiple_of(page) {
        lib.push(0);
    }
    lib.push(0xF1);
    for n in 0..=lib.len() {
        let _ = read_omf(&lib[..n], "t.lib");
    }
}

#[test]
fn bad_checksum_errors() {
    let mut bytes = obj(&[prologue(1), ledata(1, 0, &[1])]);
    // corrupt the checksum of the first record (THEADR)
    let n = usize::from(bytes[1]) + 2;
    bytes[n] = bytes[n].wrapping_add(1).max(1);
    assert!(matches!(
        read_omf(&bytes, "t.obj"),
        Err(ObjectError::BadChecksum { offset: 0 })
    ));
    // checksum byte 0 means "not computed" and is accepted
    let mut ok = obj(&[prologue(1)]);
    ok[n] = 0;
    assert!(read_omf(&ok, "t.obj").is_ok());
}

#[test]
fn rejects_non_omf() {
    assert!(read_omf(&[], "x").is_err());
    assert!(read_omf(&[0x4D, 0x5A], "x").is_err());
}

/// Prologue plus `DGROUP` (LNAME 5) of `_DATA` (2), `_BSS` (3).
fn grouped() -> Vec<Vec<u8>> {
    vec![
        theadr("T.C"),
        lnames(&["_TEXT", "CODE", "_DATA", "DATA", "DGROUP", "_BSS", "BSS"]),
        segdef16(CODE, 4, 1, 2),
        segdef16(CODE, 8, 3, 4),
        segdef16(CODE, 8, 6, 7),
        grpdef(5, &[2, 3]),
    ]
}

#[test]
fn grpdef_lists_member_sections() {
    let f = read_omf(&obj(&grouped()), "t.obj").unwrap();
    let m = &f.modules[0];
    assert_eq!(m.groups.len(), 1);
    assert_eq!(m.groups[0].name, "DGROUP");
    assert_eq!(m.groups[0].sections, [1, 2]);
    assert_eq!(m.group_of(1).map(|g| g.name.as_str()), Some("DGROUP"));
    assert_eq!(m.group_of(2).map(|g| g.name.as_str()), Some("DGROUP"));
    assert!(m.group_of(0).is_none());
}

#[test]
fn fixup_keeps_group_frame() {
    let mut parts = grouped();
    parts.push(ledata(1, 0, &[0xA1, 0, 0, 0xC3]));
    parts.push(fixup_offset(1, Some((1, 1)), 2, 4));
    let f = read_omf(&obj(&parts), "t.obj").unwrap();
    let r = &f.modules[0].sections[0].relocs;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].width, 2);
    assert_eq!(r[0].frame, Frame::Group("DGROUP".into()));
    assert_eq!(
        r[0].target,
        RefTarget::Section {
            index: 1,
            offset: 4
        }
    );
}

#[test]
fn segment_frame_is_section() {
    let mut parts = grouped();
    parts.push(ledata(1, 0, &[0xA1, 0, 0, 0xC3]));
    parts.push(fixup_offset(1, Some((0, 2)), 2, 0));
    let f = read_omf(&obj(&parts), "t.obj").unwrap();
    assert_eq!(f.modules[0].sections[0].relocs[0].frame, Frame::Section(1));
}

#[test]
fn frame_thread_is_applied() {
    let mut parts = grouped();
    parts.push(ledata(1, 0, &[0xA1, 0, 0, 0xC3]));
    // frame thread 2 = method F1 (group 1); then a fixup (F=1, thread 2) with explicit target SEGDEF 2 + 4
    let mut b = vec![0x40 | (1 << 2) | 2, 1];
    b.extend_from_slice(&[0xC4, 0x01, 0x80 | (2 << 4), 2, 4, 0]);
    parts.push(rec(0x9C, &b));
    let f = read_omf(&obj(&parts), "t.obj").unwrap();
    let r = &f.modules[0].sections[0].relocs;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].frame, Frame::Group("DGROUP".into()));
}

#[test]
fn target_frame_is_target() {
    let mut parts = grouped();
    parts.push(ledata(1, 0, &[0xA1, 0, 0, 0xC3]));
    parts.push(fixup_offset(1, None, 2, 4));
    let f = read_omf(&obj(&parts), "t.obj").unwrap();
    assert_eq!(f.modules[0].sections[0].relocs[0].frame, Frame::Target);
}

#[test]
fn undefined_frame_thread_is_unknown() {
    let bytes = obj(&[
        prologue(4),
        extdef(&["_ext"]),
        ledata(1, 0, &[0xE8, 0xFD, 0xFF, 0xC3]),
        rec(0x9C, &[0x08, 0x01, 0x84, 0x01, 0x8C]),
    ]);
    let f = read_omf(&bytes, "t.obj").unwrap();
    assert_eq!(f.modules[0].sections[0].relocs[0].frame, Frame::Unknown);
}

#[test]
fn modend_start_and_group_target() {
    // startup-like: `mov dx, DGROUP; ret`, the selector targets group 1 (T1) with frame F5; the start address is
    // SEGDEF 1 + 2 (frame F0 SEGDEF 1, target T0 SEGDEF 1, displacement 2)
    let mut parts = grouped();
    parts.push(ledata(1, 0, &[0xBA, 0, 0, 0xC3]));
    parts.push(rec(0x9C, &[0xC8, 0x01, 0x55, 0x01]));
    parts.push(rec(0x8A, &[0xC1, 0x00, 0x01, 0x01, 0x02, 0x00]));
    let f = read_omf(&parts.concat(), "c0.obj").unwrap();
    let m = &f.modules[0];
    assert_eq!(m.start, Some((0, 2)));
    let r = &m.sections[0].relocs[0];
    assert_eq!((r.offset, r.width, r.kind), (1, 2, RelocKind::Selector));
    assert_eq!(r.target, RefTarget::Group("DGROUP".into()));
    assert_eq!(r.frame, Frame::Target);

    // a module without a start address
    let f = read_omf(&obj(&grouped()), "t.obj").unwrap();
    assert_eq!(f.modules[0].start, None);
}

mod writer {
    use decovery_core::RelocKind;
    use decovery_objects::{
        Frame, RefTarget, SectionKind, WriteFixup, WriteFixupKind, WriteModule, WriteSegment,
        read_omf, write_omf, write_omf_module,
    };

    #[test]
    fn omf_writer_writes_externals_and_16_bit_segments() {
        let segments = [
            WriteSegment::new("_TEXT", "CODE", 8, false).with_align(1),
            WriteSegment::new("_TEXT32", "CODE", 8, true),
        ];
        let externals = ["_a".to_string(), "b_".to_string()];
        let mut code = vec![0u8; 8];
        code[6..8].copy_from_slice(&(-2i16).to_le_bytes());
        let fixups = [
            WriteFixup::external(1, 1, WriteFixupKind::Rel16, 2, None),
            WriteFixup::external(1, 4, WriteFixupKind::Off16, 1, Some(6)),
            WriteFixup::external(1, 6, WriteFixupKind::Off16, 1, None),
            WriteFixup::external(2, 0, WriteFixupKind::Off32, 2, Some(0x1C4)),
        ];
        let data = [(1, code.clone()), (2, vec![0u8; 8])];
        let module = WriteModule::new("m")
            .with_segments(&segments)
            .with_externals(&externals)
            .with_data(&data)
            .with_fixups(&fixups);
        let file = read_omf(&write_omf(&module).unwrap(), "M.OBJ").unwrap();
        let m = &file.modules[0];
        assert_eq!(
            m.sections.iter().map(|s| s.bits).collect::<Vec<_>>(),
            [16, 32]
        );
        assert_eq!(m.sections[0].data, code);
        let shape = |r: &decovery_objects::ObjReloc| {
            (r.offset, r.width, r.kind, r.target.clone(), r.addend)
        };
        let symbol = |n: &str| RefTarget::Symbol(n.to_string());
        assert_eq!(
            m.sections[0].relocs.iter().map(shape).collect::<Vec<_>>(),
            [
                (1, 2, RelocKind::Relative, symbol("b_"), 0),
                (4, 2, RelocKind::Absolute, symbol("_a"), 6),
                (6, 2, RelocKind::Absolute, symbol("_a"), 0),
            ]
        );
        assert_eq!(
            shape(&m.sections[1].relocs[0]),
            (0, 4, RelocKind::Absolute, symbol("b_"), 0x1C4)
        );
        // an external the module does not have
        let bad = [WriteFixup::external(1, 0, WriteFixupKind::Off16, 3, None)];
        let err = write_omf(&module.with_fixups(&bad))
            .unwrap_err()
            .to_string();
        assert!(err.contains("external 3"), "{err}");
    }

    #[test]
    fn overlapping_fixups_are_rejected() {
        // an Off32 at +0 and a 2-byte field at +1 in one run: the run's end is not the last field's end
        let segments = [WriteSegment::new("_TEXT", "CODE", 0x10, true)];
        let write = |fixups: &[WriteFixup]| {
            write_omf_module(
                "m",
                &segments,
                &[],
                &[],
                &[(1, vec![0u8; 0x10])],
                fixups,
                None,
            )
        };
        let overlapping = [
            WriteFixup::new(1, 0, WriteFixupKind::Off32, 1, Some(0)),
            WriteFixup::new(1, 1, WriteFixupKind::Off16, 1, Some(2)),
        ];
        let err = write(&overlapping).unwrap_err().to_string();
        assert!(
            err.contains("overlap") && err.contains("segment 1") && err.contains("+0x1"),
            "{err}"
        );
        // in any order, and the same field twice
        let err = write(&[overlapping[1], overlapping[0]])
            .unwrap_err()
            .to_string();
        assert!(err.contains("overlap"), "{err}");
        let twice = WriteFixup::new(1, 4, WriteFixupKind::Off16, 1, None);
        assert!(write(&[twice, twice]).is_err());
        // adjacent fields are fine
        let adjacent = [
            WriteFixup::new(1, 0, WriteFixupKind::Off32, 1, None),
            WriteFixup::new(1, 4, WriteFixupKind::Off16, 1, Some(2)),
        ];
        assert!(write(&adjacent).is_ok());
    }

    #[test]
    fn omf_writer_round_trips_through_reader() {
        let text: Vec<u8> = (0..0x900u32).map(|i| (i * 7) as u8).collect();
        let data: Vec<u8> = (0..0x40u8).collect();
        let segments = [
            WriteSegment::new("_TEXT", "CODE", 0x900, true),
            WriteSegment::new("_DATA", "DATA", 0x40, true),
            WriteSegment::new("STACK", "STACK", 0x100, true)
                .with_combine(5)
                .with_align(1),
        ];
        let groups = [("DGROUP".to_string(), vec![2, 3])];
        let publics = [("_cstart_".to_string(), 1, 0x10)];
        let mut fixups = vec![
            WriteFixup::new(1, 0x01, WriteFixupKind::Off32, 2, None),
            WriteFixup::new(1, 0x06, WriteFixupKind::Rel32, 1, None),
            WriteFixup::new(1, 0x0C, WriteFixupKind::Off16, 2, Some(0x22)),
            WriteFixup::new(1, 0x10, WriteFixupKind::Sel16, 2, None),
            WriteFixup::new(2, 0x08, WriteFixupKind::Off32, 1, None),
        ];
        // more than one run per record: over 200 fixups and over 1000 bytes
        fixups.extend(
            (0..300).map(|i| WriteFixup::new(1, 0x20 + 6 * i, WriteFixupKind::Off32, 2, None)),
        );
        let bytes = write_omf_module(
            "decovery_rebuild",
            &segments,
            &groups,
            &publics,
            &[(1, text.clone()), (2, data.clone())],
            &fixups,
            Some((1, 0x10)),
        )
        .unwrap();
        let file = read_omf(&bytes, "NB.OBJ").unwrap();
        assert!(
            file.unknown_records.is_empty(),
            "{:?}",
            file.unknown_records
        );
        let m = &file.modules[0];
        assert_eq!(m.name, "decovery_rebuild");
        let names: Vec<(&str, &str, SectionKind, u8)> = m
            .sections
            .iter()
            .map(|s| (s.name.as_str(), s.class.as_str(), s.kind, s.bits))
            .collect();
        assert_eq!(
            names,
            [
                ("_TEXT", "CODE", SectionKind::Code, 32),
                ("_DATA", "DATA", SectionKind::Data, 32),
                ("STACK", "STACK", SectionKind::Bss, 32)
            ]
        );
        assert_eq!(m.groups.len(), 1);
        assert_eq!(
            (m.groups[0].name.as_str(), &m.groups[0].sections[..]),
            ("DGROUP", &[1, 2][..])
        );
        assert_eq!(m.symbols.len(), 1);
        assert_eq!(
            (
                m.symbols[0].name.as_str(),
                m.symbols[0].section,
                m.symbols[0].offset
            ),
            ("_cstart_", 0, 0x10)
        );
        // the off16 field with a displacement is written empty, everything else as given
        let mut expected = text.clone();
        expected[0x0C..0x0E].fill(0);
        assert_eq!(m.sections[0].data, expected);
        assert_eq!(m.sections[1].data, data);
        let relocs = &m.sections[0].relocs;
        assert_eq!(relocs.len(), 304);
        let shape = |i: usize| {
            let r = &relocs[i];
            (r.offset, r.width, r.kind, r.target.clone(), r.frame.clone())
        };
        let section = |index, offset| RefTarget::Section { index, offset };
        assert_eq!(
            shape(0),
            (0x01, 4, RelocKind::Absolute, section(1, 0), Frame::Target)
        );
        assert_eq!(
            shape(1),
            (0x06, 4, RelocKind::Relative, section(0, 0), Frame::Target)
        );
        assert_eq!(
            shape(2),
            (
                0x0C,
                2,
                RelocKind::Absolute,
                section(1, 0x22),
                Frame::Target
            )
        );
        assert_eq!(
            shape(3),
            (0x10, 2, RelocKind::Selector, section(1, 0), Frame::Target)
        );
        assert_eq!(
            shape(303),
            (
                0x20 + 6 * 299,
                4,
                RelocKind::Absolute,
                section(1, 0),
                Frame::Target
            )
        );
        assert_eq!(m.sections[1].relocs.len(), 1);
        assert_eq!(m.sections[1].relocs[0].target, section(0, 0));
    }

    #[test]
    fn omf_writer_rejects_fixup_outside_data() {
        let err = write_omf_module(
            "m",
            &[WriteSegment::new("_TEXT", "CODE", 4, true)],
            &[],
            &[],
            &[(1, vec![0; 4])],
            &[WriteFixup::new(1, 2, WriteFixupKind::Off32, 1, None)],
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("segment 1 +0x2"), "{err}");
    }
}
