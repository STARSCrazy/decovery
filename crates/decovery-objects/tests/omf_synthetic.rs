//! Synthetic OMF objects built byte by byte.

use decovery_core::RelocKind;
use decovery_objects::{ObjectError, RefTarget, SectionKind, functions, read_omf};

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
