//! Synthetic LE images built inside the test; no proprietary data.

use decovery_core::{Address, ExecutableFormat, RelocKind};
use decovery_loaders::{LoadError, load_le};

const PAGE: usize = 0x100;
const HEADER: usize = 0xAC;

struct Obj {
    base: u32,
    flags: u32,
    data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Fix {
    /// 0-based source object.
    object: usize,
    /// Offset of the field inside the source object.
    offset: usize,
    /// LE source type (0x07 off32, 0x05 off16, 0x02 sel16, 0x08 rel32, ...).
    kind: u8,
    /// 1-based target object.
    target_object: u8,
    target_offset: u32,
}

fn width(kind: u8) -> usize {
    match kind {
        0x02 | 0x05 => 2,
        0x03 | 0x07 | 0x08 => 4,
        0x06 => 6,
        _ => unreachable!(),
    }
}

fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

/// MZ stub + LE header + object table + page map + fixup page table + fixup records + page data.
/// The page data comes last, so every proper prefix of the image lacks needed bytes.
fn build_le(objects: &[Obj], fixups: &[Fix]) -> Vec<u8> {
    let pages_of = |o: &Obj| o.data.len().div_ceil(PAGE);
    let total_pages: usize = objects.iter().map(pages_of).sum();
    let last_page = {
        let rem = objects.last().map_or(0, |o| o.data.len() % PAGE);
        if rem == 0 { PAGE } else { rem }
    };

    // Records per global page (1-based page index -> record bytes).
    let mut per_page: Vec<Vec<u8>> = vec![Vec::new(); total_pages];
    let mut first_page = Vec::new();
    let mut next = 0usize;
    for o in objects {
        first_page.push(next);
        next += pages_of(o);
    }
    for f in fixups {
        let size = objects[f.object].data.len();
        let pages = pages_of(&objects[f.object]);
        let page = f.offset / PAGE;
        let mut emit = |page: usize, q: i16| {
            let rec = &mut per_page[first_page[f.object] + page];
            rec.push(f.kind);
            rec.push(if f.kind == 0x02 { 0 } else { 0x10 });
            rec.extend_from_slice(&q.to_le_bytes());
            rec.push(f.target_object);
            if f.kind != 0x02 {
                rec.extend_from_slice(&f.target_offset.to_le_bytes());
            }
        };
        let q = (f.offset % PAGE) as i16;
        emit(page, q);
        if f.offset % PAGE + width(f.kind) > PAGE && page + 1 < pages && f.offset < size {
            emit(page + 1, q - PAGE as i16);
        }
    }

    let k = 0x40usize;
    let obj_tab = HEADER;
    let page_map = obj_tab + 24 * objects.len();
    let fpt = page_map + 4 * total_pages;
    let frt = fpt + 4 * (total_pages + 1);
    let records: Vec<u8> = per_page.iter().flatten().copied().collect();
    let data_pages = k + frt + records.len();

    let mut out = vec![0u8; k + HEADER];
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3C, k as u32);
    let h = k;
    out[h..h + 2].copy_from_slice(b"LE");
    put32(&mut out, h + 0x14, total_pages as u32);
    put32(&mut out, h + 0x18, 1);
    put32(&mut out, h + 0x1C, 0x10);
    put32(&mut out, h + 0x20, objects.len() as u32);
    put32(&mut out, h + 0x24, 0x40);
    put32(&mut out, h + 0x28, PAGE as u32);
    put32(&mut out, h + 0x2C, last_page as u32);
    put32(&mut out, h + 0x40, obj_tab as u32);
    put32(&mut out, h + 0x44, objects.len() as u32);
    put32(&mut out, h + 0x48, page_map as u32);
    put32(&mut out, h + 0x68, fpt as u32);
    put32(&mut out, h + 0x6C, frt as u32);
    put32(&mut out, h + 0x80, data_pages as u32);

    for (i, o) in objects.iter().enumerate() {
        for x in [
            o.data.len() as u32,
            o.base,
            o.flags,
            first_page[i] as u32 + 1,
            pages_of(o) as u32,
            0,
        ] {
            out.extend_from_slice(&x.to_le_bytes());
        }
    }
    for p in 1..=total_pages as u32 {
        out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8, 0]);
    }
    let mut cumulative = 0u32;
    out.extend_from_slice(&cumulative.to_le_bytes());
    for rec in &per_page {
        cumulative += rec.len() as u32;
        out.extend_from_slice(&cumulative.to_le_bytes());
    }
    out.extend_from_slice(&records);
    assert_eq!(out.len(), data_pages);
    for o in objects {
        out.extend_from_slice(&o.data);
        out.resize(
            out.len() + o.data.len().next_multiple_of(PAGE) - o.data.len(),
            0,
        );
    }
    // Trim the padding of the very last page down to the declared last page size.
    out.truncate(data_pages + (total_pages - 1) * PAGE + last_page);
    out
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn two_objects() -> Vec<Obj> {
    vec![
        Obj {
            base: 0x10000,
            flags: 0x2025,
            data: pattern(0x180, 1),
        },
        Obj {
            base: 0x20000,
            flags: 0x2043,
            data: pattern(0x60, 7),
        },
    ]
}

#[test]
fn loads_two_objects() {
    let image = load_le(&build_le(&two_objects(), &[])).unwrap();
    let program = &image.program;
    assert_eq!(program.format, ExecutableFormat::Le);
    assert_eq!(program.regions.len(), 2);
    assert_eq!(program.regions[0].name, "obj1");
    assert_eq!(program.regions[0].start, Address::Flat(0x10000));
    assert_eq!(program.regions[0].virtual_size, 0x180);
    assert_eq!(program.regions[0].data, pattern(0x180, 1));
    assert!(program.regions[0].permissions.execute);
    assert!(!program.regions[0].permissions.write);
    assert_eq!(program.regions[1].name, "obj2");
    assert_eq!(program.regions[1].data, pattern(0x60, 7));
    assert!(program.regions[1].permissions.write);
    assert_eq!(program.entry_points, vec![Address::Flat(0x10010)]);
    assert_eq!(image.header.entry, Address::Flat(0x10010));
    assert_eq!(image.header.stack, Address::Flat(0x20040));
    assert_eq!(image.header.page_size, PAGE as u32);
    assert_eq!(image.header.object_count, 2);
    assert_eq!(image.header.le_offset, 0x40);
    assert!(image.warnings.is_empty());
    assert!(image.raw_fixups.is_empty());
}

#[test]
fn applies_offset32_fixup() {
    let fix = Fix {
        object: 0,
        offset: 0x20,
        kind: 0x07,
        target_object: 2,
        target_offset: 0x30,
    };
    let image = load_le(&build_le(&two_objects(), &[fix])).unwrap();
    assert_eq!(
        image.program.read(Address::Flat(0x10020), 4),
        Some(&0x20030u32.to_le_bytes()[..])
    );
    assert_eq!(image.program.relocations.len(), 1);
    let r = image.program.relocations[0];
    assert_eq!(r.at, Address::Flat(0x10020));
    assert_eq!((r.kind, r.width), (RelocKind::Absolute, 4));
    assert_eq!(image.raw_fixups.len(), 1);
    let raw = &image.raw_fixups[0];
    assert_eq!(
        (raw.page, raw.object, raw.offset, raw.source_type),
        (1, 1, 0x20, 0x07)
    );
    assert_eq!((raw.target_object, raw.target_offset), (2, 0x30));
    assert!(!raw.short_target);
    // source, flags, i16 offset, object byte, u32 target offset
    assert_eq!(raw.length, 9);
}

#[test]
fn applies_fixup_straddling_page_boundary() {
    let fix = Fix {
        object: 0,
        offset: PAGE - 2,
        kind: 0x07,
        target_object: 2,
        target_offset: 0x11,
    };
    let image = load_le(&build_le(&two_objects(), &[fix])).unwrap();
    let at = Address::Flat(0x10000 + PAGE as u32 - 2);
    assert_eq!(
        image.program.read(at, 4),
        Some(&0x20011u32.to_le_bytes()[..])
    );
    // Present on both pages in the table, applied once.
    assert_eq!(image.raw_fixups.len(), 2);
    assert_eq!(image.raw_fixups[0].offset, PAGE as i32 - 2);
    assert_eq!(image.raw_fixups[1].offset, PAGE as i32 - 2);
    assert_eq!(image.raw_fixups[1].page, 2);
    assert_eq!(image.program.relocations.len(), 1);
    // Bytes around the field are untouched.
    let original = pattern(0x180, 1);
    assert_eq!(image.program.regions[0].data[PAGE - 3], original[PAGE - 3]);
    assert_eq!(image.program.regions[0].data[PAGE + 2], original[PAGE + 2]);
}

#[test]
fn relocation_targets_are_flat() {
    let fixes = [
        Fix {
            object: 0,
            offset: 0x10,
            kind: 0x07,
            target_object: 2,
            target_offset: 0x08,
        },
        Fix {
            object: 0,
            offset: 0x20,
            kind: 0x08,
            target_object: 1,
            target_offset: 0x100,
        },
        Fix {
            object: 0,
            offset: 0x30,
            kind: 0x02,
            target_object: 2,
            target_offset: 0,
        },
        Fix {
            object: 0,
            offset: 0x40,
            kind: 0x06,
            target_object: 2,
            target_offset: 4,
        },
    ];
    let image = load_le(&build_le(&two_objects(), &fixes)).unwrap();
    let relocs = &image.program.relocations;
    assert_eq!(relocs.len(), 4);
    let expected = [
        (RelocKind::Absolute, 4, 0x20008),
        (RelocKind::Relative, 4, 0x10100),
        (RelocKind::Selector, 2, 0x20000),
        (RelocKind::FarPointer, 6, 0x20004),
    ];
    for (r, (kind, w, target)) in relocs.iter().zip(expected) {
        assert_eq!((r.kind, r.width), (kind, w));
        assert_eq!(r.target, Address::Flat(target));
    }
    // rel32 is relative to the end of the field.
    let rel = i32::from_le_bytes(
        image
            .program
            .read(Address::Flat(0x10020), 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(rel, 0x10100 - (0x10020 + 4));
    // sel16 stores the target object number.
    assert_eq!(
        image.program.read(Address::Flat(0x10030), 2),
        Some(&2u16.to_le_bytes()[..])
    );
}

#[test]
fn truncated_at_every_offset_errors() {
    let fix = Fix {
        object: 0,
        offset: PAGE - 2,
        kind: 0x07,
        target_object: 2,
        target_offset: 0x11,
    };
    let bytes = build_le(&two_objects(), &[fix]);
    assert!(load_le(&bytes).is_ok());
    for len in 0..bytes.len() {
        assert!(
            load_le(&bytes[..len]).is_err(),
            "prefix of {len} bytes loaded"
        );
    }
}

#[test]
fn bad_magic_errors() {
    let mut bytes = build_le(&two_objects(), &[]);
    bytes[0x40] = b'X';
    assert!(matches!(
        load_le(&bytes),
        Err(LoadError::BadMagic { offset: 0x40 })
    ));
    let mut bytes = build_le(&two_objects(), &[]);
    bytes[0] = b'Q';
    assert!(matches!(
        load_le(&bytes),
        Err(LoadError::BadMagic { offset: 0 })
    ));
}

#[test]
fn garbage_headers_never_panic() {
    // Flip every header byte of a valid image: must return, Ok or Err.
    let bytes = build_le(&two_objects(), &[]);
    for i in 0..0x40 + HEADER + 48 {
        for value in [0x00, 0xFF, 0x80] {
            let mut copy = bytes.clone();
            copy[i] = value;
            let _ = load_le(&copy);
        }
    }
}
