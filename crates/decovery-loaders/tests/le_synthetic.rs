//! Synthetic LE images built inside the test; no proprietary data.

#[path = "support/le_builder.rs"]
mod le_builder;

use decovery_core::{Address, ExecutableFormat, RelocKind};
use decovery_loaders::{LoadError, fixup_processing_order, load_le, processing_order};
use le_builder::{Fix, HEADER, Le, Obj, PAGE, build_le, pattern};

fn two_objects() -> Vec<Obj> {
    vec![
        Obj::new(0x10000, 0x2025, pattern(0x180, 1)),
        Obj::new(0x20000, 0x2043, pattern(0x60, 7)),
    ]
}

#[test]
fn loads_two_objects() {
    let image = load_le(&build_le(two_objects(), &[])).unwrap();
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
    let image = load_le(&build_le(two_objects(), &[fix])).unwrap();
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
    let image = load_le(&build_le(two_objects(), &[fix])).unwrap();
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
    let image = load_le(&build_le(two_objects(), &fixes)).unwrap();
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
    let bytes = build_le(two_objects(), &[fix]);
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
    let mut bytes = build_le(two_objects(), &[]);
    bytes[0x40] = b'X';
    assert!(matches!(
        load_le(&bytes),
        Err(LoadError::BadMagic { offset: 0x40 })
    ));
    let mut bytes = build_le(two_objects(), &[]);
    bytes[0] = b'Q';
    assert!(matches!(
        load_le(&bytes),
        Err(LoadError::BadMagic { offset: 0 })
    ));
}

#[test]
fn garbage_headers_never_panic() {
    // Flip every header byte of a valid image: must return, Ok or Err.
    let bytes = build_le(two_objects(), &[]);
    for i in 0..0x40 + HEADER + 48 {
        for value in [0x00, 0xFF, 0x80] {
            let mut copy = bytes.clone();
            copy[i] = value;
            let _ = load_le(&copy);
        }
    }
}

#[test]
fn reads_header_fields_and_object_file_data() {
    let mut le = Le::new(two_objects(), vec![Fix::new(0, 0x20, 0x07, 2, 0x30)]);
    le.objects[1].size = 0x200;
    le.auto_data = 2;
    le.resident_name = Some("GAME".into());
    let bytes = le.build();
    let image = load_le(&bytes).unwrap();
    let h = &image.header;
    assert_eq!(h.page_count, 3);
    assert_eq!((h.entry_object, h.entry_offset), (1, 0x10));
    assert_eq!((h.stack_object, h.esp), (2, 0x40));
    assert_eq!(h.auto_data_object, 2);
    assert_eq!(h.resident_name.as_deref(), Some("GAME"));
    assert_eq!(h.fixup_section_size, 9 + 4 * 4);
    assert_eq!(image.objects.len(), 2);
    let o = &image.objects[1];
    assert_eq!(
        (o.number, o.base, o.size, o.flags),
        (2, 0x20000, 0x200, 0x2043)
    );
    assert_eq!(o.file_length, 0x60);
    // file data is stored as is, without the fixup applied
    assert_eq!(image.raw_data[0], pattern(0x180, 1));
    assert_eq!(image.raw_data[1], pattern(0x60, 7));
    assert_eq!(
        image.objects[0]
            .file_offset
            .map(|at| &bytes[at as usize..at as usize + 4]),
        Some(&pattern(4, 1)[..])
    );
}

/// Table order of WLINK's 512-byte block packing: blocks fill in processing order, the newest block comes first.
fn wlink_table_order(lengths: &[u32]) -> Vec<usize> {
    let mut blocks: Vec<Vec<usize>> = Vec::new();
    let mut size = 0;
    for (i, &len) in lengths.iter().enumerate() {
        if blocks.is_empty() || size + len > 512 {
            blocks.push(Vec::new());
            size = 0;
        }
        blocks.last_mut().unwrap().push(i);
        size += len;
    }
    blocks.into_iter().rev().flatten().collect()
}

#[test]
fn fixup_order_inverts_block_packing() {
    // one page with 67 off32 records of 9 bytes (603 bytes): processing order 0..67 is stored as 56..67, 0..56
    let mut le = Le::new(
        vec![Obj::new(0x10000, 0x2045, pattern(0x1000, 3))],
        Vec::new(),
    );
    le.page = 0x1000;
    let processing: Vec<Fix> = (0..67)
        .map(|i| Fix::new(0, 0x10 + 8 * i, 0x07, 1, i as u32))
        .collect();
    let table = wlink_table_order(&[9; 67]);
    assert_eq!(table[0], 56);
    le.fixups = table.iter().map(|&i| processing[i]).collect();
    let image = load_le(&le.build()).unwrap();
    let raw = &image.raw_fixups;
    assert_eq!(raw.iter().map(|f| f.length).sum::<u32>(), 603);
    let (order, unclear) = fixup_processing_order(raw);
    assert!(unclear.is_empty());
    let offsets: Vec<i32> = order.iter().map(|&i| raw[i].offset).collect();
    let expected: Vec<i32> = (0..67).map(|i| 0x10 + 8 * i).collect();
    assert_eq!(offsets, expected);

    // the inversion alone, with mixed lengths
    let lengths: Vec<u32> = (0..90).map(|i| if i % 3 == 0 { 7 } else { 9 }).collect();
    let table = wlink_table_order(&lengths);
    let stored: Vec<u32> = table.iter().map(|&i| lengths[i]).collect();
    let back = processing_order(&stored).unwrap();
    assert_eq!(
        back.iter().map(|&i| table[i]).collect::<Vec<_>>(),
        (0..90).collect::<Vec<_>>()
    );
    // a record larger than a block: no packing produces this page
    assert_eq!(processing_order(&[10, 600]), None);
}

#[test]
fn fixup_order_merges_page_crossing_fixups() {
    // a field over the page boundary is stored on both pages and counts once, at its first place
    let fixes = [
        Fix::new(0, 0x10, 0x07, 2, 1),
        Fix::new(0, PAGE - 2, 0x07, 2, 2),
        Fix::new(0, PAGE + 0x10, 0x07, 2, 3),
    ];
    let image = load_le(&build_le(two_objects(), &fixes)).unwrap();
    assert_eq!(image.raw_fixups.len(), 4);
    let (order, unclear) = fixup_processing_order(&image.raw_fixups);
    assert!(unclear.is_empty());
    let targets: Vec<u32> = order
        .iter()
        .map(|&i| image.raw_fixups[i].target_offset)
        .collect();
    assert_eq!(targets, [1, 2, 3]);
}
