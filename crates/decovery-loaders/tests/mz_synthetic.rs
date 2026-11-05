//! Synthetic MZ and COM files built inside the test; no proprietary data.

use decovery_core::{Address, ArchMode, ExecutableFormat, RelocKind};
use decovery_loaders::{LoadError, load_com, load_mz, mz_image_range, parse_mz_header};

struct Fields {
    pages: u16,
    last: u16,
    cs: u16,
    ip: u16,
}

/// Header of `header_paragraphs` * 16 bytes (at least 28 + 4 per relocation), then `image`.
fn mz(f: &Fields, relocs: &[(u16, u16)], image: &[u8], header_paragraphs: u16) -> Vec<u8> {
    let mut v = vec![0u8; usize::from(header_paragraphs) * 16];
    let words = [
        0x5A4D,
        f.last,
        f.pages,
        relocs.len() as u16,
        header_paragraphs,
        0,
        0xFFFF,
        0,
        0x0100,
        0,
        f.ip,
        f.cs,
        0x1C,
        0,
    ];
    for (i, w) in words.iter().enumerate() {
        v[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    for (i, (off, seg)) in relocs.iter().enumerate() {
        let at = 0x1C + i * 4;
        v[at..at + 2].copy_from_slice(&off.to_le_bytes());
        v[at + 2..at + 4].copy_from_slice(&seg.to_le_bytes());
    }
    v.extend_from_slice(image);
    v
}

fn simple(image: &[u8]) -> Vec<u8> {
    let total = 32 + image.len();
    mz(
        &Fields {
            pages: total.div_ceil(512) as u16,
            last: (total % 512) as u16,
            cs: 1,
            ip: 0x10,
        },
        &[],
        image,
        2,
    )
}

#[test]
fn loads_image_and_entry() {
    let image: Vec<u8> = (0..0x40u8).collect();
    let img = load_mz(&simple(&image)).unwrap();
    assert_eq!(img.program.format, ExecutableFormat::Mz);
    let r = &img.program.regions[0];
    assert_eq!(r.name, "image");
    assert_eq!(r.start, Address::Seg { seg: 0, off: 0 });
    assert_eq!(r.virtual_size, 0x40);
    assert_eq!(r.data, image);
    assert_eq!(r.file_offset, Some(32));
    assert_eq!(r.arch, ArchMode::X86Real16);
    assert!(r.permissions.read && r.permissions.write && r.permissions.execute);
    assert_eq!(
        img.program.entry_points,
        vec![Address::Seg { seg: 1, off: 0x10 }]
    );
    assert_eq!(
        (img.image_offset, img.image_len, img.trailing_len),
        (32, 0x40, 0)
    );
    assert!(img.warnings.is_empty());
}

#[test]
fn relocation_becomes_selector_with_segment_value() {
    let mut image = vec![0u8; 0x20];
    image[5..7].copy_from_slice(&0x0123u16.to_le_bytes());
    let f = Fields {
        pages: 1,
        last: 32 + 0x20,
        cs: 0,
        ip: 0,
    };
    let img = load_mz(&mz(&f, &[(5, 0)], &image, 2)).unwrap();
    assert_eq!(img.program.relocations.len(), 1);
    let r = &img.program.relocations[0];
    assert_eq!(r.at, Address::Seg { seg: 0, off: 5 });
    assert_eq!(r.kind, RelocKind::Selector);
    assert_eq!(r.width, 2);
    assert_eq!(
        r.target,
        Address::Seg {
            seg: 0x0123,
            off: 0
        }
    );
    assert_eq!(r.addend, 0);
    // the data stays as stored in the file
    assert_eq!(img.program.regions[0].data, image);
}

#[test]
fn image_end_uses_last_page_bytes() {
    let h = parse_mz_header(&mz(
        &Fields {
            pages: 2,
            last: 0x20,
            cs: 0,
            ip: 0,
        },
        &[],
        &[],
        2,
    ))
    .unwrap();
    assert_eq!(h.pages, 2);
    assert_eq!(mz_image_range(&h, 0x1000), (32, 0x220 - 32));
    // last_page_bytes == 0: full last page
    let h = parse_mz_header(&mz(
        &Fields {
            pages: 2,
            last: 0,
            cs: 0,
            ip: 0,
        },
        &[],
        &[],
        2,
    ))
    .unwrap();
    assert_eq!(mz_image_range(&h, 0x1000), (32, 0x400 - 32));
    // clamped to the file length
    assert_eq!(mz_image_range(&h, 0x100), (32, 0x100 - 32));
}

#[test]
fn relocation_outside_image_names_offset() {
    let image = vec![0u8; 0x20];
    let f = Fields {
        pages: 1,
        last: 32 + 0x20,
        cs: 0,
        ip: 0,
    };
    let err = load_mz(&mz(&f, &[(0x30, 0)], &image, 2)).unwrap_err();
    // entry is the first record at file offset 0x1C
    assert!(
        err.to_string().contains("0x1c"),
        "message must name the entry offset: {err}"
    );
}

#[test]
fn trailing_bytes_are_reported() {
    let mut bytes = simple(&[0u8; 0x20]);
    bytes.extend_from_slice(&[1, 2, 3, 4, 5]);
    let img = load_mz(&bytes).unwrap();
    assert_eq!(img.trailing_len, 5);
    assert_eq!(img.image_len, 0x20);
    assert_eq!(img.warnings.len(), 1);
    assert!(img.warnings[0].contains('5'));
}

#[test]
fn truncated_header_is_an_error() {
    let bytes = simple(&[0u8; 0x20]);
    for n in [0usize, 1, 2, 27] {
        assert!(matches!(
            parse_mz_header(&bytes[..n]),
            Err(LoadError::Truncated { .. } | LoadError::BadMagic { .. })
        ));
    }
    assert!(matches!(
        load_mz(&bytes[..27]),
        Err(LoadError::Truncated { .. })
    ));
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert!(matches!(
        parse_mz_header(&bad),
        Err(LoadError::BadMagic { offset: 0 })
    ));
    bad[0] = b'Z';
    bad[1] = b'M';
    assert!(parse_mz_header(&bad).is_ok());
}

#[test]
fn com_loads_at_0100() {
    let p = load_com(&[0xB8, 0x00, 0x4C, 0xCD, 0x21]).unwrap();
    assert_eq!(p.format, ExecutableFormat::Com);
    let r = &p.regions[0];
    assert_eq!(r.name, "image");
    assert_eq!(r.start, Address::Seg { seg: 0, off: 0x100 });
    assert_eq!(r.file_offset, Some(0));
    assert_eq!(r.arch, ArchMode::X86Real16);
    assert_eq!(r.data.len(), 5);
    assert_eq!(p.entry_points, vec![Address::Seg { seg: 0, off: 0x100 }]);
    assert!(p.relocations.is_empty());
}

#[test]
fn com_too_large_is_rejected() {
    assert!(load_com(&vec![0x90; 65_280]).is_ok());
    assert!(matches!(
        load_com(&vec![0x90; 65_281]),
        Err(LoadError::Unsupported(_))
    ));
}
