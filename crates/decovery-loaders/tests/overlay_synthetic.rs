//! Aztec C86 overlays from hand-built bytes.

use decovery_loaders::{
    LoadError, aztec_data_segment, find_overlay_loader, read_overlay, read_overlays,
};

/// Header words, then `code` and `data`.
fn overlay(words: [u16; 7], code: &[u8], data: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    bytes.extend_from_slice(code);
    bytes.extend_from_slice(data);
    bytes
}

fn good() -> Vec<u8> {
    overlay(
        [0xF2, 0x5000, 4, 0x9000, 2, 6, 0x5001],
        &[0x90, 0x90, 0x90, 0xC3],
        &[1, 2],
    )
}

#[test]
fn overlay_header_fields() {
    let o = read_overlay(&good(), "VTEST").unwrap();
    let h = o.header;
    assert_eq!(
        (h.corg, h.csize, h.dorg, h.dsize, h.bss, h.entry),
        (0x5000, 4, 0x9000, 2, 6, 0x5001)
    );
    assert_eq!(o.name, "VTEST");
    assert_eq!(o.code, [0x90, 0x90, 0x90, 0xC3]);
    assert_eq!(o.data, [1, 2]);
    assert_eq!((h.code_offset(), h.data_offset()), (14, 18));
}

#[test]
fn bad_magic_is_error_with_offset() {
    let mut bytes = good();
    bytes[0] = 0xF3;
    assert_eq!(
        read_overlay(&bytes, "X"),
        Err(LoadError::BadMagic { offset: 0 })
    );
    assert_eq!(
        read_overlay(&bytes[..10], "X"),
        Err(LoadError::Truncated {
            offset: 0,
            needed: 14
        })
    );
}

#[test]
fn overlay_past_file_end_is_error() {
    let bytes = good();
    // code cut short
    assert_eq!(
        read_overlay(&bytes[..16], "X"),
        Err(LoadError::Truncated {
            offset: 14,
            needed: 4
        })
    );
    // data cut short
    assert_eq!(
        read_overlay(&bytes[..19], "X"),
        Err(LoadError::Truncated {
            offset: 18,
            needed: 2
        })
    );
    // data + BSS past 64 KiB
    let big = overlay([0xF2, 0x5000, 1, 0xFFF0, 2, 0x20, 0x5000], &[0xC3], &[0, 0]);
    assert!(matches!(
        read_overlay(&big, "X"),
        Err(LoadError::Malformed { offset: 6, .. })
    ));
    // code past 64 KiB
    let big = overlay([0xF2, 0xFFFF, 2, 0, 0, 0, 0xFFFF], &[0xC3, 0xC3], &[]);
    assert!(matches!(
        read_overlay(&big, "X"),
        Err(LoadError::Malformed { offset: 2, .. })
    ));
    // entry outside the code
    let bad = overlay([0xF2, 0x5000, 1, 0, 0, 0, 0x5001], &[0xC3], &[]);
    assert!(matches!(
        read_overlay(&bad, "X"),
        Err(LoadError::Malformed { offset: 12, .. })
    ));
    // every prefix gives an error, never a panic
    for n in 0..bytes.len() {
        assert!(read_overlay(&bytes[..n], "X").is_err());
    }
}

#[test]
fn bad_overlay_does_not_hide_the_others() {
    let a = good();
    let b = [0xF2u8, 0];
    let c = good();
    let results = read_overlays([("A", &a[..]), ("B", &b[..]), ("C", &c[..])]);
    assert_eq!(results.len(), 3);
    assert!(results[0].1.is_ok());
    assert!(matches!(results[1].1, Err(LoadError::Truncated { .. })));
    assert_eq!(results[2].0, "C");
    assert!(results[2].1.is_ok());
}

#[test]
fn loader_pattern_found() {
    let ovloader = [
        0x8B, 0xDC, 0x8B, 0x47, 0x02, 0xA3, 0x34, 0x12, 0xE8, 0x02, 0x00, 0xFF, 0xE0,
    ];
    let mut code = vec![0x90; 0x40];
    code.extend_from_slice(&ovloader);
    code.extend_from_slice(&[0xC3; 8]);
    assert_eq!(find_overlay_loader(&code), Some(0x40));
    // ambiguous: two copies
    let mut twice = code.clone();
    twice.extend_from_slice(&ovloader);
    assert_eq!(find_overlay_loader(&twice), None);
    // not present
    assert_eq!(find_overlay_loader(&code[..0x45]), None);
    // the startup code's `mov bp, <data segment>`
    let mut image = vec![0u8; 0x30];
    image[0x22..0x25].copy_from_slice(&[0xBD, 0xF6, 0x0F]);
    assert_eq!(aztec_data_segment(&image, 2, 2), Some(0x0FF6));
    assert_eq!(aztec_data_segment(&image, 0, 0), None);
    assert_eq!(aztec_data_segment(&image, 0xFFFF, 0xFFFF), None);
}
