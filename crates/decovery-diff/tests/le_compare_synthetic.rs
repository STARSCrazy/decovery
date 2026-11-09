//! `compare_le` on synthetic LE images (no proprietary data).

#[path = "../../decovery-loaders/tests/support/le_builder.rs"]
mod le_builder;

use decovery_diff::compare_le;
use le_builder::{Fix, Le, Obj, build_le, pattern};

fn objects(code: Vec<u8>) -> Vec<Obj> {
    vec![
        Obj::new(0x10000, 0x2045, code),
        Obj::new(0x20000, 0x2043, pattern(0x60, 7)),
    ]
}

fn place(va: u32) -> String {
    format!("va:{va:08X}")
}

#[test]
fn identical_le_is_empty() {
    let bytes = build_le(
        objects(pattern(0x180, 1)),
        &[Fix::new(0, 0x20, 0x07, 2, 0x30)],
    );
    assert!(compare_le(&bytes, &bytes, &place, 20).is_empty());
}

#[test]
fn le_compare_reports_page_shift() {
    let original = pattern(0x180, 1);
    let mut shifted = original.clone();
    for (k, b) in [0xAA, 0xBB, 0xCC].into_iter().enumerate() {
        shifted.insert(0x50 + k, b);
    }
    shifted.truncate(0x180);
    let a = build_le(objects(original.clone()), &[]);
    let b = build_le(objects(shifted), &[]);
    assert_eq!(
        compare_le(&a, &b, &place, 20),
        [
            "object 1: 2 of 2 pages differ, first difference at va:00010050, 3 bytes inserted from there (shift)"
        ]
    );
    // the other way round the bytes are missing
    let lines = compare_le(&b, &a, &place, 20);
    assert!(
        lines[0].ends_with("3 bytes missing from there (shift)"),
        "{lines:?}"
    );
}

#[test]
fn le_compare_reports_fixup_target() {
    let code = pattern(0x180, 1);
    let a = build_le(objects(code.clone()), &[Fix::new(0, 0x20, 0x07, 2, 0x30)]);
    let b = build_le(objects(code.clone()), &[Fix::new(0, 0x20, 0x07, 1, 0x30)]);
    let lines = compare_le(&a, &b, &place, 20);
    assert_eq!(
        lines,
        [
            "object 1: 1 of 2 pages differ, first difference at va:00010022",
            "fixups: 1 pages with other content, 0 pages only in another order",
            "fixup page 1: va:00010020 targets object 1 +0x30 instead of object 2 +0x30",
        ]
    );
    // missing, extra and order-only pages
    let fixes = [
        Fix::new(0, 0x20, 0x07, 2, 0x30),
        Fix::new(0, 0x40, 0x07, 2, 0x10),
    ];
    let a = build_le(objects(code.clone()), &fixes);
    let swapped = build_le(objects(code.clone()), &[fixes[1], fixes[0]]);
    assert_eq!(
        compare_le(&a, &swapped, &place, 20),
        [
            "fixups: 0 pages with other content, 1 pages only in another order",
            "fixups only in order: page 1",
        ]
    );
    let fewer = build_le(objects(code), &fixes[..1]);
    let lines = compare_le(&a, &fewer, &place, 20);
    assert!(
        lines.contains(
            &"fixup page 1: missing at va:00010040 (original → object 2 +0x10)".to_string()
        ),
        "{lines:?}"
    );
    let lines = compare_le(&fewer, &a, &place, 20);
    assert!(
        lines.contains(&"fixup page 1: extra at va:00010040 (→ object 2 +0x10)".to_string()),
        "{lines:?}"
    );
}

#[test]
fn le_compare_reports_header_stub_and_file() {
    let code = pattern(0x180, 1);
    let a = Le::new(objects(code.clone()), Vec::new()).build();
    let mut le = Le::new(objects(code), Vec::new());
    le.stub_mark = 1;
    le.entry = (1, 0x20);
    let b = le.build();
    assert_eq!(
        compare_le(&a, &b, &place, 20),
        [
            "stub differs (original 64 bytes, rebuilt 64 bytes)",
            "header: entry 0x20 instead of 0x10",
        ]
    );
    let mut longer = a.clone();
    longer.push(0);
    assert_eq!(
        compare_le(&a, &longer, &place, 20),
        [format!(
            "file: first difference at file offset {:#x}, length {} instead of {}",
            a.len(),
            a.len() + 1,
            a.len()
        )]
    );
    assert_eq!(
        compare_le(&a, b"MZ", &place, 20)[0].split(':').next(),
        Some("rebuilt is not an LE program")
    );
}
