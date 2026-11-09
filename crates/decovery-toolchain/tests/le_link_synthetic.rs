//! Linking LE programs as one OMF module (port of Decomp's `le_binden.py`) on synthetic LE images and objects.

#[path = "../../decovery-loaders/tests/support/le_builder.rs"]
mod le_builder;

use decovery_core::Address;
use decovery_loaders::{LeImage, load_le};
use decovery_objects::{
    ObjectModule, RefTarget, WriteFixup, WriteFixupKind, WriteSegment, functions, read_omf,
    write_omf_module,
};
use decovery_toolchain::{build_insert, le_module, module_name, response_file, segment_plan};
use le_builder::{Fix, Le, Obj, pattern};

const CODE: u32 = 0x2045;
const DATA: u32 = 0x2043;

/// Code object 1 (0x200 bytes), auto data object 2 (0x60 bytes of data, a full page of 0x100 bytes in the file,
/// 0x2000 in memory) and the given far data objects.
fn program(far: usize, fixups: Vec<Fix>) -> (Vec<u8>, LeImage) {
    let mut objects = vec![
        Obj::new(0x10000, CODE, pattern(0x200, 1)),
        Obj::new(0x20000, DATA, pattern(0x60, 7)),
    ];
    objects[1].size = 0x2000;
    for i in 0..far {
        objects.push(Obj::new(
            0x30000 + 0x10000 * i as u32,
            DATA,
            pattern(0x20, 9),
        ));
    }
    let mut le = Le::new(objects, fixups);
    le.auto_data = 2;
    le.stack = (2, 0x2000);
    let bytes = le.build();
    let image = load_le(&bytes).unwrap();
    (bytes, image)
}

#[test]
fn segment_plan_splits_auto_data() {
    let (_, image) = program(1, Vec::new());
    let plan = segment_plan(&image.objects, 2, 0x1000).unwrap();
    let segments: Vec<(&str, &str, u32, u8, u8)> = plan
        .segments
        .iter()
        .map(|s| {
            (
                s.name.as_str(),
                s.class.as_str(),
                s.length,
                s.combine,
                s.align,
            )
        })
        .collect();
    assert_eq!(
        segments,
        [
            ("_TEXT", "CODE", 0x200, 2, 3),
            ("_DATA", "DATA", 0x100, 2, 3),
            ("_BSS", "BSS", 0x2000 - 0x100 - 0x1000, 2, 1),
            ("STACK", "STACK", 0x1000, 5, 1),
            ("OBJ3", "FAR_DATA", 0x20, 2, 3),
        ]
    );
    assert!(plan.segments.iter().all(|s| s.use32));
    assert_eq!(plan.groups, [("DGROUP".to_string(), vec![2, 3, 4])]);
    assert_eq!(plan.object_segment.get(&1), Some(&1));
    assert_eq!(plan.object_segment.get(&2), Some(&2));
    assert_eq!(plan.object_segment.get(&3), Some(&5));
    assert_eq!(plan.data_length.get(&2), Some(&0x100));

    // several far data objects get a group each (WLINK would merge neighbours into one object)
    let (_, image) = program(2, Vec::new());
    let plan = segment_plan(&image.objects, 2, 0x1000).unwrap();
    assert_eq!(
        plan.groups[1..],
        [
            ("OBJ3G".to_string(), vec![5]),
            ("OBJ4G".to_string(), vec![6])
        ]
    );
}

#[test]
fn stack_must_be_multiple_of_four() {
    let (_, image) = program(0, Vec::new());
    for stack in [0, 0x1002] {
        let err = segment_plan(&image.objects, 2, stack).unwrap_err();
        assert!(err.to_string().contains("divisible by 4"), "{err}");
    }
    let err = segment_plan(&image.objects, 2, 0x4000).unwrap_err();
    assert!(err.to_string().contains("uninitialized rest"), "{err}");
}

/// A Watcom-like object: `foo_` (`mov eax, offset baz_`, `call baz_` without a fixup, `ret`) and `baz_` (`ret`).
fn rebuilt() -> ObjectModule {
    let code = vec![
        0xB8, 0x0B, 0, 0, 0, // mov eax, offset baz_ (own section + 0x0B)
        0xE8, 0x01, 0, 0, 0,    // call baz_, resolved inside the object
        0xC3, // ret
        0xC3, // baz_: ret
    ];
    let bytes = write_omf_module(
        "a.c",
        &[WriteSegment::new("_TEXT", "CODE", code.len() as u32, true)],
        &[],
        &[("foo_".to_string(), 1, 0), ("baz_".to_string(), 1, 0x0B)],
        &[(1, code)],
        &[WriteFixup::new(1, 1, WriteFixupKind::Off32, 1, None)],
        None,
    )
    .unwrap();
    read_omf(&bytes, "A.OBJ").unwrap().modules.remove(0)
}

fn address_of(name: &str) -> Option<Address> {
    (name == "baz_").then_some(Address::Flat(0x10080))
}

#[test]
fn insert_replaces_bytes_and_fixups() {
    let original_fixups = vec![
        Fix::new(0, 0x41, 0x07, 2, 0x10),
        Fix::new(0, 0x100, 0x07, 2, 0x20),
        Fix::new(1, 0x08, 0x07, 1, 0x40),
    ];
    let (bytes, image) = program(0, original_fixups);
    let module = rebuilt();
    let views = functions(&module);
    let foo = views.iter().find(|f| f.name == "foo_").unwrap();
    let insert = build_insert(foo, Address::Flat(0x10040), &image, &address_of).unwrap();
    assert_eq!((insert.object, insert.offset), (1, 0x40));
    // the field holds the target's offset in its object, the call the distance from the original place
    assert_eq!(
        insert.bytes,
        [0xB8, 0x80, 0, 0, 0, 0xE8, 0x36, 0, 0, 0, 0xC3]
    );
    assert_eq!(insert.fixups, [(0x41, 1)]);
    assert!(insert.keep.is_empty());

    let (omf, hints) =
        le_module(&bytes, &image, std::slice::from_ref(&insert), 0x1000, true).unwrap();
    assert!(hints.is_empty(), "{hints:?}");
    let linked = read_omf(&omf, "NB.OBJ").unwrap().modules.remove(0);
    let text = &linked.sections[0];
    assert_eq!(text.name, "_TEXT");
    assert_eq!(&text.data[0x40..0x4B], &insert.bytes[..]);
    // outside the insert the file bytes stay
    assert_eq!(&text.data[..0x40], &pattern(0x200, 1)[..0x40]);
    let relocs: Vec<(u32, RefTarget)> = text
        .relocs
        .iter()
        .map(|r| (r.offset, r.target.clone()))
        .collect();
    let section = |index| RefTarget::Section { index, offset: 0 };
    assert_eq!(relocs, [(0x41, section(0)), (0x100, section(1))]);
    let data = &linked.sections[1];
    assert_eq!(data.relocs.len(), 1);
    assert_eq!(
        (data.relocs[0].offset, data.relocs[0].target.clone()),
        (0x08, section(0))
    );
    assert_eq!(
        linked
            .symbols
            .iter()
            .map(|s| (s.name.as_str(), s.section, s.offset))
            .collect::<Vec<_>>(),
        [("_cstart_", 0, 0x10)]
    );
}

#[test]
fn overlapping_insert_is_rejected() {
    let (bytes, image) = program(0, vec![Fix::new(0, 0x41, 0x07, 2, 0x10)]);
    let module = rebuilt();
    let views = functions(&module);
    let foo = views.iter().find(|f| f.name == "foo_").unwrap();
    let first = build_insert(foo, Address::Flat(0x10040), &image, &address_of).unwrap();
    let mut second = build_insert(foo, Address::Flat(0x10048), &image, &address_of).unwrap();
    second.name = "other".into();
    let mut beyond = build_insert(foo, Address::Flat(0x101F8), &image, &address_of).unwrap();
    beyond.name = "late".into();
    let (omf, hints) = le_module(
        &bytes,
        &image,
        &[first.clone(), second, beyond],
        0x1000,
        false,
    )
    .unwrap();
    assert_eq!(
        hints,
        [
            "other: overlaps another insert, not inserted",
            "late: extends beyond the file data of object 1, not inserted"
        ]
    );
    let linked = read_omf(&omf, "NB.OBJ").unwrap().modules.remove(0);
    assert_eq!(&linked.sections[0].data[0x40..0x4B], &first.bytes[..]);
    assert_eq!(
        &linked.sections[0].data[0x4B..0x50],
        &pattern(0x200, 1)[0x4B..0x50]
    );
}

#[test]
fn insert_reasons_name_the_problem() {
    let (_, image) = program(0, Vec::new());
    let module = rebuilt();
    let views = functions(&module);
    let foo = views.iter().find(|f| f.name == "foo_").unwrap();
    let none = |_: &str| None;
    assert_eq!(
        build_insert(foo, Address::Flat(0x10040), &image, &none).unwrap_err(),
        "baz not resolved"
    );
    let elsewhere = |_: &str| Some(Address::Flat(0x20010));
    assert_eq!(
        build_insert(foo, Address::Flat(0x10040), &image, &elsewhere).unwrap_err(),
        "relative reference to baz into another object"
    );
    assert_eq!(
        build_insert(foo, Address::Flat(0x90000), &image, &address_of).unwrap_err(),
        "0x90000 lies in no object"
    );
}

#[test]
fn response_file_lines() {
    assert_eq!(
        response_file("GAME", true),
        "format os2 le\r\noption osname='DOS/4G'\r\noption stub=STUB.EXE\r\noption nodefaultlibs\r\n\
         option start=_cstart_\r\noption map\r\nname GAME.exe\r\nfile NB\r\n"
    );
    assert!(!response_file("GAME", false).contains("option start"));
    assert_eq!(module_name("GAME"), "GAME");
    assert_eq!(module_name("main_1"), "main_1");
    assert_eq!(module_name("TOO_LONG_NAME"), "REBUILD");
    assert_eq!(module_name(""), "REBUILD");
}
