use std::collections::BTreeMap;

use decovery_core::{
    ARCHIVE_DIR, Address, archive_ids_for, archive_load, archive_remove, archive_save,
};
use serde_json::{Value, json};

fn files(pairs: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    pairs
        .iter()
        .map(|(n, b)| (n.to_string(), b.to_vec()))
        .collect()
}

fn meta(address: Address) -> Value {
    json!({"address": serde_json::to_value(address).unwrap(), "name": "f", "file": "a.c",
           "profile": "p", "flags": "-x"})
}

fn save(dir: &std::path::Path, m: &Value, pairs: &[(&str, &[u8])]) -> String {
    archive_save(dir, m, &files(pairs)).unwrap()
}

#[test]
fn same_content_same_id() {
    let dir = tempfile::tempdir().unwrap();
    let m = meta(Address::Flat(0x12340));
    let pairs: &[(&str, &[u8])] = &[
        ("function.c", b"int f(void){return 1;}"),
        ("objects/a-2.obj", &[1, 2, 3]),
    ];
    let a = save(dir.path(), &m, pairs);
    let b = save(dir.path(), &m, pairs);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
    let c = save(dir.path(), &m, &[("function.c", b"x")]);
    assert_ne!(a, c);
    let count = std::fs::read_dir(dir.path().join(ARCHIVE_DIR))
        .unwrap()
        .count();
    assert_eq!(count, 2);
    let loaded = archive_load(dir.path(), &a).unwrap();
    assert_eq!(loaded.files, files(pairs));
    assert_eq!(loaded.meta, m);
}

#[test]
fn several_objects_and_messages_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let pairs: &[(&str, &[u8])] = &[
        ("objects/m-1.obj", &[1]),
        ("objects/m-2.obj", &[2]),
        ("messages/1.txt", b"warning"),
        ("messages/2.txt", b"error"),
    ];
    let id = save(dir.path(), &meta(Address::Flat(1)), pairs);
    assert_eq!(archive_load(dir.path(), &id).unwrap().files, files(pairs));
}

#[test]
fn load_verifies_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let m = meta(Address::Flat(1));
    let id = save(dir.path(), &m, &[("function.c", b"abc")]);
    let path = dir
        .path()
        .join(ARCHIVE_DIR)
        .join(&id)
        .join("files/function.c");
    std::fs::write(&path, b"abd").unwrap();
    let error = archive_load(dir.path(), &id).unwrap_err().to_string();
    assert!(error.contains("function.c"), "{error}");
    // Saving the same content again must not silently accept the damaged entry.
    assert!(archive_save(dir.path(), &m, &files(&[("function.c", b"abc")])).is_err());
}

#[test]
fn load_rejects_extra_file_and_bad_id() {
    let dir = tempfile::tempdir().unwrap();
    let id = save(
        dir.path(),
        &meta(Address::Flat(1)),
        &[("function.c", b"abc")],
    );
    std::fs::write(
        dir.path().join(ARCHIVE_DIR).join(&id).join("files/extra"),
        b"x",
    )
    .unwrap();
    let error = archive_load(dir.path(), &id).unwrap_err().to_string();
    assert!(error.contains("extra"), "{error}");
    assert!(archive_load(dir.path(), "../x").is_err());
}

#[test]
fn bad_paths_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let m = meta(Address::Flat(1));
    let bad = [
        "",
        "a\\b",
        "/a",
        "a//b",
        "./a",
        "a/./b",
        "../a",
        "a/..",
        "a.",
        "a ",
        "dir./f",
        "con",
        "CON.txt",
        "objects/nul",
        "aux.c",
        "prn",
        "com1",
        "lpt9.obj",
        "a<b",
        "a>b",
        "a:b",
        "a\"b",
        "a|b",
        "a?b",
        "a*b",
        "a\u{1}b",
        "a\nb",
    ];
    for name in bad {
        let result = archive_save(dir.path(), &m, &files(&[(name, b"x")]));
        assert!(result.is_err(), "{name:?} must be rejected");
    }
    for name in [
        "com0",
        "com10",
        "console.c",
        "objects/a-2.obj",
        "messages/1.txt",
    ] {
        archive_save(dir.path(), &m, &files(&[(name, b"x")]))
            .unwrap_or_else(|e| panic!("{name:?} must be accepted: {e}"));
    }
}

#[test]
fn case_collision_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let m = meta(Address::Flat(1));
    for pairs in [
        vec![("Objects/a.obj", &b"1"[..]), ("objects/A.OBJ", &b"2"[..])],
        vec![("a", &b"1"[..]), ("A", &b"2"[..])],
        vec![("a", &b"1"[..]), ("a/b", &b"2"[..])],
    ] {
        let result = archive_save(dir.path(), &m, &files(&pairs));
        assert!(result.is_err(), "{pairs:?}");
    }
}

#[test]
fn ids_for_address() {
    let dir = tempfile::tempdir().unwrap();
    let one = Address::Flat(1);
    let two = Address::Flat(2);
    assert!(archive_ids_for(dir.path(), one).unwrap().is_empty());
    let x = save(dir.path(), &meta(one), &[("function.c", b"1")]);
    let y = save(dir.path(), &meta(one), &[("function.c", b"2")]);
    let z = save(dir.path(), &meta(two), &[("function.c", b"3")]);
    let mut expected = vec![x, y];
    expected.sort();
    assert_eq!(archive_ids_for(dir.path(), one).unwrap(), expected);
    assert_eq!(archive_ids_for(dir.path(), two).unwrap(), vec![z.clone()]);
    archive_remove(dir.path(), &z).unwrap();
    archive_remove(dir.path(), &z).unwrap();
    assert!(archive_ids_for(dir.path(), two).unwrap().is_empty());
}

#[test]
fn tmp_dirs_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let one = Address::Flat(1);
    let id = save(dir.path(), &meta(one), &[("function.c", b"1")]);
    let base = dir.path().join(ARCHIVE_DIR);
    let tmp = base.join(".tmp-123-abc-0");
    std::fs::create_dir_all(tmp.join("files")).unwrap();
    std::fs::copy(
        base.join(&id).join("manifest.json"),
        tmp.join("manifest.json"),
    )
    .unwrap();
    assert_eq!(archive_ids_for(dir.path(), one).unwrap(), vec![id]);
}
