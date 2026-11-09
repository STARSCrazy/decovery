//! `link` on the synthetic MZ workspace of the build tests: the fake runner serves the objects and, for the link
//! job, a prepared `REBUILD.EXE`. Skipped (with a message) without Python: set `DECOVERY_PYTHON` or put `python`
//! on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::time::Duration;

use build_fixture::{Fixture, fixture};
use decovery_core::{
    Analysis, AnalyzedFunction, ProgramRecord, RebuildResult, Workspace, read_program_record,
    save_program_record,
};
use decovery_facade::{Response, link};
use serde_json::Value;

const LINK_CONFIG: &str = "\n[rebuild.link]\nflags = \"/c/x/i\"\nstartup = \"C0S\"\nlibraries = [\"EMU\", \"MATHS\", \"CS\"]\n";
const PROGRAM_FILE: &str = "knowledge/rebuild-program.toml";

/// The fixture with `[rebuild.link]` in its configuration.
fn linking_fixture(python: &str) -> Fixture {
    let f = fixture(python, "");
    let config = f.root().join("decovery.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    // `[rebuild.link]` must follow `[rebuild]`, before `[plugins.fake]`
    let text = text.replacen(
        "\n[plugins.fake]",
        &format!("{LINK_CONFIG}\n[plugins.fake]"),
        1,
    );
    std::fs::write(config, text).unwrap();
    f
}

fn original(f: &Fixture) -> Vec<u8> {
    std::fs::read(f.root().join("t.exe")).unwrap()
}

/// The EXE the fake linker produces.
fn prepare_exe(f: &Fixture, bytes: &[u8]) {
    std::fs::write(f.objects.path().join("REBUILD.EXE"), bytes).unwrap();
}

/// An MZ file with a 32-byte header over `image`, like the fixture's original.
fn mz(image: &[u8], min_alloc: u16) -> Vec<u8> {
    let total = 32 + image.len();
    let words: [u16; 14] = [
        0x5A4D,
        (total % 512) as u16,
        total.div_ceil(512) as u16,
        0,
        2,
        min_alloc,
        0xFFFF,
        0,
        0x0100,
        0,
        0x10,
        0,
        0x1C,
        0,
    ];
    let mut v = vec![0u8; 32];
    for (i, w) in words.iter().enumerate() {
        v[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    v.extend_from_slice(image);
    v
}

fn run(f: &Fixture) -> Response {
    link(f.root(), &|_| {}).unwrap()
}

fn record(f: &Fixture) -> ProgramRecord {
    read_program_record(f.root())
        .unwrap()
        .expect("program record")
}

fn diagnosis(response: &Response) -> Vec<String> {
    response.data["diagnosis"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn seed_identical(f: &Fixture, name: &str, address: &str) {
    std::fs::write(
        f.rebuild_path(),
        format!(
            "schema = 1\n\n[[function]]\naddress = \"{address}\"\nname = \"{name}\"\nfile = \"a.c\"\nresult = \"identical\"\nverdict = \"identical\"\n"
        ),
    )
    .unwrap();
}

#[test]
fn mz_identical_link() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    let original = original(&f);
    prepare_exe(&f, &original);
    let response = run(&f);
    let r = record(&f);
    assert_eq!(r.result, RebuildResult::Identical);
    assert_eq!(r.compiler.as_deref(), Some("turbo-c-2.0"));
    assert_eq!(r.original_bytes, original.len() as u64);
    assert_eq!(r.rebuilt_bytes, original.len() as u64);
    assert_eq!((r.differing, r.first_difference), (0, None));
    assert!(r.diagnosis.is_empty() && r.message.is_none() && r.date.is_some());
    assert_eq!(
        std::fs::read(f.root().join("cache/rebuild/REBUILD.EXE")).unwrap(),
        original
    );
    let text = std::fs::read_to_string(f.root().join(PROGRAM_FILE)).unwrap();
    assert!(text.starts_with("schema = 1\n"), "{text}");
    assert!(text.contains("[program]\nresult = \"identical\""), "{text}");
    // both sources linked, in name order, with the configured startup code, flags and libraries
    assert_eq!(
        f.log("link.log"),
        ["D:\\TLINK /c/x/i D:\\LIB\\C0S A Z,REBUILD,,D:\\LIB\\EMU D:\\LIB\\MATHS D:\\LIB\\CS"]
    );
    assert_eq!(response.data["result"], "identical");
    assert_eq!(response.data["first_difference"], Value::Null);
    assert_eq!(
        response.summary,
        format!("identical ({} bytes)", original.len())
    );
    // a second link takes the objects from the cache: only the link job runs
    run(&f);
    assert_eq!(f.log("calls.log").len(), 2, "{:?}", f.log("calls.log"));
    assert_eq!(f.log("link.log").len(), 2);
    assert_eq!(record(&f).result, RebuildResult::Identical);
}

#[test]
fn mz_header_difference_is_named() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    let mut rebuilt = original(&f);
    rebuilt[16] = 0x00; // SP 0x100 -> 0x200
    rebuilt[17] = 0x02;
    prepare_exe(&f, &rebuilt);
    let response = run(&f);
    let r = record(&f);
    assert_eq!(r.result, RebuildResult::Differs);
    assert_eq!((r.differing, r.first_difference), (1, Some(17)));
    assert_eq!(
        r.diagnosis,
        [
            "header: SP: original 0x100, rebuilt 0x200",
            "load image equal, only the header or the bytes behind it differ",
        ]
    );
    assert_eq!(diagnosis(&response), r.diagnosis);
    assert_eq!(response.data["first_difference"], "0x11");
    assert_eq!(
        response.summary,
        "differs: 1 bytes, first at file offset 0x11"
    );
}

#[test]
fn missing_i_switch_hint() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    // the original keeps the zeroed data in the file and needs no extra memory; the rebuild leaves it out
    let mut image = vec![0x90u8; 0x100];
    image[0xC0..].fill(0);
    let original = mz(&image, 0);
    std::fs::write(f.root().join("t.exe"), &original).unwrap();
    prepare_exe(&f, &mz(&image[..0xC0], 4));
    let response = run(&f);
    let lines = diagnosis(&response);
    assert_eq!(
        lines,
        [
            "header: bytes on the last page: original 0x120, rebuilt 0xe0",
            "header: minalloc: original 0x0, rebuilt 0x4",
            "the original holds the uninitialized data in the file (minalloc 0, rebuilt shorter): TLINK switch /i",
            "load image: rebuilt -64 bytes against the original",
            "first difference at image offset 0xc0",
        ]
    );
    let r = record(&f);
    assert_eq!(r.differing, 3 + 0x40, "three header bytes and the length");
}

#[test]
fn shift_is_detected() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    // two bytes more before `add`: everything from 0x10 on lies 2 bytes later
    let original = original(&f);
    let mut image = original[32..].to_vec();
    image.splice(0x0E..0x0E, [0x90, 0x90]);
    prepare_exe(&f, &mz(&image, 0));
    let response = run(&f);
    let lines = diagnosis(&response);
    assert_eq!(
        &lines[1..],
        [
            "load image: rebuilt +2 bytes against the original",
            "first difference at image offset 0x10 (seg:0000:0010 in add): function missing in the rebuild or placed elsewhere",
            "the bytes from its start lie +2 bytes shifted in the rebuild: the cause is before it",
        ]
    );
    assert!(
        lines[0].starts_with("header: bytes on the last page"),
        "{lines:?}"
    );
}

#[test]
fn place_kind_rebuilt() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    seed_identical(&f, "sub", "seg:0000:0020");
    let mut rebuilt = original(&f);
    rebuilt[32 + 0x25] ^= 0xFF;
    prepare_exe(&f, &rebuilt);
    let response = run(&f);
    assert_eq!(
        diagnosis(&response),
        [
            "first difference at image offset 0x25 (seg:0000:0025 in sub): rebuilt function, the diagnose tool shows the difference"
        ]
    );
}

#[test]
fn shares_by_priority() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    // add: identical from C; zed: named by signature; a function over the gap behind add with pusha (assembly)
    // overlapping the end of add and the start of sub
    seed_identical(&f, "add", "seg:0000:0010");
    let symbols = f.root().join("knowledge/symbols.toml");
    let text = std::fs::read_to_string(&symbols).unwrap().replacen(
        "name = \"zed\"\nsource = \"human\"",
        "name = \"zed\"\nsource = \"signature\"",
        1,
    );
    std::fs::write(&symbols, text).unwrap();
    f.patch_original(0x1B, &[0x60, 0x61, 0x90, 0x90, 0xC3]);
    let seg = |off: u16| decovery_core::Address::Seg { seg: 0, off };
    {
        let ws = Workspace::open(f.root()).unwrap();
        let lock = ws.lock(Duration::from_secs(5)).unwrap();
        let mut analysis = Analysis::load(f.root()).unwrap().unwrap();
        analysis
            .functions
            .push(AnalyzedFunction::new(seg(0x18), seg(0x22), 11));
        analysis.save(f.root(), &lock).unwrap();
    }
    prepare_exe(&f, &original(&f));
    let response = run(&f);
    let shares = record(&f).shares.expect("shares");
    assert_eq!(
        (
            shares.c,
            shares.library,
            shares.assembly,
            shares.other_functions,
            shares.rest
        ),
        (11, 5, 8, 8, 0x100 - 32)
    );
    assert_eq!(response.data["shares"]["assembly"], 8);
}

#[test]
fn link_error_is_recorded() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    // no REBUILD.EXE: the linker fails
    let response = run(&f);
    let r = record(&f);
    assert_eq!(r.result, RebuildResult::Error);
    let message = r.message.clone().unwrap();
    assert!(message.starts_with("linker exit code 2"), "{message}");
    assert!(message.contains("Undefined symbol _main"), "{message}");
    assert_eq!(r.original_bytes, original(&f).len() as u64);
    assert_eq!(r.rebuilt_bytes, 0);
    assert!(r.shares.is_some());
    assert!(!f.root().join("cache/rebuild/REBUILD.EXE").exists());
    assert_eq!(response.data["result"], "error");
    assert!(
        response.summary.starts_with("error: linker exit code 2"),
        "{}",
        response.summary
    );

    // a source that does not compile: nothing is linked
    std::fs::remove_file(f.objects.path().join("Z.OBJ")).unwrap();
    std::fs::write(
        f.root().join("src/z.c"),
        "void zed(void)\n{\n}\n/* changed */\n",
    )
    .unwrap();
    run(&f);
    let r = record(&f);
    assert_eq!(r.result, RebuildResult::Error);
    let message = r.message.unwrap();
    assert!(
        message.starts_with("z.c: compiler exit code 1"),
        "{message}"
    );
    assert_eq!(f.log("link.log").len(), 1);
}

#[test]
fn program_record_round_trip_keeps_unknown_keys() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    let path = f.root().join(PROGRAM_FILE);
    std::fs::write(
        &path,
        "schema = 1\n\n[program]\nresult = \"differs\"\ncompiler = \"turbo-c-2.0\"\noriginal_bytes = 10\n\
         rebuilt_bytes = 12\ndiffering = 3\nfirst_difference = \"0x4\"\nfuture_key = \"kept\"\n\n\
         [program.shares]\nc = 1\nlibrary = 2\nassembly = 3\nother_functions = 4\nrest = 5\n",
    )
    .unwrap();
    let r = record(&f);
    assert_eq!(r.first_difference, Some(4));
    assert_eq!(r.extra["future_key"].as_str(), Some("kept"));
    assert_eq!(r.shares.as_ref().unwrap().other_functions, 4);
    let ws = Workspace::open(f.root()).unwrap();
    {
        let lock = ws.lock(Duration::from_secs(5)).unwrap();
        save_program_record(f.root(), &r, &lock).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("future_key = \"kept\""), "{first}");
        assert!(first.contains("first_difference = 4"), "{first}");
        assert!(!first.contains('\r'));
        assert_eq!(record(&f), r);
        save_program_record(f.root(), &record(&f), &lock).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        let mut unknown = r.clone();
        unknown.result = RebuildResult::Other;
        assert!(save_program_record(f.root(), &unknown, &lock).is_err());
    }
    // a new link rewrites the record and keeps the unknown key
    prepare_exe(&f, &original(&f));
    run(&f);
    let r = record(&f);
    assert_eq!(r.result, RebuildResult::Identical);
    assert_eq!(r.extra["future_key"].as_str(), Some("kept"));
}
