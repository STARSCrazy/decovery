//! `link` on the synthetic MZ workspace of the build tests: the fake runner serves the objects and, for the link
//! job, a prepared `REBUILD.EXE`. Skipped (with a message) without Python: set `DECOVERY_PYTHON` or put `python`
//! on PATH.

#[path = "support/build_fixture.rs"]
mod build_fixture;

use std::time::Duration;

use build_fixture::{Fixture, fixture};
use decovery_core::{
    Analysis, AnalyzedFunction, ClaimSource, Confidence, ProgramRecord, RebuildResult, SymbolKind,
    Workspace, read_program_record, save_program_record,
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
        [r"D:\TLINK /c/i/m D:\LIB\C0S A Z,REBUILD,,D:\LIB\EMU D:\LIB\MATHS D:\LIB\CS"]
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

/// A TLINK map of the fixture's program: `_TEXT` (code) up to 0x7F, `_DATA` from 0x80, and the publics `lines`
/// (by value).
fn prepare_map(f: &Fixture, lines: &[&str]) {
    let mut text = String::from(
        "\r\n Start  Stop   Length Name               Class\r\n\r\n \
         00000H 0007FH 00080H _TEXT              CODE\r\n \
         00080H 000FFH 00080H _DATA              DATA\r\n\r\n  \
         Address         Publics by Value\r\n\r\n",
    );
    for line in lines {
        text.push_str(&format!(" {line}\r\n"));
    }
    text.push_str("\r\nProgram entry point at 0000:0000\r\n");
    std::fs::write(f.objects.path().join("REBUILD.MAP"), text).unwrap();
}

fn symbols_text(f: &Fixture) -> String {
    std::fs::read_to_string(f.root().join("knowledge/symbols.toml")).unwrap()
}

fn hints(response: &Response) -> Vec<String> {
    response.data["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn identical_link_records_missing_publics_from_the_map() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    // zed is unknown to the knowledge base; add carries a key this version does not know
    let symbols = f.root().join("knowledge/symbols.toml");
    let text = symbols_text(&f)
        .replace(
            "[[symbol]]\naddress = \"seg:0000:0030\"\nkind = \"function\"\nname = \"zed\"\nsource = \"human\"\nconfidence = \"confirmed\"\n",
            "",
        )
        .replacen("confidence = \"confirmed\"\n", "confidence = \"confirmed\"\nfuture_key = \"kept\"\n", 1);
    std::fs::write(&symbols, text).unwrap();
    prepare_exe(&f, &original(&f));
    prepare_map(
        &f,
        &[
            "0000:0000  Abs  __turboCrt",
            "0000:0010       _add",
            "0000:0020       _sub",
            "0000:0030       _zed",
            "0000:0040       DGROUP@",
            "0008:0004       _counter",
            "0008:0010       __streams",
        ],
    );
    let response = run(&f);
    assert_eq!(response.data["result"], "identical");
    assert_eq!(response.data["symbols_added"], 4, "{:?}", hints(&response));
    assert!(hints(&response).is_empty(), "{:?}", hints(&response));
    // the map was asked for: `/x` is replaced by `/m`
    assert_eq!(
        f.log("link.log"),
        [r"D:\TLINK /c/i/m D:\LIB\C0S A Z,REBUILD,,D:\LIB\EMU D:\LIB\MATHS D:\LIB\CS"]
    );
    assert!(f.root().join("cache/rebuild/REBUILD.MAP").is_file());
    let ws = Workspace::open(f.root()).unwrap();
    let find = |name: &str| ws.symbols.iter().find(|s| s.name == name).cloned();
    let expected = [
        ("zed", "seg:0000:0030", SymbolKind::Function),
        ("DGROUP@", "seg:0000:0040", SymbolKind::Label),
        ("counter", "seg:0008:0004", SymbolKind::Global),
        ("_streams", "seg:0008:0010", SymbolKind::Global),
    ];
    for (name, address, kind) in expected {
        let s = find(name).unwrap_or_else(|| panic!("{name} missing"));
        assert_eq!(s.address.to_string(), address, "{name}");
        assert_eq!(s.kind, kind, "{name}");
        assert_eq!(s.source, ClaimSource::Link, "{name}");
        assert_eq!(s.confidence, Confidence::Confirmed, "{name}");
        assert!(
            s.evidence.as_deref().unwrap().contains("REBUILD.MAP line"),
            "{name}"
        );
    }
    // the known ones are untouched, the absolute symbol is not an address
    assert_eq!(ws.symbols.len(), 6);
    assert_eq!(find("add").unwrap().source, ClaimSource::Human);
    assert_eq!(
        find("add").unwrap().extra["future_key"].as_str(),
        Some("kept")
    );
    assert!(find("_turboCrt").is_none());
    let text = symbols_text(&f);
    assert!(text.starts_with("schema = 1\n"), "{text}");
    assert!(text.contains("source = \"link\""), "{text}");
    // a second identical link finds nothing new and leaves the file as it is
    let response = run(&f);
    assert_eq!(response.data["symbols_added"], 0);
    assert_eq!(symbols_text(&f), text);
}

#[test]
fn link_map_conflicts_are_hints_and_change_nothing() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    let before = symbols_text(&f);
    prepare_exe(&f, &original(&f));
    prepare_map(
        &f,
        &[
            // the knowledge base has add at 0010
            "0000:0040       _add",
            // and sub at 0020
            "0000:0020       _minus",
            // two names at one address
            "0008:0000       __osmajor",
            "0008:0000       __version",
        ],
    );
    let response = run(&f);
    assert_eq!(response.data["result"], "identical");
    assert_eq!(response.data["symbols_added"], 0);
    let hints = hints(&response);
    assert_eq!(hints.len(), 3, "{hints:?}");
    assert!(
        hints.iter().any(|h| h.contains(
            "add: the link map places it at seg:0000:0040, the knowledge base at seg:0000:0010"
        )),
        "{hints:?}"
    );
    assert!(
        hints.iter().any(|h| h.contains(
            "seg:0000:0020: the link map names it minus, the knowledge base holds sub there"
        )),
        "{hints:?}"
    );
    assert!(
        hints
            .iter()
            .any(|h| h.contains("__osmajor, __version share seg:0008:0000")),
        "{hints:?}"
    );
    assert_eq!(symbols_text(&f), before);
}

#[test]
fn differing_link_records_no_symbols() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    let before = symbols_text(&f);
    let mut exe = original(&f);
    let last = exe.len() - 1;
    exe[last] ^= 0xFF;
    prepare_exe(&f, &exe);
    prepare_map(&f, &["0008:0004       _counter"]);
    let response = run(&f);
    assert_eq!(response.data["result"], "differs");
    assert_eq!(response.data["symbols_added"], 0);
    assert_eq!(symbols_text(&f), before);
}

#[test]
fn malformed_link_map_is_a_hint() {
    let python = python_or_skip!();
    let f = linking_fixture(&python);
    let before = symbols_text(&f);
    prepare_exe(&f, &original(&f));
    prepare_map(&f, &["0008:0004       _counter", "0008:00ZZ       _broken"]);
    let response = run(&f);
    assert_eq!(response.data["result"], "identical");
    assert_eq!(response.data["symbols_added"], 0);
    let hints = hints(&response);
    assert_eq!(hints.len(), 1, "{hints:?}");
    assert!(
        hints[0].starts_with("REBUILD.MAP: line 10: not a SSSS:OOOO address"),
        "{hints:?}"
    );
    assert_eq!(symbols_text(&f), before);
}
