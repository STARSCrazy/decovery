//! `find similar` and `build` on overlay functions of a synthetic Aztec C86 overlay workspace.

#[path = "support/build_fixture.rs"]
mod build_fixture;
#[path = "support/overlay_fixture.rs"]
mod overlay_fixture;

use decovery_facade::{
    Budget, BuildRequest, Control, FindQuery, FindWhat, Response, Session, Variant, build, find,
};
use overlay_fixture::B_AT;

/// A buildable overlay workspace and the directory its fake runner serves objects from.
fn buildable(python: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let ws = tempfile::tempdir().unwrap();
    let objects = tempfile::tempdir().unwrap();
    overlay_fixture::write_buildable(ws.path(), python, objects.path());
    (ws, objects)
}

fn run(root: &std::path::Path, request: &BuildRequest) -> Response {
    build(root, request, &Control::progress_only(&|_| {})).unwrap()
}

fn function_variant(function: &str, source: &str) -> BuildRequest {
    let mut request = BuildRequest::default();
    request.function = Some(function.to_string());
    request.variants = vec![Variant::function(source)];
    request
}

#[test]
fn function_variant_of_an_overlay_function_reads_the_overlay() {
    let python = python_or_skip!();
    let (ws, objects) = buildable(&python);
    // the variant loads 1, as the original does
    std::fs::write(
        objects.path().join("F001.OBJ"),
        overlay_fixture::named_object("amain", &[0xB8, 1, 0, 0xC3]),
    )
    .unwrap();
    let source = "int amain()\n{\n    return 1;\n}\n";
    let response = run(ws.path(), &function_variant("amain", source));
    let v = &response.data["variants"][0];
    assert_eq!(v["verdict"], "identical", "{v}");
}

#[test]
fn find_similar_reads_overlay_functions() {
    let dir = tempfile::tempdir().unwrap();
    overlay_fixture::write(dir.path(), false);
    let session = Session::open(dir.path()).unwrap();
    let mut query = FindQuery::new(FindWhat::Similar);
    query.pattern = Some("A_ovmain".into());
    let response = find(&session, &query, Budget::default()).unwrap();
    let items = response.data["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{}", response.data);
    assert_eq!(items[0]["address"], B_AT);
}

/// An Aztec object with `amain_` = `call ext_; ret`, the call's field relocated against the external `ext_`.
fn calling_object() -> Vec<u8> {
    use decovery_objects::{AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget};
    decovery_objects::write_aztec(&AztecModuleSpec {
        name: "M".into(),
        code: vec![0xE8, 0, 0, 0xC3],
        named: vec![
            AztecSymbolSpec {
                name: "amain_".into(),
                section: AztecSection::Code,
                value: 0,
                public: true,
            },
            AztecSymbolSpec {
                name: "ext_".into(),
                section: AztecSection::Extern,
                value: 0,
                public: true,
            },
        ],
        refs: vec![AztecRefSpec {
            section: AztecSection::Code,
            offset: 1,
            width: 2,
            relative: true,
            target: AztecTarget::Named(1),
            addend: 0,
        }],
        ..AztecModuleSpec::default()
    })
}

#[test]
fn function_variant_with_an_external_call_is_judged_like_the_build() {
    let python = python_or_skip!();
    let (ws, objects) = buildable(&python);
    // the original calls some routine of the main program
    std::fs::write(
        ws.path().join("A.OVR"),
        overlay_fixture::overlay_file(&[0xE8, 0x34, 0x12, 0xC3]),
    )
    .unwrap();
    std::fs::write(objects.path().join("A.OBJ"), calling_object()).unwrap();
    std::fs::write(objects.path().join("F001.OBJ"), calling_object()).unwrap();
    let mut request = BuildRequest::default();
    request.files = vec!["a.c".into()];
    let full = run(ws.path(), &request);
    assert_eq!(full.data["functions"][0]["verdict"], "identical", "{}", full.data);
    let source = "int amain()\n{\n    ext();\n}\n";
    let response = run(ws.path(), &function_variant("amain", source));
    let v = &response.data["variants"][0];
    assert_eq!(v["verdict"], "identical", "{v}");
}

#[test]
fn function_source_for_a_function_not_in_the_file_says_what_is_expected() {
    let python = python_or_skip!();
    let (ws, _objects) = buildable(&python);
    std::fs::write(ws.path().join("src/a.c"), "int other()\n{\n    return 0;\n}\n").unwrap();
    let source = "int amain()\n{\n    return 1;\n}\n";
    let mut request = function_variant("amain", source);
    request.files = vec!["a.c".into()];
    let response = run(ws.path(), &request);
    let message = response.data["variants"][0]["message"].as_str().unwrap();
    assert!(
        message.contains("a.c: the file does not define amain yet")
            && message.contains("must be in it already"),
        "{message}"
    );
}

#[test]
fn comparison_of_a_differing_function_lists_its_differing_region() {
    let python = python_or_skip!();
    let (ws, _objects) = buildable(&python);
    let mut request = BuildRequest::default();
    request.files = vec!["a.c".into()];
    let response = run(ws.path(), &request);
    assert_eq!(response.data["functions"][0]["verdict"], "differs");
    let listed = decovery_facade::history(ws.path(), "amain", 5, Budget::default()).unwrap();
    let id = listed.data["attempts"][0]["archive"]
        .as_str()
        .unwrap_or_else(|| panic!("{}", listed.data))
        .to_string();
    let archive = decovery_facade::history_archive(ws.path(), "amain", &id, Budget::default()).unwrap();
    let text = archive.data["comparison"].as_str().unwrap();
    assert!(text.contains("rebuild against original"), "{text}");
    let differing = text
        .lines()
        .find(|l| l.starts_with('≠'))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(
        differing.contains("mov ax,5") && differing.contains("mov ax,1"),
        "{text}"
    );
}

/// An overlay file with the module's code at 5000, then the entry (`ret`), and data at 9000.
fn overlay_with_data(code: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let entry = 0x5000 + code.len() as u16;
    let size = code.len() as u16 + 1;
    for w in [0xF2u16, 0x5000, size, 0x9000, data.len() as u16, 0, entry] {
        out.extend(w.to_le_bytes());
    }
    out.extend(code);
    out.push(0xC3);
    out.extend(data);
    out
}

/// `amain_` = `mov ax, [field]; ret`, the field relocated against the data position `field` (the data is 4
/// bytes; the field holds 0, as the assembler leaves it).
fn loading_object(field: u16) -> Vec<u8> {
    use decovery_objects::{AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget};
    decovery_objects::write_aztec(&AztecModuleSpec {
        name: "M".into(),
        code: vec![0xA1, 0, 0, 0xC3],
        data: vec![0; 4],
        named: vec![AztecSymbolSpec {
            name: "amain_".into(),
            section: AztecSection::Code,
            value: 0,
            public: true,
        }],
        refs: vec![AztecRefSpec {
            section: AztecSection::Code,
            offset: 1,
            width: 2,
            relative: false,
            target: AztecTarget::Section(AztecSection::Data, field),
            addend: 0,
        }],
        ..AztecModuleSpec::default()
    })
}

#[test]
fn wrong_relocated_field_found_by_the_module_makes_the_function_differ() {
    let python = python_or_skip!();
    let (ws, objects) = buildable(&python);
    // the original loads the field at x + 4 (9004)
    std::fs::write(
        ws.path().join("A.OVR"),
        overlay_with_data(&[0xA1, 0x04, 0x90, 0xC3], &[0; 8]),
    )
    .unwrap();
    let mut request = BuildRequest::default();
    request.files = vec!["a.c".into()];

    std::fs::write(objects.path().join("A.OBJ"), loading_object(4)).unwrap();
    let right = run(ws.path(), &request);
    assert_eq!(right.data["functions"][0]["verdict"], "identical", "{}", right.data);

    // the rebuild loads x + 0: the function's bytes outside the field are equal, the module finds the field
    std::fs::write(objects.path().join("A.OBJ"), loading_object(0)).unwrap();
    std::fs::write(ws.path().join("src/a.c"), "int amain()\n{\n    return 6;\n}\n").unwrap();
    let wrong = run(ws.path(), &request);
    let f = &wrong.data["functions"][0];
    assert_eq!(f["verdict"], "differs", "{}", wrong.data);
    assert_eq!(f["blockers"][0]["kind"], "wrong-absolute-ref", "{f}");
    assert_eq!(f["blockers"][0]["at"], 1, "{f}");
}

#[test]
fn build_does_not_warn_about_a_stale_analysis() {
    let python = python_or_skip!();
    // the buildable workspace renames functions after its analysis: the analysis is stale
    let (ws, _objects) = buildable(&python);
    let session = Session::open(ws.path()).unwrap();
    assert!(decovery_facade::output::analysis_stale(&session).unwrap());
    let mut request = BuildRequest::default();
    request.files = vec!["a.c".into()];
    let response = run(ws.path(), &request);
    let text = format!("{} {}", response.summary, response.data);
    assert!(!text.contains("older than the knowledge"), "{text}");
}
