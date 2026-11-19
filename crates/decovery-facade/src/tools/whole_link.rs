//! Whole-program link in `build` (ADR 0018): after compiling, link the root program and its overlays with the
//! profile's linker through the runners and compare each linked file with the original as a whole file. Header
//! fields are named, the first difference is placed in its region (header field, image, code, data) and, where the
//! knowledge knows it, named by the function or global at that address.

use std::path::Path;

use decovery_core::{
    Address, Confidence, OverlayName, ProgramLinkConfig, RebuildConfig, Workspace,
    read_user_config, write_atomic,
};
use decovery_toolchain::{Profile, open_runners, run_whole_link};
use serde_json::{Value, json};

use super::build::{new_run_dir, runner_names, toolchain_or_cancelled};
use crate::{Control, FacadeError};

/// Where `build` keeps the linked files of the last whole-program link, relative to the workspace root.
pub const LINKED_DIR: &str = "cache/rebuild/link";

/// Names of the words of an MZ header (offsets 0 to 0x1B).
const MZ_FIELDS: [&str; 14] = [
    "signature",
    "last_page_bytes",
    "pages",
    "relocations",
    "header_paragraphs",
    "min_alloc",
    "max_alloc",
    "ss",
    "sp",
    "checksum",
    "ip",
    "cs",
    "relocation_offset",
    "overlay_number",
];

/// Names of the words of an Aztec C86 overlay header (14 bytes).
const OVERLAY_FIELDS: [&str; 7] = [
    "magic",
    "code_origin",
    "code_length",
    "data_origin",
    "data_length",
    "udata_length",
    "entry",
];

/// The kind of a linked file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileKind {
    Mz,
    Overlay,
}

/// The region of a file offset: a named header field, or a part of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Region {
    pub part: &'static str,
    pub field: Option<&'static str>,
}

fn word(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|w| u16::from_le_bytes([w[0], w[1]]))
}

fn fields(kind: FileKind) -> &'static [&'static str] {
    match kind {
        FileKind::Mz => &MZ_FIELDS,
        FileKind::Overlay => &OVERLAY_FIELDS,
    }
}

/// The region of `offset` in `file` (the original's layout).
pub(super) fn region(kind: FileKind, file: &[u8], offset: usize) -> Region {
    let names = fields(kind);
    if offset < names.len() * 2 {
        return Region {
            part: "header",
            field: Some(names[offset / 2]),
        };
    }
    let part = match kind {
        FileKind::Mz => {
            let header = word(file, 8).map_or(usize::MAX, |p| usize::from(p) * 16);
            let relocations = word(file, 6).map_or(0, usize::from);
            let table = word(file, 0x18).map_or(usize::MAX, usize::from);
            if offset >= table && offset < table.saturating_add(relocations * 4) {
                "relocation table"
            } else if offset < header {
                "header"
            } else {
                "image"
            }
        }
        FileKind::Overlay => {
            let code = word(file, 4).map_or(0, usize::from);
            if offset < 14 + code { "code" } else { "data" }
        }
    };
    Region { part, field: None }
}

/// The comparison of a linked file with the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileComparison {
    pub differing: u64,
    /// Header fields that differ: name, original, rebuilt (`None` past the end of a file).
    pub header: Vec<(&'static str, Option<u16>, Option<u16>)>,
    pub first: Option<usize>,
}

/// Byte-for-byte comparison of `rebuilt` with `original` (a length difference counts as differing bytes).
pub(super) fn compare_file(kind: FileKind, original: &[u8], rebuilt: &[u8]) -> FileComparison {
    let differing = original.iter().zip(rebuilt).filter(|(a, b)| a != b).count() as u64
        + original.len().abs_diff(rebuilt.len()) as u64;
    let first = (differing > 0).then(|| {
        original
            .iter()
            .zip(rebuilt)
            .position(|(a, b)| a != b)
            .unwrap_or(original.len().min(rebuilt.len()))
    });
    let header = fields(kind)
        .iter()
        .enumerate()
        .filter_map(|(i, &name)| {
            let (a, b) = (word(original, i * 2), word(rebuilt, i * 2));
            (a != b).then_some((name, a, b))
        })
        .collect();
    FileComparison {
        differing,
        header,
        first,
    }
}

/// The address of file `offset` through the configured segments of the root program (`overlay` `None`) or of an
/// overlay; the root falls back to the image offset after the MZ header.
pub(super) fn address_of(
    ws: &Workspace,
    overlay: Option<OverlayName>,
    file: &[u8],
    offset: usize,
) -> Option<Address> {
    let offset = offset as u64;
    for s in ws
        .config
        .target
        .segments
        .iter()
        .filter(|s| s.start.overlay() == overlay)
    {
        let Some(start) = s.file_offset else { continue };
        let len = s.file_length.unwrap_or(s.length);
        if offset < start || offset >= start + len {
            continue;
        }
        let delta = offset - start;
        return match s.start {
            Address::Seg { .. } => {
                let linear = s.start.linear()? + delta;
                s.start
                    .offset_by(delta as i64)
                    .ok()
                    .or_else(|| seg_of(linear))
            }
            at => at.offset_by(delta as i64).ok(),
        };
    }
    if overlay.is_some() {
        return None;
    }
    let header = u64::from(word(file, 8)?) * 16;
    offset.checked_sub(header).and_then(seg_of)
}

fn seg_of(linear: u64) -> Option<Address> {
    Some(Address::Seg {
        seg: u16::try_from(linear >> 4).ok()?,
        off: (linear & 0xF) as u16,
    })
}

/// The knowledge name at or before `at` in the same address space: `name` or `name+0x12`.
pub(super) fn name_near(ws: &Workspace, at: Address) -> Option<String> {
    let distance = |s: Address| -> Option<u64> {
        match (s, at) {
            (Address::Ovl { .. }, Address::Ovl { .. }) => at.bytes_from(s),
            (Address::Seg { .. }, Address::Seg { .. }) => at.bytes_from(s),
            _ => None,
        }
    };
    let (symbol, d) = ws
        .symbols
        .iter()
        .filter(|s| s.confidence != Confidence::Refuted && !s.name.is_empty())
        .filter_map(|s| distance(s.address).map(|d| (s, d)))
        .min_by_key(|(_, d)| *d)?;
    Some(if d == 0 {
        symbol.name.clone()
    } else {
        format!("{}+0x{d:X}", symbol.name)
    })
}

/// One linked file: its comparison or why there is none.
struct Outcome {
    file: String,
    overlay: Option<OverlayName>,
    line: Option<String>,
    message: Option<String>,
    json: Value,
    equal: bool,
}

/// What a whole-program link reports to `build`.
pub(super) struct LinkReport {
    pub summary: String,
    pub data: Value,
    pub hints: Vec<String>,
}

/// An input of a link: a build object (file name in the build directory) or a library object (DOS path).
enum Input {
    Object(String),
    Library(String),
}

/// Resolves the configured `entry` (a source file name or a `[rebuild] library_objects` name).
fn resolve(
    entry: &str,
    sources: &[(&str, Option<&[u8]>)],
    rebuild: &RebuildConfig,
    profile: &Profile,
    library_dir: &str,
) -> Result<Input, String> {
    if let Some((name, object)) = sources.iter().find(|(n, _)| n.eq_ignore_ascii_case(entry)) {
        return match object {
            Some(_) => {
                let stem = name.rsplit_once('.').map_or(*name, |(s, _)| s);
                Ok(Input::Object(format!(
                    "{}.{}",
                    stem.to_ascii_uppercase(),
                    profile.object_extension
                )))
            }
            None => Err(format!("{name} has no object (it did not compile)")),
        };
    }
    let library = rebuild.library_objects.iter().find(|l| {
        let file = l.rsplit(['/', '\\']).next().unwrap_or(l);
        file.eq_ignore_ascii_case(entry) || l.eq_ignore_ascii_case(entry)
    });
    match library {
        Some(l) if !l.contains(['/', '\\']) => Ok(Input::Library(format!(
            "{library_dir}\\{}",
            l.to_ascii_uppercase()
        ))),
        Some(l) => Err(format!(
            "{l}: a library object with a path cannot be linked yet; name a file in the toolchain's LIB directory"
        )),
        None => Err(format!(
            "{entry} is neither a source in src/ nor in [rebuild] library_objects"
        )),
    }
}

/// Links the root program and the overlays of `config` from the compiled `sources` (file name, object) and
/// compares them with the original files. A link that cannot run (missing object, linker error) is reported per
/// file, not as an error of the build; a runner that cannot run at all and a cancel are errors.
#[allow(clippy::too_many_arguments)]
pub(super) fn link_whole(
    ws: &Workspace,
    profile: &Profile,
    rebuild: &RebuildConfig,
    config: &ProgramLinkConfig,
    sources: &[(&str, Option<&[u8]>)],
    control: &Control,
    warnings: &mut Vec<String>,
) -> Result<LinkReport, FacadeError> {
    let Some(linker) = profile.linker.as_ref() else {
        return Err(FacadeError::Invalid(format!(
            "[link]: profile {} has no linker",
            profile.id
        )));
    };
    let root = ws.root.as_path();
    let run_dir = new_run_dir(root)?;
    let dir = run_dir.0.as_path();
    std::fs::create_dir_all(dir).map_err(|source| FacadeError::Output {
        path: dir.to_path_buf(),
        source,
    })?;
    for (name, object) in sources {
        if let Some(bytes) = object {
            let stem = name.rsplit_once('.').map_or(*name, |(s, _)| s);
            let path = dir.join(format!(
                "{}.{}",
                stem.to_ascii_uppercase(),
                profile.object_extension
            ));
            std::fs::write(&path, bytes).map_err(|source| FacadeError::Output { path, source })?;
        }
    }
    let libraries = config
        .libraries
        .clone()
        .unwrap_or_else(|| rebuild.libraries.clone());
    let root_output = config.output.clone().unwrap_or_else(|| {
        Path::new(&ws.config.target.file).file_name().map_or_else(
            || "PROGRAM.EXE".into(),
            |n| n.to_string_lossy().to_ascii_uppercase(),
        )
    });
    let root_stem = root_output
        .rsplit_once('.')
        .map_or(root_output.as_str(), |(s, _)| s)
        .to_string();
    let symbols = format!("{root_stem}.RSM");
    let mut root_flags = config.flags.clone().unwrap_or_default();
    if !config.overlays.is_empty() && !root_flags.split_whitespace().any(|w| w == "-r") {
        root_flags = format!("{root_flags} -r").trim().to_string();
    }

    let user = read_user_config()?;
    let (runners, more) = open_runners(&runner_names(ws, profile), ws, &user);
    warnings.extend(more);
    let progress = control.progress;
    let total = 1 + config.overlays.len() as u64;

    let mut link_one = |output: &str,
                        overlay: Option<OverlayName>,
                        entries: &[String],
                        extra_entries: &[String],
                        flags: &str,
                        original: Result<Vec<u8>, String>,
                        step: u64|
     -> Result<Outcome, FacadeError> {
        control.check()?;
        progress(decovery_plugin::Progress::new(
            step,
            Some(total),
            Some(format!("linking {output}")),
        ));
        let failed = |message: String, line: Option<String>| Outcome {
            file: output.to_string(),
            overlay,
            json: json!({
                "file": output,
                "result": "error",
                "message": message,
                "line": line,
            }),
            line,
            message: Some(message),
            equal: false,
        };
        let original = match original {
            Ok(o) => o,
            Err(e) => return Ok(failed(e, None)),
        };
        let mut objects = Vec::new();
        let mut extra = Vec::new();
        for (list, entries) in [(&mut objects, entries), (&mut extra, extra_entries)] {
            for entry in entries {
                match resolve(entry, sources, rebuild, profile, &linker.library_dir) {
                    Ok(Input::Object(o) | Input::Library(o)) => list.push(o),
                    Err(e) => return Ok(failed(e, None)),
                }
            }
        }
        if overlay.is_some() {
            extra.push(symbols.clone());
        }
        let line = profile
            .whole_link_line(flags, &objects, &extra, output, &libraries)
            .map_err(super::build::toolchain)?;
        if let Some((file, text)) = &line.control {
            let path = dir.join(file);
            std::fs::write(&path, text).map_err(|source| FacadeError::Output { path, source })?;
        }
        let also: Vec<String> = if overlay.is_none() && root_flags.contains("-r") {
            vec![symbols.clone()]
        } else {
            Vec::new()
        };
        let (linked, more) = run_whole_link(
            ws,
            profile,
            line.line.clone(),
            output.to_string(),
            &also,
            dir,
            &runners,
            Some(control.cancel.clone()),
            progress,
        )
        .map_err(toolchain_or_cancelled(control))?;
        warnings.extend(more);
        let Some(rebuilt) = linked.program else {
            return Ok(failed(linked.message, Some(line.line)));
        };
        let path = root.join(LINKED_DIR).join(output);
        if let Err(e) = write_atomic(&path, &rebuilt) {
            warnings.push(format!("linked {output} not kept: {e}"));
        }
        let kind = if overlay.is_some() {
            FileKind::Overlay
        } else {
            FileKind::Mz
        };
        let c = compare_file(kind, &original, &rebuilt);
        let first = c.first.map(|offset| {
            let r = region(kind, &original, offset);
            let address = address_of(ws, overlay, &original, offset);
            let name = address.and_then(|a| name_near(ws, a));
            json!({
                "offset": offset,
                "region": r.part,
                "field": r.field,
                "address": address.map(|a| a.to_string()),
                "name": name,
            })
        });
        let header: Vec<Value> = c
            .header
            .iter()
            .map(|(field, a, b)| json!({"field": field, "original": a, "rebuilt": b}))
            .collect();
        let equal = c.differing == 0;
        Ok(Outcome {
            file: output.to_string(),
            overlay,
            json: json!({
                "file": output,
                "result": if equal { "equal" } else { "differs" },
                "original_bytes": original.len(),
                "rebuilt_bytes": rebuilt.len(),
                "differing": c.differing,
                "header": header,
                "first_difference": first,
                "line": line.line,
            }),
            line: Some(line.line),
            message: None,
            equal,
        })
    };

    let original_root = std::fs::read(crate::program::target_path(ws))
        .map_err(|e| format!("cannot read the original {root_output}: {e}"));
    let root_outcome = link_one(
        &root_output,
        None,
        &config.objects,
        &[],
        &root_flags,
        original_root,
        0,
    )?;
    let root_linked = root_outcome.message.is_none();
    let mut overlays: Vec<Outcome> = Vec::new();
    for (i, o) in config.overlays.iter().enumerate() {
        let output = o
            .output
            .clone()
            .unwrap_or_else(|| format!("{}.OVR", o.name));
        let entries: Vec<String> = if !o.objects.is_empty() {
            o.objects.clone()
        } else if let Some(m) = rebuild.modules.iter().find(|m| m.overlay == o.name) {
            m.files.clone()
        } else {
            vec![format!("{}.c", o.name.as_str().to_ascii_lowercase())]
        };
        let flags = o
            .flags
            .clone()
            .or_else(|| config.overlay_flags.clone())
            .unwrap_or_default();
        let original = match ws.config.overlay(o.name) {
            None => Err(format!(
                "[[link.overlay]] {}: no [[overlay]] of that name",
                o.name
            )),
            Some(_) if !root_linked => Err(format!("not linked: {root_output} did not link")),
            Some(c) => crate::program::overlay_bytes(ws, c),
        };
        overlays.push(link_one(
            &output,
            Some(o.name),
            &entries,
            &config.overlay_objects,
            &flags,
            original,
            i as u64 + 1,
        )?);
    }
    drop(runners);
    drop(run_dir);

    let equal_overlays = overlays.iter().filter(|o| o.equal).count();
    let mut hints = Vec::new();
    for o in std::iter::once(&root_outcome).chain(&overlays) {
        if let Some(text) = describe(o) {
            hints.push(text);
        }
    }
    let root_word = match (&root_outcome.message, root_outcome.equal) {
        (Some(_), _) => "error",
        (None, true) => "equal",
        (None, false) => "differs",
    };
    let mut summary = format!("link: root {root_word}");
    if !overlays.is_empty() {
        summary.push_str(&format!(
            "; overlays {equal_overlays} of {} equal",
            overlays.len()
        ));
        let not: Vec<&str> = overlays
            .iter()
            .filter(|o| !o.equal)
            .map(|o| o.overlay.as_ref().map_or("", |n| n.as_str()))
            .take(5)
            .collect();
        if !not.is_empty() {
            summary.push_str(&format!(" (not equal: {})", not.join(", ")));
        }
    }
    let equal = root_outcome.equal && equal_overlays == overlays.len();
    let data = json!({
        "equal": equal,
        "root": root_outcome.json,
        "overlays": overlays.iter().map(|o| o.json.clone()).collect::<Vec<_>>(),
        "overlays_equal": equal_overlays,
        "overlays_total": overlays.len(),
    });
    Ok(LinkReport {
        summary,
        data,
        hints,
    })
}

/// The hint of a file that is not equal: why it did not link, or its first difference.
fn describe(o: &Outcome) -> Option<String> {
    if let Some(message) = &o.message {
        let first = message.lines().next().unwrap_or("");
        return Some(match &o.line {
            Some(line) => format!("link {}: {first} ({line})", o.file),
            None => format!("link {}: {first}", o.file),
        });
    }
    if o.equal {
        return None;
    }
    let j = &o.json;
    let f = &j["first_difference"];
    let mut place = format!("0x{:X}", f["offset"].as_u64().unwrap_or(0));
    match f["field"].as_str() {
        Some(field) => place.push_str(&format!(" (header field {field})")),
        None => place.push_str(&format!(" ({})", f["region"].as_str().unwrap_or(""))),
    }
    if let Some(at) = f["address"].as_str() {
        place.push_str(&format!(" at {at}"));
    }
    if let Some(name) = f["name"].as_str() {
        place.push_str(&format!(" in {name}"));
    }
    let mut text = format!(
        "link {}: {} bytes differ, first at {place}",
        o.file, j["differing"]
    );
    if j["original_bytes"] != j["rebuilt_bytes"] {
        text.push_str(&format!(
            "; {} bytes, original {}",
            j["rebuilt_bytes"], j["original_bytes"]
        ));
    }
    for h in j["header"].as_array().into_iter().flatten() {
        let hex = |v: &Value| v.as_u64().map_or("-".to_string(), |w| format!("0x{w:04X}"));
        text.push_str(&format!(
            "; {} {} (original {})",
            h["field"].as_str().unwrap_or(""),
            hex(&h["rebuilt"]),
            hex(&h["original"])
        ));
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay(code: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for w in [
            0xF2u16,
            0x5000,
            code.len() as u16,
            0x9000,
            data.len() as u16,
            0,
            0x5000,
        ] {
            out.extend(w.to_le_bytes());
        }
        out.extend(code);
        out.extend(data);
        out
    }

    #[test]
    fn overlay_regions_name_header_fields_code_and_data() {
        let o = overlay(&[1, 2, 3], &[4, 5]);
        assert_eq!(region(FileKind::Overlay, &o, 4).field, Some("code_length"));
        assert_eq!(region(FileKind::Overlay, &o, 13).field, Some("entry"));
        assert_eq!(region(FileKind::Overlay, &o, 14).part, "code");
        assert_eq!(region(FileKind::Overlay, &o, 16).part, "code");
        assert_eq!(region(FileKind::Overlay, &o, 17).part, "data");
    }

    #[test]
    fn mz_regions_name_header_fields_relocations_and_image() {
        let mut mz = vec![0u8; 64];
        mz[0..2].copy_from_slice(b"MZ");
        mz[6] = 2; // two relocations
        mz[8] = 2; // 32-byte header
        mz[0x18] = 0x1C;
        assert_eq!(region(FileKind::Mz, &mz, 0x10).field, Some("sp"));
        assert_eq!(region(FileKind::Mz, &mz, 0x0E).field, Some("ss"));
        assert_eq!(region(FileKind::Mz, &mz, 0x1C).part, "relocation table");
        assert_eq!(region(FileKind::Mz, &mz, 0x1F).part, "relocation table");
        assert_eq!(region(FileKind::Mz, &mz, 0x24).part, "image");
        // a broken header does not panic
        assert_eq!(region(FileKind::Mz, &[0x4D], 0x30).part, "header");
    }

    #[test]
    fn compare_names_differing_header_fields_and_the_first_difference() {
        let a = overlay(&[1, 2, 3], &[4, 5]);
        let mut b = overlay(&[1, 2, 3, 9], &[4, 5]);
        assert_eq!(compare_file(FileKind::Overlay, &a, &a).differing, 0);
        let c = compare_file(FileKind::Overlay, &a, &b);
        assert_eq!(c.header, vec![("code_length", Some(3), Some(4))]);
        assert_eq!(c.first, Some(4));
        b.truncate(3);
        let c = compare_file(FileKind::Overlay, &a, &b);
        assert_eq!(c.first, Some(3));
        assert!(
            c.header
                .iter()
                .any(|(f, _, b)| *f == "entry" && b.is_none())
        );
    }
}
