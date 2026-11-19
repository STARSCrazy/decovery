//! `diagnose`: why a rebuilt function differs from the original and what to try.

use decovery_core::Address;
use decovery_core::Program;
use decovery_diff::{
    CompareOptions, Pair, PairKind, SymbolView, classify_deviation, diagnose, instruction_pairs,
    pairs_text,
};
use decovery_objects::{FunctionView, ObjectFormat, ObjectModule, functions, read_object};
use decovery_toolchain::{Profile, rebuild_profile};
use serde_json::{Value, json};

use super::build::{OBJECTS_DIR, is_public, original_len, symbol_sizes, toolchain};

use crate::{
    Budget, FacadeError, KnowledgeView, Response, Session, function_by_name, resolve, store_handle,
};

fn no_object(name: &str, file: Option<&str>) -> FacadeError {
    FacadeError::Invalid(format!(
        "no rebuilt object for {name}; run `decovery build {}`",
        file.unwrap_or("<file>")
    ))
}

/// Diagnoses the rebuilt function `target` names (a rebuild record's name or address, else what [`resolve`]
/// resolves it to): reads its object from `cache/rebuild/obj/<stem>.obj` (the
/// file of its rebuild record), aligns its instructions with the original as the comparison does, and reports the
/// findings of the generic rules, the kind of deviation (only stack slots or registers) and the pairs side by side.
/// Pairs text beyond `budget` is cut and the full text stored as a handle.
pub fn diagnose_tool(
    session: &Session,
    target: &str,
    budget: Budget,
) -> Result<Response, FacadeError> {
    let start = function_start(session, target)?;
    let name = session.name_of(start).name;
    let record = session.rebuild.iter().find(|r| r.address == start);
    let file = record.and_then(|r| r.file.as_deref());
    let (Some(record), Some(file)) = (record, file) else {
        return Err(no_object(&name, file));
    };
    let root = &session.workspace.root;
    let stem = file
        .rsplit_once('.')
        .map_or(file, |(s, _)| s)
        .to_ascii_lowercase();
    let bytes = std::fs::read(root.join(OBJECTS_DIR).join(format!("{stem}.obj")))
        .map_err(|_| no_object(&name, Some(file)))?;
    let ws = &session.workspace;
    let (profile, _) = rebuild_profile(ws).map_err(toolchain)?;
    let object =
        read_object(profile.object_format, &bytes, &file.to_ascii_uppercase()).map_err(|e| {
            FacadeError::Invalid(format!(
                "cannot read the rebuilt object of {file}: {e}; run `decovery build {file}`"
            ))
        })?;
    let view = object
        .modules
        .iter()
        .flat_map(functions)
        .filter(is_public)
        .find(|f| f.name == record.name || profile.decoration.undecorate(f.name) == record.name)
        .ok_or_else(|| {
            FacadeError::Invalid(format!(
                "the rebuilt object of {file} does not define {}; run `decovery build {file}`",
                record.name
            ))
        })?;
    let bits = view
        .module
        .sections
        .get(view.section as usize)
        .map_or(0, |s| s.bits);
    let program = crate::program::load(ws)?;
    let knowledge = KnowledgeView::new(ws, Some(&session.analysis));
    let index = session.analysis.index();
    let length = original_len(Some(&index), &symbol_sizes(ws), start);
    let pairs = function_pairs(&view, start, &program, &knowledge, &profile, length);
    let findings = diagnose(&pairs, bits, &profile.family);
    let deviation = classify_deviation(&pairs);
    let text = pairs_text(&pairs);

    let differing = pairs.iter().filter(|p| p.kind.differs()).count();
    let mut summary = if !findings.is_empty() {
        let rules: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
        format!(
            "{name}: {} finding{} ({})",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            rules.join(", ")
        )
    } else if pairs.is_empty() {
        format!(
            "{name}: no instructions compared (the original bytes are not in the program, or the code is not 16- or 32-bit)"
        )
    } else if let Some(p) = pairs.iter().find(|p| p.kind.differs()) {
        let at = match (&p.rebuild, &p.original) {
            (Some(d), _) => format!("rebuild {:04X}", d.offset),
            (None, Some(d)) => format!("original {:04X}", d.offset),
            (None, None) => String::from("?"),
        };
        format!("{name}: no known cause, first difference at {at}")
    } else if pairs.iter().any(|p| p.kind == PairKind::Form) {
        format!("{name}: only jump widths differ")
    } else {
        format!("{name}: no differing instructions")
    };
    if let Some((kind, n)) = deviation {
        summary.push_str(&format!("; deviation: {} ({n} instructions)", kind.id()));
    }

    let mut handles = Vec::new();
    let shown = if text.chars().count() > budget.chars {
        let mut handle = store_handle(root, "diagnose-pairs", &text)?;
        handle.description = format!("instruction pairs of {name}, side by side");
        let cut = truncate(&text, budget.chars, &handle.id);
        summary.push_str(&format!("; all pairs: detail {}", handle.id));
        handles.push(handle);
        cut
    } else {
        text
    };
    let findings_json: Vec<Value> = findings
        .iter()
        .map(|f| json!({ "rule": f.rule, "text": f.text, "suggestion": f.suggestion }))
        .collect();
    let deviation_json = deviation.map_or(
        Value::Null,
        |(kind, n)| json!({ "kind": kind.id(), "instructions": n }),
    );
    let mut response = Response::new(
        summary,
        json!({
            "function": {
                "address": start.to_string(),
                "name": name,
                "file": file,
                "instructions_differing": differing,
            },
            "findings": findings_json,
            "deviation_kind": deviation_json,
            "pairs_text": shown,
        }),
    );
    response.handles = handles;
    Ok(response)
}

/// The instruction pairs of the rebuilt function `view` placed at `start` against the original, aligned as the
/// comparison does. Aztec C86 objects are compared with the image directly (no linker step, `build` uses link
/// gaps): the relocated fields of the function take the original's bytes, as in `compare_with_gaps`.
pub(super) fn function_pairs(
    view: &FunctionView,
    start: Address,
    program: &Program,
    knowledge: &KnowledgeView<'_>,
    profile: &Profile,
    length: Option<u32>,
) -> Vec<Pair> {
    let patched = (profile.object_format == ObjectFormat::Aztec)
        .then(|| with_original_fields(view, start, program, knowledge));
    let patched_view = patched.as_ref().and_then(|module| {
        functions(module)
            .into_iter()
            .find(|f| f.section == view.section && f.start == view.start)
    });
    instruction_pairs(
        patched_view.as_ref().unwrap_or(view),
        start,
        program,
        knowledge,
        &profile.decoration,
        &CompareOptions::new(profile.padding, length),
    )
}

/// A copy of the module of `f` whose relocated fields inside `f` hold the original's bytes at `start` and carry
/// no relocation any more: the fields are link gaps, the rest of the code is compared as it is. The symbols of
/// the section take the original's names at their placed addresses, so an unrelocated call to another function
/// of the module is judged by where it leads, not by the name the source still gives that function.
fn with_original_fields(
    f: &FunctionView,
    start: Address,
    program: &Program,
    symbols: &dyn SymbolView,
) -> ObjectModule {
    let mut module = f.module.clone();
    for s in module.symbols.iter_mut().filter(|s| s.section == f.section) {
        let placed = start.offset_by(i64::from(s.offset) - i64::from(f.start));
        if let Some(n) = placed
            .ok()
            .and_then(|a| symbols.name_at(a))
            .filter(|n| !n.is_default)
        {
            s.name = n.name;
        }
    }
    let original = program.read(start, f.len as usize).unwrap_or(&[]);
    if let Some(section) = module.sections.get_mut(f.section as usize) {
        let end = f.start.saturating_add(f.len);
        let (inside, outside): (Vec<_>, Vec<_>) = section
            .relocs
            .drain(..)
            .partition(|r| r.offset >= f.start && r.offset < end);
        for r in &inside {
            for q in r.offset..r.offset.saturating_add(u32::from(r.width)).min(end) {
                if let (Some(b), Some(&o)) = (
                    section.data.get_mut(q as usize),
                    original.get((q - f.start) as usize),
                ) {
                    *b = o;
                }
            }
        }
        section.relocs = outside;
    }
    module
}

/// The function `target` names: a rebuild record's address, else a name by [`function_by_name`] (the analyzed
/// function containing it when no record is at that address), else what [`resolve`] resolves it to.
pub(super) fn function_start(session: &Session, target: &str) -> Result<Address, FacadeError> {
    let trimmed = target.trim();
    if let Some(r) = session
        .rebuild
        .iter()
        .find(|r| r.address.to_string() == trimmed)
    {
        return Ok(r.address);
    }
    let by_name = function_by_name(
        &session.workspace,
        Some(&session.analysis),
        &session.rebuild,
        trimmed,
    )?;
    match by_name {
        Some(a) if session.rebuild.iter().any(|r| r.address == a) => Ok(a),
        Some(a) => Ok(session
            .analysis
            .index()
            .function_containing(a)
            .map_or(a, |f| f.start)),
        None => Ok(resolve(session, target)?.function),
    }
}

/// Lines of the side-by-side listing an attempt's `comparison.txt` keeps.
const LISTING_LINES: usize = 60;

/// The instruction pairs side by side as `diagnose` shows them (differing lines marked, long equal runs
/// collapsed, the counts at the end), cut after [`LISTING_LINES`] lines.
pub(super) fn listing(pairs: &[Pair]) -> String {
    let text = pairs_text(pairs);
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= LISTING_LINES {
        return text;
    }
    let mut out = lines[..LISTING_LINES].join("\n");
    out.push_str(&format!(
        "\n… {} more lines; the whole listing: decovery diagnose\n",
        lines.len() - LISTING_LINES
    ));
    out
}

/// The whole lines of `text` that fit into `chars`, then the marker.
fn truncate(text: &str, chars: usize, id: &str) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for line in text.split_inclusive('\n') {
        let n = line.chars().count();
        if used + n > chars {
            break;
        }
        out.push_str(line);
        used += n;
    }
    out.push_str(&format!("… truncated; full text: detail {id}\n"));
    out
}
