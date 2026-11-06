//! `diagnose`: why a rebuilt function differs from the original and what to try.

use decovery_diff::{
    CompareOptions, PairKind, classify_deviation, diagnose, instruction_pairs, pairs_text,
};
use decovery_objects::{functions, read_omf};
use decovery_toolchain::rebuild_profile;
use serde_json::{Value, json};

use super::build::{OBJECTS_DIR, is_public, original_len, symbol_sizes, toolchain};
use crate::{Budget, FacadeError, KnowledgeView, Response, Session, resolve, store_handle};

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
    // a rebuild record by name or address first, else the analyzed function the target resolves to
    let trimmed = target.trim();
    let by_record = session
        .rebuild
        .iter()
        .find(|r| r.name == trimmed || r.address.to_string() == trimmed);
    let start = match by_record {
        Some(r) => r.address,
        None => resolve(session, target)?.function,
    };
    let name = session.name_of(start).name;
    let record = by_record.or_else(|| session.rebuild.iter().find(|r| r.address == start));
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
    let object = read_omf(&bytes, &file.to_ascii_uppercase()).map_err(|e| {
        FacadeError::Invalid(format!(
            "cannot read the rebuilt object of {file}: {e}; run `decovery build {file}`"
        ))
    })?;
    let ws = &session.workspace;
    let (profile, _) = rebuild_profile(ws).map_err(toolchain)?;
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
    let pairs = instruction_pairs(
        &view,
        start,
        &program,
        &knowledge,
        &profile.decoration,
        &CompareOptions::new(profile.padding, length),
    );
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
