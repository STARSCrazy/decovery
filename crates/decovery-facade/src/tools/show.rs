//! `show`: the generated text of one function.

use std::collections::HashMap;
use std::time::Duration;

use std::path::Path;

use decovery_core::{Address, AddressRange, Analysis, DecompileInfo, LineRanges};

use serde_json::json;

use crate::exemplars::{EXEMPLARS_DISABLED, current_source, exemplars_enabled};
use crate::output::{
    STALE_ANALYSIS, analysis_stale, function_path, render_function, write_function,
};
use crate::{Budget, FacadeError, Response, Session, exemplar_index, resolve, store_handle};

const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Header and pseudo-C of the function `target` resolves to. Writes the function's file when it is missing;
/// text beyond `budget` is cut and the full text stored as a handle. The data also carries the three most
/// similar identical functions (`exemplars`, without their source; see `find similar`) and the function's
/// current definition in `src/` (`source`); neither goes into the generated file.
/// The decompiler's signature (when the analyzer sent one) is in `signature` and the summary.
pub fn show(session: &Session, target: &str, budget: Budget) -> Result<Response, FacadeError> {
    show_impl(session, target, budget, false)
}

/// `show` with the instruction address ranges of each pseudo-C line in front of it (`show --lines`); lines
/// without ranges are indented to the same column. Without line metadata the text is unchanged.
pub fn show_with_lines(
    session: &Session,
    target: &str,
    budget: Budget,
) -> Result<Response, FacadeError> {
    show_impl(session, target, budget, true)
}

fn show_impl(
    session: &Session,
    target: &str,
    budget: Budget,
    with_lines: bool,
) -> Result<Response, FacadeError> {
    let start = resolve(session, target)?.function;
    let root = &session.workspace.root;
    let fresh;
    let mut file = function_path(session, start);
    let session = if root.join(&file).exists() {
        session
    } else {
        // Under the lock the knowledge on disk is what counts: a rename saved since `session` was opened
        // must not be undone by writing the file under the old name.
        let lock = session.workspace.lock(LOCK_WAIT)?;
        fresh = Session::open(root)?;
        file = function_path(&fresh, start);
        if !root.join(&file).exists() {
            write_function(&fresh, start, &lock)?;
        }
        &fresh
    };
    let mut text = render_function(session, start)?;
    let info = DecompileInfo::load(root, start)?.unwrap_or_default();
    if with_lines && let Some(lines) = &info.lines {
        text = annotate_lines(&text, lines);
    }
    let signature = info.signature.as_ref().map(|s| s.text());
    let stale = analysis_stale(session)?;
    let name = session.name_of(start).name;
    let lines = text.lines().count();
    let mut summary = format!("{name} at {start}: {lines} lines");
    if let Some(signature) = &signature {
        summary.push_str(&format!("; signature: {signature}"));
    }
    // once per call, as a warning (not in the summary too)
    let mut warnings: Vec<String> = stale
        .then(|| STALE_ANALYSIS.to_string())
        .into_iter()
        .collect();
    let exemplars = if !exemplars_enabled(session) {
        warnings.push(EXEMPLARS_DISABLED.to_string());
        Vec::new()
    } else {
        match exemplar_index(session).and_then(|ix| ix.similar(session, start, 3)) {
            Ok(found) => found,
            Err(e) => {
                warnings.push(format!("no exemplars: {e}"));
                Vec::new()
            }
        }
    };
    if !exemplars.is_empty() {
        let list: Vec<String> = exemplars
            .iter()
            .map(|e| format!("{} ({:.2})", e.name, e.score))
            .collect();
        summary.push_str(&format!("; exemplars: {}", list.join(", ")));
    }
    let exemplars: Vec<serde_json::Value> = exemplars
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "address": e.address.to_string(),
                "file": e.file,
                "similarity": e.similarity,
                "coverage": e.coverage,
                "twin": e.twin,
            })
        })
        .collect();
    let source = current_source(session, start);
    let mut handles = Vec::new();
    let shown = if text.chars().count() > budget.chars {
        let mut handle = store_handle(root, "function-text", &text)?;
        handle.description = format!("full text of {name} ({lines} lines)");
        let cut = truncate(&text, budget.chars, &handle.id);
        handles.push(handle);
        cut
    } else {
        text
    };
    // the current definition shares the budget with the pseudo-C; beyond it, it is a handle of its own
    let source = match source {
        None => serde_json::Value::Null,
        Some((file, text)) => {
            let left = budget.chars.saturating_sub(shown.chars().count());
            if text.chars().count() > left {
                let mut handle = store_handle(root, "source-text", &text)?;
                handle.description = format!("current definition of {name} in src/{file}");
                let id = handle.id.clone();
                handles.push(handle);
                json!({ "file": file, "text": null, "handle": id })
            } else {
                json!({ "file": file, "text": text })
            }
        }
    };
    let mut response = Response::new(
        summary,
        json!({
            "address": start.to_string(),
            "name": name,
            "file": file.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"),
            "analysis_stale": stale,
            "text": shown,
            "signature": signature,
            "exemplars": exemplars,
            "source": source,
        }),
    );
    if !warnings.is_empty() {
        response.data["warnings"] = json!(warnings);
    }
    response.handles = handles;
    Ok(response)
}

/// The pseudo-C line a mismatch at byte `offset` of the function at `start` belongs to: the line whose range
/// holds that address, else the nearest mapped instruction before it. `None` without line metadata (an older
/// analyzer) or when nothing before it is mapped; an unreadable store counts the same, this is only a hint.
pub fn c_line_near(root: &Path, start: Address, offset: u32) -> Option<(u32, String)> {
    let at = start.offset_by(i64::from(offset)).ok()?;
    let hit = DecompileInfo::load(root, start).ok()??.line_of(at)?;
    let body = Analysis::decompiled(root, start).ok()??;
    let index = usize::try_from(hit.line).ok()?.checked_sub(1)?;
    let text = body.lines().nth(index).unwrap_or("").trim().to_string();
    Some((hit.line, text))
}

/// `differs near C line N: <text>` for a mismatch at byte `offset` of the function at `start`.
pub fn differs_near(root: &Path, start: Address, offset: u32) -> Option<String> {
    c_line_near(root, start, offset)
        .map(|(line, text)| format!("differs near C line {line}: {text}"))
}

/// `start..end` of each range (the end without its kind prefix), comma-separated.
fn ranges_text(ranges: &[AddressRange]) -> String {
    ranges
        .iter()
        .map(|r| {
            let end = r.end.to_string();
            let end = end
                .split_once(':')
                .map_or(end.as_str(), |(_, rest)| rest)
                .to_string();
            format!("{}..{end}", r.start)
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Prefixes the body lines (after the header, numbered from 1 like the stored pseudo-C) with their ranges.
fn annotate_lines(text: &str, lines: &[LineRanges]) -> String {
    let by_line: HashMap<u32, String> = lines
        .iter()
        .filter(|l| !l.ranges.is_empty())
        .map(|l| (l.line, ranges_text(&l.ranges)))
        .collect();
    let width = by_line
        .values()
        .map(|t| t.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::with_capacity(text.len() * 2);
    let mut in_header = true;
    let mut number = 0u32;
    for line in text.split_inclusive('\n') {
        if in_header {
            out.push_str(line);
            if line.trim_end_matches(['\r', '\n']) == " */" {
                in_header = false;
            }
            continue;
        }
        number = number.saturating_add(1);
        let prefix = by_line.get(&number).map_or("", String::as_str);
        out.push_str(&format!("{prefix:<width$} | {line}"));
    }
    out
}

/// The header (through the line ` */`) plus the following whole lines that fit into `chars`, then the marker.
fn truncate(text: &str, chars: usize, id: &str) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    let mut in_header = true;
    for line in text.split_inclusive('\n') {
        let n = line.chars().count();
        if !in_header && used + n > chars {
            break;
        }
        out.push_str(line);
        used += n;
        if in_header && line.trim_end_matches(['\r', '\n']) == " */" {
            in_header = false;
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "/* \u{2026} truncated; full text: detail {id} */\n"
    ));
    out
}
