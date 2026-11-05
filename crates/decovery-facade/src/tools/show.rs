//! `show`: the generated text of one function.

use std::time::Duration;

use serde_json::json;

use crate::output::{
    STALE_ANALYSIS, analysis_stale, function_path, render_function, write_function,
};
use crate::{Budget, FacadeError, Response, Session, resolve, store_handle};

const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Header and pseudo-C of the function `target` resolves to. Writes the function's file when it is missing;
/// text beyond `budget` is cut and the full text stored as a handle.
pub fn show(session: &Session, target: &str, budget: Budget) -> Result<Response, FacadeError> {
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
    let text = render_function(session, start)?;
    let stale = analysis_stale(session)?;
    let name = session.name_of(start).name;
    let lines = text.lines().count();
    let mut summary = format!("{name} at {start}: {lines} lines");
    if stale {
        summary.push_str(&format!(" ({STALE_ANALYSIS})"));
    }
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
    let mut response = Response::new(
        summary,
        json!({
            "address": start.to_string(),
            "name": name,
            "file": file.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"),
            "analysis_stale": stale,
            "text": shown,
        }),
    );
    response.handles = handles;
    Ok(response)
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
