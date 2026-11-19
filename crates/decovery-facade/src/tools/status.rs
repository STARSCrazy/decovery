//! `status`: how far the naming and rebuilding of the analyzed functions is.

use decovery_core::{Address, Confidence, JobState, SymbolKind, job_list};
use serde_json::json;

use super::annotate::{data_segments, is_data_address};
use super::find::distinct_callers;
use super::job::job_view;
use crate::output::{STALE_ANALYSIS, analysis_stale, status_counts};
use crate::{FacadeError, Response, Session};

/// Counts over all functions, the analysis' origin, the queued and running jobs and the next thing to do (a
/// running job first).
pub fn status(session: &Session) -> Result<Response, FacadeError> {
    let c = status_counts(session);
    let stale = analysis_stale(session)?;
    let jobs: Vec<_> = job_list(&session.workspace.root)?
        .into_iter()
        .filter(|j| !j.state.is_final())
        .collect();
    let next_step = match jobs.iter().find(|j| j.state == JobState::Running) {
        Some(job) => format!(
            "job {} ({}) is running: decovery job poll {}",
            job.id, job.kind, job.id
        ),
        None => next_step(session),
    };
    let jobs: Vec<serde_json::Value> = jobs.iter().map(job_view).collect();
    let mut summary = format!(
        "{}/{} functions named ({} confirmed, {} assumed)",
        c.named, c.functions, c.confirmed, c.assumed
    );
    if stale {
        summary.push_str(&format!(" ({STALE_ANALYSIS})"));
    }
    let in_data = functions_in_data(session);
    if !in_data.is_empty() {
        let shown: Vec<&str> = in_data.iter().take(8).map(|(n, _)| n.as_str()).collect();
        summary.push_str(&format!(
            "; {} function symbols lie in data ({}{}): decovery annotate --kind global <target>",
            in_data.len(),
            shown.join(", "),
            if in_data.len() > shown.len() {
                ", ..."
            } else {
                ""
            }
        ));
    }
    let analysis = &session.analysis;
    Ok(Response::new(
        summary,
        json!({
            "functions": c.functions,
            "named": c.named,
            "confirmed": c.confirmed,
            "assumed": c.assumed,
            "unnamed": c.unnamed,
            "by_signature": c.by_signature,
            "analysis": {
                "provider": analysis.provider.name,
                "version": analysis.provider.version,
                "created": analysis.created,
                "stale": stale,
            },
            "rebuild": {
                "identical": c.rebuild_identical,
                "differs": c.rebuild_differs,
                "error": c.rebuild_error,
                "not_tried": c.rebuild_not_tried,
            },
            "jobs": jobs,
            "functions_in_data": in_data
                .iter()
                .map(|(name, at)| json!({"name": name, "address": at.to_string()}))
                .collect::<Vec<_>>(),
            "next_step": next_step,
        }),
    ))
}

/// Active knowledge records of kind `function` at a data address (see `annotate`): the name (or address) and
/// address, in address order. Recorded before `annotate` gave data addresses the kind `global`.
fn functions_in_data(session: &Session) -> Vec<(String, Address)> {
    let segments = data_segments(session);
    let mut found: Vec<(String, Address)> = session
        .workspace
        .symbols
        .iter()
        .filter(|s| {
            s.kind == SymbolKind::Function
                && s.confidence != Confidence::Refuted
                && is_data_address(session, s.address, &segments)
        })
        .map(|s| {
            let name = if s.name.is_empty() {
                s.address.to_string()
            } else {
                s.name.clone()
            };
            (name, s.address)
        })
        .collect();
    found.sort_by_key(|(_, at)| *at);
    found
}

/// The unnamed function with the most distinct callers (ties: lowest address), else the first function
/// without a rebuild record.
fn next_step(session: &Session) -> String {
    let index = session.analysis.index();
    let mut functions: Vec<Address> = session.analysis.functions.iter().map(|f| f.start).collect();
    functions.sort();
    if functions.is_empty() {
        return "no functions in the analysis".to_string();
    }
    let best = functions
        .iter()
        .filter(|a| session.symbol_at(**a).is_none())
        .map(|a| (*a, distinct_callers(&index, *a)))
        .fold(None::<(Address, usize)>, |best, cur| match best {
            Some(b) if b.1 >= cur.1 => Some(b),
            _ => Some(cur),
        });
    if let Some((at, callers)) = best {
        let name = session.name_of(at).name;
        return format!("name {name} ({callers} callers): decovery show {name}");
    }
    let tried: std::collections::HashSet<Address> =
        session.rebuild.iter().map(|r| r.address).collect();
    match functions.iter().find(|a| !tried.contains(a)) {
        Some(at) => {
            let name = session.name_of(*at).name;
            format!("rebuild {name}: decovery show {name}")
        }
        None => "every function is named and has a rebuild record".to_string(),
    }
}
