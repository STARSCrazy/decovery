//! `status`: how far the naming and rebuilding of the analyzed functions is.

use decovery_core::Address;
use serde_json::json;

use super::find::distinct_callers;
use crate::output::{STALE_ANALYSIS, analysis_stale, status_counts};
use crate::{FacadeError, Response, Session};

/// Counts over all functions, the analysis' origin and the next thing to do.
pub fn status(session: &Session) -> Result<Response, FacadeError> {
    let c = status_counts(session);
    let stale = analysis_stale(session)?;
    let next_step = next_step(session);
    let mut summary = format!(
        "{}/{} functions named ({} confirmed, {} assumed)",
        c.named, c.functions, c.confirmed, c.assumed
    );
    if stale {
        summary.push_str(&format!(" ({STALE_ANALYSIS})"));
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
            "next_step": next_step,
        }),
    ))
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
