//! `job`: lists, polls and cancels the persistent jobs of the workspace (design 5.13, ADR 0010).

use std::path::Path;

use decovery_core::{
    JobRecord, JobState, WorkspaceError, job_lease, job_list, job_load, job_request_cancel,
    job_save, now_utc,
};
use serde_json::{Value, json};

use crate::{FacadeError, Response};

/// What `job` does.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JobAction {
    /// Every job, newest first.
    List,
    /// One job's state, progress, summary and result handle.
    Poll(String),
    /// Asks a job to stop.
    Cancel(String),
}

/// A job as tools show it: everything but its spec.
pub(crate) fn job_view(job: &JobRecord) -> Value {
    json!({
        "id": job.id,
        "kind": job.kind,
        "state": job.state.id(),
        "created": job.created,
        "started": job.started,
        "finished": job.finished,
        "resumed": job.resumed,
        "progress": job.progress.as_ref().map(|p| json!({
            "done": p.done,
            "total": p.total,
            "message": p.message,
        })),
        "summary": job.summary,
        "result": job.result,
        "error": job.error,
    })
}

/// One line about `job`.
fn describe(job: &JobRecord) -> String {
    let head = format!("job {} ({})", job.id, job.kind);
    match job.state {
        JobState::Done => match &job.result {
            Some(handle) => format!(
                "{head} done: {}; full result in handle {handle} (page it with detail)",
                job.summary.as_deref().unwrap_or("")
            ),
            None => format!("{head} done: {}", job.summary.as_deref().unwrap_or("")),
        },
        JobState::Running => match &job.progress {
            Some(p) => {
                let count = match p.total {
                    Some(total) => format!("{}/{total}", p.done),
                    None => p.done.to_string(),
                };
                match p.message.as_deref().filter(|m| !m.trim().is_empty()) {
                    Some(message) => format!("{head} running: {count} {message}"),
                    None => format!("{head} running: {count}"),
                }
            }
            None => format!("{head} running"),
        },
        JobState::Failed => format!("{head} failed: {}", job.error.as_deref().unwrap_or("")),
        JobState::Interrupted => {
            format!("{head} interrupted: {}", job.error.as_deref().unwrap_or(""))
        }
        state => format!("{head} {}", state.id()),
    }
}

fn load(root: &Path, id: &str) -> Result<JobRecord, FacadeError> {
    job_load(root, id).map_err(|e| match e {
        WorkspaceError::Io { ref source, .. }
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
            ) =>
        {
            FacadeError::Invalid(format!("no job {id}"))
        }
        other => other.into(),
    })
}

/// Runs `action` on the job store of the workspace at `root`.
pub fn job_tool(root: &Path, action: JobAction) -> Result<Response, FacadeError> {
    match action {
        JobAction::List => {
            let jobs = job_list(root)?;
            let count = |s: JobState| jobs.iter().filter(|j| j.state == s).count();
            let summary = if jobs.is_empty() {
                "no jobs".to_string()
            } else {
                format!(
                    "{} jobs ({} running, {} queued)",
                    jobs.len(),
                    count(JobState::Running),
                    count(JobState::Queued)
                )
            };
            let views: Vec<Value> = jobs.iter().map(job_view).collect();
            Ok(Response::new(summary, json!({ "jobs": views })))
        }
        JobAction::Poll(id) => {
            let job = load(root, &id)?;
            Ok(Response::new(
                describe(&job),
                json!({ "job": job_view(&job) }),
            ))
        }
        JobAction::Cancel(id) => {
            let job = load(root, &id)?;
            if job.state.is_final() {
                return Ok(Response::new(
                    format!("job {id} already {}", job.state.id()),
                    json!({ "job": job_view(&job) }),
                ));
            }
            job_request_cancel(root, &id)?;
            // a queued job nobody runs yet ends at once; a running one stops at its next cancellation point
            if job.state == JobState::Queued
                && let Some(_lease) = job_lease(root, &id)?
            {
                let mut job = load(root, &id)?;
                if job.state == JobState::Queued {
                    job.state = JobState::Cancelled;
                    job.summary = Some("cancelled before it started".into());
                    job.finished = Some(now_utc());
                    job_save(root, &job)?;
                    return Ok(Response::new(
                        format!("job {id} cancelled"),
                        json!({ "job": job_view(&job) }),
                    ));
                }
            }
            let job = load(root, &id)?;
            Ok(Response::new(
                format!("cancel requested for job {id}; it stops at its next cancellation point"),
                json!({ "job": job_view(&job) }),
            ))
        }
    }
}
