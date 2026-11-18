//! The persistent job store: one directory per long operation under `cache/jobs/` (ADR 0010).
//!
//! `cache/jobs/<id>/job.json` holds the [`JobRecord`] (written atomically), an empty `cancel` file asks the job to
//! stop, and `run.lock` is locked (an OS file lock, no pid checks) by the process that runs the job: a
//! [`JobLease`]. A job in state `running` whose lease nobody holds was lost with its process.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::analysis::now_utc;
use crate::store::write_atomic;
use crate::workspace::{SCHEMA, WorkspaceError};

/// Directory of the job store, relative to the workspace root.
pub const JOBS_DIR: &str = "cache/jobs";
const JOB_FILE: &str = "job.json";
const CANCEL_FILE: &str = "cancel";
const LEASE_FILE: &str = "run.lock";

/// Where a job is: `queued` → `running` → `done | failed | cancelled | interrupted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum JobState {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
    /// The process running it stopped twice; the job is not resumed again.
    Interrupted,
}

impl JobState {
    /// The id written to disk (`queued`, `running`, ...).
    pub fn id(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::Done => "done",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
            JobState::Interrupted => "interrupted",
        }
    }

    /// Whether the job has ended (`done`, `failed`, `cancelled`, `interrupted`).
    pub fn is_final(self) -> bool {
        !matches!(self, JobState::Queued | JobState::Running)
    }
}

/// How far a running job is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobProgress {
    pub done: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl JobProgress {
    pub fn new(done: u64, total: Option<u64>, message: Option<String>) -> Self {
        JobProgress {
            done,
            total,
            message,
        }
    }
}

/// One job: `cache/jobs/<id>/job.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobRecord {
    pub schema: u32,
    /// `j_` and 12 hex digits; ids sort by creation.
    pub id: String,
    /// The operation: `build`, `link`, `analyze`, `diagnose-deep`, `search`, `verify`.
    pub kind: String,
    /// The request of the operation as JSON; a resumed job runs again from it.
    pub spec: serde_json::Value,
    pub state: JobState,
    /// RFC 3339 UTC, to the second.
    pub created: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,
    /// How often the job was started again after its process stopped.
    #[serde(default)]
    pub resumed: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<JobProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// The handle id of the full response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The run lease of a job: an OS lock on `<dir>/run.lock`, released when dropped or when the process dies.
#[derive(Debug)]
pub struct JobLease {
    _file: File,
}

fn io_error(path: &Path, source: std::io::Error) -> WorkspaceError {
    WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Whether `id` is `j_` and 12 lowercase hex digits (so it never leaves the job store).
fn valid_id(id: &str) -> bool {
    id.len() == 14
        && id.starts_with("j_")
        && id[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn job_dir(root: &Path, id: &str) -> Result<PathBuf, WorkspaceError> {
    let dir = root.join(JOBS_DIR).join(id);
    if valid_id(id) {
        Ok(dir)
    } else {
        Err(io_error(
            &dir,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("not a job id: {id:?} (expected j_ and 12 hex digits)"),
            ),
        ))
    }
}

/// Creates the directory of a new job and returns its id: the creation time in milliseconds as 12 hex digits,
/// counted up while a directory of that id exists (another job created in the same millisecond).
fn new_job_dir(root: &Path) -> Result<String, WorkspaceError> {
    let jobs = root.join(JOBS_DIR);
    std::fs::create_dir_all(&jobs).map_err(|e| io_error(&jobs, e))?;
    let mut n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
        & 0xFFFF_FFFF_FFFF;
    loop {
        let id = format!("j_{n:012x}");
        let dir = jobs.join(&id);
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(id),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                n = (n + 1) & 0xFFFF_FFFF_FFFF;
            }
            Err(e) => return Err(io_error(&dir, e)),
        }
    }
}

fn new_record(id: String, kind: &str, spec: serde_json::Value) -> JobRecord {
    JobRecord {
        schema: SCHEMA,
        id,
        kind: kind.to_string(),
        spec,
        state: JobState::Queued,
        created: now_utc(),
        started: None,
        finished: None,
        resumed: 0,
        progress: None,
        summary: None,
        result: None,
        error: None,
        extra: serde_json::Map::new(),
    }
}

/// Creates a new job of `kind` in state `queued` (see [`new_job_dir`] for its id).
pub fn job_create(
    root: &Path,
    kind: &str,
    spec: serde_json::Value,
) -> Result<JobRecord, WorkspaceError> {
    let job = new_record(new_job_dir(root)?, kind, spec);
    job_save(root, &job)?;
    Ok(job)
}

/// Creates a new job of `kind` that the caller runs itself: the lease is taken before `job.json` is written (state
/// `running`), so no other process ever sees the job free to run. Until then the directory is no job
/// ([`job_list`] skips it).
pub fn job_create_leased(
    root: &Path,
    kind: &str,
    spec: serde_json::Value,
) -> Result<(JobRecord, JobLease), WorkspaceError> {
    let id = new_job_dir(root)?;
    let lease = job_lease(root, &id)?.ok_or_else(|| {
        io_error(
            &root.join(JOBS_DIR).join(&id).join(LEASE_FILE),
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("the lease of the new job {id} is taken"),
            ),
        )
    })?;
    let mut job = new_record(id, kind, spec);
    job.state = JobState::Running;
    job.started = Some(now_utc());
    job_save(root, &job)?;
    Ok((job, lease))
}

/// Writes `job.json` of `job` atomically.
pub fn job_save(root: &Path, job: &JobRecord) -> Result<(), WorkspaceError> {
    let path = job_dir(root, &job.id)?.join(JOB_FILE);
    let mut text = serde_json::to_string_pretty(job).map_err(|e| WorkspaceError::Json {
        path: path.clone(),
        source: Box::new(e),
    })?;
    text.push('\n');
    // `write_atomic` uses one fixed temporary name: saves from several threads (progress, final state) take turns.
    // Across processes only the lease holder saves.
    static SAVING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _turn = SAVING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    write_atomic(&path, text.as_bytes()).map_err(|e| io_error(&path, e))
}

/// Reads `job.json` of the job `id`.
pub fn job_load(root: &Path, id: &str) -> Result<JobRecord, WorkspaceError> {
    let path = job_dir(root, id)?.join(JOB_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| io_error(&path, e))?;
    let job: JobRecord = serde_json::from_str(&text).map_err(|e| WorkspaceError::Json {
        path: path.clone(),
        source: Box::new(e),
    })?;
    if job.schema != SCHEMA {
        return Err(WorkspaceError::Schema {
            path,
            found: job.schema,
        });
    }
    Ok(job)
}

/// Every job of the store, newest first. Directories that are no job (or not yet: `job.json` missing) are
/// skipped.
pub fn job_list(root: &Path) -> Result<Vec<JobRecord>, WorkspaceError> {
    let jobs = root.join(JOBS_DIR);
    let entries = match std::fs::read_dir(&jobs) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error(&jobs, e)),
    };
    let mut ids: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| io_error(&jobs, e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if valid_id(&name) && entry.path().join(JOB_FILE).is_file() {
            ids.push(name);
        }
    }
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids.iter().map(|id| job_load(root, id)).collect()
}

/// Asks the job `id` to stop: writes `<dir>/cancel`. The job must exist.
pub fn job_request_cancel(root: &Path, id: &str) -> Result<(), WorkspaceError> {
    let dir = job_dir(root, id)?;
    let job_file = dir.join(JOB_FILE);
    if !job_file.is_file() {
        return Err(io_error(
            &job_file,
            std::io::Error::new(std::io::ErrorKind::NotFound, format!("no job {id}")),
        ));
    }
    let path = dir.join(CANCEL_FILE);
    write_atomic(&path, b"").map_err(|e| io_error(&path, e))
}

/// Whether a cancel was requested for the job `id`.
pub fn job_cancel_requested(root: &Path, id: &str) -> bool {
    job_dir(root, id).is_ok_and(|dir| dir.join(CANCEL_FILE).is_file())
}

/// Takes the run lease of the job `id` without waiting; `None` when another holder (another process, or another
/// lease in this one) has it.
pub fn job_lease(root: &Path, id: &str) -> Result<Option<JobLease>, WorkspaceError> {
    let dir = job_dir(root, id)?;
    std::fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
    let path = dir.join(LEASE_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| io_error(&path, e))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(JobLease { _file: file })),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(io_error(&path, e)),
    }
}
