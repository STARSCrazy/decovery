//! Long operations as persistent jobs (design 5.13, ADR 0010): what a job runs ([`JobOperation`]), how it runs
//! under its lease with its record kept up to date ([`run_as_job`]), and the background runner of the MCP server
//! ([`JobRunner`]).
//!
//! A job's progress goes into `job.json` at most every 500 ms; its cancel flag is turned into the operation's
//! [`CancelToken`] by a watcher that looks every 200 ms. A finished job stores its full response as a handle
//! (`result`) next to the one-line `summary`. A cancel that comes too late (the operation was already recording)
//! lets the operation complete, and the job ends `done`.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use decovery_core::{
    JobLease, JobProgress, JobRecord, JobState, job_cancel_requested, job_create, job_lease,
    job_list, job_load, job_save, now_utc,
};
use decovery_plugin::{CancelToken, Progress};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::tools::{
    AnalyzeOptions, BuildRequest, LegacyCall, LegacyOperation, Variant, analyze, build,
    diagnose_deep, keep_legacy_plugin, link, search, verify,
};
use crate::{Budget, Control, FacadeError, Response, store_handle};

/// Default number of jobs the runner runs at once (`decovery mcp --max-jobs`): the bridge plugin's declared
/// `max_parallel`, so two bridge jobs never wait inside the plugin.
pub const DEFAULT_MAX_JOBS: usize = 2;
/// Shortest time between two progress writes of `job.json`.
const PROGRESS_EVERY: Duration = Duration::from_millis(500);
/// How often the cancel flag is looked at.
const CANCEL_POLL: Duration = Duration::from_millis(200);
/// The error of a job that lost its server twice.
const STOPPED_TWICE: &str = "the server stopped twice while the job ran";
/// Kind of the handle holding a job's full response.
const RESULT_HANDLE: &str = "job-result";

/// What a job runs: one long facade operation and its request.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum JobOperation {
    Build(BuildRequest),
    Link,
    Analyze(AnalyzeOptions),
    /// `diagnose` with `deep`.
    DiagnoseDeep(LegacyCall),
    Search(LegacyCall),
    Verify(LegacyCall),
}

/// Whether the MCP tool of `kind` runs in the background unless the caller says otherwise: `search` and `verify`
/// (minutes to hours; a client's tool timeout must not cut them).
pub fn background_by_default(kind: &str) -> bool {
    matches!(kind, "search" | "verify")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildSpec {
    #[serde(default)]
    files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    function: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    variants: Vec<VariantSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget: Option<usize>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    function_source: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptySpec {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyzeSpec {
    plugin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    functions: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySpec {
    target: String,
    operation: String,
    #[serde(default)]
    options: LegacyOptionsSpec,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    apply: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget: Option<usize>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyOptionsSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minutes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rounds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    all: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run: Option<String>,
}

fn spec_error(kind: &str, e: impl std::fmt::Display) -> FacadeError {
    FacadeError::Invalid(format!("not a {kind} job spec: {e}"))
}

impl JobOperation {
    /// The bridge call as the job of its tool: `diagnose-deep`, `search` or `verify`.
    pub fn legacy(call: LegacyCall) -> JobOperation {
        use LegacyOperation::*;
        match call.operation {
            Chain | Permute | Beam | Forms => JobOperation::Search(call),
            Equivalence | Behavior => JobOperation::Verify(call),
            _ => JobOperation::DiagnoseDeep(call),
        }
    }

    /// The job kind: `build`, `link`, `analyze`, `diagnose-deep`, `search`, `verify`.
    pub fn kind(&self) -> &'static str {
        match self {
            JobOperation::Build(_) => "build",
            JobOperation::Link => "link",
            JobOperation::Analyze(_) => "analyze",
            JobOperation::DiagnoseDeep(_) => "diagnose-deep",
            JobOperation::Search(_) => "search",
            JobOperation::Verify(_) => "verify",
        }
    }

    /// The request as JSON, enough to run it again ([`JobOperation::from_spec`]). A bridge call's `user_plugins`
    /// are not part of it: a job reads them from the user config again.
    pub fn spec(&self) -> Value {
        let value = match self {
            JobOperation::Build(r) => serde_json::to_value(BuildSpec {
                files: r.files.clone(),
                function: r.function.clone(),
                variants: r
                    .variants
                    .iter()
                    .map(|v| VariantSpec {
                        label: v.label.clone(),
                        source: v.source.clone(),
                        function_source: v.function_source.clone(),
                    })
                    .collect(),
                budget: r.budget,
            }),
            JobOperation::Link => serde_json::to_value(EmptySpec {}),
            JobOperation::Analyze(o) => serde_json::to_value(AnalyzeSpec {
                plugin: o.plugin.clone(),
                functions: o.functions.clone(),
            }),
            JobOperation::DiagnoseDeep(c) | JobOperation::Search(c) | JobOperation::Verify(c) => {
                serde_json::to_value(LegacySpec {
                    target: c.target.clone(),
                    operation: c.operation.id().to_string(),
                    options: LegacyOptionsSpec {
                        minutes: c.options.minutes,
                        rounds: c.options.rounds,
                        source: c.options.source.clone(),
                        all: c.options.all,
                        run: c.options.run.clone(),
                    },
                    apply: c.apply,
                    budget: Some(c.budget.chars),
                })
            }
        };
        // the spec structs hold strings, numbers and paths only
        value.unwrap_or(Value::Null)
    }

    /// The operation of a job of `kind` with `spec`; an unknown kind or a spec that is no request of it is
    /// refused.
    pub fn from_spec(kind: &str, spec: &Value) -> Result<JobOperation, FacadeError> {
        let parse = |e| spec_error(kind, e);
        match kind {
            "build" => {
                let s: BuildSpec = serde_json::from_value(spec.clone()).map_err(parse)?;
                let variants = s
                    .variants
                    .into_iter()
                    .map(|v| Variant {
                        label: v.label,
                        source: v.source,
                        function_source: v.function_source,
                    })
                    .collect();
                Ok(JobOperation::Build(BuildRequest {
                    files: s.files,
                    function: s.function,
                    variants,
                    budget: s.budget,
                    ..BuildRequest::default()
                }))
            }
            "link" => {
                let _: EmptySpec = serde_json::from_value(spec.clone()).map_err(parse)?;
                Ok(JobOperation::Link)
            }
            "analyze" => {
                let s: AnalyzeSpec = serde_json::from_value(spec.clone()).map_err(parse)?;
                Ok(JobOperation::Analyze(AnalyzeOptions {
                    plugin: s.plugin,
                    functions: s.functions,
                }))
            }
            "diagnose-deep" | "search" | "verify" => {
                let s: LegacySpec = serde_json::from_value(spec.clone()).map_err(parse)?;
                let operation = LegacyOperation::parse(&s.operation).ok_or_else(|| {
                    spec_error(kind, format!("unknown operation {:?}", s.operation))
                })?;
                let mut call = LegacyCall::new(s.target, operation);
                call.options.minutes = s.options.minutes;
                call.options.rounds = s.options.rounds;
                call.options.source = s.options.source;
                call.options.all = s.options.all;
                call.options.run = s.options.run;
                call.apply = s.apply;
                if let Some(chars) = s.budget {
                    call.budget = Budget { chars };
                }
                let op = JobOperation::legacy(call);
                if op.kind() == kind {
                    Ok(op)
                } else {
                    Err(spec_error(
                        kind,
                        format!("operation {} belongs to {}", s.operation, op.kind()),
                    ))
                }
            }
            other => Err(FacadeError::Invalid(format!(
                "unknown job kind {other:?} (expected build, link, analyze, diagnose-deep, search or verify)"
            ))),
        }
    }

    /// Runs the operation in the workspace at `root`.
    pub fn run(&self, root: &Path, control: &Control) -> Result<Response, FacadeError> {
        match self {
            JobOperation::Build(r) => build(root, r, control),
            JobOperation::Link => link(root, control),
            JobOperation::Analyze(o) => analyze(root, o, control),
            JobOperation::DiagnoseDeep(c) => diagnose_deep(root, c, control),
            JobOperation::Search(c) => search(root, c, control),
            JobOperation::Verify(c) => verify(root, c, control),
        }
    }
}

fn warn(what: &str, e: impl std::fmt::Display) {
    eprintln!("decovery: {what}: {e}");
}

/// Saves `job`; a job store that cannot be written does not stop the operation.
fn save(root: &Path, job: &JobRecord) {
    if let Err(e) = job_save(root, job) {
        warn(&format!("job {} was not saved", job.id), e);
    }
}

/// Runs `op` for the `running` job `job` (whose lease the caller holds): progress goes to `outer` and, throttled,
/// into `job.json`; the cancel flag cancels the operation; the final state, summary and result handle are saved.
fn run_tracked(
    root: &Path,
    job: JobRecord,
    op: &JobOperation,
    outer: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    let id = job.id.clone();
    let token = CancelToken::new();
    let finished = AtomicBool::new(false);
    let record = Mutex::new((job, None::<Instant>));
    let lock = || {
        record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    let progress = |p: Progress| {
        outer(p.clone());
        let mut guard = lock();
        let (job, last) = &mut *guard;
        job.progress = Some(JobProgress::new(p.done, p.total, p.message));
        if last.is_none_or(|t| t.elapsed() >= PROGRESS_EVERY) {
            save(root, job);
            *last = Some(Instant::now());
        }
    };
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !finished.load(Ordering::SeqCst) {
                if job_cancel_requested(root, &id) {
                    token.cancel();
                    return;
                }
                std::thread::sleep(CANCEL_POLL);
            }
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            op.run(root, &Control::new(&progress, token.clone()))
        }))
        .unwrap_or_else(|_| {
            Err(FacadeError::Invalid(format!(
                "the {} operation stopped unexpectedly",
                op.kind()
            )))
        });
        finished.store(true, Ordering::SeqCst);
        result
    });
    let mut job = lock().0.clone();
    job.finished = Some(now_utc());
    match &result {
        Ok(response) => {
            let stored = serde_json::to_string_pretty(response)
                .map_err(|e| FacadeError::Invalid(e.to_string()))
                .and_then(|text| store_handle(root, RESULT_HANDLE, &text));
            job.summary = Some(response.summary.clone());
            match stored {
                Ok(handle) => {
                    job.state = JobState::Done;
                    job.result = Some(handle.id);
                }
                Err(e) => {
                    job.state = JobState::Failed;
                    job.error = Some(format!("the result was not stored: {e}"));
                }
            }
        }
        Err(FacadeError::Cancelled) => {
            job.state = JobState::Cancelled;
            job.summary = Some("cancelled".into());
        }
        Err(e) => {
            job.state = JobState::Failed;
            job.error = Some(e.to_string());
        }
    }
    save(root, &job);
    result
}

/// Marks `job` running (its lease is held) and saves it.
fn start_running(root: &Path, job: &mut JobRecord) {
    job.state = JobState::Running;
    job.started = Some(now_utc());
    job.progress = None;
    save(root, job);
}

/// Runs `op` in this process as a registered job (the CLI's commands): a job record in state `running` under its
/// lease, so `status` and `job` of an MCP server see it and `job cancel` stops it; the call still waits for the
/// operation. Progress goes to `progress` too. When the job store cannot be written, the operation runs anyway.
pub fn run_as_job(
    root: &Path,
    op: &JobOperation,
    progress: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    let registered = job_create(root, op.kind(), op.spec()).and_then(|job| {
        let lease = job_lease(root, &job.id)?;
        Ok((job, lease))
    });
    match registered {
        Ok((mut job, Some(_lease))) => {
            start_running(root, &mut job);
            run_tracked(root, job, op, progress)
        }
        Ok((job, None)) => {
            warn(&format!("job {}", job.id), "its lease is taken");
            op.run(root, &Control::progress_only(progress))
        }
        Err(e) => {
            warn("the job was not registered", e);
            op.run(root, &Control::progress_only(progress))
        }
    }
}

struct Shared {
    root: PathBuf,
    queue: Mutex<VecDeque<String>>,
    ready: Condvar,
    stop: AtomicBool,
}

impl Shared {
    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<String>> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn push(&self, id: String) {
        self.queue().push_back(id);
        self.ready.notify_one();
    }
}

/// The background job runner of one MCP server process: worker threads that run queued jobs one at a time each.
/// Dropping it stops the workers once their current job ends.
pub struct JobRunner {
    shared: Arc<Shared>,
}

impl JobRunner {
    /// Resumes the jobs a stopped server left (see ADR 0010, point 4), then starts `max_jobs` workers (at least
    /// one). Bridge jobs run on the kept `decomp-legacy` plugin, so its Decomp server stays warm between jobs.
    pub fn start(root: PathBuf, max_jobs: usize) -> JobRunner {
        keep_legacy_plugin(true);
        let shared = Arc::new(Shared {
            root,
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        for id in resume(&shared.root) {
            shared.push(id);
        }
        for _ in 0..max_jobs.max(1) {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || work(&shared));
        }
        JobRunner { shared }
    }

    /// Queues a job of `kind` with `spec` and returns its record (state `queued`). An unknown kind or a spec that
    /// is no request of it is refused.
    pub fn submit(&self, kind: &str, spec: Value) -> Result<JobRecord, FacadeError> {
        JobOperation::from_spec(kind, &spec)?;
        let job = job_create(&self.shared.root, kind, spec)?;
        self.shared.push(job.id.clone());
        Ok(job)
    }
}

impl Drop for JobRunner {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.ready.notify_all();
    }
}

/// The ids to queue at start, oldest first: every `queued` job, and every `running` job whose lease is free (its
/// process stopped), re-run with `resumed + 1`, or ended `interrupted` when it was resumed before.
fn resume(root: &Path) -> Vec<String> {
    let jobs = match job_list(root) {
        Ok(jobs) => jobs,
        Err(e) => {
            warn("the job store was not read", e);
            return Vec::new();
        }
    };
    let mut queue = Vec::new();
    for mut job in jobs.into_iter().rev() {
        match job.state {
            JobState::Queued => queue.push(job.id),
            JobState::Running => {
                let _lease: JobLease = match job_lease(root, &job.id) {
                    Ok(Some(lease)) => lease,
                    // another process runs it
                    Ok(None) => continue,
                    Err(e) => {
                        warn(&format!("job {}", job.id), e);
                        continue;
                    }
                };
                if job.resumed >= 1 {
                    job.state = JobState::Interrupted;
                    job.error = Some(STOPPED_TWICE.into());
                    job.finished = Some(now_utc());
                    save(root, &job);
                } else {
                    job.resumed += 1;
                    job.state = JobState::Queued;
                    save(root, &job);
                    queue.push(job.id);
                }
            }
            _ => {}
        }
    }
    queue
}

fn work(shared: &Shared) {
    loop {
        let id = {
            let mut queue = shared.queue();
            loop {
                if shared.stop.load(Ordering::SeqCst) {
                    return;
                }
                if let Some(id) = queue.pop_front() {
                    break id;
                }
                queue = shared
                    .ready
                    .wait(queue)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        run_queued(&shared.root, &id);
    }
}

/// Runs the queued job `id` under its lease; a job another process holds, or one that has ended, is skipped.
fn run_queued(root: &Path, id: &str) {
    let _lease = match job_lease(root, id) {
        Ok(Some(lease)) => lease,
        Ok(None) => return,
        Err(e) => return warn(&format!("job {id}"), e),
    };
    let mut job = match job_load(root, id) {
        Ok(job) => job,
        Err(e) => return warn(&format!("job {id}"), e),
    };
    if job.state.is_final() {
        return;
    }
    if job_cancel_requested(root, id) {
        job.state = JobState::Cancelled;
        job.summary = Some("cancelled before it started".into());
        job.finished = Some(now_utc());
        return save(root, &job);
    }
    let op = match JobOperation::from_spec(&job.kind, &job.spec) {
        Ok(op) => op,
        Err(e) => {
            job.state = JobState::Failed;
            job.error = Some(e.to_string());
            job.finished = Some(now_utc());
            return save(root, &job);
        }
    };
    start_running(root, &mut job);
    // the outcome is in the job record
    let _ = run_tracked(root, job, &op, &|_| {});
}
