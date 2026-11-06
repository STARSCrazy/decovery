//! Runners execute the original DOS compilers. A runner is either a plugin that speaks the `runner` capability
//! (`runner/run`, see `docs/plugin-protocol.md`: an emulator or DOSBox) or the built-in [`NativeRunner`] that runs
//! the programs as host processes.
//!
//! Drive `C:` is the build directory (writable), drive `D:` the tool directory (read-only). The host side,
//! common to all runners, rejects command lines over 126 characters, snapshots drive `C:` before the call and
//! reports as `produced` the expected files that are new or changed afterwards.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime};

use decovery_core::{PluginConfig, UserConfig, Workspace, plugin_config};
use decovery_plugin::{CallOptions, CancelToken, PluginError, PluginHost};
use serde::Deserialize;
use serde_json::{Value, json};

/// Capability name and version of the runner contract.
const CAPABILITY: &str = "runner";
const CAPABILITY_VERSION: u32 = 1;
/// Error code of a plugin that cannot run some job's program.
const RUNNER_UNSUPPORTED: i64 = -32020;
/// DOS command line limit.
const MAX_COMMAND_LEN: usize = 126;
/// Added to the plugin call timeout on top of the jobs' own timeouts.
const CALL_SLACK: Duration = Duration::from_secs(30);

/// A host directory visible to the DOS side as a drive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Mount {
    pub drive: char,
    pub path: PathBuf,
    pub writable: bool,
}

impl Mount {
    pub fn new(drive: char, path: impl Into<PathBuf>, writable: bool) -> Self {
        Mount {
            drive: drive.to_ascii_uppercase(),
            path: path.into(),
            writable,
        }
    }
}

/// Command lines run one after another in one DOS session. `SET NAME=value` lines set the environment for the
/// following lines of the same job.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunJob {
    pub commands: Vec<String>,
    /// File names on drive `C:` the job must produce.
    pub expected: Vec<String>,
}

impl RunJob {
    pub fn new(commands: Vec<String>, expected: Vec<String>) -> Self {
        RunJob { commands, expected }
    }
}

/// What to run; `timeout` applies to each job.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunRequest {
    pub mounts: Vec<Mount>,
    pub jobs: Vec<RunJob>,
    pub timeout: Duration,
}

impl RunRequest {
    pub fn new(mounts: Vec<Mount>, jobs: Vec<RunJob>, timeout: Duration) -> Self {
        RunRequest {
            mounts,
            jobs,
            timeout,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum JobStatus {
    Done,
    Timeout,
    Failed,
}

/// Result of one job.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JobOutcome {
    pub status: JobStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    /// The expected files that are new or changed after the job.
    pub produced: Vec<String>,
    pub message: Option<String>,
    /// Name of the runner that ran the job.
    pub runner: String,
    expected: Vec<String>,
}

impl JobOutcome {
    /// A finished job (exit code 0) that produced all of `expected`, for tests of callers.
    #[cfg(test)]
    pub(crate) fn done_for_test(expected: Vec<String>) -> Self {
        JobOutcome {
            status: JobStatus::Done,
            exit_code: Some(0),
            stdout: String::new(),
            produced: expected.clone(),
            message: None,
            runner: "test".into(),
            expected,
        }
    }

    /// `Done`, exit code 0 and every expected file produced.
    pub fn succeeded(&self) -> bool {
        self.status == JobStatus::Done
            && self.exit_code == Some(0)
            && self
                .expected
                .iter()
                .all(|e| self.produced.iter().any(|p| p.eq_ignore_ascii_case(e)))
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RunnerError {
    /// The runner cannot run a program of the request; the next runner may.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The runner is not configured or does not start; the next runner may run.
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("{0}")]
    Failed(String),
}

pub trait Runner: Send + Sync {
    fn name(&self) -> &str;

    /// Runs every job; the outcomes are in job order.
    fn run(
        &self,
        request: &RunRequest,
        cancel: Option<CancelToken>,
    ) -> Result<Vec<JobOutcome>, RunnerError>;
}

/// What a runner reports per job, before the host adds `produced`.
#[derive(Debug, Deserialize)]
struct RawJob {
    status: JobStatus,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    message: Option<String>,
}

type Snapshot = BTreeMap<String, (u64, Option<SystemTime>)>;

fn snapshot(dir: &Path) -> Snapshot {
    let mut map = Snapshot::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return map;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_file() {
            let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
            map.insert(name, (meta.len(), meta.modified().ok()));
        }
    }
    map
}

fn c_mount(request: &RunRequest) -> Result<&Path, RunnerError> {
    request
        .mounts
        .iter()
        .find(|m| m.drive == 'C')
        .map(|m| m.path.as_path())
        .ok_or_else(|| RunnerError::Failed("no mount for drive C".into()))
}

/// The host side shared by all runners; `call` runs the jobs that passed the command line check.
fn run_checked(
    runner: &str,
    request: &RunRequest,
    call: impl FnOnce(&RunRequest) -> Result<Vec<RawJob>, RunnerError>,
) -> Result<Vec<JobOutcome>, RunnerError> {
    let c_dir = c_mount(request)?;
    let before = snapshot(c_dir);

    let mut rejected: Vec<Option<String>> = Vec::new();
    let mut valid = Vec::new();
    for job in &request.jobs {
        let too_long = job
            .commands
            .iter()
            .find(|c| c.chars().count() > MAX_COMMAND_LEN);
        match too_long {
            Some(c) => rejected.push(Some(format!(
                "command line of {} characters exceeds the DOS limit of {MAX_COMMAND_LEN}: {}...",
                c.chars().count(),
                c.chars().take(40).collect::<String>()
            ))),
            None => {
                rejected.push(None);
                valid.push(job.clone());
            }
        }
    }

    let raw = if valid.is_empty() {
        Vec::new()
    } else {
        let sub = RunRequest {
            mounts: request.mounts.clone(),
            jobs: valid,
            timeout: request.timeout,
        };
        let raw = call(&sub)?;
        if raw.len() != sub.jobs.len() {
            return Err(RunnerError::Failed(format!(
                "{runner}: {} job results for {} jobs",
                raw.len(),
                sub.jobs.len()
            )));
        }
        raw
    };
    let mut raw = raw.into_iter();

    let mut outcomes = Vec::new();
    for (job, reject) in request.jobs.iter().zip(rejected) {
        let raw = match reject {
            Some(message) => RawJob {
                status: JobStatus::Failed,
                exit_code: None,
                stdout: String::new(),
                message: Some(message),
            },
            None => raw
                .next()
                .ok_or_else(|| RunnerError::Failed(format!("{runner}: missing job result")))?,
        };
        if raw.status == JobStatus::Timeout {
            for name in &job.expected {
                if !before.contains_key(&name.to_ascii_uppercase()) {
                    let _ = std::fs::remove_file(c_dir.join(name));
                }
            }
        }
        let after = snapshot(c_dir);
        let produced = job
            .expected
            .iter()
            .filter(|name| {
                let key = name.to_ascii_uppercase();
                after
                    .get(&key)
                    .is_some_and(|now| before.get(&key) != Some(now))
            })
            .cloned()
            .collect();
        outcomes.push(JobOutcome {
            status: raw.status,
            exit_code: raw.exit_code,
            stdout: raw.stdout,
            produced,
            message: raw.message,
            runner: runner.to_string(),
            expected: job.expected.clone(),
        });
    }
    Ok(outcomes)
}

/// A runner served by a plugin with capability `runner` v1.
pub struct PluginRunner {
    name: String,
    host: Mutex<Option<PluginHost>>,
}

impl PluginRunner {
    /// Starts the plugin `name` with `config` in `cwd` and checks its capability.
    pub fn start(name: &str, config: &PluginConfig, cwd: &Path) -> Result<Self, RunnerError> {
        if config.command.is_empty() {
            return Err(RunnerError::Unavailable(format!(
                "[plugins.{name}] command is empty"
            )));
        }
        let command: Vec<OsString> = config.command.iter().map(OsString::from).collect();
        let env: Vec<(OsString, OsString)> = config
            .env
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect();
        let host = PluginHost::spawn_with_env(&command, cwd, &env)
            .map_err(|e| RunnerError::Unavailable(format!("{name}: {e}")))?;
        let found = host.info().capabilities.get(CAPABILITY).copied();
        if found != Some(CAPABILITY_VERSION) {
            let _ = host.shutdown();
            return Err(RunnerError::Unavailable(format!(
                "{name}: needs capability {CAPABILITY} v{CAPABILITY_VERSION}, the plugin offers {}",
                found.map_or_else(|| "none".to_string(), |v| format!("v{v}"))
            )));
        }
        Ok(PluginRunner {
            name: name.to_string(),
            host: Mutex::new(Some(host)),
        })
    }

    fn call(
        &self,
        request: &RunRequest,
        cancel: Option<CancelToken>,
    ) -> Result<Vec<RawJob>, RunnerError> {
        let guard = self.host.lock().unwrap_or_else(|p| p.into_inner());
        let host = guard
            .as_ref()
            .ok_or_else(|| RunnerError::Unavailable(format!("{}: shut down", self.name)))?;
        let params = json!({
            "mounts": request.mounts.iter().map(|m| json!({
                "drive": m.drive.to_string(),
                "path": m.path.to_string_lossy(),
                "writable": m.writable,
            })).collect::<Vec<_>>(),
            "current_drive": "C",
            "timeout_s": request.timeout.as_secs_f64(),
            "jobs": request.jobs.iter().map(|j| json!({"commands": j.commands})).collect::<Vec<_>>(),
        });
        let jobs = u32::try_from(request.jobs.len()).unwrap_or(u32::MAX);
        let timeout = request
            .timeout
            .saturating_mul(jobs)
            .saturating_add(CALL_SLACK);
        let result = host
            .call(
                &format!("{CAPABILITY}/run"),
                params,
                CallOptions {
                    timeout,
                    cancel,
                    on_progress: None,
                },
            )
            .map_err(|e| match e {
                PluginError::Remote { code, message } if code == RUNNER_UNSUPPORTED => {
                    RunnerError::Unsupported(format!("{}: {message}", self.name))
                }
                PluginError::Cancelled => RunnerError::Failed(format!("{}: cancelled", self.name)),
                other => RunnerError::Failed(format!("{}: {other}", self.name)),
            })?;
        let jobs = result.get("jobs").cloned().unwrap_or(Value::Null);
        serde_json::from_value(jobs)
            .map_err(|e| RunnerError::Failed(format!("{}: bad runner/run result: {e}", self.name)))
    }
}

impl Runner for PluginRunner {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(
        &self,
        request: &RunRequest,
        cancel: Option<CancelToken>,
    ) -> Result<Vec<JobOutcome>, RunnerError> {
        run_checked(&self.name, request, |sub| self.call(sub, cancel))
    }
}

impl Drop for PluginRunner {
    fn drop(&mut self) {
        let host = self.host.get_mut().unwrap_or_else(|p| p.into_inner());
        if let Some(host) = host.take() {
            let _ = host.shutdown();
        }
    }
}

/// Runs the DOS command lines as host processes (for tools that exist as native programs, and for tests).
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeRunner;

impl Runner for NativeRunner {
    fn name(&self) -> &str {
        "native"
    }

    fn run(
        &self,
        request: &RunRequest,
        cancel: Option<CancelToken>,
    ) -> Result<Vec<JobOutcome>, RunnerError> {
        run_checked("native", request, |sub| {
            sub.jobs
                .iter()
                .map(|job| native_job(sub, job, cancel.as_ref()))
                .collect()
        })
    }
}

/// Replaces a leading `C:\` or `D:\` (any mounted drive) by the mount path.
fn map_segment(segment: &str, mounts: &[Mount]) -> String {
    let mut chars = segment.chars();
    if let (Some(letter), Some(':'), Some(sep)) = (chars.next(), chars.next(), chars.next())
        && (sep == '\\' || sep == '/')
        && let Some(mount) = mounts
            .iter()
            .find(|m| m.drive == letter.to_ascii_uppercase())
    {
        let mut path = mount.path.clone();
        for part in segment[3..].split(['\\', '/']).filter(|p| !p.is_empty()) {
            path.push(part);
        }
        return path.to_string_lossy().into_owned();
    }
    segment.to_string()
}

/// Maps a token; the segments of `;`-separated lists (`SET INCLUDE=D:\INC;D:\LIB`) are mapped one by one.
fn map_token(token: &str, mounts: &[Mount]) -> String {
    token
        .split(';')
        .map(|s| map_segment(s, mounts))
        .collect::<Vec<_>>()
        .join(";")
}

/// Splits a command line at white space; double quotes group.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        tokens.push(current);
    }
    tokens
}

fn parse_set(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim_start();
    let head = rest.get(..4)?;
    if !head.eq_ignore_ascii_case("SET ") {
        return None;
    }
    let (name, value) = rest[4..].trim_start().split_once('=')?;
    Some((name.trim(), value))
}

fn failed(message: String, stdout: String) -> RawJob {
    RawJob {
        status: JobStatus::Failed,
        exit_code: None,
        stdout,
        message: Some(message),
    }
}

fn native_job(
    request: &RunRequest,
    job: &RunJob,
    cancel: Option<&CancelToken>,
) -> Result<RawJob, RunnerError> {
    let cwd = c_mount(request)?;
    let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
    let deadline = Instant::now() + request.timeout;
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut stdout = String::new();
    let mut exit_code = 0;
    let mut incomplete = false;
    for line in &job.commands {
        if let Some((name, value)) = parse_set(line) {
            env.insert(name.to_string(), map_token(value, &request.mounts));
            continue;
        }
        let tokens: Vec<String> = tokenize(line)
            .iter()
            .map(|t| map_token(t, &request.mounts))
            .collect();
        let Some((program, args)) = tokens.split_first() else {
            continue;
        };
        let mut command = Command::new(program);
        command
            .args(args)
            .envs(&env)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Ok(failed(format!("cannot start {program}: {e}"), stdout)),
        };
        let readers: Vec<_> = [
            child.stdout.take().map(spawn_reader),
            child.stderr.take().map(spawn_reader),
        ]
        .into_iter()
        .flatten()
        .collect();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {}
                Err(e) => {
                    kill_tree(&mut child);
                    return Ok(failed(format!("cannot wait for {program}: {e}"), stdout));
                }
            }
            if cancelled() || Instant::now() >= deadline {
                kill_tree(&mut child);
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let grace = Instant::now() + READER_GRACE;
        for reader in readers {
            match reader.recv_timeout(grace.saturating_duration_since(Instant::now())) {
                Ok(bytes) => stdout.push_str(&String::from_utf8_lossy(&bytes)),
                Err(_) => incomplete = true,
            }
        }
        if cancelled() {
            return Err(RunnerError::Failed("native: cancelled".into()));
        }
        let Some(status) = status else {
            return Ok(RawJob {
                status: JobStatus::Timeout,
                exit_code: None,
                stdout,
                message: Some(format!(
                    "{program} did not end within {} s{}",
                    request.timeout.as_secs_f64(),
                    if incomplete {
                        "; output may be incomplete"
                    } else {
                        ""
                    }
                )),
            });
        };
        exit_code = status.code().unwrap_or(-1);
        if exit_code != 0 {
            break;
        }
    }
    Ok(RawJob {
        status: JobStatus::Done,
        exit_code: Some(exit_code),
        stdout,
        message: incomplete.then(|| "output may be incomplete".to_string()),
    })
}

/// Ends the child and its descendants (they inherit the output pipes), then reaps the child.
fn kill_tree(child: &mut std::process::Child) {
    let pid = child.id().to_string();
    let mut killer = if cfg!(windows) {
        let mut c = Command::new("taskkill");
        c.args(["/PID", &pid, "/T", "/F"]);
        c
    } else {
        let mut c = Command::new("kill");
        c.args(["-KILL", &format!("-{pid}")]);
        c
    };
    let killed = killer
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !killed {
        let _ = child.kill();
    }
    let _ = child.wait();
}

/// How long the output readers may take after the child ended (a surviving descendant can hold the pipe).
const READER_GRACE: Duration = Duration::from_secs(2);

fn spawn_reader(mut stream: impl Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    rx
}

/// Opens the runners named in `names` in order (`native` is built in, any other name is a plugin from
/// `[plugins.<name>]` of the workspace or the user config). Runners that are not configured or do not start are
/// left out, each with a warning.
pub fn open_runners(
    names: &[String],
    ws: &Workspace,
    user: &UserConfig,
) -> (Vec<Box<dyn Runner>>, Vec<String>) {
    let mut runners: Vec<Box<dyn Runner>> = Vec::new();
    let mut warnings = Vec::new();
    for name in names {
        if name == "native" {
            runners.push(Box::new(NativeRunner));
            continue;
        }
        let Some(config) = plugin_config(ws, &user.plugins, name) else {
            warnings.push(format!(
                "runner {name}: no [plugins.{name}] entry in decovery.toml or the user config; skipped"
            ));
            continue;
        };
        match PluginRunner::start(name, &config, &ws.root) {
            Ok(runner) => runners.push(Box::new(runner)),
            Err(e) => warnings.push(format!("runner {name}: {e}; skipped")),
        }
    }
    (runners, warnings)
}

/// Runs the request with the first runner that can; `Unsupported` and `Unavailable` fall through to the next
/// runner (with a warning), any other error ends the run.
pub fn run_with_fallback(
    runners: &[Box<dyn Runner>],
    request: &RunRequest,
    cancel: Option<CancelToken>,
) -> Result<(Vec<JobOutcome>, Vec<String>), RunnerError> {
    let mut warnings = Vec::new();
    let mut last: Option<RunnerError> = None;
    for runner in runners {
        match runner.run(request, cancel.clone()) {
            Ok(outcomes) => return Ok((outcomes, warnings)),
            Err(e @ (RunnerError::Unsupported(_) | RunnerError::Unavailable(_))) => {
                warnings.push(format!("runner {}: {e}; trying the next", runner.name()));
                last = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| RunnerError::Unavailable("no runner is available".into())))
}
