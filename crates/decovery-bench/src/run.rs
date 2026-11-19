//! Persistent benchmark records and bounded scheduling of isolated task evaluations.
use super::{
    BenchError, DriverConfig, Suite, SuiteTask, ToolSet, canonical, copies_dir, io,
    prepare_copy_with,
};
use decovery_core::{
    BenchUsage, VerdictId, archive_load, attempt_distance, distance_of, now_utc, read_attempts,
    read_rebuild,
};
use decovery_facade::Progress;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunOptions {
    pub driver: String,
    pub parallel: usize,
    pub seed: u64,
    pub repeat: u32,
    pub only: Vec<String>,
    pub max_total_tokens: Option<u64>,
    pub max_total_cost_usd: Option<f64>,
    pub resume: Option<String>,
    pub decovery_exe: PathBuf,
    pub copies_dir: Option<PathBuf>,
    pub keep: bool,
    /// `Some(false)` hides exemplars in every task (`bench run --no-exemplars`); `None` follows the suite.
    pub exemplars: Option<bool>,
}
impl RunOptions {
    pub fn new(driver: impl Into<String>, decovery_exe: PathBuf) -> Self {
        Self {
            driver: driver.into(),
            parallel: 1,
            seed: 0,
            repeat: 1,
            only: Vec::new(),
            max_total_tokens: None,
            max_total_cost_usd: None,
            resume: None,
            decovery_exe,
            copies_dir: None,
            keep: false,
            exemplars: None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TaskResult {
    pub id: String,
    pub repeat: u32,
    pub workspace: String,
    pub profile: String,
    pub tags: Vec<String>,
    pub solved: bool,
    pub verdict: String,
    pub start_distance: Option<u64>,
    pub best_distance: Option<u64>,
    pub builds: u32,
    pub tool_calls: u32,
    pub searches: u32,
    pub calls_by_tool: BTreeMap<String, u32>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub cost_kind: Option<String>,
    pub wall_s: f64,
    pub exit: String,
    pub log: Option<String>,
    /// Driver sessions started after the first one because the agent ended with budget left (ADR 0009, 10).
    #[serde(default)]
    pub continuations: u32,
    /// The task's copy offered exemplars (older records: true).
    #[serde(default = "default_true")]
    pub exemplars: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
impl TaskResult {
    fn pending(task: &SuiteTask, repeat: u32) -> Self {
        Self {
            id: task.id.clone(),
            repeat,
            workspace: task.workspace.to_string_lossy().into_owned(),
            profile: String::new(),
            tags: task.tags.clone(),
            solved: false,
            verdict: "unchecked".into(),
            start_distance: None,
            best_distance: None,
            builds: 0,
            searches: 0,
            tool_calls: 0,
            calls_by_tool: BTreeMap::new(),
            input_tokens: None,
            output_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
            cost_usd: None,
            cost_kind: None,
            wall_s: 0.0,
            exit: "not-run".into(),
            log: None,
            continuations: 0,
            exemplars: task.exemplars.unwrap_or(true),
            extra: Map::new(),
        }
    }
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Totals {
    pub tasks: u32,
    pub solved: u32,
    pub builds: u32,
    pub tool_calls: u32,
    pub searches: u32,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub wall_s: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RunRecord {
    pub schema: u32,
    pub id: String,
    pub suite: String,
    pub started: String,
    pub finished: Option<String>,
    pub state: String,
    pub tool_version: String,
    pub config_hash: String,
    pub driver: String,
    pub model: Option<String>,
    pub tools: String,
    pub seed: u64,
    /// The run's default exemplar setting (suite default or `--no-exemplars`; older records: true).
    #[serde(default = "default_true")]
    pub exemplars: bool,
    pub totals: Totals,
    pub tasks: Vec<TaskResult>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
impl RunRecord {
    pub fn read(path: &Path) -> Result<Self, BenchError> {
        let bytes = std::fs::read(path).map_err(|e| io(path, e))?;
        let run: Self = serde_json::from_slice(&bytes).map_err(|e| BenchError::Suite {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        if run.schema != 1 {
            return Err(BenchError::Suite {
                path: path.to_path_buf(),
                reason: format!("unsupported schema {}", run.schema),
            });
        }
        Ok(run)
    }
}

fn json_file(path: &Path, value: &impl Serialize) -> Result<(), BenchError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| BenchError::Suite {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    decovery_core::write_atomic(path, &bytes).map_err(|e| io(path, e))
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn key(id: &str) -> String {
    let safe: String = id
        .chars()
        .take(48)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}-{}", &hash(id.as_bytes())[..12])
}
fn valid_run_id(id: &str) -> bool {
    let parts: Vec<_> = id.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 8
        && parts[1].len() == 6
        && parts[2].len() == 6
        && parts[0]
            .bytes()
            .chain(parts[1].bytes())
            .all(|b| b.is_ascii_digit())
        && parts[2].bytes().all(|b| b.is_ascii_hexdigit())
}
fn totals(run: &mut RunRecord) {
    let mut total = Totals {
        extra: run.totals.extra.clone(),
        ..Totals::default()
    };
    let previous: Vec<TaskResult> = run
        .extra
        .get("previous_attempts")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    for t in run
        .tasks
        .iter()
        .chain(previous.iter())
        .filter(|t| t.exit != "not-run")
    {
        total.tasks = total.tasks.saturating_add(1);
        total.solved = total.solved.saturating_add(u32::from(t.solved));
        total.builds = total.builds.saturating_add(t.builds);
        total.tool_calls = total.tool_calls.saturating_add(t.tool_calls);
        total.searches = total.searches.saturating_add(t.searches);
        total.wall_s += t.wall_s;
        for (sum, value) in [
            (&mut total.input_tokens, t.input_tokens),
            (&mut total.output_tokens, t.output_tokens),
            (&mut total.cache_read_tokens, t.cache_read_tokens),
            (&mut total.cache_write_tokens, t.cache_write_tokens),
        ] {
            if let Some(value) = value {
                *sum = Some(sum.unwrap_or(0).saturating_add(value));
            }
        }
        if let Some(cost) = t.cost_usd {
            total.cost_usd = Some(total.cost_usd.unwrap_or(0.0) + cost);
        }
    }
    run.totals = total;
}
fn limit_reached(run: &RunRecord, options: &RunOptions) -> bool {
    let tokens = run
        .totals
        .input_tokens
        .unwrap_or(0)
        .saturating_add(run.totals.output_tokens.unwrap_or(0))
        .saturating_add(run.totals.cache_write_tokens.unwrap_or(0));
    options.max_total_tokens.is_some_and(|max| tokens >= max)
        || options
            .max_total_cost_usd
            .is_some_and(|max| run.totals.cost_usd.unwrap_or(0.0) >= max)
}

pub fn run_suite(
    suite: &Suite,
    driver: &DriverConfig,
    options: &RunOptions,
    progress: &dyn Fn(Progress),
) -> Result<RunRecord, BenchError> {
    if options.parallel == 0
        || options.repeat == 0
        || options
            .max_total_cost_usd
            .is_some_and(|c| !c.is_finite() || c < 0.0)
    {
        return Err(BenchError::Driver {
            task: suite.name.clone(),
            reason: "parallel/repeat must be positive and cost limits finite/nonnegative".into(),
        });
    }
    for only in &options.only {
        if !suite.tasks.iter().any(|t| &t.id == only) {
            return Err(BenchError::Driver {
                task: only.clone(),
                reason: "unknown task id".into(),
            });
        }
    }
    let exe = canonical(&options.decovery_exe)?;
    let user = decovery_core::read_user_config()?;
    let copies = options
        .copies_dir
        .clone()
        .or(user.bench.copies_dir)
        .unwrap_or_else(copies_dir);
    let config = json!({"suite":suite,"driver":driver,"seed":options.seed,"repeat":options.repeat,"only":options.only,"max_total_tokens":options.max_total_tokens,"max_total_cost_usd":options.max_total_cost_usd,"exemplars":options.exemplars});
    let config_hash = hash(
        &serde_json::to_vec(&config).map_err(|e| BenchError::Driver {
            task: suite.name.clone(),
            reason: e.to_string(),
        })?,
    );
    let store = suite.dir.join("bench");
    std::fs::create_dir_all(&store).map_err(|e| io(&store, e))?;
    let tools = match suite.defaults.tools {
        ToolSet::Core => "core",
        ToolSet::CoreLegacy => "core-legacy",
    };
    let mut run = if let Some(id) = &options.resume {
        if !valid_run_id(id) {
            return Err(BenchError::Driver {
                task: id.clone(),
                reason: "invalid run id".into(),
            });
        }
        let run = RunRecord::read(&store.join(format!("{id}.json")))?;
        if run.config_hash != config_hash {
            return Err(BenchError::Driver {
                task: id.clone(),
                reason: "resume configuration differs from the recorded run".into(),
            });
        }
        run
    } else {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time: String = now_utc().chars().filter(char::is_ascii_digit).collect();
        let entropy = format!(
            "{:?}-{}-{config_hash}",
            std::time::SystemTime::now(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let id = format!(
            "{}-{}-{}",
            &time[..8],
            &time[8..14],
            &hash(entropy.as_bytes())[..6]
        );
        RunRecord {
            schema: 1,
            id,
            suite: suite.name.clone(),
            started: now_utc(),
            finished: None,
            state: "running".into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            config_hash,
            driver: options.driver.clone(),
            model: None,
            tools: tools.into(),
            seed: options.seed,
            exemplars: options.exemplars.unwrap_or(suite.defaults.exemplars),
            totals: Totals::default(),
            tasks: suite
                .tasks
                .iter()
                .filter(|t| options.only.is_empty() || options.only.contains(&t.id))
                .flat_map(|t| (1..=options.repeat).map(|repeat| TaskResult::pending(t, repeat)))
                .collect(),
            extra: Map::new(),
        }
    };
    let path = store.join(format!("{}.json", run.id));
    let logs = store.join(&run.id);
    std::fs::create_dir_all(&logs).map_err(|e| io(&logs, e))?;
    let copy_root = copies.join(&run.id);
    std::fs::create_dir_all(&copy_root).map_err(|e| io(&copy_root, e))?;
    let mut queue = VecDeque::new();
    for task in &suite.tasks {
        for repeat in 1..=options.repeat {
            if run.tasks.iter().any(|r| {
                r.id == task.id
                    && r.repeat == repeat
                    && matches!(r.exit.as_str(), "not-run" | "quota")
            }) {
                queue.push_back((task.clone(), repeat));
            }
        }
    }
    run.state = "running".into();
    run.finished = None;
    totals(&mut run);
    json_file(&path, &run)?;
    let mut paused = false;
    std::thread::scope(|scope| -> Result<(), BenchError> {
        let (send, receive) = mpsc::channel();
        let mut active = 0;
        loop {
            while active < options.parallel && !paused && !limit_reached(&run, options) {
                let Some((task, repeat)) = queue.pop_front() else {
                    break;
                };
                let old = run
                    .tasks
                    .iter()
                    .find(|r| r.id == task.id && r.repeat == repeat)
                    .cloned();
                let previous_count = run
                    .extra
                    .get("previous_attempts")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                if let Some(old) = old.filter(|r| r.exit == "quota") {
                    let value = serde_json::to_value(old).map_err(|e| BenchError::Driver {
                        task: task.id.clone(),
                        reason: e.to_string(),
                    })?;
                    run.extra
                        .entry("previous_attempts")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .ok_or_else(|| BenchError::Driver {
                            task: task.id.clone(),
                            reason: "invalid previous_attempts record".into(),
                        })?
                        .push(value);
                }
                let attempt = previous_count + 1;
                let tx = send.clone();
                let exe = &exe;
                let logs = &logs;
                let copy_root = &copy_root;
                let id = run.id.clone();
                std::thread::Builder::new()
                    .name("decovery-bench-task".into())
                    .spawn_scoped(scope, move || {
                        let result = evaluate(
                            suite, driver, options, &task, repeat, attempt, &id, exe, copy_root,
                            logs,
                        );
                        let _ = tx.send(result);
                    })
                    .map_err(|e| io(logs, e))?;
                active += 1;
            }
            if active == 0 {
                break;
            }
            match receive.recv_timeout(Duration::from_millis(100)) {
                Ok(task) => {
                    active -= 1;
                    paused |= task.exit == "quota";
                    if run.model.is_none() {
                        run.model = task
                            .extra
                            .get("model")
                            .and_then(Value::as_str)
                            .map(str::to_string);
                    }
                    if let Some(old) = run
                        .tasks
                        .iter_mut()
                        .find(|r| r.id == task.id && r.repeat == task.repeat)
                    {
                        *old = task;
                    }
                    totals(&mut run);
                    run.tasks
                        .sort_by(|a, b| a.id.cmp(&b.id).then(a.repeat.cmp(&b.repeat)));
                    json_file(&path, &run)?;
                    progress(Progress::new(
                        run.tasks.iter().filter(|t| t.exit != "not-run").count() as u64,
                        Some(run.tasks.len() as u64),
                        Some("bench task finished".into()),
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(e) => {
                    return Err(BenchError::Driver {
                        task: suite.name.clone(),
                        reason: e.to_string(),
                    });
                }
            }
        }
        Ok(())
    })?;
    run.state = if paused {
        "paused"
    } else if !queue.is_empty() {
        "stopped-at-limit"
    } else {
        "done"
    }
    .into();
    run.finished = Some(now_utc());
    totals(&mut run);
    run.tasks
        .sort_by(|a, b| a.id.cmp(&b.id).then(a.repeat.cmp(&b.repeat)));
    json_file(&path, &run)?;
    Ok(run)
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    suite: &Suite,
    driver: &DriverConfig,
    options: &RunOptions,
    task: &SuiteTask,
    repeat: u32,
    attempt: usize,
    run_id: &str,
    exe: &Path,
    copies: &Path,
    logs: &Path,
) -> TaskResult {
    let began = Instant::now();
    let mut result = TaskResult::pending(task, repeat);
    result.exemplars = options
        .exemplars
        .or(task.exemplars)
        .unwrap_or(suite.defaults.exemplars);
    result.exit = "driver-error".into();
    let key = format!("{}-{repeat}", key(&task.id));
    let copy_parent = copies.join(format!("{key}-attempt-{attempt}"));
    let log_dir = logs.join(&key).join(format!("attempt-{attempt}"));
    let outcome = (|| -> Result<(), BenchError> {
        std::fs::create_dir_all(&log_dir).map_err(|e| io(&log_dir, e))?;
        let copy = prepare_copy_with(
            task,
            task.start.unwrap_or(suite.defaults.start),
            suite.defaults.tools,
            result.exemplars,
            &copy_parent.join("workspace"),
        )?;
        result.profile = copy.profile.clone();
        result.start_distance = build(
            exe,
            &copy.root,
            &copy.file,
            &copy.name,
            &log_dir.join("start-build.log"),
        )?
        .1;
        let prompt = match &suite.defaults.prompt {
            Some(path) => std::fs::read_to_string(path).map_err(|e| io(path, e))?,
            None => include_str!("prompt.md").into(),
        };
        let tools = if suite.defaults.tools == ToolSet::Core {
            "core"
        } else {
            "core-legacy"
        };
        let mut prompt = prompt;
        for (key, value) in [
            ("{function}", copy.name.clone()),
            ("{file}", copy.file.clone()),
            ("{max_builds}", suite.defaults.max_builds.to_string()),
            (
                "{max_tool_calls}",
                suite.defaults.max_tool_calls.to_string(),
            ),
            ("{max_searches}", suite.defaults.max_searches.to_string()),
            ("{wall_minutes}", suite.defaults.wall_minutes.to_string()),
            ("{tools}", tools.into()),
            (
                "{jobs}",
                if tools == "core-legacy" {
                    "search and verify run as background jobs: poll them with job (action poll); a job's                      builds count when its result is recorded.
"
                } else {
                    ""
                }
                .into(),
            ),
        ] {
            prompt = prompt.replace(key, &value);
        }
        let prompt_path = log_dir.join("prompt.md");
        super::copy::write(&prompt_path, prompt.as_bytes())?;
        let limits = log_dir.join("limits.json");
        json_file(
            &limits,
            &json!({"schema":1,"max_builds":suite.defaults.max_builds,"max_tool_calls":suite.defaults.max_tool_calls,"max_searches":suite.defaults.max_searches,"tools":tools}),
        )?;
        let mcp = log_dir.join("mcp.json");
        let jobs = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .checked_div(options.parallel)
            .unwrap_or(1)
            .max(1);
        json_file(
            &mcp,
            &json!({"schema":1,"mcpServers":{"decovery":{"command":exe,"args":["mcp","--workspace",copy.root,"--limits",limits,"--jobs",jobs.to_string()]}}}),
        )?;
        let d = &suite.defaults;
        let wall = Duration::from_secs(u64::from(d.wall_minutes) * 60);
        let driver_began = Instant::now();
        let mut session_prompt = prompt_path.clone();
        let mut warnings = Vec::new();
        let mut session_logs = Vec::new();
        let mut session: u32 = 0;
        loop {
            let suffix = if session == 0 {
                String::new()
            } else {
                format!("-continuation-{session}")
            };
            let report = log_dir.join(format!("result{suffix}.json"));
            let log = log_dir.join(format!("driver{suffix}.log"));
            if session == 0 {
                result.log = Some(log.to_string_lossy().into_owned());
            }
            session_logs.push(log.to_string_lossy().into_owned());
            // limits apply to the whole task: a continuation gets what the earlier sessions left
            let remaining_wall = wall.saturating_sub(driver_began.elapsed());
            let tokens_used = task_tokens(&result);
            let cost_used = result.cost_usd.unwrap_or(0.0);
            let mut bindings = BTreeMap::new();
            for (key, value) in [
                ("{prompt}", session_prompt.to_string_lossy().into_owned()),
                ("{mcp_config}", mcp.to_string_lossy().into_owned()),
                ("{workdir}", copy.root.to_string_lossy().into_owned()),
                ("{result}", report.to_string_lossy().into_owned()),
                ("{seed}", format!("{}", options.seed)),
                (
                    "{max_tokens}",
                    d.max_tokens
                        .map_or(String::new(), |v| v.saturating_sub(tokens_used).to_string()),
                ),
                (
                    "{max_cost_usd}",
                    d.max_cost_usd
                        .map_or(String::new(), |v| (v - cost_used).max(0.0).to_string()),
                ),
                ("{wall_seconds}", remaining_wall.as_secs().to_string()),
            ] {
                bindings.insert(key, value);
            }
            result.exit = "driver-error".into();
            match super::driver::invoke(
                &task.id,
                driver,
                &bindings,
                &copy.root,
                &log,
                remaining_wall,
                &format!("bench:{run_id}"),
            ) {
                Ok(outcome) => {
                    result.exit = outcome.exit;
                    result
                        .extra
                        .insert("driver_exit_code".into(), json!(outcome.code));
                    result.extra.insert("driver_pid".into(), json!(outcome.pid));
                    warnings.extend(outcome.warnings);
                    if let Some(r) = outcome.result {
                        if !result.extra.contains_key("model") || r.model.is_some() {
                            result.extra.insert("model".into(), json!(r.model));
                        }
                        result.input_tokens = add(result.input_tokens, r.input_tokens);
                        result.output_tokens = add(result.output_tokens, r.output_tokens);
                        result.cache_read_tokens =
                            add(result.cache_read_tokens, r.cache_read_tokens);
                        result.cache_write_tokens =
                            add(result.cache_write_tokens, r.cache_write_tokens);
                        result.cost_usd = match (result.cost_usd, r.cost_usd) {
                            (None, None) => None,
                            (a, b) => Some(a.unwrap_or(0.0) + b.unwrap_or(0.0)),
                        };
                        result.cost_kind = r.cost_kind.or(result.cost_kind.take());
                        result
                            .extra
                            .insert("driver_extra".into(), Value::Object(r.extra));
                    }
                }
                Err(e) => {
                    result
                        .extra
                        .insert("driver_error".into(), json!(e.to_string()));
                }
            }
            result.extra.insert("warnings".into(), json!(warnings));
            let build_log = log_dir.join(format!("final-build{suffix}.log"));
            judge(exe, task, &copy, &build_log, &mut result)?;
            if result.exit == "quota" {
                break;
            }
            if result.solved || result.exit != "ok" || session >= d.max_continuations {
                break;
            }
            let usage = BenchUsage::load(&copy.root)?;
            let budget_left = usage.builds < d.max_builds
                && usage.tool_calls < d.max_tool_calls
                && d.max_tokens.is_none_or(|m| task_tokens(&result) < m)
                && d.max_cost_usd
                    .is_none_or(|m| result.cost_usd.unwrap_or(0.0) < m)
                && driver_began.elapsed() < wall;
            if !budget_left {
                break;
            }
            session += 1;
            let text =
                continuation_prompt(session, d.max_continuations, &result, &usage, d, &prompt);
            session_prompt = log_dir.join(format!("prompt-continuation-{session}.md"));
            super::copy::write(&session_prompt, text.as_bytes())?;
        }
        result.continuations = session;
        result
            .extra
            .insert("session_logs".into(), json!(session_logs));
        let usage = BenchUsage::load(&copy.root)?;
        if result.exit == "ok" && limit_spent(&copy.root, &usage, suite)? {
            result.exit = "call-limit".into();
        }
        result.builds = usage.builds;
        result.searches = usage.searches;
        result.tool_calls = usage.tool_calls;
        result.calls_by_tool = usage.calls_by_tool.clone();
        json_file(&log_dir.join("usage.json"), &usage)?;
        let calls = copy.root.join("cache/calls");
        if calls.is_dir() {
            std::fs::create_dir_all(log_dir.join("calls")).map_err(|e| io(&log_dir, e))?;
            for entry in std::fs::read_dir(&calls).map_err(|e| io(&calls, e))? {
                let entry = entry.map_err(|e| io(&calls, e))?;
                if entry.path().extension().is_some_and(|e| e == "jsonl") {
                    std::fs::copy(entry.path(), log_dir.join("calls").join(entry.file_name()))
                        .map_err(|e| io(&entry.path(), e))?;
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = outcome {
        result.extra.insert("error".into(), json!(e.to_string()));
        result.exit = "driver-error".into();
    }
    if !options.keep && copy_parent.exists() {
        match (copy_parent.canonicalize(), copies.canonicalize()) {
            (Ok(target), Ok(root)) if target.starts_with(&root) && target != root => {
                if let Err(e) = std::fs::remove_dir_all(&target) {
                    result
                        .extra
                        .insert("cleanup_error".into(), json!(e.to_string()));
                }
            }
            _ => {
                result.extra.insert(
                    "cleanup_error".into(),
                    json!("copy directory is outside the run root"),
                );
            }
        }
    }
    result.wall_s = began.elapsed().as_secs_f64();
    result
}

fn add(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
    }
}
/// Tokens a task has used, counted like the drivers count them against `max_tokens`.
fn task_tokens(result: &TaskResult) -> u64 {
    result
        .input_tokens
        .unwrap_or(0)
        .saturating_add(result.output_tokens.unwrap_or(0))
}
fn continuation_prompt(
    session: u32,
    max: u32,
    result: &TaskResult,
    usage: &BenchUsage,
    d: &super::TaskDefaults,
    task_prompt: &str,
) -> String {
    let distance = |d: Option<u64>| d.map_or_else(|| "unknown".to_string(), |d| d.to_string());
    format!(
        "This is continuation {session} of at most {max} for this task. An earlier session ended on its own          while budget was left and the function is not solved yet. You are a new session: you see only this          workspace, its attempt history and this prompt.

         Current state: decovery's verdict is {verdict}, best distance {best} (start distance {start}).          Used so far: {builds} of {max_builds} builds, {calls} of {max_calls} tool calls. Start with status          and history to see the earlier attempts, then keep going until the verdict is identical or a limit          is reached; do not stop while budget remains.

         The original task follows. Its limits are totals for the whole task, including earlier sessions.

         ---

{task_prompt}",
        verdict = result.verdict,
        best = distance(result.best_distance),
        start = distance(result.start_distance),
        builds = usage.builds,
        max_builds = d.max_builds,
        calls = usage.tool_calls,
        max_calls = d.max_tool_calls,
    )
}

/// Records the attempt distances and, unless the driver stopped on quota, splices the best identical attempt and
/// sets decovery's own verdict from one harness build.
fn judge(
    exe: &Path,
    task: &SuiteTask,
    copy: &super::TaskCopy,
    build_log: &Path,
    result: &mut TaskResult,
) -> Result<(), BenchError> {
    let (attempts, warnings) = read_attempts(&copy.root, copy.address)?;
    result
        .extra
        .insert("attempt_warnings".into(), json!(warnings));
    result.best_distance = attempts
        .iter()
        .filter_map(attempt_distance)
        .chain(result.start_distance)
        .chain(result.best_distance)
        .min();
    if result.exit == "quota" {
        return Ok(());
    }
    for a in attempts
        .iter()
        .rev()
        .filter(|a| a.verdict == Some(VerdictId::Identical))
    {
        let Some(id) = &a.archive else {
            continue;
        };
        if let Ok(entry) = archive_load(&copy.root, id)
            && entry.meta["address"] == json!(copy.address)
            && let Some(body) = entry.files.get("function.c")
            && let Ok(body) = std::str::from_utf8(body)
        {
            let path = copy.root.join("src").join(&copy.file);
            let source = std::fs::read_to_string(&path).map_err(|e| io(&path, e))?;
            let replacement = decovery_toolchain::splice_function(&source, &copy.name, body)
                .map_err(|e| BenchError::Driver {
                    task: task.id.clone(),
                    reason: e.to_string(),
                })?;
            if replacement != source {
                super::copy::write(&path, replacement.as_bytes())?;
            }
            break;
        }
    }
    let (verdict, distance) = build(exe, &copy.root, &copy.file, &copy.name, build_log)?;
    result.verdict = verdict;
    result.solved = result.verdict == "identical";
    result.best_distance = result.best_distance.into_iter().chain(distance).min();
    Ok(())
}

/// The agent ended after the endpoint refused a call while one of its limits was spent.
fn limit_spent(root: &Path, usage: &BenchUsage, suite: &Suite) -> Result<bool, BenchError> {
    let d = &suite.defaults;
    let spent = usage.tool_calls >= d.max_tool_calls
        || usage.builds >= d.max_builds
        || (d.max_searches > 0 && usage.searches >= d.max_searches);
    if !spent {
        return Ok(false);
    }
    let (calls, _) = decovery_core::calls::read_calls(root)?;
    Ok(calls
        .iter()
        .any(|c| c.outcome == "refused" && c.actor.as_deref() != Some("bench-harness")))
}

fn build(
    exe: &Path,
    root: &Path,
    file: &str,
    name: &str,
    log: &Path,
) -> Result<(String, Option<u64>), BenchError> {
    let output = Command::new(exe)
        .args(["--workspace"])
        .arg(root)
        .args(["--json", "build", file, "--function", name])
        .env("DECOVERY_ACTOR", "bench-harness")
        .output()
        .map_err(|e| io(exe, e))?;
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    super::copy::write(log, &bytes)?;
    // 0 = identical, 1 = built but not identical; anything else did not build, so `rebuild.toml` still holds an
    // older record (possibly the agent's) that must not become the harness's verdict
    if !matches!(output.status.code(), Some(0 | 1)) {
        return Ok(("unchecked".into(), None));
    }
    let record = read_rebuild(root)?.into_iter().find(|r| r.name == name);
    Ok(record.map_or(("unchecked".into(), None), |r| {
        (
            r.verdict.map_or("unchecked", VerdictId::id).into(),
            distance_of(r.result, r.verdict, Some(r.instructions_differing)),
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prompt_asks_to_continue_until_identical_or_a_limit() {
        let prompt = include_str!("prompt.md");
        assert!(prompt.contains("byte-identical build"));
        assert!(prompt.contains("the verdict is identical or a limit is reached"));
        assert!(prompt.contains("do not stop while budget remains"));
    }

    #[test]
    fn failed_harness_build_does_not_reuse_a_stale_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("knowledge")).unwrap();
        // a record left by an earlier build (for example the agent's), saying identical
        std::fs::write(
            root.join("knowledge/rebuild.toml"),
            "schema = 1\n[[function]]\naddress = \"flat:00000010\"\nname = \"sub\"\nfile = \"a.c\"\nresult = \"identical\"\nverdict = \"identical\"\n",
        )
        .unwrap();
        // the test binary rejects the build arguments and exits non-zero without touching the record
        let exe = std::env::current_exe().unwrap();
        let (verdict, distance) =
            build(&exe, root, "a.c", "sub", &root.join("final-build.log")).unwrap();
        assert_eq!(
            verdict, "unchecked",
            "a failed build must not report the old verdict"
        );
        assert_eq!(distance, None);
    }
}
