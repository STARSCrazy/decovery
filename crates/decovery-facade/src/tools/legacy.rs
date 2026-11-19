//! The Decomp legacy bridge (ADR 0007): `diagnose` with `deep`, `search` and `verify` run Decomp's tools through
//! the `decomp-legacy` plugin (capability `legacy` v1) on a shadow of the workspace in `cache/legacy/decomp/`.
//!
//! Decomp's reports pass through unchanged (`report`, `report_language = "de"`); every field decovery adds is
//! English. Verdicts stay decovery's: a candidate source a search finds is built by decovery's own `build` (a
//! function-level attempt next to the current source of the function), and Decomp's equivalence result is
//! evidence with `source = "decomp"`, never a decovery verdict.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use decovery_core::{
    Address, AttemptOrigin, Confidence, RebuildResult, SymbolKind, VerdictId, Workspace,
    distance_of, write_atomic,
};
use decovery_plugin::{CallOptions, PluginError, PluginHost, Progress};
use decovery_toolchain::{definitions, from_cp437, splice_function};
use serde_json::{Map, Value, json};

use super::build::{BuildRequest, SOURCE_DIR, build, file_of_function, read_text};
use super::diagnose::diagnose_tool;
use super::history::RecordAs;
use super::variants::Variant;
use crate::plugins::{PluginConfig, plugin_config, read_user_plugins};
use crate::{
    Budget, Control, FacadeError, Handle, Response, Session, function_by_name, resolve,
    store_handle,
};

/// Name of the bridge plugin in `[plugins.<name>]`.
pub const LEGACY_PLUGIN: &str = "decomp-legacy";
/// The shadow workspace, relative to the workspace root.
pub const SHADOW_DIR: &str = "cache/legacy/decomp";
const CAPABILITY: &str = "legacy";
const CAPABILITY_VERSION: u32 = 1;
/// Timeout of an operation without `minutes` (Decomp's reports, the equivalence and behaviour checks).
const BASE_TIMEOUT_S: u64 = 900;
/// What the host waits beyond `timeout_s` before it gives up on the plugin.
const HOST_SLACK: Duration = Duration::from_secs(60);
const NO_PLUGIN: &str = "no plugin decomp-legacy registered; run `decovery setup decomp-legacy --decomp <Decomp checkout>`";
const NO_LEGACY: &str = "no [legacy] decomp_workspace in decovery.toml; `decovery migrate` writes it (the absolute path of the Decomp workspace this workspace was migrated from), or add it by hand";

/// One Decomp operation of the bridge (ADR 0007, decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LegacyOperation {
    /// `diagnose --deep context`: Decomp's context package.
    Context,
    /// `diagnose --deep structure`: structure comparison per source line, block, loop and stack slot.
    Structure,
    /// `diagnose --deep registers`: Watcom register allocation replayed.
    Registers,
    /// `diagnose --deep slots`: Watcom stack slots replayed.
    Slots,
    /// `diagnose --deep joint`: changes that meet the register and the stack goal together.
    Joint,
    /// `search --strategy chain`: Decomp's search chain.
    Chain,
    /// `search --strategy permute`: the permuter.
    Permute,
    /// `search --strategy beam`: beam search over the form catalogue.
    Beam,
    /// `search --strategy forms`: every form of the catalogue at every place.
    Forms,
    /// `verify --check equivalence`: static and dynamic equivalence evidence.
    Equivalence,
    /// `verify --check behavior`: behaviour in the emulator or DOSBox.
    Behavior,
}

/// Which facade tool an operation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tool {
    Diagnose,
    Search,
    Verify,
}

impl LegacyOperation {
    /// All operations.
    pub const ALL: [LegacyOperation; 11] = [
        LegacyOperation::Context,
        LegacyOperation::Structure,
        LegacyOperation::Registers,
        LegacyOperation::Slots,
        LegacyOperation::Joint,
        LegacyOperation::Chain,
        LegacyOperation::Permute,
        LegacyOperation::Beam,
        LegacyOperation::Forms,
        LegacyOperation::Equivalence,
        LegacyOperation::Behavior,
    ];

    /// The protocol name (`legacy/run` `operation`).
    pub fn id(self) -> &'static str {
        match self {
            LegacyOperation::Context => "context",
            LegacyOperation::Structure => "structure",
            LegacyOperation::Registers => "registers",
            LegacyOperation::Slots => "slots",
            LegacyOperation::Joint => "joint",
            LegacyOperation::Chain => "chain",
            LegacyOperation::Permute => "permute",
            LegacyOperation::Beam => "beam",
            LegacyOperation::Forms => "forms",
            LegacyOperation::Equivalence => "equivalence",
            LegacyOperation::Behavior => "behavior",
        }
    }

    /// The operation named `id`.
    pub fn parse(id: &str) -> Option<LegacyOperation> {
        LegacyOperation::ALL.into_iter().find(|op| op.id() == id)
    }

    fn tool(self) -> Tool {
        match self {
            LegacyOperation::Context
            | LegacyOperation::Structure
            | LegacyOperation::Registers
            | LegacyOperation::Slots
            | LegacyOperation::Joint => Tool::Diagnose,
            LegacyOperation::Chain
            | LegacyOperation::Permute
            | LegacyOperation::Beam
            | LegacyOperation::Forms => Tool::Search,
            LegacyOperation::Equivalence | LegacyOperation::Behavior => Tool::Verify,
        }
    }

    /// The options this operation takes (ADR 0007, protocol table).
    fn allows(self, option: &str) -> bool {
        use LegacyOperation::*;
        match option {
            "minutes" => matches!(self, Chain | Permute | Beam | Forms | Slots | Equivalence),
            "rounds" => matches!(self, Chain | Permute | Beam | Forms),
            "source" => matches!(self, Registers | Slots | Joint | Structure | Permute),
            "all" => self == Registers,
            "run" => self == Behavior,
            _ => false,
        }
    }
}

/// The closed set of options a bridge operation can take; which operation takes which is checked before the
/// plugin is called.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct LegacyOptions {
    /// Time budget in minutes (`--minuten`).
    pub minutes: Option<f64>,
    /// Search rounds (`--runden`).
    pub rounds: Option<u32>,
    /// A candidate source of the function (`--datei`); a relative path that does not exist is taken from the
    /// workspace root.
    pub source: Option<PathBuf>,
    /// The full register report (`--alle`).
    pub all: bool,
    /// Name of a recorded runtime run (`--lauf`).
    pub run: Option<String>,
}

/// One bridge call: the function (a name or address), the operation and its options.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct LegacyCall {
    pub target: String,
    pub operation: LegacyOperation,
    pub options: LegacyOptions,
    /// `search` only: write the candidate's function into `src/` when decovery's verdict on it is better than the
    /// current one, then record it with a normal build.
    pub apply: bool,
    /// Characters of report text (and of Decomp's JSON) returned inline; the rest is stored as a handle.
    pub budget: Budget,
    /// The user config's plugins; `None`: read from the user config when the workspace has no
    /// `[plugins.decomp-legacy]`.
    pub user_plugins: Option<BTreeMap<String, PluginConfig>>,
}

impl LegacyCall {
    pub fn new(target: impl Into<String>, operation: LegacyOperation) -> Self {
        LegacyCall {
            target: target.into(),
            operation,
            options: LegacyOptions::default(),
            apply: false,
            budget: Budget::default(),
            user_plugins: None,
        }
    }
}

// -- the plugin, kept alive across calls on request ------------------------------------------------------------

static KEEP_ALIVE: AtomicBool = AtomicBool::new(false);

type PoolKey = (PathBuf, Vec<String>, BTreeMap<String, String>);
static POOL: Mutex<Vec<(PoolKey, Arc<PluginHost>)>> = Mutex::new(Vec::new());

/// Keeps the `decomp-legacy` plugin running between calls (per workspace and plugin command), so its Decomp server
/// and Ghidra project stay open; the MCP server turns it on. Off (the default), every call starts the plugin and
/// shuts it down afterwards.
pub fn keep_legacy_plugin(on: bool) {
    KEEP_ALIVE.store(on, Ordering::SeqCst);
    if !on {
        pool().clear();
    }
}

fn pool() -> std::sync::MutexGuard<'static, Vec<(PoolKey, Arc<PluginHost>)>> {
    POOL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn spawn(root: &Path, config: &PluginConfig) -> Result<PluginHost, FacadeError> {
    if config.command.is_empty() {
        return Err(FacadeError::Plugin(format!(
            "{LEGACY_PLUGIN}: [plugins.{LEGACY_PLUGIN}] command is empty; run `decovery setup decomp-legacy --decomp <Decomp checkout>`"
        )));
    }
    let command: Vec<OsString> = config.command.iter().map(OsString::from).collect();
    let env: Vec<(OsString, OsString)> = config
        .env
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
    let host = PluginHost::spawn_with_env(&command, root, &env).map_err(|e| match e {
        PluginError::Spawn(e) => FacadeError::Plugin(format!(
            "{LEGACY_PLUGIN}: cannot start {}: {e}; run `decovery setup decomp-legacy --decomp <Decomp checkout>`",
            config.command[0]
        )),
        other => bridge_error(other),
    })?;
    let found = host.info().capabilities.get(CAPABILITY).copied();
    if found != Some(CAPABILITY_VERSION) {
        return Err(FacadeError::Plugin(format!(
            "{LEGACY_PLUGIN}: needs capability {CAPABILITY} v{CAPABILITY_VERSION}, the plugin offers {}",
            found.map_or_else(|| "none".to_string(), |v| format!("v{v}"))
        )));
    }
    Ok(host)
}

/// Runs `legacy/run` on a pooled or a fresh plugin.
fn call_plugin(
    root: &Path,
    config: &PluginConfig,
    params: Value,
    timeout: Duration,
    control: &Control,
) -> Result<Value, FacadeError> {
    let progress = control.progress;
    let sink = |p: Progress| {
        let message = p
            .message
            .clone()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| "Decomp is working".to_string());
        progress(Progress::new(p.done, p.total, Some(message)));
    };
    let options = || CallOptions {
        timeout,
        cancel: Some(control.cancel.clone()),
        on_progress: Some(&sink),
    };
    if !KEEP_ALIVE.load(Ordering::SeqCst) {
        let host = spawn(root, config)?;
        let result = host.call("legacy/run", params, options());
        let _ = host.shutdown();
        return result.map_err(bridge_error);
    }
    let key: PoolKey = (
        root.to_path_buf(),
        config.command.clone(),
        config.env.clone(),
    );
    let pooled = pool()
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, h)| h.clone());
    let host = match pooled {
        Some(host) => host,
        None => {
            let host = Arc::new(spawn(root, config)?);
            pool().push((key.clone(), host.clone()));
            host
        }
    };
    let result = host.call("legacy/run", params, options());
    if matches!(
        result,
        Err(PluginError::Exited | PluginError::Protocol(_) | PluginError::Timeout)
    ) {
        // a dead or hung plugin is started afresh by the next call
        pool().retain(|(_, h)| !Arc::ptr_eq(h, &host));
    }
    result.map_err(bridge_error)
}

/// The plugin's errors (ADR 0007, protocol errors) as messages naming what to do.
fn bridge_error(e: PluginError) -> FacadeError {
    match e {
        PluginError::Remote {
            code,
            message,
            data,
        } => match code {
            -32602 => FacadeError::Invalid(format!("{LEGACY_PLUGIN}: {message}")),
            -32020 => FacadeError::Plugin(format!(
                "{LEGACY_PLUGIN}: Decomp is unavailable: {message}; check the Decomp checkout of `decovery setup decomp-legacy --decomp <Decomp checkout>`"
            )),
            -32021 => FacadeError::Plugin(format!(
                "{LEGACY_PLUGIN}: the Decomp workspace is missing or not a Decomp workspace: {message}; check [legacy] decomp_workspace in decovery.toml"
            )),
            -32022 => {
                let exit = data
                    .as_ref()
                    .and_then(|d| d.get("exit_code"))
                    .map_or_else(|| "?".to_string(), Value::to_string);
                let tail = data
                    .as_ref()
                    .and_then(|d| d.get("stderr_tail"))
                    .and_then(Value::as_str)
                    .map(str::trim_end)
                    .filter(|t| !t.is_empty())
                    .map_or_else(String::new, |t| format!("\n{t}"));
                FacadeError::Plugin(format!(
                    "{LEGACY_PLUGIN}: the Decomp command failed (exit code {exit}): {message}{tail}"
                ))
            }
            _ => FacadeError::Plugin(format!("{LEGACY_PLUGIN}: {message} (error {code})")),
        },
        PluginError::Cancelled => FacadeError::Cancelled,
        PluginError::Timeout => FacadeError::Plugin(format!(
            "{LEGACY_PLUGIN}: no answer in time; the Decomp command was cancelled"
        )),
        other => FacadeError::Plugin(format!("{LEGACY_PLUGIN}: {other}")),
    }
}

// -- the request ---------------------------------------------------------------------------------------------

/// The function a call is about: a rebuild record's address first, then a name by [`function_by_name`], then a
/// function symbol's address, else what [`resolve`] resolves to.
pub(super) struct Function {
    pub(super) address: Address,
    pub(super) name: String,
}

/// Refuses an overlay function: the `decomp-legacy` plugin takes `flat:` and `seg:` addresses only.
fn no_overlay(function: &Function, what: &str) -> Result<(), FacadeError> {
    match function.address.overlay() {
        Some(overlay) => Err(FacadeError::Invalid(format!(
            "{what} is not available for overlay functions: {} ({}) lies in overlay {overlay}, and the              decomp-legacy plugin takes flat: and seg: addresses only; use `decovery diagnose` without --deep",
            function.name, function.address
        ))),
        None => Ok(()),
    }
}

pub(super) fn function_of(session: &Session, target: &str) -> Result<Function, FacadeError> {
    let trimmed = target.trim();
    if let Some(r) = session
        .rebuild
        .iter()
        .find(|r| r.address.to_string() == trimmed)
    {
        return Ok(Function {
            address: r.address,
            name: session
                .symbol_at(r.address)
                .map_or_else(|| r.name.clone(), |s| s.name.clone()),
        });
    }
    // an exact name of the knowledge wins over a rebuild record's name; several candidates are an error
    if let Some(address) = function_by_name(
        &session.workspace,
        Some(&session.analysis),
        &session.rebuild,
        trimmed,
    )? {
        let name = match session.symbol_at(address) {
            Some(s) => s.name.clone(),
            None => session
                .rebuild
                .iter()
                .find(|r| r.address == address)
                .map_or_else(|| session.name_of(address).name, |r| r.name.clone()),
        };
        return Ok(Function { address, name });
    }
    // a function symbol of the knowledge by its name or address (also outside the configured segments)
    if let Some(symbol) = session.workspace.symbols.iter().find(|s| {
        s.kind == SymbolKind::Function
            && s.confidence != Confidence::Refuted
            && (s.name == trimmed || s.address.to_string() == trimmed)
    }) {
        return Ok(Function {
            address: symbol.address,
            name: symbol.name.clone(),
        });
    }
    let address = resolve(session, target)?.function;
    Ok(Function {
        address,
        name: session.name_of(address).name,
    })
}

/// The options as `legacy/run` takes them, after checking that `operation` takes each one.
fn options_json(
    root: &Path,
    operation: LegacyOperation,
    options: &LegacyOptions,
) -> Result<Map<String, Value>, FacadeError> {
    let mut out = Map::new();
    let mut set = |name: &str, value: Value| {
        if operation.allows(name) {
            out.insert(name.to_string(), value);
            Ok(())
        } else {
            Err(FacadeError::Invalid(format!(
                "option {name} does not apply to {}",
                operation.id()
            )))
        }
    };
    if let Some(minutes) = options.minutes {
        if !(minutes.is_finite() && minutes > 0.0) {
            return Err(FacadeError::Invalid(format!(
                "minutes must be a positive number, got {minutes}"
            )));
        }
        set("minutes", json!(minutes))?;
    }
    if let Some(rounds) = options.rounds {
        if rounds == 0 {
            return Err(FacadeError::Invalid("rounds must be at least 1".into()));
        }
        set("rounds", json!(rounds))?;
    }
    if let Some(source) = &options.source {
        let path = source_path(root, source)?;
        set("source", json!(path.to_string_lossy()))?;
    }
    if options.all {
        set("all", json!(true))?;
    }
    if let Some(run) = &options.run {
        if run.trim().is_empty() {
            return Err(FacadeError::Invalid("the run name is empty".into()));
        }
        set("run", json!(run))?;
    }
    Ok(out)
}

/// `source` as an absolute path of an existing file: relative to the current directory, else to the workspace root.
fn source_path(root: &Path, source: &Path) -> Result<PathBuf, FacadeError> {
    let candidates = if source.is_absolute() {
        vec![source.to_path_buf()]
    } else {
        let mut list = Vec::new();
        if let Ok(cwd) = std::path::absolute(source) {
            list.push(cwd);
        }
        list.push(root.join(source));
        list
    };
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| FacadeError::Invalid(format!("source {} not found", source.display())))
}

/// decovery's function and global names, as `legacy/run` takes them.
fn symbols_json(ws: &Workspace) -> Vec<Value> {
    ws.symbols
        .iter()
        .filter(|s| s.confidence != Confidence::Refuted && !s.name.is_empty())
        .filter_map(|s| {
            let kind = match s.kind {
                SymbolKind::Function => "function",
                SymbolKind::Global => "global",
                _ => return None,
            };
            Some(json!({"address": s.address.to_string(), "kind": kind, "name": s.name}))
        })
        .collect()
}

/// The time an operation may take: `minutes` (times the steps of a chain) plus start-up, at least the base.
fn timeout_s(operation: LegacyOperation, minutes: Option<f64>) -> u64 {
    let Some(minutes) = minutes else {
        return BASE_TIMEOUT_S;
    };
    // a chain runs several search steps, each with the budget
    let factor = if operation == LegacyOperation::Chain {
        8.0
    } else {
        2.0
    };
    let seconds = (minutes * 60.0 * factor).min(7.0 * 24.0 * 3600.0) as u64 + 600;
    seconds.max(BASE_TIMEOUT_S)
}

/// The Decomp workspace of `[legacy]`, absolute, checked to hold `decomp.toml`.
fn decomp_workspace(ws: &Workspace) -> Result<PathBuf, FacadeError> {
    let text = ws
        .config
        .legacy
        .as_ref()
        .and_then(|l| l.decomp_workspace.as_deref())
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| FacadeError::Invalid(NO_LEGACY.into()))?;
    let path = Path::new(text);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        ws.root.join(path)
    };
    if !path.join("decomp.toml").is_file() {
        return Err(FacadeError::Invalid(format!(
            "{} is not a Decomp workspace (no decomp.toml); check [legacy] decomp_workspace in decovery.toml",
            path.display()
        )));
    }
    Ok(path)
}

/// What `legacy/run` answered.
struct Answer {
    exit_code: i64,
    report: String,
    report_language: String,
    json: Value,
    candidate: Option<(PathBuf, String)>,
    artifacts: Vec<String>,
    shadow: Value,
    seconds: f64,
}

fn parse_answer(result: Value) -> Result<Answer, FacadeError> {
    let bad =
        |what: &str| FacadeError::Plugin(format!("{LEGACY_PLUGIN}: bad legacy/run result: {what}"));
    if !result.is_object() {
        return Err(bad("not an object"));
    }
    let candidate = match &result["candidate"] {
        Value::Null => None,
        c => {
            let path = c["path"]
                .as_str()
                .ok_or_else(|| bad("candidate without path"))?;
            let kind = c["kind"].as_str().unwrap_or("module");
            if kind != "module" && kind != "function" {
                return Err(bad(&format!("candidate kind {kind:?}")));
            }
            Some((PathBuf::from(path), kind.to_string()))
        }
    };
    Ok(Answer {
        exit_code: result["exit_code"].as_i64().unwrap_or(0),
        report: result["report"].as_str().unwrap_or_default().to_string(),
        report_language: result["report_language"]
            .as_str()
            .unwrap_or("de")
            .to_string(),
        json: result["json"].clone(),
        candidate,
        artifacts: result["artifacts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str().map(String::from))
            .collect(),
        shadow: result["shadow"].clone(),
        seconds: result["seconds"].as_f64().unwrap_or(0.0),
    })
}

/// Checks the call, builds the `legacy/run` params and runs them.
fn run_bridge(
    root: &Path,
    session: &Session,
    function: &Function,
    call: &LegacyCall,
    control: &Control,
) -> Result<Answer, FacadeError> {
    control.check()?;
    let progress = control.progress;
    let ws = &session.workspace;
    let options = options_json(root, call.operation, &call.options)?;
    let decomp = decomp_workspace(ws)?;
    let config = {
        let user = match &call.user_plugins {
            Some(user) => user.clone(),
            None if ws.config.plugins.contains_key(LEGACY_PLUGIN) => BTreeMap::new(),
            None => read_user_plugins()?,
        };
        plugin_config(ws, &user, LEGACY_PLUGIN)
            .ok_or_else(|| FacadeError::Plugin(NO_PLUGIN.into()))?
    };
    let timeout = timeout_s(call.operation, call.options.minutes);
    let params = json!({
        "decomp_workspace": decomp.to_string_lossy(),
        "shadow_dir": root.join(SHADOW_DIR).to_string_lossy(),
        "sources_dir": root.join(SOURCE_DIR).to_string_lossy(),
        "symbols": symbols_json(ws),
        "operation": call.operation.id(),
        "function": function.address.to_string(),
        "options": options,
        "timeout_s": timeout,
    });
    progress(Progress::new(
        0,
        None,
        Some(format!("Decomp {}: {}", call.operation.id(), function.name)),
    ));
    let result = call_plugin(
        root,
        &config,
        params,
        Duration::from_secs(timeout) + HOST_SLACK,
        control,
    )?;
    control.check()?;
    parse_answer(result)
}

/// Absolute workspace root, required to be UTF-8 (the paths go into JSON).
fn absolute_root(root: &Path) -> Result<PathBuf, FacadeError> {
    let root = std::path::absolute(root)
        .map_err(|e| FacadeError::Invalid(format!("bad workspace path: {e}")))?;
    if root.to_str().is_none() {
        return Err(FacadeError::Invalid(
            "the workspace path is not valid UTF-8".into(),
        ));
    }
    Ok(root)
}

fn check_tool(call: &LegacyCall, tool: Tool, what: &str) -> Result<(), FacadeError> {
    if call.operation.tool() != tool {
        return Err(FacadeError::Invalid(format!(
            "{} is not {what}",
            call.operation.id()
        )));
    }
    if call.apply && tool != Tool::Search {
        return Err(FacadeError::Invalid("apply only applies to search".into()));
    }
    Ok(())
}

// -- shared response parts -----------------------------------------------------------------------------------

/// Report, Decomp's JSON and the run facts; text over the budget goes into handles.
fn answer_data(
    root: &Path,
    answer: &Answer,
    function: &Function,
    budget: Budget,
    handles: &mut Vec<Handle>,
) -> Result<Map<String, Value>, FacadeError> {
    let mut data = Map::new();
    data.insert(
        "function".into(),
        json!({"address": function.address.to_string(), "name": function.name}),
    );
    data.insert("backend".into(), json!(LEGACY_PLUGIN));
    let report = if answer.report.chars().count() > budget.chars {
        let mut handle = store_handle(root, "legacy-report", &answer.report)?;
        handle.description = format!("Decomp's report on {} (German)", function.name);
        let cut = cut_lines(&answer.report, budget.chars, &handle.id);
        data.insert("report_handle".into(), json!(handle.id));
        handles.push(handle);
        cut
    } else {
        answer.report.clone()
    };
    data.insert("report".into(), json!(report));
    data.insert("report_language".into(), json!(answer.report_language));
    let json_text = answer.json.to_string();
    if !answer.json.is_null() && json_text.chars().count() > budget.chars {
        let pretty = serde_json::to_string_pretty(&answer.json).unwrap_or(json_text);
        let mut handle = store_handle(root, "legacy-json", &pretty)?;
        handle.description = format!("Decomp's JSON on {}", function.name);
        data.insert("json".into(), Value::Null);
        data.insert("json_handle".into(), json!(handle.id));
        handles.push(handle);
    } else {
        data.insert("json".into(), answer.json.clone());
    }
    data.insert("artifacts".into(), json!(answer.artifacts));
    data.insert("shadow".into(), answer.shadow.clone());
    data.insert("exit_code".into(), json!(answer.exit_code));
    data.insert("seconds".into(), json!(answer.seconds));
    Ok(data)
}

/// The whole lines of `text` that fit into `chars`, then the marker.
fn cut_lines(text: &str, chars: usize, id: &str) -> String {
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
    out.push_str(&format!("… truncated; full report: detail {id}\n"));
    out
}

fn report_lines(answer: &Answer) -> usize {
    answer.report.lines().count()
}

// -- diagnose --deep -----------------------------------------------------------------------------------------

/// `diagnose` with `deep`: Decomp's report for `call.operation` (`context`, `structure`, `registers`, `slots`,
/// `joint`) next to decovery's own diagnosis (or why there is none, e.g. no object yet).
pub fn diagnose_deep(
    root: &Path,
    call: &LegacyCall,
    control: &Control,
) -> Result<Response, FacadeError> {
    check_tool(call, Tool::Diagnose, "a deep diagnosis")?;
    let root = absolute_root(root)?;
    let session = Session::open(&root)?;
    let function = function_of(&session, &call.target)?;
    no_overlay(&function, "deep diagnosis (--deep)")?;
    let answer = run_bridge(&root, &session, &function, call, control)?;
    let mut handles = Vec::new();
    let mut data = answer_data(&root, &answer, &function, call.budget, &mut handles)?;
    data.insert("operation".into(), json!(call.operation.id()));
    let own = match diagnose_tool(&session, &call.target, call.budget) {
        Ok(response) => {
            handles.extend(response.handles);
            json!({"summary": response.summary, "data": response.data})
        }
        Err(e) => json!({"error": e.to_string()}),
    };
    let own_summary = own["summary"]
        .as_str()
        .or_else(|| own["error"].as_str())
        .unwrap_or_default()
        .to_string();
    data.insert("decovery".into(), own);
    let mut response = Response::new(
        format!(
            "{}: Decomp {} report ({} lines, {:.0} s); decovery: {own_summary}",
            function.name,
            call.operation.id(),
            report_lines(&answer),
            answer.seconds
        ),
        Value::Object(data),
    );
    response.handles = handles;
    Ok(response)
}

// -- search --------------------------------------------------------------------------------------------------

/// `search`: runs Decomp's search (`chain`, `permute`, `beam`, `forms`). A candidate it returns is built by decovery
/// as a function-level attempt next to the function's current source (both in one `build` call with variants), so
/// the verdict is decovery's. With `apply`, a candidate whose verdict is better (identical, or fewer differing
/// instructions) is spliced into the function's file in `src/` and recorded by a normal build; otherwise nothing in
/// `src/` changes.
pub fn search(root: &Path, call: &LegacyCall, control: &Control) -> Result<Response, FacadeError> {
    check_tool(call, Tool::Search, "a search strategy")?;
    let root = absolute_root(root)?;
    let session = Session::open(&root)?;
    let function = function_of(&session, &call.target)?;
    no_overlay(&function, "Decomp's search")?;
    let answer = run_bridge(&root, &session, &function, call, control)?;
    let mut handles = Vec::new();
    let mut data = answer_data(&root, &answer, &function, call.budget, &mut handles)?;
    data.insert("strategy".into(), json!(call.operation.id()));
    let decomp_part = format!(
        "{}: Decomp {} ({:.0} s)",
        function.name,
        call.operation.id(),
        answer.seconds
    );
    let Some((path, kind)) = &answer.candidate else {
        data.insert("candidate".into(), Value::Null);
        let mut response =
            Response::new(format!("{decomp_part}: no candidate"), Value::Object(data));
        response.handles = handles;
        return Ok(response);
    };
    let mut extra = Map::new();
    if let Some(report) = report_artifact(&answer.artifacts) {
        extra.insert("decomp_report".into(), json!(report));
    }
    let record = RecordAs {
        origin: Some(AttemptOrigin::Search),
        label: Some(format!("search:{}", call.operation.id())),
        skip_labels: vec!["current".to_string()],
        extra,
    };
    let judged = judge_candidate(&root, &function, path, kind, call.apply, record, control)?;
    let summary = format!("{decomp_part}: {}", judged.summary);
    data.insert("candidate".into(), judged.data);
    let mut response = Response::new(summary, Value::Object(data));
    response.handles = handles;
    Ok(response)
}

struct Judged {
    summary: String,
    data: Value,
}

/// The artifact that holds Decomp's report (`ergebnis.txt`), else the first artifact.
fn report_artifact(artifacts: &[String]) -> Option<&str> {
    artifacts
        .iter()
        .find(|a| a.replace('\\', "/").ends_with("/ergebnis.txt"))
        .or(artifacts.first())
        .map(String::as_str)
}

/// A text file as UTF-8, else code page 437 (what Decomp's rebuild sources may be), with LF line ends.
fn read_candidate(path: &Path) -> Result<String, FacadeError> {
    let bytes = std::fs::read(path).map_err(|e| {
        FacadeError::Plugin(format!(
            "{LEGACY_PLUGIN}: cannot read the candidate {}: {e}",
            path.display()
        ))
    })?;
    let text = String::from_utf8(bytes).unwrap_or_else(|e| from_cp437(e.as_bytes()));
    Ok(text.replace("\r\n", "\n"))
}

/// The definition of `name` in `text`, when it defines it exactly once.
fn definition_of(text: &str, name: &str) -> Option<String> {
    let found: Vec<_> = definitions(text)
        .into_iter()
        .filter(|d| d.name == name)
        .collect();
    match found.as_slice() {
        [one] => Some(text[one.start..one.end].to_string()),
        _ => None,
    }
}

/// `true` when `candidate` is better than `current` (variant JSON of `build`): it was compared, has no inline
/// assembly, and is closer to identical by the one distance of the core (`decovery_core::distance_of`).
fn better(candidate: &Value, current: &Value) -> bool {
    let distance = |v: &Value| {
        let verdict = serde_json::from_value::<VerdictId>(v["verdict"].clone()).ok();
        let differing = v["instructions_differing"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok());
        // The variant JSON has no Decomp result; only the verdict says whether it was compared.
        distance_of(RebuildResult::Error, verdict, differing)
    };
    let cheat = candidate["blockers"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|b| b["kind"] == "inline-assembly");
    let Some(candidate) = distance(candidate).filter(|_| !cheat) else {
        return false;
    };
    distance(current).is_none_or(|current| candidate < current)
}

fn verdict_text(v: &Value) -> String {
    format!(
        "{} ({} instructions differ)",
        v["verdict"].as_str().unwrap_or("?"),
        v["instructions_differing"]
    )
}

/// Builds the candidate next to the current source and, with `apply`, writes it when it is better. Only the
/// candidate is recorded as an attempt (`record`); the follow-up build of an applied candidate repeats that attempt
/// and appends nothing. A cancel before the candidate is written leaves `src/` unchanged and records nothing; once it
/// is written, its follow-up build is not interrupted.
fn judge_candidate(
    root: &Path,
    function: &Function,
    path: &Path,
    kind: &str,
    apply: bool,
    record: RecordAs,
    control: &Control,
) -> Result<Judged, FacadeError> {
    let progress = control.progress;
    let name = function.name.as_str();
    let candidate_text = read_candidate(path)?;
    let file = file_of_function(root, name)?;
    let file_path = root.join(SOURCE_DIR).join(&file);
    let raw = read_text(&file_path)?;
    let crlf = raw.contains("\r\n");
    let current_text = raw.replace("\r\n", "\n");

    // a function-level attempt when the function can be taken from the candidate, else the whole file
    let candidate_def = match kind {
        "function" => Some(candidate_text.clone()),
        _ => definition_of(&candidate_text, name),
    };
    let current_def = definition_of(&current_text, name);
    let (evaluated_as, variants) = match (&candidate_def, &current_def) {
        (Some(candidate), Some(current)) => (
            "function",
            vec![
                Variant::function(current.clone()).with_label("current"),
                Variant::function(candidate.clone()).with_label("candidate"),
            ],
        ),
        _ => (
            "module",
            vec![
                Variant::new(current_text.clone()).with_label("current"),
                Variant::new(candidate_text.clone()).with_label("candidate"),
            ],
        ),
    };
    let request = BuildRequest {
        function: Some(name.to_string()),
        files: vec![file.clone()],
        variants,
        record,
        ..BuildRequest::default()
    };
    progress(Progress::new(
        0,
        None,
        Some(format!("building the candidate for {name}")),
    ));
    let ranked = build(root, &request, control)?;
    let by_label = |label: &str| {
        ranked.data["variants"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|v| v["label"] == label)
            .cloned()
            .unwrap_or(Value::Null)
    };
    let current = by_label("current");
    let candidate = by_label("candidate");
    let improved = better(&candidate, &current);

    let mut applied = false;
    let mut build_result = Value::Null;
    let note = if !apply {
        if improved {
            "better than the current source; pass apply to write it into src/".to_string()
        } else {
            "not better than the current source".to_string()
        }
    } else if !improved {
        "not applied: decovery's verdict on the candidate is not better than on the current source"
            .to_string()
    } else if evaluated_as != "function" {
        format!(
            "not applied: the candidate's definition of {name} could not be taken from the file; it was judged as a whole file"
        )
    } else {
        let definition = candidate_def.as_deref().unwrap_or_default();
        let spliced = splice_function(&current_text, name, definition)
            .map_err(|e| FacadeError::Invalid(format!("cannot apply the candidate: {e}")))?;
        let text = if crlf {
            spliced.replace('\n', "\r\n")
        } else {
            spliced
        };
        control.check()?;
        write_atomic(&file_path, text.as_bytes()).map_err(|source| FacadeError::Output {
            path: file_path.clone(),
            source,
        })?;
        applied = true;
        let request = BuildRequest {
            function: Some(name.to_string()),
            files: vec![file.clone()],
            ..BuildRequest::default()
        };
        let built = build(root, &request, &Control::progress_only(progress))?;
        let record = built.data["functions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|f| f["name"] == name)
            .cloned()
            .unwrap_or(Value::Null);
        build_result = json!({"summary": built.summary, "function": record});
        format!("applied to {SOURCE_DIR}/{file} and recorded")
    };
    let summary = format!(
        "candidate {} vs current {}; {note}",
        verdict_text(&candidate),
        verdict_text(&current)
    );
    Ok(Judged {
        summary,
        data: json!({
            "path": path.to_string_lossy(),
            "kind": kind,
            "file": file,
            "evaluated_as": evaluated_as,
            "verdict": candidate,
            "current": current,
            "improved": improved,
            "applied": applied,
            "note": note,
            "build": build_result,
        }),
    })
}

// -- verify --------------------------------------------------------------------------------------------------

/// `verify`: Decomp's equivalence or behaviour check. Its result is reported as `evidence` with
/// `source = "decomp"`; nothing is recorded as a decovery verdict.
pub fn verify(root: &Path, call: &LegacyCall, control: &Control) -> Result<Response, FacadeError> {
    check_tool(call, Tool::Verify, "a check")?;
    let root = absolute_root(root)?;
    let session = Session::open(&root)?;
    let function = function_of(&session, &call.target)?;
    no_overlay(&function, "Decomp's verify")?;
    let answer = run_bridge(&root, &session, &function, call, control)?;
    let mut handles = Vec::new();
    let mut data = answer_data(&root, &answer, &function, call.budget, &mut handles)?;
    data.insert("check".into(), json!(call.operation.id()));
    let finding = decomp_verdict(&answer.json, 3);
    data.insert(
        "evidence".into(),
        json!({
            "source": "decomp",
            "check": call.operation.id(),
            "decomp_verdict": finding,
            "note": "evidence from Decomp, not a decovery verdict; nothing was recorded",
        }),
    );
    let outcome = finding.map_or_else(
        || format!("report ({} lines)", report_lines(&answer)),
        |v| format!("Decomp says {v}"),
    );
    let mut response = Response::new(
        format!(
            "{}: Decomp {}: {outcome} (evidence, not a decovery verdict)",
            function.name,
            call.operation.id()
        ),
        Value::Object(data),
    );
    response.handles = handles;
    Ok(response)
}

/// The first text under a key `verdict` or `urteil` (Decomp's name) in `json`, searched `depth` levels deep.
fn decomp_verdict(json: &Value, depth: u32) -> Option<String> {
    match json {
        Value::Object(map) => {
            for key in ["verdict", "urteil"] {
                if let Some(text) = map.get(key).and_then(Value::as_str) {
                    return Some(text.to_string());
                }
            }
            if depth == 0 {
                return None;
            }
            map.values().find_map(|v| decomp_verdict(v, depth - 1))
        }
        Value::Array(items) if depth > 0 => items.iter().find_map(|v| decomp_verdict(v, depth - 1)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_round_trip_and_belong_to_one_tool() {
        for op in LegacyOperation::ALL {
            assert_eq!(LegacyOperation::parse(op.id()), Some(op));
        }
        assert_eq!(LegacyOperation::parse("vergabe"), None);
        assert_eq!(LegacyOperation::Registers.tool(), Tool::Diagnose);
        assert_eq!(LegacyOperation::Beam.tool(), Tool::Search);
        assert_eq!(LegacyOperation::Behavior.tool(), Tool::Verify);
    }

    #[test]
    fn options_follow_the_protocol_table() {
        let root = Path::new(".");
        let mut o = LegacyOptions {
            minutes: Some(2.5),
            rounds: Some(3),
            ..LegacyOptions::default()
        };
        let chain = options_json(root, LegacyOperation::Chain, &o).unwrap();
        assert_eq!(Value::Object(chain), json!({"minutes": 2.5, "rounds": 3}));
        let error = options_json(root, LegacyOperation::Context, &o).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("minutes does not apply to context")
        );
        o = LegacyOptions {
            all: true,
            ..LegacyOptions::default()
        };
        assert!(options_json(root, LegacyOperation::Registers, &o).is_ok());
        assert!(options_json(root, LegacyOperation::Slots, &o).is_err());
        o = LegacyOptions {
            run: Some("login".into()),
            ..LegacyOptions::default()
        };
        assert!(options_json(root, LegacyOperation::Behavior, &o).is_ok());
        assert!(options_json(root, LegacyOperation::Equivalence, &o).is_err());
        o = LegacyOptions {
            minutes: Some(0.0),
            ..LegacyOptions::default()
        };
        assert!(options_json(root, LegacyOperation::Chain, &o).is_err());
        o = LegacyOptions {
            source: Some(PathBuf::from("does/not/exist.c")),
            ..LegacyOptions::default()
        };
        let error = options_json(root, LegacyOperation::Registers, &o).unwrap_err();
        assert!(error.to_string().contains("not found"), "{error}");
    }

    #[test]
    fn timeouts_grow_with_the_budget() {
        assert_eq!(timeout_s(LegacyOperation::Context, None), BASE_TIMEOUT_S);
        assert_eq!(
            timeout_s(LegacyOperation::Permute, Some(1.0)),
            BASE_TIMEOUT_S
        );
        assert_eq!(timeout_s(LegacyOperation::Permute, Some(10.0)), 1800);
        assert_eq!(timeout_s(LegacyOperation::Chain, Some(10.0)), 5400);
    }

    #[test]
    fn better_needs_a_compared_candidate_without_inline_assembly() {
        let v = |verdict: &str, n: u64| json!({"verdict": verdict, "instructions_differing": n, "blockers": []});
        assert!(better(&v("identical", 0), &v("differs", 3)));
        assert!(better(&v("differs", 2), &v("differs", 3)));
        assert!(!better(&v("differs", 3), &v("differs", 3)));
        assert!(!better(&v("identical", 0), &v("identical", 0)));
        assert!(!better(&v("error", 0), &v("differs", 3)));
        assert!(better(&v("differs", 9), &v("error", 0)));
        let cheat = json!({"verdict": "differs", "instructions_differing": 0,
            "blockers": [{"kind": "inline-assembly"}]});
        assert!(!better(&cheat, &v("differs", 3)));
    }

    #[test]
    fn decomp_verdicts_are_found_in_nested_json() {
        assert_eq!(
            decomp_verdict(
                &json!({"funktionen": [{"urteil": "gleichwertig_belegt"}]}),
                3
            )
            .as_deref(),
            Some("gleichwertig_belegt")
        );
        assert_eq!(
            decomp_verdict(&json!({"verdict": "x"}), 0).as_deref(),
            Some("x")
        );
        assert_eq!(decomp_verdict(&Value::Null, 3), None);
    }

    #[test]
    fn plugin_errors_name_the_fix() {
        let remote = |code, data| PluginError::Remote {
            code,
            message: "boom".into(),
            data,
        };
        let text = bridge_error(remote(-32020, None)).to_string();
        assert!(text.contains("setup decomp-legacy"), "{text}");
        let text = bridge_error(remote(-32021, None)).to_string();
        assert!(text.contains("[legacy] decomp_workspace"), "{text}");
        let text = bridge_error(remote(
            -32022,
            Some(json!({"exit_code": 3, "stderr_tail": "Traceback\nKeyError\n"})),
        ))
        .to_string();
        assert!(
            text.contains("exit code 3") && text.ends_with("KeyError"),
            "{text}"
        );
        assert!(matches!(
            bridge_error(remote(-32602, None)),
            FacadeError::Invalid(_)
        ));
    }
}
