//! `analyze`: run an analyzer plugin (analyzer v2 + decompiler v2, e.g. Ghidra) over the target and store its
//! results as the workspace analysis, then regenerate the output.
//!
//! Flow: lock, load the program, spawn the plugin, `analyzer/open` (project in `cache/<plugin>/`),
//! `analyzer/apply` (knowledge), `analyzer/export`, `decompiler/decompile` in batches, shut the plugin down,
//! save `knowledge/analysis/` and write the output.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_core::{
    Address, Analysis, AnalyzedFunction, CallEdge, Confidence, DataAccess, Program, Provider,
    ReferenceKind, StringItem, Symbol, SymbolKind, Workspace, WorkspaceLock, knowledge_hash,
    read_rebuild, read_references, write_atomic,
};
use decovery_plugin::protocol::INLINE_LIMIT;
use decovery_plugin::{Blob, CallOptions, PluginError, PluginHost, PluginInfo, Progress};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::plugins::{PluginConfig, plugin_config, read_user_plugins};
use crate::{FacadeError, Response, Session, resolve, write_all};

const LOCK_WAIT: Duration = Duration::from_secs(10);
/// Building and analyzing a large program in Ghidra takes long.
const OPEN_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const STEP_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// The plugin's per-function decompiler timeout, plus slack per batch.
const PER_FUNCTION: Duration = Duration::from_secs(60);
const BATCH: usize = 200;
/// Large region blobs, by blake3, relative to the workspace root.
const BLOBS_DIR: &str = "cache/blobs";
const NO_ANALYZER: &str = "no analyzer configured; run decovery setup ghidra";
const ANALYZER_VERSION: u32 = 2;
const DECOMPILER_VERSION: u32 = 2;
const EXPORT_SCHEMA: u32 = 1;

/// What `analyze` runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzeOptions {
    /// Plugin name as in `[plugins.<name>]`.
    pub plugin: String,
    /// Targets (names, addresses, `file:0x…`) whose bodies are decompiled again; `None`: all functions.
    pub functions: Option<Vec<String>>,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        AnalyzeOptions {
            plugin: "ghidra".into(),
            functions: None,
        }
    }
}

/// Runs the analyzer plugin over the workspace target and stores the analysis (see the module docs).
///
/// The plugin comes from `decovery.toml [plugins.<name>]`, else from the user config. With a selection only the
/// selected functions' bodies are replaced; functions, calls, strings and data accesses are always refreshed.
pub fn analyze(
    root: &Path,
    options: &AnalyzeOptions,
    progress: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    let workspace = Workspace::open(root)?;
    let user = if workspace.config.plugins.contains_key(&options.plugin) {
        BTreeMap::new()
    } else {
        read_user_plugins()?
    };
    analyze_with_user_plugins(root, options, &user, progress)
}

/// [`analyze`] with the user config's plugins given instead of read from the user config file.
pub fn analyze_with_user_plugins(
    root: &Path,
    options: &AnalyzeOptions,
    user: &BTreeMap<String, PluginConfig>,
    progress: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    let name = options.plugin.as_str();
    check_plugin_name(name)?;
    if options.functions.as_ref().is_some_and(Vec::is_empty) {
        return Err(FacadeError::Invalid("empty function selection".into()));
    }
    let root = std::path::absolute(root)
        .map_err(|e| FacadeError::Invalid(format!("bad workspace path: {e}")))?;
    if root.to_str().is_none() {
        return Err(FacadeError::Invalid(
            "the workspace path is not valid UTF-8".into(),
        ));
    }
    let workspace = Workspace::open(&root)?;
    let config = plugin_config(&workspace, user, name).ok_or_else(|| no_config(name))?;
    if config.command.is_empty() {
        return Err(FacadeError::Plugin(format!(
            "{name}: [plugins.{name}] command is empty"
        )));
    }
    let lock = workspace.lock(LOCK_WAIT)?;
    // Read everything again under the lock.
    let workspace = Workspace::open(&root)?;
    let target = workspace.config.target.sha256.clone();
    let old = Analysis::load(&root)?.filter(|a| a.target_sha256 == target);
    let program = crate::program::load(&workspace)?;
    let knowledge = knowledge_hash(&root)?;
    let apply = apply_params(&workspace)?;
    let program_hash = blake3_hex(program_description(&program).to_string().as_bytes());
    let description = materialize(&root, &program)?;
    let project_dir = root.join("cache").join(name);

    let command: Vec<OsString> = config.command.iter().map(OsString::from).collect();
    let env: Vec<(OsString, OsString)> = config
        .env
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
    progress(stage(&format!("starting {name}")));
    let host =
        PluginHost::spawn_with_env(&command, &root, &env).map_err(|e| plugin_error(name, e))?;
    let request = RunRequest {
        name,
        root: &root,
        workspace: &workspace,
        project_dir: &project_dir,
        description,
        program_hash,
        calling_convention: workspace.config.analysis.calling_convention.clone(),
        apply,
        selection: options.functions.as_deref(),
        progress,
    };
    let outcome = drive(&host, &request);
    let shutdown = host.shutdown();
    let mut outcome = outcome?;
    if let Err(e) = shutdown {
        outcome.warnings.push(format!("{name}: shutdown: {e}"));
    }
    store(
        &root,
        &lock,
        old.as_ref(),
        &target,
        &knowledge,
        outcome,
        progress,
    )
}

struct RunRequest<'a> {
    name: &'a str,
    root: &'a Path,
    workspace: &'a Workspace,
    project_dir: &'a Path,
    description: Value,
    program_hash: String,
    calling_convention: Option<String>,
    apply: Value,
    selection: Option<&'a [String]>,
    progress: &'a dyn Fn(Progress),
}

/// One decompiled (or failed) function.
struct Decompiled {
    start: Address,
    body: String,
    error: Option<String>,
}

struct Outcome {
    info: PluginInfo,
    export: ExportFile,
    /// The selected function starts; `None` for a full run.
    selection: Option<BTreeSet<Address>>,
    decompiled: Vec<Decompiled>,
    warnings: Vec<String>,
}

#[derive(Deserialize)]
struct ExportFile {
    schema: u32,
    #[serde(default)]
    functions: Vec<ExportFunction>,
    #[serde(default)]
    calls: Vec<CallEdge>,
    #[serde(default)]
    strings: Vec<StringItem>,
    #[serde(default)]
    data_accesses: Vec<DataAccess>,
}

#[derive(Deserialize)]
struct ExportFunction {
    start: Address,
    end: Address,
    body_size: u32,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct DecompileEntry {
    address: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    disassembly: Vec<(String, String)>,
}

/// All plugin calls; the caller shuts the plugin down afterwards, also on error.
fn drive(host: &PluginHost, r: &RunRequest<'_>) -> Result<Outcome, FacadeError> {
    let name = r.name;
    let info = host.info().clone();
    for (capability, version) in [
        ("analyzer", ANALYZER_VERSION),
        ("decompiler", DECOMPILER_VERSION),
    ] {
        let found = info.capabilities.get(capability).copied();
        if found != Some(version) {
            return Err(FacadeError::Plugin(format!(
                "{name}: needs capability {capability} v{version}, the plugin offers {}",
                found.map_or_else(|| "none".to_string(), |v| format!("v{v}"))
            )));
        }
    }
    let call = |method: &str, params: Value, timeout: Duration, sink: &dyn Fn(Progress)| {
        host.call(
            method,
            params,
            CallOptions {
                timeout,
                cancel: None,
                on_progress: Some(sink),
            },
        )
        .map_err(|e| plugin_error(name, e))
    };
    let project_text = path_text(r.project_dir);

    (r.progress)(stage("opening program"));
    let mut options = Map::new();
    if let Some(cc) = &r.calling_convention {
        options.insert("calling_convention".into(), json!(cc));
    }
    let open_sink = labelled(r.progress, "analyzing");
    call(
        "analyzer/open",
        json!({
            "program": r.description,
            "project_dir": project_text,
            "program_hash": r.program_hash,
            "options": options,
        }),
        OPEN_TIMEOUT,
        &open_sink,
    )?;

    (r.progress)(stage("applying knowledge"));
    let applied = call(
        "analyzer/apply",
        r.apply.clone(),
        STEP_TIMEOUT,
        &labelled(r.progress, "applying knowledge"),
    )?;
    let mut warnings: Vec<String> = applied["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w.as_str().map(String::from))
        .collect();

    (r.progress)(stage("exporting analysis"));
    let out_path = r.project_dir.join("export.json");
    let exported = call(
        "analyzer/export",
        json!({"out_path": path_text(&out_path)}),
        STEP_TIMEOUT,
        &labelled(r.progress, "exporting analysis"),
    )?;
    let export = read_export(name, &out_path, &exported)?;

    let selection = match r.selection {
        Some(targets) => Some(resolve_selection(r, &export, targets)?),
        None => None,
    };
    let addresses: Vec<Address> = match &selection {
        Some(set) => set.iter().copied().collect(),
        None => {
            let set: BTreeSet<Address> = export.functions.iter().map(|f| f.start).collect();
            set.into_iter().collect()
        }
    };

    let out_dir = r.project_dir.join("decompiled");
    let total = addresses.len() as u64;
    let mut decompiled = Vec::with_capacity(addresses.len());
    for (index, batch) in addresses.chunks(BATCH).enumerate() {
        let offset = (index * BATCH) as u64;
        (r.progress)(Progress::new(
            offset,
            Some(total),
            Some("decompiling".into()),
        ));
        let sink = |p: Progress| {
            let message = p
                .message
                .clone()
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "decompiling".into());
            (r.progress)(Progress::new(offset + p.done, Some(total), Some(message)));
        };
        let timeout = PER_FUNCTION * (batch.len() as u32) + PER_FUNCTION;
        let result = call(
            "decompiler/decompile",
            json!({
                "addresses": batch.iter().map(Address::to_string).collect::<Vec<_>>(),
                "out_dir": path_text(&out_dir),
            }),
            timeout,
            &sink,
        )?;
        let entries: Vec<DecompileEntry> = serde_json::from_value(result).map_err(|e| {
            FacadeError::Plugin(format!("{name}: bad decompiler/decompile result: {e}"))
        })?;
        decompiled.extend(collect_batch(name, batch, entries, &mut warnings)?);
    }
    (r.progress)(Progress::new(total, Some(total), Some("decompiled".into())));
    Ok(Outcome {
        info,
        export,
        selection,
        decompiled,
        warnings,
    })
}

/// Pairs the plugin's entries with the requested addresses (request order); reads the written C files.
fn collect_batch(
    name: &str,
    batch: &[Address],
    entries: Vec<DecompileEntry>,
    warnings: &mut Vec<String>,
) -> Result<Vec<Decompiled>, FacadeError> {
    let requested: HashSet<Address> = batch.iter().copied().collect();
    let mut by_address: HashMap<Address, DecompileEntry> = HashMap::new();
    for entry in entries {
        let at = entry.address.parse::<Address>().map_err(|e| {
            FacadeError::Plugin(format!(
                "{name}: bad address {:?} in decompile result: {e}",
                entry.address
            ))
        })?;
        if !requested.contains(&at) {
            warnings.push(format!(
                "{name}: decompile result for {at}, which was not requested; ignored"
            ));
        } else if let std::collections::hash_map::Entry::Vacant(slot) = by_address.entry(at) {
            slot.insert(entry);
        } else {
            warnings.push(format!(
                "{name}: duplicate decompile result for {at}; the first is used"
            ));
        }
    }
    let mut out = Vec::with_capacity(batch.len());
    for &start in batch {
        let decompiled = match by_address.remove(&start) {
            Some(DecompileEntry {
                path: Some(path),
                error: None,
                ..
            }) => {
                let bytes = std::fs::read(&path).map_err(|e| {
                    FacadeError::Plugin(format!("{name}: cannot read decompiled file {path}: {e}"))
                })?;
                Decompiled {
                    start,
                    body: String::from_utf8_lossy(&bytes).replace("\r\n", "\n"),
                    error: None,
                }
            }
            Some(entry) => {
                let error = entry
                    .error
                    .unwrap_or_else(|| "decompilation failed".to_string());
                Decompiled {
                    start,
                    body: failure_body(&error, &entry.disassembly),
                    error: Some(error),
                }
            }
            None => {
                let error = "the plugin returned no result".to_string();
                Decompiled {
                    start,
                    body: failure_body(&error, &[]),
                    error: Some(error),
                }
            }
        };
        out.push(decompiled);
    }
    Ok(out)
}

/// English counterpart of Decomp's failure body: error, then the disassembly as `<address>  <text>` lines.
fn failure_body(error: &str, disassembly: &[(String, String)]) -> String {
    let listing = if disassembly.is_empty() {
        "(not available)".to_string()
    } else {
        disassembly
            .iter()
            .map(|(at, text)| format!("{at}  {text}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "/* decompilation failed: {} */\n/* Disassembly:\n{}\n*/\n",
        safe(error),
        safe(&listing)
    )
}

fn safe(text: &str) -> String {
    text.replace("*/", "* /")
}

/// The selected targets resolved against the freshly exported functions.
fn resolve_selection(
    r: &RunRequest<'_>,
    export: &ExportFile,
    targets: &[String],
) -> Result<BTreeSet<Address>, FacadeError> {
    let session = Session {
        workspace: r.workspace.clone(),
        analysis: new_analysis(
            Provider::new("", ""),
            &r.workspace.config.target.sha256,
            "",
            export,
        ),
        rebuild: read_rebuild(r.root)?,
    };
    targets
        .iter()
        .map(|t| resolve(&session, t).map(|found| found.function))
        .collect()
}

fn new_analysis(
    provider: Provider,
    target: &str,
    knowledge: &str,
    export: &ExportFile,
) -> Analysis {
    let mut analysis = Analysis::new(provider, target, knowledge, super::annotate::today());
    analysis.functions = export
        .functions
        .iter()
        .map(|f| {
            let mut function = AnalyzedFunction::new(f.start, f.end, f.body_size);
            function.provider_name = f.name.clone();
            function
        })
        .collect();
    analysis.calls = export.calls.clone();
    analysis.strings = export.strings.clone();
    analysis.data_accesses = export.data_accesses.clone();
    analysis
}

fn read_export(name: &str, out_path: &Path, result: &Value) -> Result<ExportFile, FacadeError> {
    let path = result["path"]
        .as_str()
        .map_or_else(|| out_path.to_path_buf(), PathBuf::from);
    let bytes = std::fs::read(&path).map_err(|e| {
        FacadeError::Plugin(format!(
            "{name}: cannot read export {}: {e}",
            path.display()
        ))
    })?;
    if let Some(expected) = result["blake3"].as_str()
        && blake3_hex(&bytes) != expected
    {
        return Err(FacadeError::Plugin(format!(
            "{name}: export {} does not match its blake3",
            path.display()
        )));
    }
    let export: ExportFile = serde_json::from_slice(&bytes)
        .map_err(|e| FacadeError::Plugin(format!("{name}: bad export {}: {e}", path.display())))?;
    if export.schema != EXPORT_SCHEMA {
        return Err(FacadeError::Plugin(format!(
            "{name}: export schema {} is not supported (expected {EXPORT_SCHEMA})",
            export.schema
        )));
    }
    Ok(export)
}

/// Saves analysis and bodies, removes bodies of vanished functions (R9), writes the output.
fn store(
    root: &Path,
    lock: &WorkspaceLock,
    old: Option<&Analysis>,
    target: &str,
    knowledge: &str,
    outcome: Outcome,
    progress: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    progress(stage("saving analysis"));
    let provider = Provider::new(outcome.info.name.clone(), outcome.info.version.clone());
    let mut analysis = new_analysis(provider, target, knowledge, &outcome.export);
    let errors: HashMap<Address, Option<String>> = outcome
        .decompiled
        .iter()
        .map(|d| (d.start, d.error.clone()))
        .collect();
    let old_errors: HashMap<Address, Option<String>> = old
        .map(|a| {
            a.functions
                .iter()
                .map(|f| (f.start, f.decompile_error.clone()))
                .collect()
        })
        .unwrap_or_default();
    for f in &mut analysis.functions {
        f.decompile_error = match errors.get(&f.start) {
            Some(error) => error.clone(),
            None => old_errors.get(&f.start).cloned().flatten(),
        };
    }
    // Bodies first: an I/O failure part-way leaves the old analysis.json with old or new bodies, never the new
    // analysis with old bodies.
    for d in &outcome.decompiled {
        Analysis::save_decompiled(root, d.start, &d.body, lock)?;
    }
    analysis.save(root, lock)?;
    // R9: a full run removes the bodies of functions that are gone; a selection run never prunes.
    if outcome.selection.is_none() {
        let keep: HashSet<Address> = analysis.functions.iter().map(|f| f.start).collect();
        Analysis::remove_decompiled_except(root, &keep, lock)?;
    }

    progress(stage("writing output"));
    let session = Session::open(root)?;
    let report = write_all(&session, lock)?;
    let failed = outcome
        .decompiled
        .iter()
        .filter(|d| d.error.is_some())
        .count();
    let decompiled = outcome.decompiled.len() - failed;
    let summary = format!(
        "{} {}: {} functions, {decompiled} decompiled, {failed} failed; output: {} written, {} removed",
        analysis.provider.name,
        analysis.provider.version,
        analysis.functions.len(),
        report.written,
        report.removed
    );
    Ok(Response::new(
        summary,
        json!({
            "provider": analysis.provider.name,
            "version": analysis.provider.version,
            "functions": analysis.functions.len(),
            "calls": analysis.calls.len(),
            "strings": analysis.strings.len(),
            "data_accesses": analysis.data_accesses.len(),
            "decompiled": decompiled,
            "failed": failed,
            "written": report.written,
            "removed": report.removed,
            "warnings": outcome.warnings,
        }),
    ))
}

/// The `analyzer/apply` params from the knowledge: active symbols, `types.h`, references.
fn apply_params(workspace: &Workspace) -> Result<Value, FacadeError> {
    let symbols: Vec<Value> = workspace
        .symbols
        .iter()
        .filter(|s| s.confidence != Confidence::Refuted)
        .filter_map(symbol_value)
        .collect();
    let references: Vec<Value> = read_references(&workspace.root)?
        .iter()
        .filter_map(|r| {
            let kind = match r.kind {
                ReferenceKind::Call => "call",
                ReferenceKind::Jump => "jump",
                _ => return None,
            };
            Some(json!({"from": r.from.to_string(), "to": r.to.to_string(), "kind": kind}))
        })
        .collect();
    Ok(json!({
        "symbols": symbols,
        "types_h": workspace.types_h()?,
        "references": references,
    }))
}

fn symbol_value(s: &Symbol) -> Option<Value> {
    let kind = match s.kind {
        SymbolKind::Function => "function",
        SymbolKind::Global => "global",
        SymbolKind::Label => "label",
        _ => return None,
    };
    let mut v = Map::new();
    v.insert("address".into(), json!(s.address.to_string()));
    v.insert("kind".into(), json!(kind));
    let optional = [
        ("name", Some(&s.name)),
        ("signature", s.signature.as_ref()),
        ("comment", s.comment.as_ref()),
        ("data_type", s.data_type.as_ref()),
    ];
    for (key, value) in optional {
        if let Some(text) = value.filter(|t| !t.is_empty()) {
            v.insert(key.into(), json!(text));
        }
    }
    let locals: Vec<Value> = s
        .locals
        .iter()
        .map(|l| {
            let mut local = Map::new();
            local.insert("place".into(), json!(l.place));
            local.insert("name".into(), json!(l.name));
            if let Some(t) = &l.data_type {
                local.insert("data_type".into(), json!(t));
            }
            Value::Object(local)
        })
        .collect();
    v.insert("locals".into(), Value::Array(locals));
    let comments: Vec<Value> = s
        .line_comments
        .iter()
        .map(|c| json!({"address": c.address.to_string(), "text": c.text}))
        .collect();
    v.insert("line_comments".into(), Value::Array(comments));
    Some(Value::Object(v))
}

/// decovery's program description (design 5.11 item 5):
/// `{format, entry_points, regions: [{name, start, size, arch, permissions, blob}]}`.
///
/// Regions below 64 KiB carry their bytes inline; larger ones name `cache/blobs/<blake3>` relative to the
/// workspace root (`analyze` writes the file and sends the absolute path). The blake3 of this value's JSON text
/// is the `program_hash`, so it does not depend on where the workspace lies.
pub fn program_description(program: &Program) -> Value {
    describe(program, |data| region_blob(data, None))
}

/// The description as sent: large blobs written to `cache/blobs/` and named by absolute path.
fn materialize(root: &Path, program: &Program) -> Result<Value, FacadeError> {
    let dir = root.join(BLOBS_DIR);
    for region in &program.regions {
        if region.data.len() < INLINE_LIMIT {
            continue;
        }
        let path = dir.join(blake3_hex(&region.data));
        let present = std::fs::metadata(&path).is_ok_and(|m| m.len() == region.data.len() as u64);
        if !present {
            write_atomic(&path, &region.data)
                .map_err(|source| FacadeError::Output { path, source })?;
        }
    }
    Ok(describe(program, |data| region_blob(data, Some(&dir))))
}

fn describe(program: &Program, blob: impl Fn(&[u8]) -> Value) -> Value {
    let regions: Vec<Value> = program
        .regions
        .iter()
        .map(|r| {
            let p = r.permissions;
            let permissions: String = [(p.read, 'r'), (p.write, 'w'), (p.execute, 'x')]
                .iter()
                .map(|&(on, c)| if on { c } else { '-' })
                .collect();
            json!({
                "name": r.name,
                "start": r.start.to_string(),
                "size": r.virtual_size,
                "arch": r.arch,
                "permissions": permissions,
                "blob": blob(&r.data),
            })
        })
        .collect();
    json!({
        "format": program.format,
        "entry_points": program.entry_points.iter().map(Address::to_string).collect::<Vec<_>>(),
        "regions": regions,
    })
}

/// Inline below the limit; else the file `<dir>/<blake3>` (`dir` absolute) or `cache/blobs/<blake3>`.
fn region_blob(data: &[u8], dir: Option<&Path>) -> Value {
    if let Ok(blob) = Blob::inline(data) {
        return blob.to_json();
    }
    let hash = blake3_hex(data);
    let path = match dir {
        Some(dir) => path_text(&dir.join(&hash)),
        None => format!("{BLOBS_DIR}/{hash}"),
    };
    json!({"blob": {"path": path, "blake3": hash}})
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Paths below the workspace root, which was checked to be UTF-8.
fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Forwards plugin progress, filling in `label` when the plugin sends no message.
fn labelled<'a>(progress: &'a dyn Fn(Progress), label: &'a str) -> impl Fn(Progress) + 'a {
    move |p: Progress| {
        let message = p
            .message
            .clone()
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| label.to_string());
        progress(Progress::new(p.done, p.total, Some(message)));
    }
}

fn stage(message: &str) -> Progress {
    Progress::new(0, None, Some(message.to_string()))
}

fn no_config(name: &str) -> FacadeError {
    if name == "ghidra" {
        FacadeError::Plugin(NO_ANALYZER.into())
    } else {
        FacadeError::Plugin(format!(
            "no analyzer configured for plugin {name}; add [plugins.{name}] command = [...] to decovery.toml"
        ))
    }
}

/// Plugin names become directory names below `cache/`.
fn check_plugin_name(name: &str) -> Result<(), FacadeError> {
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(FacadeError::Invalid(format!(
            "plugin name {name:?} must consist of letters, digits, '_' and '-'"
        )))
    }
}

fn plugin_error(name: &str, e: PluginError) -> FacadeError {
    match e {
        PluginError::Remote { code, message } => {
            FacadeError::Plugin(format!("{name}: {message} (error {code})"))
        }
        other => FacadeError::Plugin(format!("{name}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_body_matches_decomp_layout() {
        assert_eq!(
            failure_body("timeout */", &[("flat:00010000".into(), "RET".into())]),
            "/* decompilation failed: timeout * / */\n/* Disassembly:\nflat:00010000  RET\n*/\n"
        );
        assert_eq!(
            failure_body("gone", &[]),
            "/* decompilation failed: gone */\n/* Disassembly:\n(not available)\n*/\n"
        );
    }

    #[test]
    fn unexpected_decompile_entries_become_warnings() {
        let entry = |address: &str, error: &str| DecompileEntry {
            address: address.into(),
            path: None,
            error: Some(error.into()),
            disassembly: Vec::new(),
        };
        let batch = [Address::Flat(0x10000), Address::Flat(0x10100)];
        let mut warnings = Vec::new();
        let out = collect_batch(
            "fake",
            &batch,
            vec![
                entry("flat:00010000", "first"),
                entry("flat:00010000", "second"),
                entry("flat:00020000", "stray"),
            ],
            &mut warnings,
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].error.as_deref(), Some("first"));
        assert_eq!(
            out[1].error.as_deref(),
            Some("the plugin returned no result")
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("duplicate") && warnings[0].contains("flat:00010000"));
        assert!(warnings[1].contains("not requested") && warnings[1].contains("flat:00020000"));
    }

    #[test]
    fn plugin_names_are_checked() {
        assert!(check_plugin_name("ghidra").is_ok());
        assert!(check_plugin_name("my-plugin_2").is_ok());
        assert!(check_plugin_name("").is_err());
        assert!(check_plugin_name("../x").is_err());
    }

    #[test]
    fn remote_errors_name_the_plugin() {
        let e = plugin_error(
            "ghidra",
            PluginError::Remote {
                code: -32010,
                message: "Ghidra unavailable".into(),
            },
        );
        assert_eq!(
            e.to_string(),
            "plugin error: ghidra: Ghidra unavailable (error -32010)"
        );
    }
}
