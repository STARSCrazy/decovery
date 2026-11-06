//! `build`: compile the rebuild sources, compare their objects with the original and record the results.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use decovery_core::{
    Address, Analysis, BlockerRecord, RebuildRecord, RebuildResult, VerdictId, Workspace,
    merge_rebuild, read_rebuild, read_user_config, save_rebuild, today, write_atomic,
};
use decovery_diff::{Blocker, Comparison, ModuleOptions, Placement, SymbolView, Verdict};
use decovery_objects::{FunctionView, ObjectFile, functions, read_omf};
use decovery_plugin::Progress;
use decovery_toolchain::{
    CheatFinding, CompiledFile, cache_misses, compile, find_cheats, find_sources, open_runners,
    rebuild_profile, stage_text,
};
use serde_json::{Value, json};

use crate::{
    Budget, Change, FacadeError, KnowledgeView, Response, Session, store_handle, write_affected,
};

const LOCK_WAIT: Duration = Duration::from_secs(30);
/// Rebuild sources, relative to the workspace root.
pub const SOURCE_DIR: &str = "src";
/// Build directories (one per build, deleted afterwards), relative to the workspace root.
pub const RUNS_DIR: &str = "cache/rebuild/runs";
/// The objects of the last build per source, relative to the workspace root.
pub const OBJECTS_DIR: &str = "cache/rebuild/obj";
/// `format` of the metadata file beside each kept object.
pub const OBJECT_FORMAT: &str = "decovery-obj/1";

static BUILD_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A source text to build instead of the file (Task 12).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Variant {
    pub label: String,
    pub source: String,
}

/// What to build: `files` (names in `src/`; empty = all sources), optionally reported for one `function` only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuildRequest {
    pub files: Vec<String>,
    pub function: Option<String>,
    pub variants: Vec<Variant>,
}

/// The build directory; removed when dropped.
struct RunDir(PathBuf);

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn toolchain(e: decovery_toolchain::ToolchainError) -> FacadeError {
    FacadeError::Invalid(e.to_string())
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// One source of the build.
struct Source {
    /// Name in `src/` (`ai.c`), as recorded in `file`.
    name: String,
    /// Staged DOS name (`AI.C`).
    dos_name: String,
    flags: String,
    /// Source text with LF line ends, for the inline-assembly check.
    text: String,
    compiled: Option<CompiledFile>,
    /// Why the source has no object.
    error: Option<String>,
    /// The profile has no way to build this source (an assembler file without an assembler run): not built, its
    /// records and its kept object stay as they are.
    skipped: bool,
}

/// A compared function of the build.
struct Built {
    source: usize,
    name: String,
    address: Address,
    code_hash: String,
}

/// `[rebuild] file_flags` for a source: by its name, else by its DOS name, else case-insensitively.
fn file_flags<'a>(table: &'a BTreeMap<String, String>, name: &str) -> Option<&'a String> {
    table
        .get(name)
        .or_else(|| table.get(&name.to_ascii_uppercase()))
        .or_else(|| {
            table
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        })
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Compiles the C sources of `src/` (all, or `request.files`) through the runners (object cache first, all misses
/// in one request), compares every public function of the objects with the original in one module comparison,
/// downgrades functions with inline assembly, and records the results under the workspace lock: rebuild records,
/// kept objects and the affected output files. Assembler sources are not built yet; they fail with a message.
pub fn build(
    root: &Path,
    request: &BuildRequest,
    progress: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    let started = Instant::now();
    if !request.variants.is_empty() {
        return Err(FacadeError::Invalid(
            "build variants are not supported yet".into(),
        ));
    }
    let ws = Workspace::open(root)?;
    let analysis = Analysis::load(root)?.filter(|a| a.target_sha256 == ws.config.target.sha256);
    let (profile, default_flags) = rebuild_profile(&ws).map_err(toolchain)?;
    let rebuild = ws.config.rebuild.clone().unwrap_or_default();
    let all = request.files.is_empty() && request.function.is_none();
    let files = match (&request.function, request.files.is_empty()) {
        (Some(function), true) => vec![file_of_function(root, function)?],
        _ => request.files.clone(),
    };
    let set = find_sources(&root.join(SOURCE_DIR), &files).map_err(toolchain)?;
    let existing_files: Vec<String> = set.sources.iter().map(|p| file_name(p)).collect();
    let built_files: Vec<String> = existing_files
        .iter()
        .filter(|name| is_c(name))
        .cloned()
        .collect();

    // stage
    let run_dir = RunDir(root.join(RUNS_DIR).join(format!(
        "build-{}-{}",
        std::process::id(),
        BUILD_COUNTER.fetch_add(1, Ordering::Relaxed)
    )));
    if run_dir.0.exists() {
        std::fs::remove_dir_all(&run_dir.0).map_err(|source| FacadeError::Output {
            path: run_dir.0.clone(),
            source,
        })?;
    }
    for header in &set.headers {
        let text = read_text(header)?;
        stage_text(&file_name(header), &text, &run_dir.0).map_err(toolchain)?;
    }
    let mut sources: Vec<Source> = Vec::new();
    for path in &set.sources {
        let name = file_name(path);
        let flags = file_flags(&rebuild.file_flags, &name)
            .cloned()
            .unwrap_or_else(|| default_flags.clone());
        let mut source = Source {
            dos_name: name.to_ascii_uppercase(),
            name,
            flags,
            text: String::new(),
            compiled: None,
            error: None,
            skipped: false,
        };
        if !is_c(&source.name) {
            source.skipped = true;
        } else {
            match read_text(path).and_then(|text| {
                stage_text(&source.name, &text, &run_dir.0)
                    .map_err(toolchain)
                    .map(|_| text)
            }) {
                Ok(text) => source.text = text.replace("\r\n", "\n"),
                Err(e) => source.error = Some(e.to_string()),
            }
        }
        sources.push(source);
    }

    // compile: cache hits, then all misses in one runner request
    let compile_started = Instant::now();
    let staged: Vec<usize> = (0..sources.len())
        .filter(|&i| sources[i].error.is_none() && !sources[i].skipped)
        .collect();
    let jobs_input: Vec<(String, String)> = staged
        .iter()
        .map(|&i| (sources[i].dos_name.clone(), sources[i].flags.clone()))
        .collect();
    let mut warnings: Vec<String> = Vec::new();
    progress(Progress::new(
        0,
        Some(jobs_input.len() as u64),
        Some(format!("compiling {} sources", jobs_input.len())),
    ));
    let user = read_user_config()?;
    let runner_names = if rebuild.runners.is_empty() {
        profile.runners.clone()
    } else {
        rebuild.runners.clone()
    };
    let needs_runner = !jobs_input.is_empty()
        && cache_misses(&ws, &profile, &jobs_input, &run_dir.0).map_err(toolchain)? > 0;
    let runners = if needs_runner {
        let (runners, more) = open_runners(&runner_names, &ws, &user);
        warnings.extend(more);
        runners
    } else {
        Vec::new()
    };
    let (compiled, more) = if jobs_input.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        compile(&ws, &profile, &jobs_input, &run_dir.0, &runners, None).map_err(toolchain)?
    };
    drop(runners);
    warnings.extend(more);
    let jobs = compiled.iter().filter(|c| !c.cached).count();
    let cached = compiled.len() - jobs;
    for (&i, file) in staged.iter().zip(compiled) {
        if file.object.is_none() {
            sources[i].error = Some(if file.message.is_empty() {
                "compile failed".to_string()
            } else {
                file.message.clone()
            });
        }
        sources[i].compiled = Some(file);
    }
    let input_hashes = input_hashes(&run_dir.0)?;
    drop(run_dir);
    let compile_ms = ms(compile_started.elapsed());

    // read objects
    let compare_started = Instant::now();
    let mut objects: Vec<(usize, ObjectFile)> = Vec::new();
    for (i, source) in sources.iter_mut().enumerate() {
        let Some(bytes) = source.compiled.as_ref().and_then(|c| c.object.as_ref()) else {
            continue;
        };
        match read_omf(bytes, &source.dos_name) {
            Ok(object) => objects.push((i, object)),
            Err(e) => source.error = Some(format!("cannot read the object: {e}")),
        }
    }

    // place every public function of a code section at its original
    let knowledge = KnowledgeView::new(&ws, analysis.as_ref());
    let index = analysis.as_ref().map(Analysis::index);
    let mut hints: Vec<String> = Vec::new();
    let mut placements: Vec<Placement<'_>> = Vec::new();
    let mut placed: Vec<Built> = Vec::new();
    let mut taken: HashMap<Address, String> = HashMap::new();
    for (i, object) in &objects {
        for module in &object.modules {
            for view in functions(module).into_iter().filter(|f| is_public(f)) {
                let raw = view.name;
                let c_name = profile.decoration.undecorate(raw);
                let found = knowledge
                    .address_of(c_name)
                    .map(|a| (c_name, a))
                    .or_else(|| {
                        (c_name != raw)
                            .then(|| knowledge.address_of(raw).map(|a| (raw, a)))
                            .flatten()
                    });
                let Some((name, address)) = found else {
                    hints.push(format!("{c_name}: no counterpart in the original"));
                    continue;
                };
                if let Some(other) = taken.get(&address) {
                    hints.push(format!(
                        "{name}: {address} is already rebuilt by {other}; this copy in {} is ignored",
                        sources[*i].name
                    ));
                    continue;
                }
                taken.insert(address, sources[*i].name.clone());
                let original_len = index
                    .as_ref()
                    .and_then(|ix| ix.function_at(address))
                    .and_then(|f| {
                        f.end
                            .linear()?
                            .checked_sub(f.start.linear()?)?
                            .checked_add(1)
                    })
                    .or_else(|| symbol_size(&ws, address))
                    .and_then(|n| u32::try_from(n).ok());
                let code_hash = blake3::hash(view.code()).to_hex()[..16].to_string();
                placed.push(Built {
                    source: *i,
                    name: name.to_string(),
                    address,
                    code_hash,
                });
                placements.push(Placement::new(view, address, original_len));
            }
        }
    }
    progress(Progress::new(
        0,
        Some(placements.len() as u64),
        Some(format!("comparing {} functions", placements.len())),
    ));
    let comparisons: Vec<Comparison> = if placements.is_empty() {
        Vec::new()
    } else {
        let program = crate::program::load(&ws)?;
        let options = ModuleOptions::new(profile.padding, rebuild.frames.clone());
        let module = decovery_diff::compare_module(
            &placements,
            &program,
            &knowledge,
            &profile.decoration,
            &options,
        );
        warnings.extend(module.warnings);
        module.functions
    };
    drop(placements);

    // inline assembly
    let mut cheats: Vec<BTreeMap<String, Vec<CheatFinding>>> = Vec::new();
    for source in &sources {
        let mut by_function: BTreeMap<String, Vec<CheatFinding>> = BTreeMap::new();
        if is_c(&source.name) {
            for finding in find_cheats(&source.text) {
                hints.push(format!(
                    "{}:{}: {} {}",
                    source.name,
                    finding.line,
                    finding.kind.id(),
                    finding
                        .function
                        .as_deref()
                        .map_or_else(|| "outside a function".to_string(), |f| format!("in {f}"))
                ));
                if let Some(f) = &finding.function {
                    by_function.entry(f.clone()).or_default().push(finding);
                }
            }
        }
        cheats.push(by_function);
    }
    let compare_ms = ms(compare_started.elapsed());

    // records of this build
    let date = today();
    let mut new_records: Vec<RebuildRecord> = Vec::new();
    for (built, comparison) in placed.iter().zip(&comparisons) {
        let source = &sources[built.source];
        let mut r = record(built, comparison, source, &profile.id, &date);
        if let Some(findings) = cheats[built.source].get(&built.name) {
            r.blockers.push(blocker_record(&Blocker::InlineAssembly));
            // an unchecked comparison stays unchecked (and keeps its message); the findings are added
            if r.verdict != Some(VerdictId::Unchecked) {
                r.verdict = Some(VerdictId::Differs);
            }
            if r.result == RebuildResult::Identical {
                r.result = RebuildResult::Differs;
            }
            let found = findings
                .iter()
                .map(|f| format!("line {}: {} {}", f.line, f.kind.id(), f.text))
                .collect::<Vec<_>>()
                .join("\n");
            r.message = Some(match r.message.take() {
                Some(before) => format!("{before}\n{found}"),
                None => found,
            });
        }
        new_records.push(r);
    }

    // record under the lock
    let record_started = Instant::now();
    let lock = ws.lock(LOCK_WAIT)?;
    let old = read_rebuild(root)?;
    for source in sources.iter().filter(|s| s.error.is_some()) {
        let message = source.error.clone().unwrap_or_default();
        let before: Vec<&RebuildRecord> = old
            .iter()
            .filter(|r| r.file.as_deref() == Some(source.name.as_str()))
            .collect();
        if before.is_empty() {
            hints.push(format!(
                "{}: {}",
                source.name,
                message.lines().next().unwrap_or("")
            ));
        }
        for b in before {
            let mut r = RebuildRecord::new(b.address, b.name.clone(), RebuildResult::Error);
            r.file = Some(source.name.clone());
            r.compiler = Some(profile.id.clone());
            r.flags = Some(source.flags.clone());
            r.verdict = Some(VerdictId::Unchecked);
            r.message = Some(message.clone());
            r.date = Some(date.clone());
            new_records.push(r);
        }
    }
    for source in sources.iter().filter(|s| s.skipped) {
        hints.push(format!("no assembler available for {}", source.name));
    }
    let mut affected: BTreeSet<Address> = old
        .iter()
        .filter(|r| match &r.file {
            Some(f) => built_files.contains(f) || (all && !existing_files.contains(f)),
            None => all,
        })
        .map(|r| r.address)
        .collect();
    affected.extend(new_records.iter().map(|r| r.address));
    let merged = merge_rebuild(old, new_records.clone(), &built_files, all, &existing_files);
    save_rebuild(root, &merged, &lock)?;
    keep_objects(root, &sources, &new_records, &input_hashes, &profile.id)?;
    if analysis.is_some() {
        let session = Session::open(root)?;
        write_affected(
            &session,
            &Change::Rebuild {
                addresses: affected.into_iter().collect(),
            },
            &lock,
        )?;
    }
    drop(lock);
    let record_ms = ms(record_started.elapsed());

    let timing = json!({
        "compile_ms": compile_ms,
        "compare_ms": compare_ms,
        "record_ms": record_ms,
        "total_ms": ms(started.elapsed()),
        "jobs": jobs,
        "cached": cached,
    });
    respond(
        root,
        request,
        &sources,
        new_records,
        hints,
        warnings,
        timing,
    )
}

/// The file whose rebuild records hold `function`.
fn file_of_function(root: &Path, function: &str) -> Result<String, FacadeError> {
    read_rebuild(root)?
        .into_iter()
        .find(|r| r.name == function || r.address.to_string() == function)
        .and_then(|r| r.file)
        .ok_or_else(|| {
            FacadeError::Invalid(format!(
                "no rebuild record names the file of {function}; build its file instead"
            ))
        })
}

fn read_text(path: &Path) -> Result<String, FacadeError> {
    std::fs::read_to_string(path)
        .map_err(|e| FacadeError::Invalid(format!("cannot read {}: {e}", path.display())))
}

fn is_c(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".c")
}

/// Name and bytes of every staged file.
fn staged_files(build_dir: &Path) -> std::io::Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    if !build_dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(build_dir)? {
        let entry = entry?;
        if entry.path().is_file() {
            out.push((
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path())?,
            ));
        }
    }
    out.sort();
    Ok(out)
}

/// blake3 of every staged input (sources and headers), by DOS name.
fn input_hashes(build_dir: &Path) -> Result<BTreeMap<String, String>, FacadeError> {
    let files = staged_files(build_dir).map_err(|source| FacadeError::Output {
        path: build_dir.to_path_buf(),
        source,
    })?;
    Ok(files
        .into_iter()
        .filter(|(n, _)| {
            let upper = n.to_ascii_uppercase();
            [".C", ".H", ".S", ".ASM"]
                .iter()
                .any(|e| upper.ends_with(e))
        })
        .map(|(n, b)| (n, blake3::hash(&b).to_hex().to_string()))
        .collect())
}

fn is_public(f: &FunctionView<'_>) -> bool {
    f.module
        .symbols
        .iter()
        .any(|s| s.public && s.name == f.name && s.section == f.section && s.offset == f.start)
}

fn symbol_size(ws: &Workspace, at: Address) -> Option<u64> {
    ws.symbols
        .iter()
        .find(|s| s.address == at && s.confidence != decovery_core::Confidence::Refuted)
        .and_then(|s| s.size)
}

fn verdict_id(v: &Verdict) -> VerdictId {
    match v {
        Verdict::Identical => VerdictId::Identical,
        Verdict::Equivalent { .. } => VerdictId::Equivalent,
        Verdict::Differs => VerdictId::Differs,
        _ => VerdictId::Unchecked,
    }
}

fn blocker_record(b: &Blocker) -> BlockerRecord {
    BlockerRecord::new(b.kind(), b.at(), b.count())
}

/// The record of one compared function: Decomp's `result`, decovery's verdict and blockers, the metrics.
fn record(
    built: &Built,
    c: &Comparison,
    source: &Source,
    compiler: &str,
    date: &str,
) -> RebuildRecord {
    let m = &c.metrics;
    let verdict = verdict_id(&c.verdict);
    let result = if verdict == VerdictId::Unchecked {
        RebuildResult::Error
    } else if m.differing == 0 && m.refs_wrong == 0 {
        RebuildResult::Identical
    } else {
        RebuildResult::Differs
    };
    let mut r = RebuildRecord::new(built.address, built.name.clone(), result);
    r.file = Some(source.name.clone());
    r.compiler = Some(compiler.to_string());
    r.flags = Some(source.flags.clone());
    r.verdict = Some(verdict);
    r.blockers = c.blockers.iter().map(blocker_record).collect();
    if result == RebuildResult::Error {
        r.message = Some("the original bytes of the function are not in the program".into());
    }
    r.bytes = m.bytes;
    r.equal = m.equal;
    r.gaps = m.gaps;
    r.differing = m.differing;
    r.refs_ok = m.refs_ok;
    r.refs_wrong = m.refs_wrong;
    r.refs_unchecked = m.refs_unchecked;
    r.instructions_differing = m.instructions_differing;
    r.padding_bytes = m.padding;
    r.first_difference = m.first_difference;
    r.code_hash = Some(built.code_hash.clone());
    r.date = Some(date.to_string());
    r
}

/// Copies each object built in this run to `cache/rebuild/obj/<stem>.obj` with `<stem>.json` (inputs, identical
/// functions). A source without a new object (skipped, or failed this time) keeps whatever is kept there.
fn keep_objects(
    root: &Path,
    sources: &[Source],
    records: &[RebuildRecord],
    inputs: &BTreeMap<String, String>,
    profile: &str,
) -> Result<(), FacadeError> {
    let dir = root.join(OBJECTS_DIR);
    let output = |path: PathBuf| move |source| FacadeError::Output { path, source };
    for source in sources {
        let stem = source
            .name
            .rsplit_once('.')
            .map_or(source.name.as_str(), |(s, _)| s)
            .to_ascii_lowercase();
        let obj_path = dir.join(format!("{stem}.obj"));
        let meta_path = dir.join(format!("{stem}.json"));
        let object = source
            .compiled
            .as_ref()
            .and_then(|c| c.object.as_ref())
            .filter(|_| source.error.is_none());
        let Some(object) = object else {
            continue;
        };
        let identical: serde_json::Map<String, Value> = records
            .iter()
            .filter(|r| {
                r.file.as_deref() == Some(source.name.as_str())
                    && r.verdict == Some(VerdictId::Identical)
            })
            .map(|r| (r.name.clone(), json!({ "address": r.address.to_string() })))
            .collect();
        let meta = json!({
            "schema": 1,
            "format": OBJECT_FORMAT,
            "file": source.name,
            "profile": profile,
            "flags": source.flags,
            "inputs": inputs,
            "object": blake3::hash(object).to_hex().to_string(),
            "identical": identical,
        });
        let text = serde_json::to_string_pretty(&meta)
            .map_err(|e| FacadeError::Invalid(e.to_string()))?
            + "\n";
        write_atomic(&obj_path, object).map_err(output(obj_path.clone()))?;
        write_atomic(&meta_path, text.as_bytes()).map_err(output(meta_path.clone()))?;
    }
    Ok(())
}

fn function_json(r: &RebuildRecord) -> Value {
    json!({
        "address": r.address.to_string(),
        "name": r.name,
        "file": r.file,
        "verdict": r.verdict.map(VerdictId::id),
        "result": r.result.id(),
        "blockers": r.blockers.iter().map(|b| {
            let mut v = json!({ "kind": b.kind });
            if let Some(at) = b.at { v["at"] = json!(at); }
            if let Some(count) = b.count { v["count"] = json!(count); }
            v
        }).collect::<Vec<_>>(),
        "bytes": r.bytes,
        "differing": r.differing,
        "instructions_differing": r.instructions_differing,
    })
}

fn respond(
    root: &Path,
    request: &BuildRequest,
    sources: &[Source],
    mut records: Vec<RebuildRecord>,
    hints: Vec<String>,
    warnings: Vec<String>,
    timing: Value,
) -> Result<Response, FacadeError> {
    records.sort_by_key(|r| r.address);
    if let Some(function) = &request.function {
        records.retain(|r| &r.name == function || r.address.to_string() == *function);
    }
    let count = |v: VerdictId| records.iter().filter(|r| r.verdict == Some(v)).count();
    let (identical, differs, unchecked) = (
        count(VerdictId::Identical),
        count(VerdictId::Differs),
        count(VerdictId::Unchecked),
    );
    let failed = sources.iter().filter(|s| s.error.is_some()).count();
    let skipped = sources.iter().filter(|s| s.skipped).count();
    let files: Vec<Value> = sources
        .iter()
        .map(|s| {
            let cached = s.compiled.as_ref().is_some_and(|c| c.cached);
            let mut v = json!({
                "file": s.name,
                "status": if s.skipped {
                    "skipped"
                } else if s.error.is_some() {
                    "error"
                } else {
                    "compiled"
                },
                "cached": cached,
            });
            if let Some(m) = &s.error {
                v["message"] = json!(m);
            }
            v
        })
        .collect();

    let label = match sources {
        [one] => one.name.clone(),
        _ => format!("{} files", sources.len()),
    };
    let mut summary = format!(
        "{label}: {} functions, {identical} identical",
        records.len()
    );
    if differs > 0 {
        summary.push_str(&format!(", {differs} differ"));
    }
    if unchecked > 0 {
        summary.push_str(&format!(", {unchecked} unchecked"));
    }
    if failed > 0 {
        summary.push_str(&format!(
            "; {failed} file{} failed",
            if failed == 1 { "" } else { "s" }
        ));
    }
    if skipped > 0 {
        summary.push_str(&format!("; {skipped} skipped"));
    }

    // problems first; identical functions only as far as the budget allows
    let mut ordered: Vec<&RebuildRecord> = records
        .iter()
        .filter(|r| r.verdict != Some(VerdictId::Identical))
        .collect();
    ordered.extend(
        records
            .iter()
            .filter(|r| r.verdict == Some(VerdictId::Identical)),
    );
    let budget = Budget::default().chars;
    let mut used = 0usize;
    let mut shown = Vec::new();
    for r in &ordered {
        let v = function_json(r);
        let n = v.to_string().len();
        if used + n > budget {
            break;
        }
        used += n;
        shown.push(v);
    }
    let mut handles = Vec::new();
    if shown.len() < records.len() {
        let text: String = records
            .iter()
            .map(|r| format!("{}\n", function_json(r)))
            .collect();
        let mut handle = store_handle(root, "build-functions", &text)?;
        handle.description = format!(
            "all {} built functions, one JSON object per line",
            records.len()
        );
        summary.push_str(&format!("; all functions: detail {}", handle.id));
        handles.push(handle);
    }
    let mut response = Response::new(
        summary,
        json!({
            "files": files,
            "functions": shown,
            "functions_total": records.len(),
            "hints": hints,
            "warnings": warnings,
            "counts": {
                "functions": records.len(),
                "identical": identical,
                "differs": differs,
                "unchecked": unchecked,
                "files": sources.len(),
                "failed_files": failed,
                "skipped_files": skipped,
            },
            "timing": timing,
        }),
    );
    response.handles = handles;
    Ok(response)
}
