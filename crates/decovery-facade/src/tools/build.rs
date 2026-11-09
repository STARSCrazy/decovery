//! `build`: compile the rebuild sources, compare their objects with the original and record the results.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use decovery_core::{
    Address, Analysis, BlockerRecord, Program, RebuildRecord, RebuildResult, TargetFormat,
    VerdictId, Workspace, merge_rebuild, read_rebuild, read_user_config, save_rebuild, today,
    write_atomic,
};
use decovery_diff::{Blocker, Comparison, ModuleOptions, Placement, SymbolView, Verdict};
use decovery_objects::{FunctionView, ObjectFile, functions, read_omf};
use decovery_plugin::Progress;
use decovery_toolchain::{
    CheatFinding, CompiledFile, Profile, SourceJob, SourceSet, compile_planned, definitions,
    find_cheats, find_sources, open_runners, plan_compile, rebuild_profile, stage_text,
    startup_object,
};
use serde_json::{Value, json};

use super::variants::{Variant, build_variants};
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

/// What to build: `files` (names in `src/`; empty = all sources), optionally reported for one `function` only
/// (a name or an address; without `files` its file is the one its rebuild record names, else the only source that
/// defines it). With `variants` the request compiles those candidates (whole files or definitions of `function`)
/// for `function` and ranks them instead; nothing is recorded then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuildRequest {
    pub files: Vec<String>,
    pub function: Option<String>,
    pub variants: Vec<Variant>,
    /// Characters of the function list returned inline (default [`Budget::default`]); the rest is a handle.
    pub budget: Option<usize>,
}

/// The build directory; removed when dropped.
pub(super) struct RunDir(pub(super) PathBuf);

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The frame bases the program's startup object ([`startup_object`]) proves in the original (ADR 0006 item 10),
/// for an MZ target; why the startup gives none goes into `warnings` (nothing when the toolchain has none).
pub(super) fn startup_frames(
    ws: &Workspace,
    profile: &Profile,
    program: &Program,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, Address> {
    if ws.config.target.format != TargetFormat::Mz {
        return BTreeMap::new();
    }
    let path = match startup_object(ws, profile) {
        Ok(Some(path)) => path,
        Ok(None) => return BTreeMap::new(),
        Err(e) => {
            warnings.push(format!("no startup object for the frame bases: {e}"));
            return BTreeMap::new();
        }
    };
    let name = file_name(&path);
    let configured = ws
        .config
        .rebuild
        .as_ref()
        .and_then(|r| r.link.as_ref())
        .is_some_and(|l| l.startup.is_some());
    let object = match std::fs::read(&path) {
        Ok(bytes) => read_omf(&bytes, &name).map_err(|e| e.to_string()),
        // the profile's default startup missing from a tool directory (a partial toolchain): nothing to say
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !configured => {
            return BTreeMap::new();
        }
        Err(e) => Err(e.to_string()),
    };
    match object {
        Ok(object) => match object.modules.first() {
            Some(module) => {
                let found = decovery_diff::startup_frames(module, program);
                warnings.extend(found.warnings);
                found.frames
            }
            None => {
                warnings.push(format!("startup object {} has no module", path.display()));
                BTreeMap::new()
            }
        },
        Err(e) => {
            warnings.push(format!(
                "cannot read the startup object {}: {e}",
                path.display()
            ));
            BTreeMap::new()
        }
    }
}

pub(super) fn toolchain(e: decovery_toolchain::ToolchainError) -> FacadeError {
    FacadeError::Invalid(e.to_string())
}

pub(super) fn ms(d: Duration) -> u64 {
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
pub(super) struct Built {
    pub(super) source: usize,
    pub(super) name: String,
    pub(super) address: Address,
    code_hash: String,
}

/// `[rebuild] file_flags` for a source: by its name, else by its DOS name, else case-insensitively.
pub(super) fn file_flags<'a>(
    table: &'a BTreeMap<String, String>,
    name: &str,
) -> Option<&'a String> {
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

/// Size and modification time of the files a [`Session`] is read from (configuration, symbols, analysis): when they
/// are unchanged at record time, the session is built from what the build already holds instead of read again.
#[derive(Debug, PartialEq, Eq)]
struct SessionStamps(Vec<Option<(u64, Option<SystemTime>)>>);

impl SessionStamps {
    fn of(root: &Path) -> Self {
        let files = [
            decovery_core::workspace::CONFIG_FILE,
            decovery_core::workspace::SYMBOLS_FILE,
            decovery_core::analysis::ANALYSIS_FILE,
        ];
        SessionStamps(
            files
                .iter()
                .map(|f| {
                    std::fs::metadata(root.join(f))
                        .ok()
                        .map(|m| (m.len(), m.modified().ok()))
                })
                .collect(),
        )
    }
}

pub(super) fn file_name(path: &Path) -> String {
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
        return build_variants(root, request, progress, started);
    }
    let stamps = SessionStamps::of(root);
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
    let run_dir = new_run_dir(root)?;
    stage_headers(&set, &run_dir.0)?;
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
    let jobs_input: Vec<SourceJob> = staged
        .iter()
        .map(|&i| SourceJob::new(sources[i].dos_name.clone(), sources[i].flags.clone()))
        .collect();
    let Compiled {
        files: compiled,
        input_hashes,
        mut warnings,
    } = compile_jobs(&ws, &profile, &jobs_input, &run_dir.0, progress)?;
    let jobs = compiled.iter().filter(|c| !c.cached).count();
    let cached = compiled.len() - jobs;
    for (&i, file) in staged.iter().zip(compiled) {
        if file.object.is_none() {
            sources[i].error = Some(failure_text(&file));
        }
        sources[i].compiled = Some(file);
    }
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
    let symbol_sizes = symbol_sizes(&ws);
    let mut hints: Vec<String> = Vec::new();
    let refs: Vec<(usize, &str, &ObjectFile)> = objects
        .iter()
        .map(|(i, object)| (*i, sources[*i].name.as_str(), object))
        .collect();
    let (placements, placed) = place_objects(
        &knowledge,
        &profile,
        index.as_ref(),
        &symbol_sizes,
        &refs,
        &mut hints,
    );
    drop(refs);
    progress(Progress::new(
        0,
        Some(placements.len() as u64),
        Some(format!("comparing {} functions", placements.len())),
    ));
    let comparisons: Vec<Comparison> = if placements.is_empty() {
        Vec::new()
    } else {
        let program = crate::program::load(&ws)?;
        // the diagnosis reads the instruction pairs of the comparison: no second decode
        let options = ModuleOptions::new(profile.padding, rebuild.frames.clone())
            .with_startup_frames(startup_frames(&ws, &profile, &program, &mut warnings))
            .with_diagnosis(profile.family.clone());
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
    if let Some(analysis) = analysis {
        // what the build loaded is still what is on disk (checked under the lock): no second parse
        let session = if SessionStamps::of(root) == stamps {
            Session {
                workspace: ws,
                analysis,
                rebuild: merged,
            }
        } else {
            Session::open(root)?
        };
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

/// A fresh build directory of its own (unique per call, so builds do not collide without the workspace lock).
pub(super) fn new_run_dir(root: &Path) -> Result<RunDir, FacadeError> {
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
    Ok(run_dir)
}

/// Stages the headers of `set` in `dir`; returns blake3 (hex) of each staged header by DOS name.
pub(super) fn stage_headers(
    set: &SourceSet,
    dir: &Path,
) -> Result<BTreeMap<String, String>, FacadeError> {
    let mut hashes = BTreeMap::new();
    for header in &set.headers {
        let text = read_text(header)?;
        let dos_name = stage_text(&file_name(header), &text, dir).map_err(toolchain)?;
        let bytes = std::fs::read(dir.join(&dos_name)).map_err(|source| FacadeError::Output {
            path: dir.join(&dos_name),
            source,
        })?;
        hashes.insert(dos_name, blake3::hash(&bytes).to_hex().to_string());
    }
    Ok(hashes)
}

/// The file of `function`: the one its rebuild record names, else the only source in `src/` that defines it.
pub(super) fn file_of_function(root: &Path, function: &str) -> Result<String, FacadeError> {
    let recorded = read_rebuild(root)?
        .into_iter()
        .find(|r| r.name == function || r.address.to_string() == function)
        .and_then(|r| r.file);
    if let Some(file) = recorded {
        return Ok(file);
    }
    let set = find_sources(&root.join(SOURCE_DIR), &[]).map_err(toolchain)?;
    let mut defining = Vec::new();
    for path in set.sources.iter().filter(|p| is_c(&file_name(p))) {
        if definitions(&read_text(path)?)
            .iter()
            .any(|d| d.name == function)
        {
            defining.push(file_name(path));
        }
    }
    match defining.len() {
        1 => Ok(defining.remove(0)),
        0 => Err(FacadeError::Invalid(format!(
            "no rebuild record names the file of {function} and no source in {SOURCE_DIR}/ defines it; name the file"
        ))),
        _ => Err(FacadeError::Invalid(format!(
            "{function} is defined in {}; name the file",
            defining.join(", ")
        ))),
    }
}

/// Places every public function of the `objects` (id, name for hints, object) at its original: a function without
/// counterpart in the original, or one whose address an earlier object already took, is left out with a hint.
pub(super) fn place_objects<'o>(
    knowledge: &KnowledgeView<'_>,
    profile: &Profile,
    index: Option<&decovery_core::AnalysisIndex<'_>>,
    symbol_sizes: &HashMap<Address, Option<u64>>,
    objects: &[(usize, &str, &'o ObjectFile)],
    hints: &mut Vec<String>,
) -> (Vec<Placement<'o>>, Vec<Built>) {
    let mut placements = Vec::new();
    let mut placed = Vec::new();
    let mut taken: HashMap<Address, String> = HashMap::new();
    for &(id, source, object) in objects {
        for module in &object.modules {
            for view in functions(module).into_iter().filter(|f| is_public(f)) {
                let raw = view.name;
                let Some((name, address)) = place_name(knowledge, profile, raw) else {
                    hints.push(format!(
                        "{}: no counterpart in the original",
                        profile.decoration.undecorate(raw)
                    ));
                    continue;
                };
                if let Some(other) = taken.get(&address) {
                    hints.push(format!(
                        "{name}: {address} is already rebuilt by {other}; this copy in {source} is ignored"
                    ));
                    continue;
                }
                taken.insert(address, source.to_string());
                let original_len = original_len(index, symbol_sizes, address);
                let code_hash = blake3::hash(view.code()).to_hex()[..16].to_string();
                placed.push(Built {
                    source: id,
                    name: name.to_string(),
                    address,
                    code_hash,
                });
                placements.push(Placement::new(view, address, original_len));
            }
        }
    }
    (placements, placed)
}

/// The C name and original address of a function of an object, as the build places it: by the undecorated name,
/// else by the raw one.
fn place_name<'a>(
    knowledge: &KnowledgeView<'_>,
    profile: &Profile,
    raw: &'a str,
) -> Option<(&'a str, Address)> {
    let c_name = profile.decoration.undecorate(raw);
    knowledge
        .address_of(c_name)
        .map(|a| (c_name, a))
        .or_else(|| {
            (c_name != raw)
                .then(|| knowledge.address_of(raw).map(|a| (raw, a)))
                .flatten()
        })
}

/// Length of the original function at `address`: from the analysis, else the symbol's size.
pub(super) fn original_len(
    index: Option<&decovery_core::AnalysisIndex<'_>>,
    symbol_sizes: &HashMap<Address, Option<u64>>,
    address: Address,
) -> Option<u32> {
    index
        .and_then(|ix| ix.function_at(address))
        .and_then(|f| {
            f.end
                .linear()?
                .checked_sub(f.start.linear()?)?
                .checked_add(1)
        })
        .or_else(|| symbol_sizes.get(&address).copied().flatten())
        .and_then(|n| u32::try_from(n).ok())
}

/// What [`compile_jobs`] returns: one file per job, the hashes of everything staged, the runners' warnings.
pub(super) struct Compiled {
    pub(super) files: Vec<CompiledFile>,
    pub(super) input_hashes: BTreeMap<String, String>,
    pub(super) warnings: Vec<String>,
}

/// Compiles the staged `jobs_input` in `run_dir`: inputs read once, object cache first, all misses in one runner
/// request (started only when there are misses). `progress` also gets what the runner reports per finished job.
pub(super) fn compile_jobs(
    ws: &Workspace,
    profile: &Profile,
    jobs_input: &[SourceJob],
    run_dir: &Path,
    progress: &dyn Fn(Progress),
) -> Result<Compiled, FacadeError> {
    let mut warnings: Vec<String> = Vec::new();
    progress(Progress::new(
        0,
        Some(jobs_input.len() as u64),
        Some(format!("compiling {} sources", jobs_input.len())),
    ));
    let user = read_user_config()?;
    let runner_names = runner_names(ws, profile);
    // every input (tool fingerprint, sources, headers, cached objects) is read once, here
    let plan = if jobs_input.is_empty() {
        None
    } else {
        Some(plan_compile(ws, profile, jobs_input, run_dir).map_err(toolchain)?)
    };
    let input_hashes = plan
        .as_ref()
        .map(|p| p.input_hashes().clone())
        .unwrap_or_default();
    let needs_runner = plan.as_ref().is_some_and(|p| p.misses() > 0);
    let runners = if needs_runner {
        let (runners, more) = open_runners(&runner_names, ws, &user);
        warnings.extend(more);
        runners
    } else {
        Vec::new()
    };
    let (files, more) = match plan {
        None => (Vec::new(), Vec::new()),
        Some(plan) => compile_planned(ws, profile, plan, run_dir, &runners, None, progress)
            .map_err(toolchain)?,
    };
    drop(runners);
    warnings.extend(more);
    Ok(Compiled {
        files,
        input_hashes,
        warnings,
    })
}

/// The runners to try: `[rebuild] runners`, else the profile's.
pub(super) fn runner_names(ws: &Workspace, profile: &Profile) -> Vec<String> {
    match ws.config.rebuild.as_ref() {
        Some(r) if !r.runners.is_empty() => r.runners.clone(),
        _ => profile.runners.clone(),
    }
}

/// Why a file without object failed.
pub(super) fn failure_text(file: &CompiledFile) -> String {
    if file.message.is_empty() {
        "compile failed".to_string()
    } else {
        file.message.clone()
    }
}

pub(super) fn blocker_json(b: &BlockerRecord) -> Value {
    let mut v = json!({ "kind": b.kind });
    if let Some(at) = b.at {
        v["at"] = json!(at);
    }
    if let Some(count) = b.count {
        v["count"] = json!(count);
    }
    v
}

pub(super) fn read_text(path: &Path) -> Result<String, FacadeError> {
    std::fs::read_to_string(path)
        .map_err(|e| FacadeError::Invalid(format!("cannot read {}: {e}", path.display())))
}

pub(super) fn is_c(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".c")
}

pub(super) fn is_public(f: &FunctionView<'_>) -> bool {
    f.module
        .symbols
        .iter()
        .any(|s| s.public && s.name == f.name && s.section == f.section && s.offset == f.start)
}

/// The `size` of the first active (not refuted) symbol at each address, built once per build.
pub(super) fn symbol_sizes(ws: &Workspace) -> HashMap<Address, Option<u64>> {
    let mut sizes = HashMap::new();
    for s in ws
        .symbols
        .iter()
        .filter(|s| s.confidence != decovery_core::Confidence::Refuted)
    {
        sizes.entry(s.address).or_insert(s.size);
    }
    sizes
}

pub(super) fn verdict_id(v: &Verdict) -> VerdictId {
    match v {
        Verdict::Identical => VerdictId::Identical,
        Verdict::Equivalent { .. } => VerdictId::Equivalent,
        Verdict::Differs => VerdictId::Differs,
        _ => VerdictId::Unchecked,
    }
}

pub(super) fn blocker_record(b: &Blocker) -> BlockerRecord {
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
    r.diagnoses = c.diagnoses.clone();
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
    let mut v = json!({
        "address": r.address.to_string(),
        "name": r.name,
        "file": r.file,
        "verdict": r.verdict.map(VerdictId::id),
        "result": r.result.id(),
        "blockers": r.blockers.iter().map(blocker_json).collect::<Vec<_>>(),
        "bytes": r.bytes,
        "differing": r.differing,
        "instructions_differing": r.instructions_differing,
    });
    if !r.diagnoses.is_empty() {
        v["diagnoses"] = json!(r.diagnoses);
    }
    v
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
    let budget = request.budget.unwrap_or(Budget::default().chars);
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
