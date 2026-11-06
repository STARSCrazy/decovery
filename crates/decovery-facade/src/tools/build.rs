//! `build`: compile the rebuild sources, compare their objects with the original and record the results.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use decovery_core::{
    Address, Analysis, BlockerRecord, RebuildRecord, RebuildResult, VerdictId, Workspace,
    merge_rebuild, read_rebuild, read_user_config, save_rebuild, today, write_atomic,
};
use decovery_diff::{Blocker, Comparison, ModuleOptions, Placement, SymbolView, Verdict};
use decovery_objects::{FunctionView, ObjectFile, functions, read_omf};
use decovery_plugin::Progress;
use decovery_toolchain::{
    CheatFinding, CompiledFile, compile_planned, find_cheats, find_sources, open_runners,
    plan_compile, rebuild_profile, stage_text,
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

/// Most variants one `build` call compiles.
pub const MAX_VARIANTS: usize = 64;

/// A candidate source text for one function, compiled instead of the function's file (`build` with `variants`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Variant {
    pub label: Option<String>,
    pub source: String,
}

impl Variant {
    pub fn new(source: impl Into<String>) -> Self {
        Variant {
            label: None,
            source: source.into(),
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// What to build: `files` (names in `src/`; empty = all sources), optionally reported for one `function` only.
/// With `variants` the request compiles those candidate sources for `function` and ranks them instead; nothing is
/// recorded then.
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
    let mut placements: Vec<Placement<'_>> = Vec::new();
    let mut placed: Vec<Built> = Vec::new();
    let mut taken: HashMap<Address, String> = HashMap::new();
    for (i, object) in &objects {
        for module in &object.modules {
            for view in functions(module).into_iter().filter(|f| is_public(f)) {
                let raw = view.name;
                let Some((name, address)) = place_name(&knowledge, &profile, raw) else {
                    hints.push(format!(
                        "{}: no counterpart in the original",
                        profile.decoration.undecorate(raw)
                    ));
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
                let original_len = original_len(index.as_ref(), &symbol_sizes, address);
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

/// The file of `function`: the one its rebuild record names, else the only source in `src/` that defines it.
fn file_of_function(root: &Path, function: &str) -> Result<String, FacadeError> {
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
        if defines_function(&read_text(path)?, function) {
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

/// Whether `text` has a definition of the C function `name`: a line starting in column 0 with an identifier, holding
/// `name(` and neither ending in `;` (a prototype) nor assigning (an initializer).
fn defines_function(text: &str, name: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.lines().any(|line| {
        if !line
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || line.trim_end().ends_with(';')
            || line.contains('=')
        {
            return false;
        }
        let mut from = 0;
        while let Some(found) = line[from..].find(name) {
            let at = from + found;
            let rest = &line[at + name.len()..];
            if !line[..at].chars().next_back().is_some_and(ident)
                && rest.trim_start().starts_with('(')
            {
                return true;
            }
            from = at + name.len();
        }
        false
    })
}

/// The C name and original address of a function of an object, as the build places it: by the undecorated name,
/// else by the raw one.
fn place_name<'a>(
    knowledge: &KnowledgeView<'_>,
    profile: &decovery_toolchain::Profile,
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
fn original_len(
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
struct Compiled {
    files: Vec<CompiledFile>,
    input_hashes: BTreeMap<String, String>,
    warnings: Vec<String>,
}

/// Compiles the staged `jobs_input` (DOS name, flags) in `run_dir`: inputs read once, object cache first, all
/// misses in one runner request (started only when there are misses).
fn compile_jobs(
    ws: &Workspace,
    profile: &decovery_toolchain::Profile,
    jobs_input: &[(String, String)],
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
    let rebuild = ws.config.rebuild.clone().unwrap_or_default();
    let runner_names = if rebuild.runners.is_empty() {
        profile.runners.clone()
    } else {
        rebuild.runners.clone()
    };
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
        Some(plan) => {
            compile_planned(ws, profile, plan, run_dir, &runners, None).map_err(toolchain)?
        }
    };
    drop(runners);
    warnings.extend(more);
    Ok(Compiled {
        files,
        input_hashes,
        warnings,
    })
}

/// Why a file without object failed.
fn failure_text(file: &CompiledFile) -> String {
    if file.message.is_empty() {
        "compile failed".to_string()
    } else {
        file.message.clone()
    }
}

/// The outcome of one variant.
struct VariantResult {
    /// 1-based: the variant's position in the request, also the number in its staged name (`V001.C`).
    index: usize,
    label: Option<String>,
    verdict: &'static str,
    /// The variant has a comparison with the original (compiled, function found, original bytes available).
    checked: bool,
    instructions_differing: u32,
    differing: u32,
    refs_wrong: u32,
    blockers: Vec<BlockerRecord>,
    message: Option<String>,
}

impl VariantResult {
    fn unchecked(
        index: usize,
        label: Option<String>,
        verdict: &'static str,
        message: String,
    ) -> Self {
        VariantResult {
            index,
            label,
            verdict,
            checked: false,
            instructions_differing: 0,
            differing: 0,
            refs_wrong: 0,
            blockers: Vec::new(),
            message: Some(message),
        }
    }

    /// Variants with a comparison first; among them identical first, then fewer differing instructions, then fewer
    /// differing bytes plus wrong references, then the order of the request.
    fn rank(&self) -> (bool, bool, u32, u32, usize) {
        (
            !self.checked,
            self.verdict != "identical",
            self.instructions_differing,
            self.differing.saturating_add(self.refs_wrong),
            self.index,
        )
    }

    fn json(&self) -> Value {
        let mut v = json!({
            "index": self.index,
            "label": self.label,
            "verdict": self.verdict,
            "instructions_differing": self.instructions_differing,
            "differing": self.differing,
            "refs_wrong": self.refs_wrong,
            "blockers": self.blockers.iter().map(blocker_json).collect::<Vec<_>>(),
        });
        if let Some(m) = &self.message {
            v["message"] = json!(m);
        }
        v
    }
}

/// `build` with variants: compiles the candidate sources of `request.variants` for `request.function` (all cache
/// misses in one runner request), compares the function of each variant's object with the original and ranks the
/// variants. Records, kept objects and output files stay untouched.
fn build_variants(
    root: &Path,
    request: &BuildRequest,
    progress: &dyn Fn(Progress),
    started: Instant,
) -> Result<Response, FacadeError> {
    let function = request.function.as_deref().ok_or_else(|| {
        FacadeError::Invalid("build with variants needs a function (--function <name>)".into())
    })?;
    if request.variants.len() > MAX_VARIANTS {
        return Err(FacadeError::Invalid(format!(
            "at most {MAX_VARIANTS} variants per call, got {}",
            request.variants.len()
        )));
    }
    if request.files.len() > 1 {
        return Err(FacadeError::Invalid(
            "build with variants takes at most one file (the one the variants replace)".into(),
        ));
    }
    let ws = Workspace::open(root)?;
    let analysis = Analysis::load(root)?.filter(|a| a.target_sha256 == ws.config.target.sha256);
    let (profile, default_flags) = rebuild_profile(&ws).map_err(toolchain)?;
    let rebuild = ws.config.rebuild.clone().unwrap_or_default();
    let file = match request.files.first() {
        Some(file) => file.clone(),
        None => file_of_function(root, function)?,
    };
    let flags = file_flags(&rebuild.file_flags, &file)
        .cloned()
        .unwrap_or(default_flags);
    // the variants replace `file`; the headers of src/ are staged beside them
    let set = find_sources(&root.join(SOURCE_DIR), &[]).map_err(toolchain)?;
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
    let staged_name = |i: usize| format!("V{:03}.C", i + 1);
    let mut errors: Vec<Option<String>> = vec![None; request.variants.len()];
    let mut jobs_input: Vec<(String, String)> = Vec::new();
    let mut staged: Vec<usize> = Vec::new();
    for (i, variant) in request.variants.iter().enumerate() {
        match stage_text(&staged_name(i), &variant.source, &run_dir.0) {
            Ok(dos_name) => {
                jobs_input.push((dos_name, flags.clone()));
                staged.push(i);
            }
            Err(e) => errors[i] = Some(e.to_string()),
        }
    }

    let compile_started = Instant::now();
    let Compiled {
        files: compiled,
        mut warnings,
        ..
    } = compile_jobs(&ws, &profile, &jobs_input, &run_dir.0, progress)?;
    drop(run_dir);
    let jobs = compiled.iter().filter(|c| !c.cached).count();
    let cached = compiled.len() - jobs;
    let compile_ms = ms(compile_started.elapsed());

    // compare the function of each variant's object
    let compare_started = Instant::now();
    let mut objects: Vec<Option<ObjectFile>> = Vec::new();
    objects.resize_with(request.variants.len(), || None);
    for (&i, file) in staged.iter().zip(&compiled) {
        match &file.object {
            None => errors[i] = Some(failure_text(file)),
            Some(bytes) => match read_omf(bytes, &staged_name(i)) {
                Ok(object) => objects[i] = Some(object),
                Err(e) => errors[i] = Some(format!("cannot read the object: {e}")),
            },
        }
    }
    let knowledge = KnowledgeView::new(&ws, analysis.as_ref());
    let index = analysis.as_ref().map(Analysis::index);
    let symbol_sizes = symbol_sizes(&ws);
    let options = ModuleOptions::new(profile.padding, rebuild.frames.clone());
    let mut program = None;
    let mut results: Vec<VariantResult> = Vec::new();
    for (i, variant) in request.variants.iter().enumerate() {
        let (number, label) = (i + 1, variant.label.clone());
        if let Some(message) = errors[i].take() {
            results.push(VariantResult::unchecked(number, label, "error", message));
            continue;
        }
        let Some(object) = &objects[i] else {
            continue;
        };
        let found = object.modules.iter().find_map(|module| {
            functions(module)
                .into_iter()
                .filter(|f| is_public(f))
                .find_map(|view| {
                    let (name, address) = place_name(&knowledge, &profile, view.name)?;
                    (name == function || address.to_string() == function)
                        .then_some((view, name, address))
                })
        });
        let Some((view, name, address)) = found else {
            results.push(VariantResult::unchecked(
                number,
                label,
                "unchecked",
                format!(
                    "the object does not define {function} (or it has no counterpart in the original)"
                ),
            ));
            continue;
        };
        let placements = [Placement::new(
            view,
            address,
            original_len(index.as_ref(), &symbol_sizes, address),
        )];
        if program.is_none() {
            program = Some(crate::program::load(&ws)?);
        }
        let Some(program) = program.as_ref() else {
            continue;
        };
        let module = decovery_diff::compare_module(
            &placements,
            program,
            &knowledge,
            &profile.decoration,
            &options,
        );
        warnings.extend(module.warnings);
        let Some(comparison) = module.functions.into_iter().next() else {
            results.push(VariantResult::unchecked(
                number,
                label,
                "unchecked",
                format!("{function} was not compared"),
            ));
            continue;
        };
        let m = &comparison.metrics;
        let mut verdict = verdict_id(&comparison.verdict);
        let checked = verdict != VerdictId::Unchecked;
        let mut blockers: Vec<BlockerRecord> =
            comparison.blockers.iter().map(blocker_record).collect();
        let mut message = (!checked)
            .then(|| "the original bytes of the function are not in the program".to_string());
        // inline assembly is never identical (find_cheats needs LF text)
        let text = variant.source.replace("\r\n", "\n");
        let findings: Vec<CheatFinding> = find_cheats(&text)
            .into_iter()
            .filter(|f| f.function.as_deref() == Some(name))
            .collect();
        if !findings.is_empty() {
            blockers.push(blocker_record(&Blocker::InlineAssembly));
            if checked {
                verdict = VerdictId::Differs;
            }
            let found = findings
                .iter()
                .map(|f| format!("line {}: {} {}", f.line, f.kind.id(), f.text))
                .collect::<Vec<_>>()
                .join("\n");
            message = Some(match message {
                Some(before) => format!("{before}\n{found}"),
                None => found,
            });
        }
        results.push(VariantResult {
            index: number,
            label,
            verdict: verdict.id(),
            checked,
            instructions_differing: m.instructions_differing,
            differing: m.differing,
            refs_wrong: m.refs_wrong,
            blockers,
            message,
        });
    }
    results.sort_by_key(VariantResult::rank);
    let compare_ms = ms(compare_started.elapsed());

    let best = results.first().filter(|r| r.checked);
    let failed = results.iter().filter(|r| r.verdict == "error").count();
    let n = results.len();
    let mut summary = format!("{function}: {n} variant{}", if n == 1 { "" } else { "s" });
    match best {
        Some(r) => summary.push_str(&format!(
            ", best variant {} {} ({} instructions, {} bytes differ)",
            r.index, r.verdict, r.instructions_differing, r.differing
        )),
        None => summary.push_str(", none could be compared"),
    }
    if failed > 0 {
        summary.push_str(&format!("; {failed} failed to compile"));
    }
    Ok(Response::new(
        summary,
        json!({
            "function": function,
            "best": best.map(|r| r.index),
            "variants": results.iter().map(VariantResult::json).collect::<Vec<_>>(),
            "warnings": warnings,
            "timing": {
                "compile_ms": compile_ms,
                "compare_ms": compare_ms,
                "total_ms": ms(started.elapsed()),
                "jobs": jobs,
                "cached": cached,
            },
        }),
    ))
}

fn blocker_json(b: &BlockerRecord) -> Value {
    let mut v = json!({ "kind": b.kind });
    if let Some(at) = b.at {
        v["at"] = json!(at);
    }
    if let Some(count) = b.count {
        v["count"] = json!(count);
    }
    v
}

fn read_text(path: &Path) -> Result<String, FacadeError> {
    std::fs::read_to_string(path)
        .map_err(|e| FacadeError::Invalid(format!("cannot read {}: {e}", path.display())))
}

fn is_c(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".c")
}

fn is_public(f: &FunctionView<'_>) -> bool {
    f.module
        .symbols
        .iter()
        .any(|s| s.public && s.name == f.name && s.section == f.section && s.offset == f.start)
}

/// The `size` of the first active (not refuted) symbol at each address, built once per build.
fn symbol_sizes(ws: &Workspace) -> HashMap<Address, Option<u64>> {
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
        "blockers": r.blockers.iter().map(blocker_json).collect::<Vec<_>>(),
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
