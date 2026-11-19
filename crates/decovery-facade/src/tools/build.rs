//! `build`: compile the rebuild sources, compare their objects with the original and record the results.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use decovery_core::{
    Address, Analysis, BlockerRecord, OverlayName, Program, RebuildRecord, RebuildResult,
    TargetFormat, VerdictId, Workspace, merge_rebuild, read_rebuild, read_user_config,
    save_rebuild, today, write_atomic,
};
use decovery_diff::{Blocker, Comparison, ModuleOptions, Placement, SymbolView, Verdict};
use decovery_objects::{FunctionView, ObjectFile, ObjectFormat, functions, read_object};
use decovery_plugin::Progress;
use decovery_toolchain::{
    AssembleError, BUILTIN_ASSEMBLER, CheatFinding, CompiledFile, JobSpan, Profile, Runner,
    SourceJob, SourceSet, assemble_listing, assembler_profile, compile_planned, definitions,
    find_cheats, find_sources, open_runners, plan_compile, rebuild_profile, stage_text,
    startup_object, tool_dir, tool_fingerprint,
};
use serde_json::{Value, json};

use super::history::{
    AttemptSource, RecordAs, Tried, fingerprint_of, mark_archived, record_attempts,
};
use super::variants::{Variant, build_variants};
use crate::{
    Budget, Change, Control, FacadeError, KnowledgeView, Response, Session, store_handle,
    write_affected,
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
/// for `function` and ranks them instead; only their attempts are recorded then (`history`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuildRequest {
    pub files: Vec<String>,
    pub function: Option<String>,
    pub variants: Vec<Variant>,
    /// Characters of the function list returned inline (default [`Budget::default`]); the rest is a handle.
    pub budget: Option<usize>,
    /// How the attempts of this build are recorded when the caller is not the agent (the bridge's `search`).
    pub(crate) record: RecordAs,
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
        Ok(bytes) => read_object(profile.object_format, &bytes, &name).map_err(|e| e.to_string()),
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

/// The profile's string-literal sections (ADR 0006 item 12) for the modules of `compiled`, the objects its
/// compiler wrote (assembler sources are compared in full).
pub(super) fn literal_sections(
    profile: &Profile,
    compiled: &[&ObjectFile],
) -> Option<decovery_diff::LiteralSections> {
    let spec = profile.literals.as_ref()?;
    let modules = compiled
        .iter()
        .flat_map(|o| o.modules.iter().map(|m| m.name.clone()))
        .collect();
    Some(decovery_diff::LiteralSections::new(
        spec.sections.iter().cloned().collect(),
        spec.align,
        modules,
    ))
}

pub(super) fn toolchain(e: decovery_toolchain::ToolchainError) -> FacadeError {
    FacadeError::Invalid(e.to_string())
}

/// [`toolchain`], or [`FacadeError::Cancelled`] when `control` was cancelled (a runner request ends in an error then).
pub(super) fn toolchain_or_cancelled<'c>(
    control: &'c Control<'_>,
) -> impl FnOnce(decovery_toolchain::ToolchainError) -> FacadeError + 'c {
    move |e| {
        if control.is_cancelled() {
            FacadeError::Cancelled
        } else {
            toolchain(e)
        }
    }
}

pub(super) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Adds `timeline` (phases and compile jobs in ms since `started`), `slots`, `lower_bound_ms`, `saturation` and
/// `efficiency` (plan decision 5) to `timing`. Jobs without reported times are left out of the timeline.
fn add_timeline(
    timing: &mut Value,
    started: Instant,
    phases: &[(&str, Instant, Instant)],
    sources: &[Source],
) {
    let at = |t: Instant| ms(t.saturating_duration_since(started));
    let mut slots = 1;
    let mut spans: Vec<JobSpan> = Vec::new();
    let mut jobs: Vec<Value> = Vec::new();
    for source in sources {
        let Some(times) = source.compiled.as_ref().and_then(|c| c.times) else {
            continue;
        };
        let (Some(start), Some(end)) = (times.started_ms, times.ended_ms) else {
            continue;
        };
        let queued = at(times.submitted);
        slots = slots.max(times.slots);
        let span = JobSpan {
            queued_ms: queued,
            start_ms: queued + start,
            end_ms: queued + end,
        };
        spans.push(span);
        jobs.push(json!({
            "file": source.name,
            "queued_ms": span.queued_ms,
            "start_ms": span.start_ms,
            "end_ms": span.end_ms,
            "cpu_ms": times.cpu_ms,
        }));
    }
    jobs.sort_by_key(|j| j["start_ms"].as_u64());
    let wall = phases.last().map_or(0, |p| at(p.2));
    let compile = phases
        .iter()
        .find(|p| p.0 == "compile")
        .map_or(0, |p| ms(p.2.saturating_duration_since(p.1)));
    let throughput = decovery_toolchain::throughput(&spans, slots, wall, compile);
    let round = |x: f64| (x * 1000.0).round() / 1000.0;
    timing["timeline"] = json!({
        "phases": phases.iter().map(|(name, from, to)| json!({
            "name": name, "start_ms": at(*from), "end_ms": at(*to),
        })).collect::<Vec<_>>(),
        "jobs": jobs,
    });
    timing["slots"] = json!(slots);
    timing["lower_bound_ms"] = json!(throughput.lower_bound_ms);
    timing["saturation"] = json!(throughput.saturation.map(round));
    timing["efficiency"] = json!(round(throughput.efficiency));
}

/// One source of the build.
struct Source {
    /// Name in `src/` (`ai.c`), as recorded in `file`.
    name: String,
    /// Staged DOS name (`AI.C`).
    dos_name: String,
    flags: String,
    /// What builds the source, as recorded in `compiler`: the profile, [`BUILTIN_ASSEMBLER`] or the profile that
    /// runs the assembler.
    compiler: String,
    /// Source text with LF line ends, for the inline-assembly check (C) and the attempt records.
    text: String,
    compiled: Option<CompiledFile>,
    /// Why the source has no object.
    error: Option<String>,
    /// The profile has no way to build this source (an assembler file neither the built-in assembler nor an
    /// assembler run can build): not built, its records and its kept object stay as they are.
    skipped: bool,
    /// Why it was skipped, when there is more to say than that no assembler is available.
    skip_hint: Option<String>,
}

/// The workspace and profile that run the profile's assembler, when the toolchain is there: its directory (the
/// workspace's `[rebuild] tool_dir` only when the assembler is the compiler's own profile, else the user config's
/// `[toolchains]` entry) holds the profile's fingerprint files.
fn profile_assembler(ws: &Workspace, profile: &Profile) -> Option<(Workspace, Profile)> {
    let assembler = assembler_profile(profile).ok().flatten()?;
    let mut ws = ws.clone();
    if assembler.id != profile.id
        && let Some(rebuild) = ws.config.rebuild.as_mut()
    {
        rebuild.tool_dir = None;
    }
    let user = read_user_config().ok()?;
    let dir = tool_dir(&assembler, ws.config.rebuild.as_ref(), &user, &ws.root).ok()?;
    tool_fingerprint(&assembler, &dir).ok()?;
    Some((ws, assembler))
}

pub(super) fn is_asm(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".asm")
}

/// A compared function of the build.
pub(super) struct Built {
    pub(super) source: usize,
    /// The function's name in the source (what pragmas and variants name it by).
    pub(super) name: String,
    /// The name the build reports: the knowledge's name at the address, else [`Built::name`].
    pub(super) label: String,
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
/// kept objects and the affected output files. MASM sources (`.asm`) go to the built-in assembler first
/// ([`assemble_listing`]); one with a line outside its subset is assembled by the profile's assembler when that
/// toolchain is there, else skipped with the line. Other assembler sources (`.s`) are skipped.
///
/// Cancellation ([`Control::cancel`]) is checked before compiling, passed to the runner request, and checked after
/// compiling and before recording; a cancelled build records nothing (no rebuild records, kept objects, output or
/// attempts). Recording is never interrupted.
pub fn build(
    root: &Path,
    request: &BuildRequest,
    control: &Control,
) -> Result<Response, FacadeError> {
    let started = Instant::now();
    control.check()?;
    if !request.variants.is_empty() {
        return build_variants(root, request, control, started);
    }
    let progress = control.progress;
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

    // the runners start while the sources are staged
    let opening = Some(Opening::start(&ws, &profile)?);

    // stage; the built-in assembler builds what it can right here
    let run_dir = new_run_dir(root)?;
    let headers = stage_headers(&set, &run_dir.0)?;
    let mut sources: Vec<Source> = Vec::new();
    let mut assembler: Option<Option<(Workspace, Profile)>> = None;
    let mut assembler_jobs: Vec<usize> = Vec::new();
    let mut assembled_inputs: BTreeMap<String, String> = BTreeMap::new();
    for path in &set.sources {
        let name = file_name(path);
        let flags = file_flags(&rebuild.file_flags, &name)
            .cloned()
            .unwrap_or_else(|| default_flags.clone());
        let mut source = Source {
            dos_name: name.to_ascii_uppercase(),
            name,
            flags,
            compiler: profile.id.clone(),
            text: String::new(),
            compiled: None,
            error: None,
            skipped: false,
            skip_hint: None,
        };
        if is_asm(&source.name) {
            match stage_hashed(path, &source.name, &run_dir.0) {
                Err(e) => source.error = Some(e.to_string()),
                Ok((text, hash)) => {
                    source.flags = String::new();
                    source.text = text.replace("\r\n", "\n");
                    match assemble_listing(&source.dos_name, &text) {
                        Ok(object) => {
                            source.compiler = BUILTIN_ASSEMBLER.to_string();
                            source.compiled = Some(CompiledFile::built(&source.dos_name, object));
                            assembled_inputs.insert(source.dos_name.clone(), hash);
                        }
                        Err(AssembleError::Unsupported { line, text }) => {
                            match assembler.get_or_insert_with(|| profile_assembler(&ws, &profile))
                            {
                                Some((_, assembler)) => {
                                    source.compiler = assembler.id.clone();
                                    assembler_jobs.push(sources.len());
                                }
                                None => {
                                    source.skipped = true;
                                    source.skip_hint = Some(format!(
                                        "{}: line {line} is outside the built-in assembler subset ({text}) \
                                         and no assembler is available",
                                        source.name
                                    ));
                                }
                            }
                        }
                        Err(e) => source.error = Some(e.to_string()),
                    }
                }
            }
        } else if !is_c(&source.name) {
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

    let built_files: Vec<String> = sources
        .iter()
        .filter(|s| !s.skipped)
        .map(|s| s.name.clone())
        .collect();

    // compile: cache hits, then all misses in one runner request
    let compile_started = Instant::now();
    let mut staged: Vec<usize> = (0..sources.len())
        .filter(|&i| is_c(&sources[i].name) && sources[i].error.is_none() && !sources[i].skipped)
        .collect();
    let jobs_input: Vec<SourceJob> = staged
        .iter()
        .map(|&i| SourceJob::new(sources[i].dos_name.clone(), sources[i].flags.clone()))
        .collect();
    let Compiled {
        files: mut compiled,
        mut input_hashes,
        mut warnings,
        closing,
    } = compile_jobs(&ws, &profile, &jobs_input, &run_dir.0, control, opening)?;
    if let Some(Some((asm_ws, asm_profile))) =
        assembler.as_ref().filter(|_| !assembler_jobs.is_empty())
    {
        // the sources the built-in assembler cannot take, through the profile's assembler
        let asm_input: Vec<SourceJob> = assembler_jobs
            .iter()
            .map(|&i| SourceJob::new(sources[i].dos_name.clone(), String::new()))
            .collect();
        let more = compile_jobs(asm_ws, asm_profile, &asm_input, &run_dir.0, control, None)?;
        compiled.extend(more.files);
        input_hashes.extend(more.input_hashes);
        warnings.extend(more.warnings);
        staged.extend(assembler_jobs.iter().copied());
    }
    input_hashes.extend(assembled_inputs);
    let jobs = compiled.iter().filter(|c| !c.cached).count();
    let cached = compiled.len() - jobs;
    let assembled = sources
        .iter()
        .filter(|s| s.compiler == BUILTIN_ASSEMBLER && s.compiled.is_some())
        .count();
    for (&i, file) in staged.iter().zip(compiled) {
        if file.object.is_none() {
            sources[i].error = Some(failure_text(&file));
        }
        sources[i].compiled = Some(file);
    }
    drop(run_dir);
    control.check()?;
    let compile_ended = Instant::now();
    let compile_ms = ms(compile_ended - compile_started);

    // read objects
    let compare_started = Instant::now();
    let mut objects: Vec<(usize, ObjectFile)> = Vec::new();
    for (i, source) in sources.iter_mut().enumerate() {
        let Some(bytes) = source.compiled.as_ref().and_then(|c| c.object.as_ref()) else {
            continue;
        };
        // the built-in assembler writes OMF; the compiler and the profile's assembler their profile's format
        let format = if source.compiler == profile.id {
            profile.object_format
        } else {
            decovery_toolchain::profile(&source.compiler)
                .map_or(ObjectFormat::Omf, |p| p.object_format)
        };
        match read_object(format, bytes, &source.dos_name) {
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
    let mut originals: HashMap<Address, String> = HashMap::new();
    progress(Progress::new(
        0,
        Some(placements.len() as u64),
        Some(format!("comparing {} functions", placements.len())),
    ));
    let comparisons: Vec<Comparison> = if placements.is_empty() {
        Vec::new()
    } else {
        let program = crate::program::load(&ws)?;
        for p in &placements {
            if let Some(bytes) = p
                .original_len
                .and_then(|len| program.read(p.at, len as usize))
            {
                originals.insert(p.at, super::history::hex(bytes));
            }
        }
        let compiled: Vec<&ObjectFile> = objects
            .iter()
            .filter(|(i, _)| sources[*i].compiler == profile.id && is_c(&sources[*i].name))
            .map(|(_, object)| object)
            .collect();
        compare_placed(
            &ws,
            &profile,
            &rebuild.frames,
            &knowledge,
            &program,
            &placements,
            &compiled,
            &mut warnings,
        )
    };
    drop(placements);

    // whole overlay modules (Aztec C86): the objects whose functions lie in one overlay, in source order
    let modules = if profile.object_format == ObjectFormat::Aztec {
        let mut of_source: BTreeMap<usize, OverlayName> = BTreeMap::new();
        for b in &placed {
            if let Some(name) = b.address.overlay() {
                of_source.entry(b.source).or_insert(name);
            }
        }
        let assigned: Vec<(OverlayName, &ObjectFile)> = objects
            .iter()
            .filter_map(|(i, object)| of_source.get(i).map(|&name| (name, object)))
            .collect();
        overlay_modules(&ws, &assigned, &mut warnings)
    } else {
        Vec::new()
    };

    // inline assembly
    let mut cheats: Vec<Vec<CheatFinding>> = Vec::new();
    for source in &sources {
        let mut findings: Vec<CheatFinding> = Vec::new();
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
                findings.push(finding);
            }
        }
        cheats.push(findings);
    }
    let compare_ended = Instant::now();
    let compare_ms = ms(compare_ended - compare_started);

    // records of this build
    let date = today();
    let mut new_records: Vec<RebuildRecord> = Vec::new();
    for (built, comparison) in placed.iter().zip(&comparisons) {
        let source = &sources[built.source];
        let mut r = record(built, comparison, source, &date);
        // a code pragma or a finding outside any function blocks every function of the file
        let findings: Vec<&CheatFinding> = cheats[built.source]
            .iter()
            .filter(|f| f.blocks(&built.name))
            .collect();
        if !findings.is_empty() {
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
                .map(|f| f.describe(&built.name))
                .collect::<Vec<_>>()
                .join("\n");
            r.message = Some(match r.message.take() {
                Some(before) => format!("{before}\n{found}"),
                None => found,
            });
        }
        new_records.push(r);
    }

    let fingerprint = fingerprint_of(&ws, &profile);

    // record under the lock; from here on a cancel takes effect after recording
    control.check()?;
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
            r.compiler = Some(source.compiler.clone());
            r.flags = Some(source.flags.clone());
            r.verdict = Some(VerdictId::Unchecked);
            r.message = Some(message.clone());
            r.date = Some(date.clone());
            new_records.push(r);
        }
    }
    for source in sources.iter().filter(|s| s.skipped) {
        hints.push(
            source
                .skip_hint
                .clone()
                .unwrap_or_else(|| format!("no assembler available for {}", source.name)),
        );
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
    keep_objects(root, &sources, &new_records, &input_hashes)?;
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
        // the exemplar index is cache data: a failure to refresh it does not fail the build
        if let Err(e) = crate::exemplar_index(&session) {
            warnings.push(format!("exemplar index not refreshed: {e}"));
        }
    }
    drop(lock);
    let record_ended = Instant::now();
    let record_ms = ms(record_ended - record_started);

    // attempts, outside the workspace lock
    let tried = attempts_of(
        &sources,
        &new_records,
        &headers,
        &fingerprint,
        &originals,
        &request.record,
    );
    warnings.extend(record_attempts(root, tried));

    // the runners have stopped before the build answers
    drop(closing);
    let ended = Instant::now();
    let mut timing = json!({
        "compile_ms": compile_ms,
        "compare_ms": compare_ms,
        "record_ms": record_ms,
        "total_ms": ms(ended - started),
        "jobs": jobs,
        "cached": cached,
        "assembled": assembled,
    });
    let phases = [
        ("stage", started, compile_started),
        ("compile", compile_started, compile_ended),
        ("compare", compare_started, compare_ended),
        ("record", record_started, record_ended),
        ("attempts", record_ended, ended),
    ];
    add_timeline(&mut timing, started, &phases, &sources);
    respond(
        root,
        request,
        &sources,
        new_records,
        hints,
        warnings,
        timing,
    )
    .map(|mut response| {
        add_modules(&mut response, modules);
        response
    })
}

/// Compares the placed functions with the original. An Aztec object has no linker (phase 4): each function is
/// compared against the image with its relocated fields as link gaps, and the module comparison's data anchors
/// are not computed (their warnings would describe a comparison the verdicts do not come from; an overlay's data
/// and BSS are judged by [`overlay_modules`]).
#[allow(clippy::too_many_arguments)]
fn compare_placed(
    ws: &Workspace,
    profile: &Profile,
    frames: &BTreeMap<String, Address>,
    knowledge: &KnowledgeView<'_>,
    program: &Program,
    placements: &[Placement<'_>],
    compiled: &[&ObjectFile],
    warnings: &mut Vec<String>,
) -> Vec<Comparison> {
    if profile.object_format == ObjectFormat::Aztec {
        return placements
            .iter()
            .map(|p| {
                let len = p.function.code().len();
                let image = program.read(p.at, len).unwrap_or(&[]);
                decovery_diff::compare_with_gaps(&p.function, image, p.at)
            })
            .collect();
    }
    // the diagnosis reads the instruction pairs of the comparison: no second decode
    let mut options = ModuleOptions::new(profile.padding, frames.clone())
        .with_startup_frames(startup_frames(ws, profile, program, warnings))
        .with_diagnosis(profile.family.clone());
    if let Some(literals) = literal_sections(profile, compiled) {
        options = options.with_literals(literals);
    }
    let module = decovery_diff::compare_module(
        placements,
        program,
        knowledge,
        &profile.decoration,
        &options,
    );
    warnings.extend(module.warnings);
    module.functions
}

/// Adds the overlay module verdicts to a build response (data `modules`, a note in the summary).
fn add_modules(response: &mut Response, modules: Vec<Value>) {
    if modules.is_empty() {
        return;
    }
    let same = modules
        .iter()
        .filter(|m| m["identical"] == json!(true))
        .count();
    response.summary.push_str(&format!(
        "; overlay modules: {same} of {} identical",
        modules.len()
    ));
    for m in &modules {
        if let (Some(overlay), Some(first)) = (m["overlay"].as_str(), m["findings"][0].as_str()) {
            response.summary.push_str(&format!(" ({overlay}: {first})"));
        }
    }
    response.data["modules"] = json!(modules);
}

/// Module verdicts of the overlays that `assigned` objects (in source order) belong to.
pub(super) fn overlay_modules(
    ws: &Workspace,
    assigned: &[(OverlayName, &ObjectFile)],
    warnings: &mut Vec<String>,
) -> Vec<Value> {
    let mut groups: BTreeMap<OverlayName, Vec<&ObjectFile>> = BTreeMap::new();
    for &(name, object) in assigned {
        groups.entry(name).or_default().push(object);
    }
    let mut out = Vec::new();
    for (name, objects) in groups {
        let Some(config) = ws.config.overlay(name) else {
            continue;
        };
        let overlay = match crate::program::read_overlay_of(ws, config) {
            Ok(o) => o,
            Err(e) => {
                warnings.push(e);
                continue;
            }
        };
        let v = decovery_diff::compare_overlay_module(&objects, &overlay);
        let m = &v.code.metrics;
        // data whose every byte is a link gap was not compared: it is unchecked, not equal
        let data_state = if v.data_size.1 > 0 && v.data_gaps >= v.data_size.1 {
            "unchecked"
        } else if v.data_equal {
            "equal"
        } else {
            "differs"
        };
        out.push(json!({
            "overlay": name.as_str(),
            "identical": v.identical,
            "code": {
                "bytes": v.code_size.1,
                "original_bytes": v.code_size.0,
                "differing": m.differing,
                "instructions_differing": m.instructions_differing,
                "first_difference": m.first_difference,
                "refs_ok": m.refs_ok,
                "refs_wrong": m.refs_wrong,
                "refs_unchecked": m.refs_unchecked,
                "gaps": m.gaps,
                "blockers": v.code.blockers.iter().take(16).map(|b| {
                    json!({"kind": b.kind(), "at": b.at(), "count": b.count()})
                }).collect::<Vec<_>>(),
            },
            "data": {
                "state": data_state,
                "equal": data_state == "equal",
                "bytes": v.data_size.1,
                "gaps": v.data_gaps,
                "overlay_bytes": v.data_size.0,
                "differing": v.data_diffs.len(),
                "first_differences": v.data_diffs.iter().take(16).collect::<Vec<_>>(),
            },
            "bss": {
                "original": v.bss.0,
                "rebuilt": v.bss.1,
                "state": if v.bss.0 == v.bss.1 { "equal" } else { "differs" },
                "checked": "size",
            },
            "externals": v.externals.len(),
            "ambiguous": v.ambiguous,
            "findings": v.findings,
        }));
    }
    out
}

/// Reads the source at `path`, stages it as `name` in `dir` and returns its text and blake3 (hex) of the staged
/// bytes.
pub(super) fn stage_hashed(
    path: &Path,
    name: &str,
    dir: &Path,
) -> Result<(String, String), FacadeError> {
    let text = read_text(path)?;
    let dos_name = stage_text(name, &text, dir).map_err(toolchain)?;
    let staged = dir.join(&dos_name);
    let bytes = std::fs::read(&staged).map_err(|source| FacadeError::Output {
        path: staged.clone(),
        source,
    })?;
    Ok((text, blake3::hash(&bytes).to_hex().to_string()))
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
        let overlay = object_overlay(knowledge, profile, object);
        for module in &object.modules {
            for view in functions(module).into_iter().filter(|f| is_public(f)) {
                let raw = view.name;
                let found = overlay
                    .and_then(|o| place_in_overlay(knowledge, profile, raw, o))
                    .or_else(|| place_name(knowledge, profile, raw));
                let Some((name, address)) = found else {
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
                let label = knowledge
                    .name_at(address)
                    .filter(|n| !n.is_default)
                    .map_or_else(|| name.to_string(), |n| n.name);
                placed.push(Built {
                    source: id,
                    name: name.to_string(),
                    label,
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

/// The overlay that holds an object's functions: the one overlay all its by-name placed functions lie in.
fn object_overlay(
    knowledge: &KnowledgeView<'_>,
    profile: &Profile,
    object: &ObjectFile,
) -> Option<OverlayName> {
    let mut found = None;
    for module in &object.modules {
        for view in functions(module).into_iter().filter(|f| is_public(f)) {
            let Some((_, address)) = place_name(knowledge, profile, view.name) else {
                continue;
            };
            match (found, address.overlay()) {
                (_, None) => return None,
                (None, Some(o)) => found = Some(o),
                (Some(f), Some(o)) if f != o => return None,
                _ => {}
            }
        }
    }
    found
}

/// A function of an object that lies in `overlay`, by the overlay-qualified name `<OVERLAY>_<name>`: names must be
/// unique across overlays, so Decomp's analysis names each overlay's own copy of a name used in every overlay
/// (`ovmain`) that way. Only an address inside `overlay` counts.
fn place_in_overlay<'a>(
    knowledge: &KnowledgeView<'_>,
    profile: &Profile,
    raw: &'a str,
    overlay: OverlayName,
) -> Option<(&'a str, Address)> {
    let c_name = profile.decoration.undecorate(raw);
    let address = knowledge.address_of(&format!("{overlay}_{c_name}"))?;
    (address.overlay() == Some(overlay)).then_some((c_name, address))
}

/// Length of the original function at `address`: from the analysis, else the symbol's size.
pub(super) fn original_len(
    index: Option<&decovery_core::AnalysisIndex<'_>>,
    symbol_sizes: &HashMap<Address, Option<u64>>,
    address: Address,
) -> Option<u32> {
    index
        .and_then(|ix| ix.function_at(address))
        .and_then(|f| f.end.bytes_from(f.start)?.checked_add(1))
        .or_else(|| symbol_sizes.get(&address).copied().flatten())
        .and_then(|n| u32::try_from(n).ok())
}

/// What [`compile_jobs`] returns: one file per job, the hashes of everything staged, the runners' warnings.
pub(super) struct Compiled {
    pub(super) files: Vec<CompiledFile>,
    pub(super) input_hashes: BTreeMap<String, String>,
    pub(super) warnings: Vec<String>,
    /// The runners, shutting down; the build keeps this until it answers.
    pub(super) closing: Closing,
}

type Opened = (Vec<Box<dyn Runner>>, Vec<String>);

/// Runners started in the background while the build stages its sources, so a plugin's start-up overlaps the
/// staging.
pub(super) struct Opening(std::thread::JoinHandle<Opened>);

impl Opening {
    pub(super) fn start(ws: &Workspace, profile: &Profile) -> Result<Self, FacadeError> {
        let user = read_user_config()?;
        let names = runner_names(ws, profile);
        let ws = ws.clone();
        Ok(Opening(std::thread::spawn(move || {
            open_runners(&names, &ws, &user)
        })))
    }

    fn wait(self) -> Opened {
        self.0
            .join()
            .unwrap_or_else(|_| (Vec::new(), vec!["runners: start-up failed".to_string()]))
    }
}

/// Runners shutting down in a thread of their own (a plugin may take a while to stop its workers); dropping it
/// waits for them, so no plugin outlives the build.
#[derive(Default)]
pub(super) struct Closing(Vec<std::thread::JoinHandle<()>>);

impl Closing {
    fn close(&mut self, runners: Vec<Box<dyn Runner>>) {
        if !runners.is_empty() {
            self.0.push(std::thread::spawn(move || drop(runners)));
        }
    }
}

impl Drop for Closing {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Compiles the staged `jobs_input` in `run_dir`: inputs read once, object cache first, all misses in one runner
/// request (started only when there are misses). `control` also gets what the runner reports per finished job;
/// its cancel token goes to the runner request, and a cancel before or during compiling ends in
/// [`FacadeError::Cancelled`].
pub(super) fn compile_jobs(
    ws: &Workspace,
    profile: &Profile,
    jobs_input: &[SourceJob],
    run_dir: &Path,
    control: &Control,
    opening: Option<Opening>,
) -> Result<Compiled, FacadeError> {
    // on an early return the runners started early are dropped (shut down) here
    let opened = opening.map(Opening::wait);
    control.check()?;
    let mut closing = Closing::default();
    let mut warnings: Vec<String> = Vec::new();
    let progress = control.progress;
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
    let runners = match opened {
        Some((runners, more)) => {
            warnings.extend(more);
            if needs_runner {
                runners
            } else {
                closing.close(runners);
                Vec::new()
            }
        }
        None if needs_runner => {
            let (runners, more) = open_runners(&runner_names, ws, &user);
            warnings.extend(more);
            runners
        }
        None => Vec::new(),
    };
    let (files, more) = match plan {
        None => (Vec::new(), Vec::new()),
        Some(plan) => {
            let compiled = compile_planned(
                ws,
                profile,
                plan,
                run_dir,
                &runners,
                Some(control.cancel.clone()),
                progress,
            );
            control.check()?;
            compiled.map_err(toolchain)?
        }
    };
    // a plugin stopping its workers takes a while: that overlaps the comparison
    closing.close(runners);
    warnings.extend(more);
    Ok(Compiled {
        files,
        input_hashes,
        warnings,
        closing,
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
fn record(built: &Built, c: &Comparison, source: &Source, date: &str) -> RebuildRecord {
    let m = &c.metrics;
    let verdict = verdict_id(&c.verdict);
    let result = if verdict == VerdictId::Unchecked {
        RebuildResult::Error
    } else if m.differing == 0 && m.refs_wrong == 0 {
        RebuildResult::Identical
    } else {
        RebuildResult::Differs
    };
    let mut r = RebuildRecord::new(built.address, built.label.clone(), result);
    r.file = Some(source.name.clone());
    r.compiler = Some(source.compiler.clone());
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

/// The attempts of a full or file build: one per recorded function (compared, or failed with its file), with
/// origin `build`; identical ones and the compared others are archived (one attempt per function and call).
fn attempts_of(
    sources: &[Source],
    records: &[RebuildRecord],
    headers: &BTreeMap<String, String>,
    fingerprint: &str,
    originals: &HashMap<Address, String>,
    record_as: &RecordAs,
) -> Vec<Tried> {
    let attempt_sources: Vec<AttemptSource> = sources
        .iter()
        .map(|s| {
            AttemptSource::new(
                &s.name,
                &s.text,
                &s.compiler,
                &s.flags,
                headers,
                fingerprint,
            )
        })
        .collect();
    let mut tried = Vec::new();
    for r in records {
        let Some(i) = sources
            .iter()
            .position(|s| r.file.as_deref() == Some(s.name.as_str()))
        else {
            continue;
        };
        let (source, attempt_source) = (&sources[i], &attempt_sources[i]);
        let original = originals.get(&r.address).map_or("", String::as_str);
        let mut a = attempt_source.attempt(
            r.address,
            &r.name,
            decovery_core::AttemptOrigin::Build,
            r.result,
            original,
        );
        a.verdict = r.verdict;
        if r.result != RebuildResult::Error {
            a.instructions_differing = Some(r.instructions_differing);
            a.bytes_differing = Some(r.differing);
        }
        a.blockers = r.blockers.iter().map(|b| b.kind.clone()).collect();
        a.diagnosis = r.diagnoses.clone();
        if let Some(message) = &r.message {
            a.extra.insert("message".into(), json!(message));
        }
        record_as.apply(&mut a);
        let compiled = source.compiled.as_ref();
        let object = compiled
            .and_then(|c| c.object.as_deref())
            .filter(|_| source.error.is_none())
            .map(|bytes| (object_name(&source.dos_name), bytes));
        let message = compiled.map(|c| c.message.as_str());
        let files =
            attempt_source.files(&a, object.as_ref().map(|(n, b)| (n.as_str(), *b)), message);
        tried.push(Tried {
            record: a,
            files,
            archive: false,
        });
    }
    mark_archived(&mut tried);
    tried
}

/// `A.OBJ` for the staged source `A.C`.
pub(super) fn object_name(dos_name: &str) -> String {
    let stem = dos_name.rsplit_once('.').map_or(dos_name, |(s, _)| s);
    format!("{stem}.OBJ")
}

/// Copies each object built in this run to `cache/rebuild/obj/<stem>.obj` with `<stem>.json` (inputs, identical
/// functions). A source without a new object (skipped, or failed this time) keeps whatever is kept there.
fn keep_objects(
    root: &Path,
    sources: &[Source],
    records: &[RebuildRecord],
    inputs: &BTreeMap<String, String>,
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
            "profile": source.compiler,
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

/// One function of the response; a differing one with a first difference and line metadata also carries the
/// pseudo-C line of the original it is near (`c_line`, `near`).
fn function_json(root: &Path, r: &RebuildRecord) -> Value {
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
    if r.result == RebuildResult::Differs
        && let Some(offset) = r.first_difference
        && let Some((line, text)) = super::c_line_near(root, r.address, offset)
    {
        v["c_line"] = json!(line);
        v["near"] = json!(format!("differs near C line {line}: {text}"));
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
        // the knowledge's name, the address, or the default name a source may still use
        records.retain(|r| {
            &r.name == function
                || r.address.to_string() == *function
                || crate::session::default_name(r.address) == *function
        });
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
        let v = function_json(root, r);
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
            .map(|r| format!("{}\n", function_json(root, r)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use decovery_objects::{
        AztecModuleSpec, AztecSection, AztecSymbolSpec, read_aztec, write_aztec,
    };

    /// An overlay workspace: module `f_` = `mov ax, 1; ret` at 5000, `$ovbgn` (`ret`) at 5004, data "x" plus one
    /// library byte, BSS 2.
    fn workspace(bss: u16) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t.com"), [0xC3u8]).unwrap();
        let mut ovr = Vec::new();
        for w in [0xF2u16, 0x5000, 5, 0x9000, 2, bss, 0x5004] {
            ovr.extend(w.to_le_bytes());
        }
        ovr.extend([0xB8, 1, 0, 0xC3, 0xC3, b'x', 0xEE]);
        std::fs::write(dir.path().join("A.OVR"), &ovr).unwrap();
        std::fs::write(
            dir.path().join("decovery.toml"),
            "schema = 1

[target]
file = \"t.com\"
sha256 = \"aa\"
format = \"com\"
processor = \"x86\"

             [[overlay]]
name = \"A\"
file = \"A.OVR\"
sha256 = \"bb\"
format = \"aztec-c86\"
size = 21
",
        )
        .unwrap();
        dir
    }

    fn object() -> ObjectFile {
        let spec = AztecModuleSpec {
            name: "A".into(),
            code: vec![0xB8, 1, 0, 0xC3],
            data: vec![b'x'],
            bss: 2,
            named: vec![AztecSymbolSpec {
                name: "f_".into(),
                section: AztecSection::Code,
                value: 0,
                public: true,
            }],
            ..AztecModuleSpec::default()
        };
        read_aztec(&write_aztec(&spec), "A.O").unwrap()
    }

    #[test]
    fn overlay_module_verdict_is_reported() {
        let object = object();
        let name = OverlayName::new("A").unwrap();
        for (bss, identical) in [(2, true), (4, false)] {
            let dir = workspace(bss);
            let ws = Workspace::open(dir.path()).unwrap();
            let mut warnings = Vec::new();
            let modules = overlay_modules(&ws, &[(name, &object)], &mut warnings);
            assert!(warnings.is_empty(), "{warnings:?}");
            assert_eq!(modules.len(), 1);
            assert_eq!(modules[0]["overlay"], "A");
            assert_eq!(modules[0]["identical"], identical, "{}", modules[0]);
            assert_eq!(modules[0]["code"]["bytes"], 4);
            assert_eq!(modules[0]["bss"]["original"], bss);
            assert_eq!(modules[0]["data"]["equal"], true);
            assert_eq!(modules[0]["data"]["state"], "equal");
            assert_eq!(modules[0]["data"]["gaps"], 0);
            assert_eq!(modules[0]["bss"]["checked"], "size");
            let bss_state = if identical { "equal" } else { "differs" };
            assert_eq!(modules[0]["bss"]["state"], bss_state);
        }
    }

    #[test]
    fn partial_overlay_module_names_the_covered_range() {
        // the rebuilt object covers 4 of the overlay's code bytes: the original is extended by two bytes
        let dir = workspace(2);
        let path = dir.path().join("A.OVR");
        let mut file = std::fs::read(&path).unwrap();
        // header words: magic, corg, csize, dorg, dsize, bss, entry; code follows the 14-byte header
        let csize = u16::from_le_bytes([file[4], file[5]]);
        let entry = u16::from_le_bytes([file[12], file[13]]);
        file[4..6].copy_from_slice(&(csize + 2).to_le_bytes());
        file[12..14].copy_from_slice(&(entry + 2).to_le_bytes());
        file.splice(14 + 4..14 + 4, [0x90, 0x90]);
        std::fs::write(&path, file).unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let object = object();
        let mut warnings = Vec::new();
        let modules = overlay_modules(
            &ws,
            &[(OverlayName::new("A").unwrap(), &object)],
            &mut warnings,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        let first = modules[0]["findings"][0].as_str().unwrap_or_default();
        assert!(
            first.contains("covers only 0x0000..0x0004 of 0x0000..0x0006"),
            "{}",
            modules[0]
        );
        assert_eq!(modules[0]["code"]["instructions_differing"], 0);
    }

    #[test]
    fn unreadable_overlay_is_a_warning() {
        let dir = workspace(2);
        std::fs::remove_file(dir.path().join("A.OVR")).unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let object = object();
        let mut warnings = Vec::new();
        let modules = overlay_modules(
            &ws,
            &[(OverlayName::new("A").unwrap(), &object)],
            &mut warnings,
        );
        assert!(modules.is_empty());
        assert_eq!(warnings.len(), 1);
    }

    fn aztec_object(names: &[&str]) -> ObjectFile {
        let spec = AztecModuleSpec {
            name: "M".into(),
            code: vec![0xC3; 2 * names.len()],
            named: names
                .iter()
                .enumerate()
                .map(|(i, n)| AztecSymbolSpec {
                    name: (*n).into(),
                    section: AztecSection::Code,
                    value: 2 * i as u16,
                    public: true,
                })
                .collect(),
            ..AztecModuleSpec::default()
        };
        read_aztec(&write_aztec(&spec), "M.O").unwrap()
    }

    #[test]
    fn overlay_main_is_placed_in_its_own_overlay() {
        let dir = workspace(2);
        std::fs::create_dir_all(dir.path().join("knowledge")).unwrap();
        let mut symbols = String::from("schema = 1\n\n");
        for (address, name) in [
            ("ovl:A:0000:5000", "A_ovmain"),
            ("ovl:B:0000:5000", "B_ovmain"),
            ("ovl:B:0000:5010", "helper"),
        ] {
            symbols.push_str(&format!(
                "[[symbol]]\naddress = \"{address}\"\nkind = \"function\"\nname = \"{name}\"\nsource = \"human\"\nconfidence = \"confirmed\"\n\n"
            ));
        }
        std::fs::write(dir.path().join("knowledge/symbols.toml"), symbols).unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let knowledge = KnowledgeView::new(&ws, None);
        let profile = decovery_toolchain::profile("aztec-c86-4.2b").unwrap();
        let with_helper = aztec_object(&["ovmain_", "helper_"]);
        let alone = aztec_object(&["ovmain_"]);
        let objects = [(0, "b.c", &with_helper), (1, "x.c", &alone)];
        let mut hints = Vec::new();
        let (_, placed) = place_objects(
            &knowledge,
            &profile,
            None,
            &HashMap::new(),
            &objects,
            &mut hints,
        );
        let at: Vec<_> = placed
            .iter()
            .map(|b| (b.name.as_str(), b.address.to_string()))
            .collect();
        assert_eq!(
            at,
            [
                ("ovmain", "ovl:B:0000:5000".to_string()),
                ("helper", "ovl:B:0000:5010".to_string())
            ]
        );
        assert_eq!(
            hints,
            ["ovmain: no counterpart in the original"],
            "no overlay to qualify the name with"
        );
    }

    #[test]
    fn data_of_link_gaps_only_is_unchecked_not_equal() {
        use decovery_objects::{AztecRefSpec, AztecTarget};
        // the module's two data bytes are a segment paragraph: a link gap, nothing is compared
        let spec = AztecModuleSpec {
            name: "A".into(),
            code: vec![0xB8, 1, 0, 0xC3],
            data: vec![0, 0],
            bss: 2,
            named: vec![AztecSymbolSpec {
                name: "f_".into(),
                section: AztecSection::Code,
                value: 0,
                public: true,
            }],
            refs: vec![AztecRefSpec {
                section: AztecSection::Data,
                offset: 0,
                width: 2,
                relative: false,
                target: AztecTarget::Paragraph(AztecSection::Data),
                addend: 0,
            }],
            ..AztecModuleSpec::default()
        };
        let object = read_aztec(&write_aztec(&spec), "A.O").unwrap();
        let dir = workspace(2);
        let ws = Workspace::open(dir.path()).unwrap();
        let mut warnings = Vec::new();
        let modules = overlay_modules(
            &ws,
            &[(OverlayName::new("A").unwrap(), &object)],
            &mut warnings,
        );
        let data = &modules[0]["data"];
        assert_eq!(data["state"], "unchecked", "{}", modules[0]);
        assert_eq!(data["equal"], false);
        assert_eq!(data["gaps"], 2);
    }

    #[test]
    fn aztec_functions_carry_no_data_anchor_warnings() {
        use decovery_objects::{AztecRefSpec, AztecTarget};
        // `mov ax, [x]; ret` with its data field relocated: the data lies in the overlay, not in a frame
        let spec = AztecModuleSpec {
            name: "A".into(),
            code: vec![0xA1, 0, 0, 0xA1, 0, 0, 0xC3],
            data: vec![b'x'],
            named: vec![AztecSymbolSpec {
                name: "f_".into(),
                section: AztecSection::Code,
                value: 0,
                public: true,
            }],
            refs: [1u16, 4]
                .map(|offset| AztecRefSpec {
                    section: AztecSection::Code,
                    offset,
                    width: 2,
                    relative: false,
                    target: AztecTarget::Section(AztecSection::Data, 0),
                    addend: 0,
                })
                .to_vec(),
            ..AztecModuleSpec::default()
        };
        let object = read_aztec(&write_aztec(&spec), "A.O").unwrap();
        let dir = workspace(2);
        // the original's two fields name different positions of the same item: no anchor for its frame
        let mut ovr = Vec::new();
        for w in [0xF2u16, 0x5000, 8, 0x9000, 2, 2, 0x5007] {
            ovr.extend(w.to_le_bytes());
        }
        ovr.extend([0xA1, 0x00, 0x90, 0xA1, 0x01, 0x90, 0xC3, 0xC3, b'x', 0xEE]);
        std::fs::write(dir.path().join("A.OVR"), &ovr).unwrap();
        let toml = dir.path().join("decovery.toml");
        let config = std::fs::read_to_string(&toml).unwrap().replace(
            "[[overlay]]",
            "[[target.segment]]\nname = \"A.code\"\nstart = \"ovl:A:0000:5000\"\nlength = 8\n\
             file_offset = 14\npermissions = \"rx\"\n\n[[overlay]]",
        );
        std::fs::write(&toml, config).unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let knowledge = KnowledgeView::new(&ws, None);
        let program = crate::program::load(&ws).unwrap();
        let profile = decovery_toolchain::profile("aztec-c86-4.2b").unwrap();
        let at: Address = "ovl:A:0000:5000".parse().unwrap();
        let view = functions(&object.modules[0]).remove(0);
        let placements = [Placement::new(view, at, Some(7))];
        // the module comparison would anchor the data in a frame and warn about it
        let module = decovery_diff::compare_module(
            &placements,
            &program,
            &knowledge,
            &profile.decoration,
            &ModuleOptions::new(profile.padding, BTreeMap::new()),
        );
        assert!(!module.warnings.is_empty(), "the case must provoke a warning: {:?}", module.functions);
        let mut warnings = Vec::new();
        let compared = compare_placed(
            &ws,
            &profile,
            &BTreeMap::new(),
            &knowledge,
            &program,
            &placements,
            &[&object],
            &mut warnings,
        );
        assert_eq!(compared.len(), 1);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_function_built_under_its_default_name_is_shown_by_its_knowledge_name() {
        let dir = workspace(2);
        std::fs::create_dir_all(dir.path().join("knowledge")).unwrap();
        std::fs::write(
            dir.path().join("knowledge/symbols.toml"),
            "schema = 1\n\n[[symbol]]\naddress = \"ovl:A:0000:5002\"\nkind = \"function\"\n\
             name = \"draw_stats\"\nsource = \"human\"\nconfidence = \"confirmed\"\n",
        )
        .unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let knowledge = KnowledgeView::new(&ws, None);
        let profile = decovery_toolchain::profile("aztec-c86-4.2b").unwrap();
        let object = aztec_object(&["fun_A_0000_5000_", "fun_A_0000_5002_"]);
        let mut hints = Vec::new();
        let (_, placed) = place_objects(
            &knowledge,
            &profile,
            None,
            &HashMap::new(),
            &[(0, "a.c", &object)],
            &mut hints,
        );
        let shown: Vec<_> = placed
            .iter()
            .map(|b| (b.name.as_str(), b.label.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                ("fun_A_0000_5000", "fun_A_0000_5000"),
                ("fun_A_0000_5002", "draw_stats")
            ]
        );
    }
}
