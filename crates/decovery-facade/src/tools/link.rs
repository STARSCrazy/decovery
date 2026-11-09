//! `link`: compile all rebuild sources, link them with the original linker into the whole program and compare it
//! with the original file (port of Decomp's `nachbau_linken`, `_anteile` and `_linkdiagnose`).

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use decovery_core::{
    Address, Analysis, AnalyzedFunction, ClaimSource, Confidence, ProgramRecord, RebuildRecord,
    RebuildResult, SegmentConfig, Shares, Symbol, SymbolKind, TargetFormat, Workspace,
    read_program_record, read_rebuild, read_user_config, save_program_record, today, write_atomic,
};
use decovery_diff::{Place, PlaceKind, Stage, classify_code, diagnose_mz_link, load_image};
use decovery_plugin::Progress;
use decovery_toolchain::{
    Profile, SourceJob, compile_planned, find_sources, link as run_link, open_runners,
    plan_compile, rebuild_profile, stage_text,
};
use rayon::prelude::*;
use serde_json::{Value, json};

use super::build::{
    failure_text, file_flags, file_name, is_c, ms, new_run_dir, read_text, runner_names,
    stage_headers, toolchain,
};
use crate::session::default_name;
use crate::{FacadeError, Response};

const LOCK_WAIT: Duration = Duration::from_secs(30);
/// The linked program of the last `link`, relative to the workspace root.
pub const LINKED_FILE: &str = "cache/rebuild/REBUILD.EXE";
/// Name of the linked program (without extension) as the linker writes it.
const OUTPUT: &str = "REBUILD";

/// Links the whole program and records the comparison with the original in `knowledge/rebuild-program.toml`
/// (MZ; LE is dispatched to its own linking, other formats are refused).
pub fn link(root: &Path, progress: &dyn Fn(Progress)) -> Result<Response, FacadeError> {
    let ws = Workspace::open(root)?;
    match ws.config.target.format {
        TargetFormat::Mz => link_mz(root, ws, progress),
        TargetFormat::Le => link_le(&ws),
        format => Err(FacadeError::Invalid(format!(
            "link supports MZ and LE, not {format:?}"
        ))),
    }
}

/// LE: the original image with the identical rebuilds inserted, linked as one module.
fn link_le(_ws: &Workspace) -> Result<Response, FacadeError> {
    Err(FacadeError::Invalid(
        "linking LE programs is not implemented yet".into(),
    ))
}

fn link_mz(
    root: &Path,
    ws: Workspace,
    progress: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    let started = Instant::now();
    let (profile, default_flags) = rebuild_profile(&ws).map_err(toolchain)?;
    let rebuild = ws.config.rebuild.clone().unwrap_or_default();
    let link_config = rebuild.link.clone().ok_or_else(|| {
        FacadeError::Invalid(
            "decovery.toml has no [rebuild.link]; for example:\n[rebuild.link]\nstartup = \"C0S\"\n\
             libraries = [\"EMU\", \"MATHS\", \"CS\"]\nflags = \"/c/x/i\""
                .into(),
        )
    })?;
    let target = crate::program::target_path(&ws);
    let original = std::fs::read(&target).map_err(|e| {
        FacadeError::Invalid(format!("cannot read target {}: {e}", target.display()))
    })?;
    let analysis = Analysis::load(root)?.filter(|a| a.target_sha256 == ws.config.target.sha256);
    let mut hints: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // stage the C sources and the headers
    let set = find_sources(&root.join(super::SOURCE_DIR), &[]).map_err(toolchain)?;
    let run_dir = new_run_dir(root)?;
    stage_headers(&set, &run_dir.0)?;
    let mut jobs: Vec<SourceJob> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut message: Option<String> = None;
    for path in &set.sources {
        let name = file_name(path);
        if !is_c(&name) {
            hints.push(format!("{name}: not linked, no assembler available"));
            continue;
        }
        let staged = read_text(path)
            .and_then(|text| stage_text(&name, &text, &run_dir.0).map_err(toolchain));
        if let Err(e) = staged {
            message.get_or_insert_with(|| format!("{name}: {e}"));
            continue;
        }
        let flags = file_flags(&rebuild.file_flags, &name)
            .cloned()
            .unwrap_or_else(|| default_flags.clone());
        jobs.push(SourceJob::new(name.to_ascii_uppercase(), flags));
        names.push(name);
    }

    // compile (object cache first) and link with the same runners
    let compile_started = Instant::now();
    let user = read_user_config()?;
    let (runners, more) = open_runners(&runner_names(&ws, &profile), &ws, &user);
    warnings.extend(more);
    let mut linked = None;
    if message.is_none() {
        progress(Progress::new(
            0,
            Some(jobs.len() as u64),
            Some(format!("compiling {} sources", jobs.len())),
        ));
        let plan = plan_compile(&ws, &profile, &jobs, &run_dir.0).map_err(toolchain)?;
        let (files, more) =
            compile_planned(&ws, &profile, plan, &run_dir.0, &runners, None, progress)
                .map_err(toolchain)?;
        warnings.extend(more);
        let failed = files.iter().zip(&names).find(|(f, _)| f.object.is_none());
        if let Some((file, name)) = failed {
            message = Some(format!("{name}: {}", failure_text(file)));
        } else {
            let objects: Vec<(String, Vec<u8>)> = files
                .into_iter()
                .map(|f| {
                    let stem = f.file.rsplit_once('.').map_or(f.file.as_str(), |(s, _)| s);
                    (stem.to_string(), f.object.unwrap_or_default())
                })
                .collect();
            progress(Progress::new(0, Some(1), Some("linking".to_string())));
            let (result, more) = run_link(
                &ws,
                &profile,
                &objects,
                &link_config,
                OUTPUT,
                &run_dir.0,
                &runners,
                None,
                progress,
            )
            .map_err(toolchain)?;
            warnings.extend(more);
            if result.program.is_none() {
                message = Some(result.message.clone());
            }
            linked = Some(result);
        }
    }
    drop(runners);
    drop(run_dir);
    let build_ms = ms(compile_started.elapsed());

    // compare
    let compare_started = Instant::now();
    let rebuild_records = read_rebuild(root)?;
    let layout = Layout::new(
        &ws,
        analysis.as_ref(),
        &rebuild_records,
        &profile,
        &original,
    );
    let shares = analysis.as_ref().map(|_| layout.shares());
    let exe = linked.as_ref().and_then(|l| l.program.as_deref());
    let mut record = ProgramRecord::new(RebuildResult::Error);
    record.compiler = Some(profile.id.clone());
    record.original_bytes = original.len() as u64;
    record.date = Some(today());
    record.shares = shares;
    match exe {
        None => record.message = message.clone(),
        Some(exe) => {
            let differing_bytes = original.iter().zip(exe).filter(|(a, b)| a != b).count();
            let differing = differing_bytes as u64 + original.len().abs_diff(exe.len()) as u64;
            record.rebuilt_bytes = exe.len() as u64;
            record.differing = differing;
            if differing == 0 {
                record.result = RebuildResult::Identical;
            } else {
                record.result = RebuildResult::Differs;
                record.first_difference = Some(
                    original
                        .iter()
                        .zip(exe)
                        .position(|(a, b)| a != b)
                        .unwrap_or(original.len().min(exe.len())) as u64,
                );
                record.diagnosis = diagnose_mz_link(&original, exe, &|at| layout.place(at));
            }
        }
    }
    let compare_ms = ms(compare_started.elapsed());

    // record under the lock; unknown keys of the previous record stay
    let lock = ws.lock(LOCK_WAIT)?;
    if let Some(before) = read_program_record(root)? {
        record.extra = before.extra;
    }
    save_program_record(root, &record, &lock)?;
    if let Some(exe) = exe {
        let path = root.join(LINKED_FILE);
        write_atomic(&path, exe).map_err(|source| FacadeError::Output { path, source })?;
    }
    drop(lock);

    let timing = json!({
        "build_ms": build_ms,
        "compare_ms": compare_ms,
        "total_ms": ms(started.elapsed()),
    });
    Ok(respond(
        &record,
        exe.is_some(),
        linked.as_ref().map(|l| l.line.as_str()),
        hints,
        warnings,
        timing,
    ))
}

/// What lies in the original load image: the analysis' functions sorted by image offset (with what each one is)
/// and the named globals, for [`Layout::place`] (binary search) and [`Layout::shares`].
struct Layout<'a> {
    functions: Vec<Located<'a>>,
    /// Named globals by image offset.
    globals: Vec<(u64, &'a Symbol)>,
    segments: &'a [SegmentConfig],
    image_len: u64,
}

/// A function of the analysis at its place in the load image.
struct Located<'a> {
    /// Image offsets of the first and the last byte.
    start: u64,
    end: u64,
    address: Address,
    name: Option<&'a str>,
    /// Rebuilt identically: `Some(true)` from an assembler source, `Some(false)` from C.
    identical: Option<bool>,
    library: bool,
    /// Classified as assembler (only looked at when neither identical nor library).
    assembly: bool,
}

impl<'a> Layout<'a> {
    fn new(
        ws: &'a Workspace,
        analysis: Option<&'a Analysis>,
        records: &[RebuildRecord],
        profile: &Profile,
        original: &[u8],
    ) -> Self {
        let image = load_image(original);
        let mut symbols: HashMap<Address, &Symbol> = HashMap::new();
        for s in &ws.symbols {
            if s.confidence != Confidence::Refuted && !s.name.is_empty() {
                symbols.entry(s.address).or_insert(s);
            }
        }
        let identical: HashMap<Address, bool> = records
            .iter()
            .filter(|r| {
                r.effective_result() == RebuildResult::Identical && r.instructions_differing == 0
            })
            .map(|r| {
                (
                    r.address,
                    r.file.as_deref().is_some_and(is_assembler_source),
                )
            })
            .collect();
        let functions: &[AnalyzedFunction] = analysis.map_or(&[], |a| a.functions.as_slice());
        let mut located: Vec<Located<'a>> = functions
            .par_iter()
            .filter_map(|f| {
                let (start, end) = (f.start.linear()?, f.end.linear()?);
                if end < start {
                    return None;
                }
                let symbol = symbols.get(&f.start).copied();
                let library = symbol.is_some_and(|s| {
                    s.source == ClaimSource::Signature
                        || s.library.as_deref().is_some_and(|l| !l.is_empty())
                });
                let identical = identical.get(&f.start).copied();
                let assembly = identical.is_none() && !library && {
                    let code = usize::try_from(start)
                        .ok()
                        .and_then(|s| image.get(s..))
                        .map_or(&[][..], |rest| {
                            let len = usize::try_from(end - start + 1).unwrap_or(usize::MAX);
                            &rest[..len.min(rest.len())]
                        });
                    classify_code(code, profile.bits, &profile.prologue, false, None).0
                        == Stage::Assembly
                };
                Some(Located {
                    start,
                    end,
                    address: f.start,
                    name: symbol.map(|s| s.name.as_str()),
                    identical,
                    library,
                    assembly,
                })
            })
            .collect();
        located.sort_by_key(|f| (f.start, f.end));
        let mut globals: Vec<(u64, &Symbol)> = symbols
            .values()
            .filter(|s| s.kind == SymbolKind::Global)
            .filter_map(|s| Some((s.address.linear()?, *s)))
            .collect();
        globals.sort_by_key(|(at, s)| (*at, s.address));
        Layout {
            functions: located,
            globals,
            segments: &ws.config.target.segments,
            image_len: image.len() as u64,
        }
    }

    /// What lies at `offset` of the load image: the function containing it (library, rebuilt, assembly or other),
    /// else the nearest named global before it, else data at its address.
    fn place(&self, offset: u64) -> Option<Place> {
        let after = self.functions.partition_point(|f| f.start <= offset);
        if let Some(f) = after
            .checked_sub(1)
            .map(|i| &self.functions[i])
            .filter(|f| offset <= f.end)
        {
            let kind = if f.library {
                PlaceKind::Library
            } else if f.identical.is_some() {
                PlaceKind::Rebuilt
            } else if f.assembly {
                PlaceKind::Assembly
            } else {
                PlaceKind::Function
            };
            let at = moved(f.address, offset - f.start);
            let name = f
                .name
                .map_or_else(|| default_name(f.address), str::to_string);
            return Some(Place::new(
                format!(
                    "{} in {name}",
                    at.map_or_else(String::new, |a| a.to_string())
                ),
                Some(kind),
                Some(f.start),
            ));
        }
        let after = self.globals.partition_point(|(at, _)| *at <= offset);
        if let Some(&(at, s)) = after.checked_sub(1).map(|i| &self.globals[i]) {
            let delta = offset - at;
            let address = moved(s.address, delta).map_or_else(String::new, |a| a.to_string());
            return Some(Place::new(
                format!("{address}, {}+{delta:#x}", s.name),
                Some(PlaceKind::Data),
                None,
            ));
        }
        self.segments
            .iter()
            .find_map(|s| {
                let start = s.start.linear()?;
                (start <= offset && offset < start.saturating_add(s.length))
                    .then(|| moved(s.start, offset - start))
                    .flatten()
            })
            .map(|a| Place::new(a.to_string(), Some(PlaceKind::Data), None))
    }

    /// Bytes of the load image by origin; each byte counts for the first of c, library, assembly, other functions.
    fn shares(&self) -> Shares {
        const REST: u8 = 0;
        const C: u8 = 1;
        const LIBRARY: u8 = 2;
        const ASSEMBLY: u8 = 3;
        const OTHER: u8 = 4;
        let mut owner = vec![REST; usize::try_from(self.image_len).unwrap_or(0)];
        for f in &self.functions {
            let rank = match f.identical {
                Some(false) => C,
                Some(true) => ASSEMBLY,
                None if f.library => LIBRARY,
                None if f.assembly => ASSEMBLY,
                None => OTHER,
            };
            let end = usize::try_from(f.end.saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(owner.len());
            let start = usize::try_from(f.start).unwrap_or(usize::MAX).min(end);
            for byte in &mut owner[start..end] {
                if *byte == REST || rank < *byte {
                    *byte = rank;
                }
            }
        }
        let mut counts = [0u64; 5];
        for &byte in &owner {
            counts[usize::from(byte)] += 1;
        }
        let mut shares = Shares::default();
        shares.rest = counts[usize::from(REST)];
        shares.c = counts[usize::from(C)];
        shares.library = counts[usize::from(LIBRARY)];
        shares.assembly = counts[usize::from(ASSEMBLY)];
        shares.other_functions = counts[usize::from(OTHER)];
        shares
    }
}

/// `address` moved forward by `delta` bytes, when it stays representable.
fn moved(address: Address, delta: u64) -> Option<Address> {
    address.offset_by(i64::try_from(delta).ok()?).ok()
}

fn is_assembler_source(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.ends_with(".asm") || lower.ends_with(".s")
}

fn shares_json(s: &Shares) -> Value {
    json!({
        "c": s.c,
        "library": s.library,
        "assembly": s.assembly,
        "other_functions": s.other_functions,
        "rest": s.rest,
    })
}

fn respond(
    r: &ProgramRecord,
    written: bool,
    line: Option<&str>,
    hints: Vec<String>,
    warnings: Vec<String>,
    timing: Value,
) -> Response {
    let summary = match r.result {
        RebuildResult::Identical => format!("identical ({} bytes)", r.original_bytes),
        RebuildResult::Differs => {
            let mut s = format!("differs: {} bytes", r.differing);
            if let Some(at) = r.first_difference {
                s.push_str(&format!(", first at file offset {at:#x}"));
            }
            if r.rebuilt_bytes != r.original_bytes {
                s.push_str(&format!(
                    "; rebuilt {} bytes, original {}",
                    r.rebuilt_bytes, r.original_bytes
                ));
            }
            s
        }
        _ => format!(
            "error: {}",
            r.message
                .as_deref()
                .and_then(|m| m.lines().next())
                .unwrap_or("link failed")
        ),
    };
    Response::new(
        summary,
        json!({
            "result": r.result.id(),
            "compiler": r.compiler,
            "original_bytes": r.original_bytes,
            "rebuilt_bytes": r.rebuilt_bytes,
            "differing": r.differing,
            "first_difference": r.first_difference.map(|at| format!("{at:#x}")),
            "message": r.message,
            "file": written.then_some(LINKED_FILE),
            "link_line": line,
            "diagnosis": r.diagnosis,
            "shares": r.shares.as_ref().map(shares_json),
            "hints": hints,
            "warnings": warnings,
            "timing": timing,
        }),
    )
}
