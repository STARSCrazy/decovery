//! `link`: link the whole program with the original linker and compare it with the original file (port of
//! Decomp's `nachbau_linken`, `_nachbau_linken_le`, `_le_einsaetze`, `_anteile` and `_linkdiagnose`). MZ compiles
//! all rebuild sources and links them; LE hands the original image with the identical rebuilds inserted to WLINK as
//! one module.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::{Duration, Instant};

use decovery_core::{
    Address, Analysis, AnalyzedFunction, ClaimSource, Confidence, ProgramRecord, RebuildRecord,
    RebuildResult, SegmentConfig, Shares, Symbol, SymbolKind, TargetFormat, Used, Workspace,
    read_program_record, read_rebuild, read_user_config, save_program_record, today, write_atomic,
};
use decovery_diff::{
    Decoration, Place, PlaceKind, Stage, SymbolView, classify_code, compare_le, diagnose_mz_link,
    load_image,
};
use decovery_loaders::{LeImage, load_le};
use decovery_objects::{functions, read_omf};
use decovery_plugin::Progress;
use decovery_toolchain::{
    BUILTIN_ASSEMBLER, Insert, LE_DEFAULT_STACK, Linked, MapFormat, Profile, SourceJob, SourceSet,
    assembler_profile, build_insert, compile_planned, find_sources, le_linker, le_module,
    link as run_link, link_le, module_name, open_runners, plan_compile, rebuild_profile,
    stage_text, usable_inserts,
};
use rayon::prelude::*;
use serde_json::{Value, json};

use super::build::{
    OBJECT_FORMAT, OBJECTS_DIR, failure_text, file_flags, file_name, is_asm, is_c, ms, new_run_dir,
    read_text, runner_names, stage_headers, toolchain,
};
use super::link_symbols::{Candidate, additions, candidates};
use crate::session::{default_name, parse_default_name, parse_flat_default_name};
use crate::{FacadeError, KnowledgeView, Response};

const LOCK_WAIT: Duration = Duration::from_secs(30);
/// The linked program of the last `link`, relative to the workspace root.
pub const LINKED_FILE: &str = "cache/rebuild/REBUILD.EXE";
/// The linker's map of the last `link` (when the profile's linker writes one), relative to the workspace root.
pub const LINKED_MAP: &str = "cache/rebuild/REBUILD.MAP";
/// Name of the linked program (without extension) as the linker writes it.
const OUTPUT: &str = "REBUILD";
/// File name of the map in hints.
const OUTPUT_MAP: &str = "REBUILD.MAP";

/// Most diagnosis lines of an LE comparison (fixup lines and order-only pages listed).
const LE_DIAGNOSIS_LINES: usize = 20;

/// Links the whole program and records the comparison with the original in `knowledge/rebuild-program.toml`
/// (MZ and LE; other formats are refused).
pub fn link(root: &Path, progress: &dyn Fn(Progress)) -> Result<Response, FacadeError> {
    let ws = Workspace::open(root)?;
    match ws.config.target.format {
        TargetFormat::Mz => link_mz(root, ws, progress),
        TargetFormat::Le => link_le_program(root, ws, progress),
        format => Err(FacadeError::Invalid(format!(
            "link supports MZ and LE, not {format:?}"
        ))),
    }
}

fn link_mz(
    root: &Path,
    mut ws: Workspace,
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
        load_image(&original),
        Positions::Linear,
    );
    let exe = linked.as_ref().and_then(|l| l.program.as_deref());
    let mut record = program_record(&profile, &original, exe, message.clone());
    record.shares = analysis.as_ref().map(|_| layout.shares());
    if record.result == RebuildResult::Differs
        && let Some(exe) = exe
    {
        record.diagnosis = diagnose_mz_link(&original, exe, &|at| layout.place(at));
    }
    let compare_ms = ms(compare_started.elapsed());
    let map = linked.as_ref().and_then(|l| l.map.as_deref());
    // only an identical program proves the map's addresses
    let candidates = match (record.result, map, map_format(&profile)) {
        (RebuildResult::Identical, Some(map), Some(format)) => Some(candidates(
            map,
            format,
            OUTPUT_MAP,
            &profile.decoration,
            analysis.as_ref(),
            &mut hints,
        )),
        _ => None,
    };
    let added = store(
        &mut ws,
        &mut record,
        exe,
        map,
        candidates.as_deref(),
        &mut hints,
        &mut warnings,
    )?;

    let timing = json!({
        "build_ms": build_ms,
        "compare_ms": compare_ms,
        "total_ms": ms(started.elapsed()),
    });
    Ok(respond(
        &record,
        exe.is_some(),
        linked.as_ref().map(|l| l.line.as_str()),
        added,
        hints,
        warnings,
        timing,
    ))
}

/// The map format of the profile's linker, when decovery reads its map.
fn map_format(profile: &Profile) -> Option<MapFormat> {
    profile
        .linker
        .as_ref()
        .and_then(|l| l.map.as_ref())
        .map(|m| m.format)
}

/// The program record of a link: compiler, sizes, date, and against the original the result, the number of
/// differing bytes (plus the length difference) and the first differing file offset; `message` without a program.
fn program_record(
    profile: &Profile,
    original: &[u8],
    exe: Option<&[u8]>,
    message: Option<String>,
) -> ProgramRecord {
    let mut record = ProgramRecord::new(RebuildResult::Error);
    record.compiler = Some(profile.id.clone());
    record.original_bytes = original.len() as u64;
    record.date = Some(today());
    let Some(exe) = exe else {
        record.message = message;
        return record;
    };
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
    }
    record
}

/// Records `record` under the lock (unknown keys of the previous record stay), keeps the linked program and its
/// map, and adds the proven symbols of `candidates` the knowledge base lacks ([`additions`]). Returns how many
/// symbols were added; a symbol file that cannot be written is a warning, the link result stays recorded.
fn store(
    ws: &mut Workspace,
    record: &mut ProgramRecord,
    exe: Option<&[u8]>,
    map: Option<&[u8]>,
    candidates: Option<&[Candidate]>,
    hints: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<usize, FacadeError> {
    let root = ws.root.clone();
    let lock = ws.lock(LOCK_WAIT)?;
    if let Some(before) = read_program_record(&root)? {
        record.extra = before.extra;
    }
    save_program_record(&root, record, &lock)?;
    if let Some(exe) = exe {
        let path = root.join(LINKED_FILE);
        write_atomic(&path, exe).map_err(|source| FacadeError::Output { path, source })?;
    }
    let map_path = root.join(LINKED_MAP);
    match map.filter(|_| exe.is_some()) {
        Some(map) => write_atomic(&map_path, map).map_err(|source| FacadeError::Output {
            path: map_path,
            source,
        })?,
        None => {
            // no map of an earlier link next to this program
            let _ = std::fs::remove_file(&map_path);
        }
    }
    let mut added = 0;
    if let Some(candidates) = candidates.filter(|c| !c.is_empty()) {
        match ws.add_symbols(|current| additions(current, candidates, hints), &lock) {
            Ok(list) => added = list.len(),
            Err(e) => warnings.push(format!(
                "symbol addresses from the link map not recorded: {e}"
            )),
        }
    }
    drop(lock);
    Ok(added)
}

/// LE: the original image with the identical rebuilds inserted ([`le_inserts`]), handed as one module to the linker
/// of `[rebuild.link] profile` (else the compiler's), linked with the original's stub and compared with the
/// original ([`compare_le`]). `[rebuild.link]` is optional: `insert` (default true), `stack` (default 4096).
fn link_le_program(
    root: &Path,
    mut ws: Workspace,
    progress: &dyn Fn(Progress),
) -> Result<Response, FacadeError> {
    let started = Instant::now();
    let (compiler, default_flags) = rebuild_profile(&ws).map_err(toolchain)?;
    let rebuild = ws.config.rebuild.clone().unwrap_or_default();
    let link_config = rebuild.link.clone().unwrap_or_default();
    let profile = match &link_config.profile {
        Some(id) => decovery_toolchain::profile(id).map_err(toolchain)?,
        None => compiler.clone(),
    };
    // early: can this profile link LE programs at all?
    let start_option = le_linker(&profile).map_err(toolchain)?.start_option;
    let target = crate::program::target_path(&ws);
    let original = std::fs::read(&target).map_err(|e| {
        FacadeError::Invalid(format!("cannot read target {}: {e}", target.display()))
    })?;
    let image = load_le(&original).map_err(|e| {
        FacadeError::Invalid(format!("cannot load target {}: {e}", target.display()))
    })?;
    let analysis = Analysis::load(root)?.filter(|a| a.target_sha256 == ws.config.target.sha256);
    let records = read_rebuild(root)?;
    let mut warnings: Vec<String> = Vec::new();
    let run_dir = new_run_dir(root)?;

    // the module
    let module_started = Instant::now();
    let (inserts, mut hints) = if link_config.insert.unwrap_or(true) {
        let knowledge = KnowledgeView::new(&ws, analysis.as_ref());
        let sources = Sources {
            root,
            dir: &run_dir.0,
            compiler: &compiler,
            default_flags: &default_flags,
            file_flags: &rebuild.file_flags,
        };
        le_inserts(&sources, &records, &image, &knowledge)?
    } else {
        (Vec::new(), Vec::new())
    };
    let stack = link_config.stack.unwrap_or(LE_DEFAULT_STACK);
    let (module, more) =
        le_module(&original, &image, &inserts, stack, !start_option).map_err(toolchain)?;
    hints.extend(more);
    let mut used = Used::default();
    for i in usable_inserts(&image, &inserts).0 {
        used.functions += 1;
        used.bytes += inserts[i].bytes.len() as u64;
    }
    let module_ms = ms(module_started.elapsed());

    // link
    let link_started = Instant::now();
    let name = module_name(image.header.resident_name.as_deref().unwrap_or(""));
    let stub = original
        .get(..usize::try_from(image.header.le_offset).unwrap_or(usize::MAX))
        .unwrap_or(&original);
    let user = read_user_config()?;
    let (runners, more) = open_runners(&runner_names(&ws, &profile), &ws, &user);
    warnings.extend(more);
    progress(Progress::new(0, Some(1), Some("linking".to_string())));
    let (linked, more): (Linked, Vec<String>) = link_le(
        &ws, &profile, &module, stub, &name, &run_dir.0, &runners, None, progress,
    )
    .map_err(toolchain)?;
    warnings.extend(more);
    drop(runners);
    drop(run_dir);
    let link_ms = ms(link_started.elapsed());

    // compare
    let compare_started = Instant::now();
    let segments = &ws.config.target.segments;
    let image_bytes = segment_image(&image, segments);
    let layout = Layout::new(
        &ws,
        analysis.as_ref(),
        &records,
        &compiler,
        &image_bytes,
        Positions::segments(segments),
    );
    let exe = linked.program.as_deref();
    let mut record = program_record(&profile, &original, exe, Some(linked.message.clone()));
    record.shares = analysis.as_ref().map(|_| layout.shares());
    record.used = Some(used);
    if record.result == RebuildResult::Differs
        && let Some(exe) = exe
    {
        let place = |va: u32| {
            let at = Address::Flat(va);
            layout
                .positions
                .of(at)
                .and_then(|p| layout.place(p))
                .map_or_else(|| at.to_string(), |p| p.description)
        };
        record.diagnosis = compare_le(&original, exe, &place, LE_DIAGNOSIS_LINES);
    }
    let compare_ms = ms(compare_started.elapsed());
    let added = store(
        &mut ws,
        &mut record,
        exe,
        None,
        None,
        &mut hints,
        &mut warnings,
    )?;

    let timing = json!({
        "module_ms": module_ms,
        "link_ms": link_ms,
        "compare_ms": compare_ms,
        "total_ms": ms(started.elapsed()),
    });
    Ok(respond(
        &record,
        exe.is_some(),
        Some(linked.line.as_str()),
        added,
        hints,
        warnings,
        timing,
    ))
}

/// What the provenance check of the kept objects needs; sources are staged into `dir`.
struct Sources<'a> {
    root: &'a Path,
    dir: &'a Path,
    compiler: &'a Profile,
    default_flags: &'a str,
    file_flags: &'a BTreeMap<String, String>,
}

/// The `<stem>.json` beside a kept object, as `build` writes it.
#[derive(serde::Deserialize)]
struct KeptMeta {
    schema: u32,
    format: String,
    file: String,
    profile: String,
    flags: String,
    inputs: BTreeMap<String, String>,
    object: String,
    identical: BTreeMap<String, KeptFunction>,
}

#[derive(serde::Deserialize)]
struct KeptFunction {
    address: String,
}

/// Port of `_le_einsaetze`: every function whose rebuild record is identical with no differing instruction (flat
/// address) as an [`Insert`], built from the object the last `build` kept for its file
/// (`cache/rebuild/obj/<stem>.obj`) when that object is still current: its metadata names the compiler, the flags
/// and the hashes of the source and of every header as staged now, the function as identical at this address, and
/// the object's hash. Files are handled in parallel. Hints name every function left out and why, and inserts that
/// keep linker bytes of the original.
fn le_inserts(
    sources: &Sources<'_>,
    records: &[RebuildRecord],
    image: &LeImage,
    knowledge: &KnowledgeView<'_>,
) -> Result<(Vec<Insert>, Vec<String>), FacadeError> {
    let mut by_file: BTreeMap<&str, Vec<&RebuildRecord>> = BTreeMap::new();
    for r in records.iter().filter(|r| {
        r.effective_result() == RebuildResult::Identical
            && r.instructions_differing == 0
            && matches!(r.address, Address::Flat(_))
    }) {
        by_file
            .entry(r.file.as_deref().unwrap_or(""))
            .or_default()
            .push(r);
    }
    if by_file.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let set = find_sources(&sources.root.join(super::SOURCE_DIR), &[]).map_err(toolchain)?;
    let headers = stage_headers(&set, sources.dir)?;
    let decoration = &sources.compiler.decoration;
    let address_of = |name: &str| reference_address(knowledge, decoration, name);
    let per_file: Vec<(Vec<Insert>, Vec<String>)> = by_file
        .par_iter()
        .map(|(file, records)| {
            if !is_c(file) && !is_asm(file) {
                // `build` keeps no object for other assembler sources
                let reason = if file.is_empty() {
                    "the record names no source file".to_string()
                } else {
                    format!("{file} is not built (no assembler available)")
                };
                let hints = records
                    .iter()
                    .map(|r| format!("{}: {reason}, not inserted", r.name))
                    .collect();
                return (Vec::new(), hints);
            }
            match current_object(sources, &set, &headers, file) {
                Err(reason) => (
                    Vec::new(),
                    records
                        .iter()
                        .map(|r| {
                            format!(
                                "{}: {reason}; run `decovery build {file}` first, not inserted",
                                r.name
                            )
                        })
                        .collect(),
                ),
                Ok((meta, object)) => file_inserts(
                    file,
                    records,
                    &meta,
                    &object,
                    image,
                    decoration,
                    &address_of,
                ),
            }
        })
        .collect();
    let mut inserts = Vec::new();
    let mut hints = Vec::new();
    for (i, h) in per_file {
        inserts.extend(i);
        hints.extend(h);
    }
    // by place, as Decomp takes them (records by address): of two overlapping inserts the first wins
    inserts.sort_by_key(|e| (e.object, e.offset));
    Ok((inserts, hints))
}

/// The kept object of `file` with its metadata when it is current, else why not.
fn current_object(
    sources: &Sources<'_>,
    set: &SourceSet,
    headers: &BTreeMap<String, String>,
    file: &str,
) -> Result<(KeptMeta, Vec<u8>), String> {
    let path = set
        .sources
        .iter()
        .find(|p| file_name(p) == file)
        .ok_or_else(|| format!("the source {file} does not exist"))?;
    let text = read_text(path).map_err(|e| e.to_string())?;
    let dos_name = stage_text(file, &text, sources.dir).map_err(|e| e.to_string())?;
    let staged = std::fs::read(sources.dir.join(&dos_name)).map_err(|e| e.to_string())?;
    let stem = file
        .rsplit_once('.')
        .map_or(file, |(s, _)| s)
        .to_ascii_lowercase();
    let dir = sources.root.join(OBJECTS_DIR);
    let meta: KeptMeta = std::fs::read_to_string(dir.join(format!("{stem}.json")))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .ok_or_else(|| "no kept object".to_string())?;
    // an assembler source is built without flags, by the built-in assembler or the profile's assembler
    let (flags, builder_ok) = if is_asm(file) {
        let assembler = assembler_profile(sources.compiler).ok().flatten();
        let ok =
            meta.profile == BUILTIN_ASSEMBLER || assembler.is_some_and(|a| a.id == meta.profile);
        ("", ok)
    } else {
        (
            file_flags(sources.file_flags, file).map_or(sources.default_flags, String::as_str),
            meta.profile == sources.compiler.id,
        )
    };
    let staged_hash = blake3::hash(&staged).to_hex().to_string();
    let current = meta.schema == 1
        && meta.format == OBJECT_FORMAT
        && meta.file == file
        && builder_ok
        && meta.flags == flags
        && meta.inputs.get(&dos_name) == Some(&staged_hash)
        // a byte listing includes no header; a build of assembler sources alone records none
        && (is_asm(file)
            || headers
                .iter()
                .all(|(h, hash)| meta.inputs.get(h) == Some(hash)));
    if !current {
        return Err("the kept object is stale (source, headers, flags or compiler changed)".into());
    }
    let object =
        std::fs::read(dir.join(format!("{stem}.obj"))).map_err(|_| "no kept object".to_string())?;
    if blake3::hash(&object).to_hex().as_str() != meta.object {
        return Err("the kept object does not match its metadata".into());
    }
    Ok((meta, object))
}

/// The inserts of the identical functions of one file from its current kept object.
fn file_inserts(
    file: &str,
    records: &[&RebuildRecord],
    meta: &KeptMeta,
    object: &[u8],
    image: &LeImage,
    decoration: &Decoration,
    address_of: &(dyn Fn(&str) -> Option<Address> + Sync),
) -> (Vec<Insert>, Vec<String>) {
    let (mut inserts, mut hints) = (Vec::new(), Vec::new());
    let parsed = match read_omf(object, &file.to_ascii_uppercase()) {
        Ok(parsed) => parsed,
        Err(e) => {
            hints.extend(records.iter().map(|r| {
                format!(
                    "{}: the kept object of {file} cannot be read ({e}), not inserted",
                    r.name
                )
            }));
            return (inserts, hints);
        }
    };
    let views: Vec<_> = parsed.modules.iter().flat_map(functions).collect();
    for r in records {
        let checked = meta
            .identical
            .get(&r.name)
            .is_some_and(|f| f.address == r.address.to_string());
        if !checked {
            hints.push(format!(
                "{}: the last build did not find it identical at {}; run `decovery build {file}` first, not inserted",
                r.name, r.address
            ));
            continue;
        }
        let Some(f) = views
            .iter()
            .find(|f| decoration.undecorate(f.name) == r.name || f.name == r.name)
        else {
            hints.push(format!(
                "{}: missing in the kept object of {file}, not inserted",
                r.name
            ));
            continue;
        };
        match build_insert(f, r.address, image, address_of) {
            Ok(mut insert) => {
                insert.name = r.name.clone();
                if !insert.keep.is_empty() {
                    hints.push(format!(
                        "{}: {} linker bytes without a name taken from the original",
                        r.name,
                        insert.keep.len()
                    ));
                }
                inserts.push(insert);
            }
            Err(reason) => hints.push(format!("{}: {reason}, not inserted", r.name)),
        }
    }
    (inserts, hints)
}

/// Port of `_verweis_adresse`: where a public name of an object lies in the original. The C name first, then the
/// raw name (the prefix belongs to the name: Watcom `-4s`, `_dos_setvect`), then a default name (`fun_`, and on a
/// flat target `FUN_` and `DAT_` with eight hex digits) at any address, as Decomp's link took them: the link inserts
/// only functions the build found identical, and compares the linked pages afterwards.
fn reference_address(
    knowledge: &KnowledgeView<'_>,
    decoration: &Decoration,
    name: &str,
) -> Option<Address> {
    let c = decoration.undecorate(name);
    knowledge
        .address_of(c)
        .or_else(|| (c != name).then(|| knowledge.address_of(name)).flatten())
        .or_else(|| parse_default_name(c))
        .or_else(|| {
            knowledge
                .is_flat()
                .then(|| parse_flat_default_name(c).map(|(at, _)| at))
                .flatten()
        })
}

/// The load image of an LE program for the shares: the configured segments back to back, each its full length
/// (uninitialized parts zero).
fn segment_image(image: &LeImage, segments: &[SegmentConfig]) -> Vec<u8> {
    let total = segments
        .iter()
        .map(|s| usize::try_from(s.length).unwrap_or(0))
        .sum();
    let mut out = vec![0u8; total];
    let mut start = 0usize;
    for s in segments {
        let len = usize::try_from(s.length).unwrap_or(0);
        let source = s.start.linear().and_then(|at| {
            let region = image.program.region_at(s.start)?;
            let from = usize::try_from(at.checked_sub(region.start.linear()?)?).ok()?;
            region.data.get(from..)
        });
        if let Some(bytes) = source {
            let n = bytes.len().min(len);
            out[start..start + n].copy_from_slice(&bytes[..n]);
        }
        start += len;
    }
    out
}

/// Where an address lies in the image the shares count over.
enum Positions {
    /// MZ: the linear address is the load image offset.
    Linear,
    /// LE: the segments back to back: (linear start, length, image offset).
    Segments(Vec<(u64, u64, u64)>),
}

impl Positions {
    fn segments(segments: &[SegmentConfig]) -> Self {
        let mut at = 0u64;
        Positions::Segments(
            segments
                .iter()
                .filter_map(|s| {
                    let entry = (s.start.linear()?, s.length, at);
                    at += s.length;
                    Some(entry)
                })
                .collect(),
        )
    }

    /// The image offset of `at`.
    fn of(&self, at: Address) -> Option<u64> {
        let linear = at.linear()?;
        match self {
            Positions::Linear => Some(linear),
            Positions::Segments(list) => list
                .iter()
                .find(|&&(start, len, _)| start <= linear && linear - start < len)
                .map(|&(start, _, offset)| offset + linear - start),
        }
    }
}

/// What lies in the original load image (MZ: the file without its header; LE: the segments back to back): the
/// analysis' functions sorted by image offset (with what each one is) and the named globals, for [`Layout::place`]
/// (binary search) and [`Layout::shares`].
struct Layout<'a> {
    functions: Vec<Located<'a>>,
    /// Per function (same index): the largest end of it and all functions before it, so that [`Layout::place`] finds
    /// a function enclosing an offset even when a later-starting one ends before it.
    max_end: Vec<u64>,
    /// Named globals by image offset.
    globals: Vec<(u64, &'a Symbol)>,
    segments: &'a [SegmentConfig],
    positions: Positions,
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
        image: &[u8],
        positions: Positions,
    ) -> Self {
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
                let len = f.end.linear()?.checked_sub(f.start.linear()?)?;
                let start = positions.of(f.start)?;
                let end = start.checked_add(len)?;
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
        let max_end = located
            .iter()
            .scan(0u64, |max, f| {
                *max = (*max).max(f.end);
                Some(*max)
            })
            .collect();
        let mut globals: Vec<(u64, &Symbol)> = symbols
            .values()
            .filter(|s| s.kind == SymbolKind::Global)
            .filter_map(|s| Some((positions.of(s.address)?, *s)))
            .collect();
        globals.sort_by_key(|(at, s)| (*at, s.address));
        Layout {
            functions: located,
            max_end,
            globals,
            segments: &ws.config.target.segments,
            positions,
            image_len: image.len() as u64,
        }
    }

    /// The function containing `offset` with the nearest start.
    fn enclosing(&self, offset: u64) -> Option<&Located<'a>> {
        let after = self.functions.partition_point(|f| f.start <= offset);
        (0..after)
            .rev()
            .take_while(|&i| self.max_end[i] >= offset)
            .map(|i| &self.functions[i])
            .find(|f| offset <= f.end)
    }

    /// What lies at `offset` of the load image: the function containing it (library, rebuilt, assembly or other),
    /// else the nearest named global before it, else data at its address.
    fn place(&self, offset: u64) -> Option<Place> {
        if let Some(f) = self.enclosing(offset) {
            let kind = if f.library {
                PlaceKind::Library
            } else if f.identical.is_some() {
                PlaceKind::Rebuilt
            } else if f.assembly {
                PlaceKind::Assembly
            } else {
                PlaceKind::Function
            };
            let delta = offset - f.start;
            let name = f
                .name
                .map_or_else(|| default_name(f.address), str::to_string);
            let description = match moved(f.address, delta) {
                Some(at) => format!("{at} in {name}"),
                None => format!("{name}+{delta:#x}"),
            };
            return Some(Place::new(description, Some(kind), Some(f.start)));
        }
        let after = self.globals.partition_point(|(at, _)| *at <= offset);
        if let Some(&(at, s)) = after.checked_sub(1).map(|i| &self.globals[i]) {
            let delta = offset - at;
            let description = match moved(s.address, delta) {
                Some(address) => format!("{address}, {}+{delta:#x}", s.name),
                None => format!("{}+{delta:#x}", s.name),
            };
            return Some(Place::new(description, Some(PlaceKind::Data), None));
        }
        self.segments
            .iter()
            .find_map(|s| {
                let start = self.positions.of(s.start)?;
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
    symbols_added: usize,
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
            "used": r.used.as_ref().map(|u| json!({ "functions": u.functions, "bytes": u.bytes })),
            "symbols_added": symbols_added,
            "hints": hints,
            "warnings": warnings,
            "timing": timing,
        }),
    )
}
