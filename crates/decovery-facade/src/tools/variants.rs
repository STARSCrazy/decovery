//! `build` with variants: compile up to [`MAX_VARIANTS`] candidate sources for one function in one runner request,
//! compare the function of each and rank them. Nothing is recorded, kept or written to `output/`.
//!
//! Each distinct variant text is staged under the file's own name in a directory of its own (`V001/TICK.C`) next to
//! copies of the headers, and compiled there: `__FILE__`, compiler messages, the compile line and so the object
//! cache key are those of the file in a full build. Equal texts are compiled once.
//!
//! The function is judged like in a full build: the variant's object is compared together with the last good objects
//! of the other source files, so the reference anchors (ADR 0006) are agreed on by all their fields, not by the
//! function alone.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Instant;

use decovery_core::{Analysis, BlockerRecord, Program, VerdictId, Workspace};
use decovery_diff::{Blocker, ModuleOptions};
use decovery_objects::{ObjectFile, read_omf};
use decovery_plugin::Progress;
use decovery_toolchain::{
    CheatFinding, Profile, SourceJob, SourceSet, find_cheats, find_sources, rebuild_profile,
    to_dos_bytes,
};
use serde_json::{Value, json};

use super::build::{
    BuildRequest, Compiled, OBJECT_FORMAT, OBJECTS_DIR, SOURCE_DIR, blocker_json, blocker_record,
    compile_jobs, failure_text, file_flags, file_name, file_of_function, is_c, ms, new_run_dir,
    place_objects, read_text, stage_headers, symbol_sizes, toolchain, verdict_id,
};
use crate::{FacadeError, KnowledgeView, Response};

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

/// The outcome of one variant.
#[derive(Clone)]
struct VariantResult {
    /// 1-based: the variant's position in the request, also the number in its directory name (`V001`).
    index: usize,
    label: Option<String>,
    verdict: &'static str,
    /// The variant has a comparison with the original (compiled, function found, original bytes available).
    checked: bool,
    /// The function has inline assembly: never identical, ranked after every variant without.
    cheat: bool,
    instructions_differing: u32,
    differing: u32,
    refs_wrong: u32,
    blockers: Vec<BlockerRecord>,
    message: Option<String>,
}

impl VariantResult {
    fn unchecked(verdict: &'static str, message: String) -> Self {
        VariantResult {
            index: 0,
            label: None,
            verdict,
            checked: false,
            cheat: false,
            instructions_differing: 0,
            differing: 0,
            refs_wrong: 0,
            blockers: Vec::new(),
            message: Some(message),
        }
    }

    /// Variants with a comparison first; among them those without inline assembly, then identical first, fewer
    /// differing instructions, fewer differing bytes plus wrong references, and the order of the request.
    fn rank(&self) -> (bool, bool, bool, u32, u32, usize) {
        (
            !self.checked,
            self.cheat,
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

/// `variant 2` or `variant 2 (label)`: how messages name a variant.
fn describe(index: usize, label: Option<&str>) -> String {
    match label {
        Some(label) => format!("variant {index} ({label})"),
        None => format!("variant {index}"),
    }
}

/// A distinct staged text: the variants with this text share one directory, one compile and one comparison.
struct Group {
    dir: String,
    /// The first variant with this text.
    first: usize,
    bytes: Vec<u8>,
}

/// The last good objects of the other C sources of `set` from `cache/rebuild/obj` (read only), for the reference
/// anchors. An object counts only when its metadata says it was built from the current text of its source and the
/// current headers, with the current flags and profile. Returns the objects (name, object) and warnings.
fn kept_objects(
    root: &Path,
    set: &SourceSet,
    profile: &Profile,
    flags_of: &dyn Fn(&str) -> String,
    replaced: &str,
    headers: &BTreeMap<String, String>,
) -> (Vec<(String, ObjectFile)>, Vec<String>) {
    let dir = root.join(OBJECTS_DIR);
    let mut kept = Vec::new();
    let mut left_out: Vec<String> = Vec::new();
    for path in &set.sources {
        let name = file_name(path);
        if !is_c(&name) || name.eq_ignore_ascii_case(replaced) {
            continue;
        }
        let dos_name = name.to_ascii_uppercase();
        let stem = name
            .rsplit_once('.')
            .map_or(name.as_str(), |(s, _)| s)
            .to_ascii_lowercase();
        let usable = (|| {
            let bytes = std::fs::read(dir.join(format!("{stem}.obj"))).ok()?;
            let meta: Value =
                serde_json::from_slice(&std::fs::read(dir.join(format!("{stem}.json"))).ok()?)
                    .ok()?;
            let text = read_text(path).ok()?;
            let source = to_dos_bytes(&name, &text).ok()?;
            let inputs = meta.get("inputs")?;
            let same =
                |key: &str, hash: &str| inputs.get(key).and_then(Value::as_str) == Some(hash);
            let current = meta.get("format")?.as_str()? == OBJECT_FORMAT
                && meta.get("profile")?.as_str()? == profile.id
                && meta.get("flags")?.as_str()? == flags_of(&name)
                && meta.get("object")?.as_str()? == blake3::hash(&bytes).to_hex().as_str()
                && same(&dos_name, blake3::hash(&source).to_hex().as_str())
                && headers.iter().all(|(h, hash)| same(h, hash));
            current.then(|| read_omf(&bytes, &dos_name).ok()).flatten()
        })();
        match usable {
            Some(object) => kept.push((name, object)),
            None => left_out.push(name),
        }
    }
    let mut warnings = Vec::new();
    if !left_out.is_empty() {
        let shown: Vec<&str> = left_out.iter().take(5).map(String::as_str).collect();
        warnings.push(format!(
            "reference anchors: the kept objects of {} other file{} are missing or out of date and left out ({}{}); build them for a stronger check",
            left_out.len(),
            if left_out.len() == 1 { "" } else { "s" },
            shown.join(", "),
            if left_out.len() > shown.len() { ", ..." } else { "" }
        ));
    }
    (kept, warnings)
}

/// What the comparison of every variant needs.
struct Compare<'a> {
    knowledge: &'a KnowledgeView<'a>,
    profile: &'a Profile,
    index: Option<&'a decovery_core::AnalysisIndex<'a>>,
    symbol_sizes: &'a HashMap<decovery_core::Address, Option<u64>>,
    program: &'a Program,
    options: &'a ModuleOptions,
    function: &'a str,
    /// Last good objects of the other files.
    others: &'a [(String, ObjectFile)],
}

impl Compare<'_> {
    /// Compares the variant's `object` together with the other files' objects (one module comparison, as in a full
    /// build) and returns the result for `function`. `text` is the variant source (LF) for the inline-assembly check.
    fn run(
        &self,
        object: &ObjectFile,
        text: &str,
        warnings: &mut BTreeSet<String>,
    ) -> VariantResult {
        let mut objects: Vec<(usize, &str, &ObjectFile)> = vec![(0, "the variant", object)];
        objects.extend(
            self.others
                .iter()
                .enumerate()
                .map(|(k, (name, object))| (k + 1, name.as_str(), object)),
        );
        let mut hints = Vec::new();
        let (placements, placed) = place_objects(
            self.knowledge,
            self.profile,
            self.index,
            self.symbol_sizes,
            &objects,
            &mut hints,
        );
        let function = self.function;
        let Some(at) = placed.iter().position(|b| {
            b.source == 0 && (b.name == function || b.address.to_string() == function)
        }) else {
            return VariantResult::unchecked(
                "unchecked",
                format!(
                    "the object does not define {function} (or it has no counterpart in the original)"
                ),
            );
        };
        let module = decovery_diff::compare_module(
            &placements,
            self.program,
            self.knowledge,
            &self.profile.decoration,
            self.options,
        );
        warnings.extend(module.warnings);
        let Some(comparison) = module.functions.get(at) else {
            return VariantResult::unchecked("unchecked", format!("{function} was not compared"));
        };
        let m = &comparison.metrics;
        let mut verdict = verdict_id(&comparison.verdict);
        let checked = verdict != VerdictId::Unchecked;
        let mut blockers: Vec<BlockerRecord> =
            comparison.blockers.iter().map(blocker_record).collect();
        let mut message = (!checked)
            .then(|| "the original bytes of the function are not in the program".to_string());
        // inline assembly is never identical
        let findings: Vec<CheatFinding> = find_cheats(text)
            .into_iter()
            .filter(|f| f.function.as_deref() == Some(placed[at].name.as_str()))
            .collect();
        let cheat = !findings.is_empty();
        if cheat {
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
        VariantResult {
            index: 0,
            label: None,
            verdict: verdict.id(),
            checked,
            cheat,
            instructions_differing: m.instructions_differing,
            differing: m.differing,
            refs_wrong: m.refs_wrong,
            blockers,
            message,
        }
    }
}

/// `build` with variants: compiles the candidate sources of `request.variants` for `request.function` (all cache
/// misses in one runner request), compares the function of each variant's object with the original and ranks the
/// variants. Records, kept objects and output files stay untouched.
pub(super) fn build_variants(
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
    let set = find_sources(&root.join(SOURCE_DIR), &[]).map_err(toolchain)?;
    let own = set
        .sources
        .iter()
        .map(|p| file_name(p))
        .find(|n| n.eq_ignore_ascii_case(&file));
    let Some(file) = own.filter(|n| is_c(n)) else {
        return Err(FacadeError::Invalid(format!(
            "{file} is not a C source in {SOURCE_DIR}/; the variants replace one"
        )));
    };
    let flags_of = |name: &str| {
        file_flags(&rebuild.file_flags, name)
            .cloned()
            .unwrap_or_else(|| default_flags.clone())
    };
    let flags = flags_of(&file);
    let dos_name = file.to_ascii_uppercase();

    // one directory per distinct text
    let count = request.variants.len();
    let mut errors: Vec<Option<String>> = vec![None; count];
    let mut group_of: Vec<usize> = vec![0; count];
    let mut groups: Vec<Group> = Vec::new();
    let mut seen: HashMap<blake3::Hash, usize> = HashMap::new();
    for (i, variant) in request.variants.iter().enumerate() {
        match to_dos_bytes(&file, &variant.source) {
            Err(e) => errors[i] = Some(e.to_string()),
            Ok(bytes) => {
                let hash = blake3::hash(&bytes);
                let g = *seen.entry(hash).or_insert_with(|| {
                    groups.push(Group {
                        dir: format!("V{:03}", i + 1),
                        first: i,
                        bytes,
                    });
                    groups.len() - 1
                });
                group_of[i] = g;
            }
        }
    }
    let run_dir = new_run_dir(root)?;
    let headers = stage_headers(&set, &run_dir.0)?;
    let output = |path: std::path::PathBuf| move |source| FacadeError::Output { path, source };
    for group in &groups {
        let dir = run_dir.0.join(&group.dir);
        std::fs::create_dir_all(&dir).map_err(output(dir.clone()))?;
        std::fs::write(dir.join(&dos_name), &group.bytes).map_err(output(dir.join(&dos_name)))?;
        for header in headers.keys() {
            std::fs::copy(run_dir.0.join(header), dir.join(header))
                .map_err(output(dir.join(header)))?;
        }
    }

    // compile: cache hits, then all misses in one runner request
    let compile_started = Instant::now();
    let jobs_input: Vec<SourceJob> = groups
        .iter()
        .map(|g| SourceJob::new(dos_name.clone(), flags.clone()).in_dir(g.dir.clone()))
        .collect();
    let Compiled {
        files: compiled,
        mut warnings,
        ..
    } = compile_jobs(&ws, &profile, &jobs_input, &run_dir.0, progress)?;
    drop(run_dir);
    if compiled.len() != groups.len() {
        return Err(FacadeError::Invalid(format!(
            "internal error: {} compile results for {} distinct variants",
            compiled.len(),
            groups.len()
        )));
    }
    let jobs = compiled.iter().filter(|c| !c.cached).count();
    let cached = compiled.len() - jobs;
    let compile_ms = ms(compile_started.elapsed());

    // objects of the distinct variants
    let compare_started = Instant::now();
    let mut group_errors: Vec<Option<String>> = vec![None; groups.len()];
    let mut objects: Vec<Option<ObjectFile>> = Vec::new();
    objects.resize_with(groups.len(), || None);
    for (g, file) in compiled.iter().enumerate() {
        match &file.object {
            None => group_errors[g] = Some(failure_text(file)),
            Some(bytes) => match read_omf(bytes, &dos_name) {
                Ok(object) => objects[g] = Some(object),
                Err(e) => group_errors[g] = Some(format!("cannot read the object: {e}")),
            },
        }
    }

    // judge each distinct variant like a full build: with the kept objects of the other files
    let mut compared: Vec<Option<VariantResult>> = vec![None; groups.len()];
    let mut compare_warnings: BTreeSet<String> = BTreeSet::new();
    if objects.iter().any(Option::is_some) {
        let (others, more) = kept_objects(root, &set, &profile, &flags_of, &file, &headers);
        warnings.extend(more);
        let knowledge = KnowledgeView::new(&ws, analysis.as_ref());
        let index = analysis.as_ref().map(Analysis::index);
        let sizes = symbol_sizes(&ws);
        let program = crate::program::load(&ws)?;
        let options = ModuleOptions::new(profile.padding, rebuild.frames.clone());
        let compare = Compare {
            knowledge: &knowledge,
            profile: &profile,
            index: index.as_ref(),
            symbol_sizes: &sizes,
            program: &program,
            options: &options,
            function,
            others: &others,
        };
        let total = objects.iter().flatten().count() as u64;
        let mut done = 0;
        for (g, object) in objects.iter().enumerate() {
            let Some(object) = object else { continue };
            let text = request.variants[groups[g].first]
                .source
                .replace("\r\n", "\n");
            compared[g] = Some(compare.run(object, &text, &mut compare_warnings));
            done += 1;
            progress(Progress::new(
                done,
                Some(total),
                Some(format!("compared {done} of {total} variants")),
            ));
        }
    }
    warnings.extend(compare_warnings);

    // one result per variant, in the order of the request
    let mut results: Vec<VariantResult> = Vec::with_capacity(count);
    for (i, variant) in request.variants.iter().enumerate() {
        let name = describe(i + 1, variant.label.as_deref());
        let mut result = match &errors[i] {
            Some(error) => VariantResult::unchecked("error", format!("{name}: {error}")),
            None => {
                let g = group_of[i];
                match (&group_errors[g], &compared[g]) {
                    (Some(error), _) => {
                        VariantResult::unchecked("error", format!("{name}: {error}"))
                    }
                    (None, Some(result)) => result.clone(),
                    (None, None) => VariantResult::unchecked(
                        "error",
                        format!("{name}: no result (internal error)"),
                    ),
                }
            }
        };
        result.index = i + 1;
        result.label = variant.label.clone();
        results.push(result);
    }
    results.sort_by_key(VariantResult::rank);
    let compare_ms = ms(compare_started.elapsed());

    let best = results.first().filter(|r| r.checked);
    let failed = results.iter().filter(|r| r.verdict == "error").count();
    let mut summary = format!(
        "{function}: {count} variant{}",
        if count == 1 { "" } else { "s" }
    );
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
                "distinct": groups.len(),
            },
        }),
    ))
}
