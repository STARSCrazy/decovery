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

use decovery_core::{
    Analysis, BlockerRecord, Program, VerdictId, Workspace, read_rebuild, write_atomic,
};
use decovery_diff::{Blocker, ModuleOptions, SharedFunctions, same_code};
use decovery_objects::{FunctionView, ObjectFile, functions, read_omf};
use decovery_plugin::Progress;
use decovery_toolchain::{
    CheatFinding, CompiledFile, Profile, SourceJob, SourceSet, definitions, find_cheats,
    find_sources, rebuild_profile, shrink, splice_function, to_dos_bytes,
};
use rayon::prelude::*;
use serde_json::{Value, json};

use super::build::{
    BuildRequest, Compiled, OBJECT_FORMAT, OBJECTS_DIR, SOURCE_DIR, blocker_json, blocker_record,
    compile_jobs, failure_text, file_flags, file_name, file_of_function, is_c, ms, new_run_dir,
    place_objects, read_text, stage_headers, symbol_sizes, toolchain, verdict_id,
};
use crate::{FacadeError, KnowledgeView, Response};

/// Most variants one `build` call compiles.
pub const MAX_VARIANTS: usize = 64;

/// A candidate for one function (`build` with `variants`): either a whole replacement of the function's file
/// (`source`) or one definition of the function (`function_source`), which is spliced into the current file and
/// compiled in a file shrunk to the function and what its code needs, when that gives the same code. Exactly one of
/// the two is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Variant {
    pub label: Option<String>,
    pub source: Option<String>,
    pub function_source: Option<String>,
}

impl Variant {
    /// A whole replacement of the function's file.
    pub fn new(source: impl Into<String>) -> Self {
        Variant {
            source: Some(source.into()),
            ..Variant::default()
        }
    }

    /// One definition of the function.
    pub fn function(function_source: impl Into<String>) -> Self {
        Variant {
            function_source: Some(function_source.into()),
            ..Variant::default()
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
    /// Function variants: whether the variant was compiled in the shrunk file, and why (not).
    shrunk: Option<(bool, String)>,
    /// A shrunk variant judged identical, judged again on its full file: this is the full file's result.
    confirmed_on_full: bool,
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
            shrunk: None,
            confirmed_on_full: false,
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
        if let Some((shrunk, reason)) = &self.shrunk {
            v["shrunk"] = json!(shrunk);
            v["shrink_reason"] = json!(reason);
        }
        if self.confirmed_on_full {
            v["confirmed_on"] = json!("full");
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
    /// The text with LF line ends, for the inline-assembly check.
    text: String,
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
    /// The functions of the kept objects of the other files, prepared once for every variant.
    shared: SharedFunctions<'a>,
}

impl Compare<'_> {
    /// Compares the variant's `object` together with the other files' functions (the anchors of one module comparison,
    /// as in a full build) and returns the result for `function` and the comparison's warnings. `text` is the
    /// variant source (LF) for the inline-assembly check. Independent of every other call.
    fn run(&self, object: &ObjectFile, text: &str) -> (VariantResult, Vec<String>) {
        let objects: Vec<(usize, &str, &ObjectFile)> = vec![(0, "the variant", object)];
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
            return (
                VariantResult::unchecked(
                    "unchecked",
                    format!(
                        "the object does not define {function} (or it has no counterpart in the original)"
                    ),
                ),
                Vec::new(),
            );
        };
        let module = decovery_diff::compare_module_with(
            &placements,
            &self.shared,
            self.program,
            self.knowledge,
            &self.profile.decoration,
            self.options,
        );
        let warnings = module.warnings;
        let Some(comparison) = module.functions.get(at) else {
            return (
                VariantResult::unchecked("unchecked", format!("{function} was not compared")),
                warnings,
            );
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
        (
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
                shrunk: None,
                confirmed_on_full: false,
            },
            warnings,
        )
    }
}

/// The shrink check results, relative to the workspace root: `<key>.json` per file version.
pub const SHRINK_DIR: &str = "cache/rebuild/shrink";

/// The distinct texts of a call, each with its own directory.
#[derive(Default)]
struct Texts {
    groups: Vec<Group>,
    seen: HashMap<blake3::Hash, usize>,
}

impl Texts {
    /// The group of `text` (staged as `name`), a new one in `dir` when no other variant has this text.
    fn add(&mut self, name: &str, text: &str, dir: String) -> Result<usize, String> {
        let bytes = to_dos_bytes(name, text).map_err(|e| e.to_string())?;
        let hash = blake3::hash(&bytes);
        let groups = &mut self.groups;
        Ok(*self.seen.entry(hash).or_insert_with(|| {
            groups.push(Group {
                dir,
                text: text.to_string(),
                bytes,
            });
            groups.len() - 1
        }))
    }
}

/// The C name of `function` (a name or an address): an address is named by its rebuild record.
fn c_name_of(root: &Path, function: &str) -> Result<String, FacadeError> {
    Ok(read_rebuild(root)?
        .into_iter()
        .find(|r| r.address.to_string() == function)
        .map_or_else(|| function.to_string(), |r| r.name))
}

/// What one variant compiles.
struct Attempt {
    /// The whole file (LF line ends): the variant's source, or the file with the function spliced in.
    full: String,
    /// Function variants with something to drop: the shrunk file and the key of its check.
    shrunk: Option<(String, String)>,
}

/// The key of the shrink check of a file version: blake3 of the spliced file without the body of `function`, the
/// profile id, its prelude, the flags and the staged headers (DOS name and blake3, as in the object cache key).
/// Every attempt at the function in this version of the rest of the file shares it.
fn shrink_key(
    spliced: &str,
    function: &str,
    profile: &Profile,
    flags: &str,
    headers: &BTreeMap<String, String>,
) -> String {
    let mut hasher = blake3::Hasher::new();
    match definitions(spliced).iter().find(|d| d.name == function) {
        Some(d) => {
            hasher.update(&spliced.as_bytes()[..d.brace]);
            hasher.update(&spliced.as_bytes()[d.end..]);
        }
        None => {
            hasher.update(spliced.as_bytes());
        }
    }
    let prelude = profile.prelude.join("\n");
    for part in [profile.id.as_str(), prelude.as_str(), flags] {
        hasher.update(b"\0");
        hasher.update(part.as_bytes());
    }
    for (name, hash) in headers {
        hasher.update(b"\0");
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(hash.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// A stored shrink check: (valid, reason).
fn read_check(root: &Path, key: &str) -> Option<(bool, String)> {
    let bytes = std::fs::read(root.join(SHRINK_DIR).join(format!("{key}.json"))).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    (v.get("schema")?.as_u64()? == 1).then_some(())?;
    Some((
        v.get("valid")?.as_bool()?,
        v.get("reason")?.as_str()?.to_string(),
    ))
}

fn write_check(root: &Path, key: &str, valid: bool, reason: &str) -> Result<(), FacadeError> {
    let path = root.join(SHRINK_DIR).join(format!("{key}.json"));
    let text = serde_json::to_string_pretty(&json!({
        "schema": 1,
        "valid": valid,
        "reason": reason,
    }))
    .map_err(|e| FacadeError::Invalid(e.to_string()))?
        + "\n";
    write_atomic(&path, text.as_bytes()).map_err(|source| FacadeError::Output { path, source })
}

/// The functions of `object` with the C name `function` (statics are local publics).
fn function_in<'o>(
    object: &'o ObjectFile,
    profile: &Profile,
    function: &str,
) -> Vec<FunctionView<'o>> {
    object
        .modules
        .iter()
        .flat_map(functions)
        .filter(|f| f.name == function || profile.decoration.undecorate(f.name) == function)
        .collect()
}

/// Judges a shrink check from the objects of the full and the shrunk file: (valid, reason, store it). A full file
/// that does not compile or lacks the function says nothing about the file version and is not stored.
fn judge_check(
    full: &CompiledFile,
    shrunk: &CompiledFile,
    dos_name: &str,
    profile: &Profile,
    function: &str,
    dropped: usize,
) -> (bool, String, bool) {
    let read = |file: &CompiledFile| {
        file.object
            .as_ref()
            .and_then(|bytes| read_omf(bytes, dos_name).ok())
    };
    let Some(full) = read(full) else {
        return (false, "the full file does not compile".into(), false);
    };
    let Some(shrunk) = read(shrunk) else {
        return (false, "the shrunk file does not compile".into(), true);
    };
    let (in_full, in_shrunk) = (
        function_in(&full, profile, function),
        function_in(&shrunk, profile, function),
    );
    let Some(a) = in_full.first() else {
        return (
            false,
            format!("the object of the full file does not define {function}"),
            false,
        );
    };
    match in_shrunk.first() {
        None => (
            false,
            format!("the object of the shrunk file does not define {function}"),
            true,
        ),
        Some(b) if same_code(a, b) => (
            true,
            format!(
                "same code, {dropped} function{} dropped",
                if dropped == 1 { "" } else { "s" }
            ),
            true,
        ),
        Some(_) => (false, format!("different code for {function}"), true),
    }
}

impl Compare<'_> {
    /// Compares the objects of `groups` (all, or those in `only`) in parallel with [`Compare::run`] and stores each
    /// result in `compared`; the calling thread reports progress as they end.
    fn run_all(
        &self,
        objects: &[Option<ObjectFile>],
        groups: &[Group],
        only: Option<&BTreeSet<usize>>,
        compared: &mut [Option<VariantResult>],
        warnings: &mut BTreeSet<String>,
        progress: &dyn Fn(Progress),
    ) {
        let selected: Vec<(usize, &ObjectFile)> = objects
            .iter()
            .enumerate()
            .filter(|(g, _)| only.is_none_or(|only| only.contains(g)))
            .filter_map(|(g, object)| Some((g, object.as_ref()?)))
            .collect();
        let total = selected.len() as u64;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                selected
                    .par_iter()
                    .for_each_with(sender, |sender, &(g, object)| {
                        let _ = sender.send((g, self.run(object, &groups[g].text)));
                    });
            });
            for done in 1..=total {
                let Ok((g, (result, more))) = receiver.recv() else {
                    break;
                };
                compared[g] = Some(result);
                warnings.extend(more);
                progress(Progress::new(
                    done,
                    Some(total),
                    Some(format!("compared {done} of {total} variants")),
                ));
            }
        });
    }
}

/// `build` with variants: compiles the candidates of `request.variants` for `request.function` (all cache misses in
/// one runner request), compares the function of each variant's object with the original and ranks the variants.
/// Records, kept objects and output files stay untouched.
///
/// A function variant is spliced into the current file. When the file can be shrunk, the shrunk file is compiled;
/// whether it gives the function the same code as the full file is checked once per file version (key: the file
/// without the function's body, profile, flags and headers) by compiling both in the same request, and stored in
/// [`SHRINK_DIR`]. When it does not, the variant is judged on the full file (a second request compiles the full
/// files that were not compiled yet). A shrunk variant judged identical is only a candidate: all candidates are
/// judged again on their full files (one more request for those not compiled yet), and that result is final
/// (`confirmed_on: "full"`).
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
    for (i, variant) in request.variants.iter().enumerate() {
        if variant.source.is_some() == variant.function_source.is_some() {
            return Err(FacadeError::Invalid(format!(
                "{}: exactly one of source and function_source must be given",
                describe(i + 1, variant.label.as_deref())
            )));
        }
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
        .find(|p| file_name(p).eq_ignore_ascii_case(&file));
    let Some(own_path) = own.filter(|p| is_c(&file_name(p))) else {
        return Err(FacadeError::Invalid(format!(
            "{file} is not a C source in {SOURCE_DIR}/; the variants replace one"
        )));
    };
    let file = file_name(own_path);
    let flags_of = |name: &str| {
        file_flags(&rebuild.file_flags, name)
            .cloned()
            .unwrap_or_else(|| default_flags.clone())
    };
    let flags = flags_of(&file);
    let dos_name = file.to_ascii_uppercase();

    let run_dir = new_run_dir(root)?;
    let headers = stage_headers(&set, &run_dir.0)?;

    // what each variant compiles
    let count = request.variants.len();
    let mut errors: Vec<Option<String>> = vec![None; count];
    let mut attempts: Vec<Option<Attempt>> = Vec::with_capacity(count);
    let function_variants = request.variants.iter().any(|v| v.function_source.is_some());
    let (file_text, c_name) = if function_variants {
        (
            read_text(own_path)?.replace("\r\n", "\n"),
            c_name_of(root, function)?,
        )
    } else {
        (String::new(), String::new())
    };
    let mut shrink_state: Vec<Option<(bool, String)>> = vec![None; count];
    let mut dropped_of: HashMap<String, usize> = HashMap::new();
    for (i, variant) in request.variants.iter().enumerate() {
        let attempt = match (&variant.source, &variant.function_source) {
            (Some(source), _) => Ok(Attempt {
                full: source.replace("\r\n", "\n"),
                shrunk: None,
            }),
            (None, Some(function_source)) => {
                splice_function(&file_text, &c_name, &function_source.replace("\r\n", "\n"))
                    .map(|spliced| match shrink(&spliced, &[c_name.as_str()]) {
                        None => {
                            shrink_state[i] = Some((false, "nothing to drop".into()));
                            Attempt {
                                full: spliced,
                                shrunk: None,
                            }
                        }
                        Some(shrunk) => {
                            let key = shrink_key(&spliced, &c_name, &profile, &flags, &headers);
                            dropped_of.insert(key.clone(), shrunk.dropped.len());
                            Attempt {
                                full: spliced,
                                shrunk: Some((shrunk.text, key)),
                            }
                        }
                    })
                    .map_err(|e| e.to_string())
            }
            (None, None) => Err("no source".to_string()),
        };
        match attempt {
            Ok(attempt) => attempts.push(Some(attempt)),
            Err(e) => {
                errors[i] = Some(e);
                attempts.push(None);
            }
        }
    }
    let known: HashMap<String, (bool, String)> = dropped_of
        .keys()
        .filter_map(|key| Some((key.clone(), read_check(root, key)?)))
        .collect();

    // one directory per distinct text: `V001` the text a variant is judged on first, `F001` its full file
    let mut texts = Texts::default();
    let add = |texts: &mut Texts, text: &str, dir: String| texts.add(&file, text, dir);
    let mut ranked: Vec<usize> = vec![0; count];
    // key -> (full group, shrunk group) of the first variant with the key, for every check this call makes
    let mut checks: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (i, attempt) in attempts.iter().enumerate() {
        let Some(attempt) = attempt else { continue };
        let full_dir = || format!("F{:03}", i + 1);
        let own_dir = format!("V{:03}", i + 1);
        let chosen = match &attempt.shrunk {
            None if request.variants[i].source.is_some() => add(&mut texts, &attempt.full, own_dir),
            None => add(&mut texts, &attempt.full, full_dir()),
            Some((text, key)) => match known.get(key) {
                Some((valid, reason)) => {
                    shrink_state[i] = Some((*valid, reason.clone()));
                    if *valid {
                        add(&mut texts, text, own_dir)
                    } else {
                        add(&mut texts, &attempt.full, full_dir())
                    }
                }
                // unchecked: the shrunk file on speculation, and the full file once per key
                None if checks.contains_key(key) => add(&mut texts, text, own_dir),
                None => add(&mut texts, &attempt.full, full_dir()).and_then(|full| {
                    let shrunk = add(&mut texts, text, own_dir)?;
                    checks.insert(key.clone(), (full, shrunk));
                    Ok(shrunk)
                }),
            },
        };
        match chosen {
            Ok(g) => ranked[i] = g,
            Err(e) => errors[i] = Some(e),
        }
    }

    let output = |path: std::path::PathBuf| move |source| FacadeError::Output { path, source };
    let stage = |groups: &[Group]| -> Result<(), FacadeError> {
        for group in groups {
            let dir = run_dir.0.join(&group.dir);
            std::fs::create_dir_all(&dir).map_err(output(dir.clone()))?;
            std::fs::write(dir.join(&dos_name), &group.bytes)
                .map_err(output(dir.join(&dos_name)))?;
            for header in headers.keys() {
                std::fs::copy(run_dir.0.join(header), dir.join(header))
                    .map_err(output(dir.join(header)))?;
            }
        }
        Ok(())
    };
    // compile: cache hits, then all misses in one runner request
    let compile_started = Instant::now();
    let compile = |groups: &[Group]| -> Result<Compiled, FacadeError> {
        stage(groups)?;
        let jobs_input: Vec<SourceJob> = groups
            .iter()
            .map(|g| SourceJob::new(dos_name.clone(), flags.clone()).in_dir(g.dir.clone()))
            .collect::<Result<_, _>>()
            .map_err(toolchain)?;
        let compiled = compile_jobs(&ws, &profile, &jobs_input, &run_dir.0, progress)?;
        if compiled.files.len() != groups.len() {
            return Err(FacadeError::Invalid(format!(
                "internal error: {} compile results for {} distinct texts",
                compiled.files.len(),
                groups.len()
            )));
        }
        Ok(compiled)
    };
    let Compiled {
        files: mut compiled,
        mut warnings,
        ..
    } = compile(&texts.groups)?;

    // the shrink checks of this call; an invalid shrunk file sends its variants to the full file
    let mut decided: BTreeMap<String, (bool, String)> = BTreeMap::new();
    for (key, &(full, shrunk)) in &checks {
        let (valid, reason, store) = judge_check(
            &compiled[full],
            &compiled[shrunk],
            &dos_name,
            &profile,
            &c_name,
            dropped_of.get(key).copied().unwrap_or(0),
        );
        if store {
            write_check(root, key, valid, &reason)?;
        }
        decided.insert(key.clone(), (valid, reason));
    }
    let first_groups = texts.groups.len();
    for (i, attempt) in attempts.iter().enumerate() {
        let Some(Attempt {
            full,
            shrunk: Some((_, key)),
        }) = attempt
        else {
            continue;
        };
        let Some((valid, reason)) = decided.get(key) else {
            continue;
        };
        shrink_state[i] = Some((*valid, reason.clone()));
        if !*valid && errors[i].is_none() {
            match add(&mut texts, full, format!("F{:03}", i + 1)) {
                Ok(g) => ranked[i] = g,
                Err(e) => errors[i] = Some(e),
            }
        }
    }
    if texts.groups.len() > first_groups {
        let more = compile(&texts.groups[first_groups..])?;
        compiled.extend(more.files);
        warnings.extend(more.warnings);
    }
    let mut compile_time = compile_started.elapsed();
    let compile_first = compile_time;

    // objects of the distinct texts some variant is judged on
    let compare_started = Instant::now();
    let judged: BTreeSet<usize> = (0..count)
        .filter(|&i| errors[i].is_none())
        .map(|i| ranked[i])
        .collect();
    let mut group_errors: Vec<Option<String>> = Vec::new();
    let mut objects: Vec<Option<ObjectFile>> = Vec::new();
    let read_objects = |judged: &BTreeSet<usize>,
                        compiled: &[CompiledFile],
                        objects: &mut Vec<Option<ObjectFile>>,
                        group_errors: &mut Vec<Option<String>>| {
        objects.resize_with(compiled.len(), || None);
        group_errors.resize(compiled.len(), None);
        for &g in judged {
            let file = &compiled[g];
            match &file.object {
                None => group_errors[g] = Some(failure_text(file)),
                Some(bytes) => match read_omf(bytes, &dos_name) {
                    Ok(object) => objects[g] = Some(object),
                    Err(e) => group_errors[g] = Some(format!("cannot read the object: {e}")),
                },
            }
        }
    };
    read_objects(&judged, &compiled, &mut objects, &mut group_errors);

    // judge each distinct variant like a full build: with the kept objects of the other files
    let mut compared: Vec<Option<VariantResult>> = vec![None; texts.groups.len()];
    // variant -> the group of its full file, for shrunk variants judged identical (confirmed on the full file)
    let mut confirmed: Vec<Option<usize>> = vec![None; count];
    let mut compare_warnings: BTreeSet<String> = BTreeSet::new();
    if objects.iter().any(Option::is_some) {
        let (others, more) = kept_objects(root, &set, &profile, &flags_of, &file, &headers);
        warnings.extend(more);
        let knowledge = KnowledgeView::new(&ws, analysis.as_ref());
        let index = analysis.as_ref().map(Analysis::index);
        let sizes = symbol_sizes(&ws);
        let program = crate::program::load(&ws)?;
        let options = ModuleOptions::new(profile.padding, rebuild.frames.clone());
        // the kept objects' functions are placed and prepared once, whatever the number of variants
        let kept: Vec<(usize, &str, &ObjectFile)> = others
            .iter()
            .enumerate()
            .map(|(k, (name, object))| (k + 1, name.as_str(), object))
            .collect();
        let (kept_placements, _) = place_objects(
            &knowledge,
            &profile,
            index.as_ref(),
            &sizes,
            &kept,
            &mut Vec::new(),
        );
        let shared = SharedFunctions::new(
            &kept_placements,
            &program,
            &knowledge,
            &profile.decoration,
            &options,
        );
        let compare = Compare {
            knowledge: &knowledge,
            profile: &profile,
            index: index.as_ref(),
            symbol_sizes: &sizes,
            program: &program,
            options: &options,
            function,
            shared,
        };
        compare.run_all(
            &objects,
            &texts.groups,
            None,
            &mut compared,
            &mut compare_warnings,
            progress,
        );

        // `identical` from a shrunk file is a candidate only: shrunk objects lack the anchor votes of the dropped
        // functions, and one check serves bodies with other dependencies. Every candidate is judged again on its
        // full file, all of them in one more request (equal texts once, the object cache first).
        let first_groups = texts.groups.len();
        for (i, attempt) in attempts.iter().enumerate() {
            let shrunk = shrink_state[i].as_ref().is_some_and(|(shrunk, _)| *shrunk);
            let identical = compared[ranked[i]]
                .as_ref()
                .is_some_and(|r| r.verdict == "identical");
            let Some(attempt) = attempt.as_ref().filter(|_| shrunk && identical) else {
                continue;
            };
            if errors[i].is_some() {
                continue;
            }
            match add(&mut texts, &attempt.full, format!("F{:03}", i + 1)) {
                Ok(g) => confirmed[i] = Some(g),
                Err(e) => errors[i] = Some(e),
            }
        }
        if texts.groups.len() > first_groups {
            let confirm_started = Instant::now();
            let more = compile(&texts.groups[first_groups..])?;
            compiled.extend(more.files);
            warnings.extend(more.warnings);
            compile_time += confirm_started.elapsed();
        }
        let to_judge: BTreeSet<usize> = confirmed
            .iter()
            .flatten()
            .copied()
            .filter(|&g| compared.get(g).is_none_or(Option::is_none))
            .collect();
        if !to_judge.is_empty() {
            read_objects(&to_judge, &compiled, &mut objects, &mut group_errors);
            compared.resize(compiled.len(), None);
            compare.run_all(
                &objects,
                &texts.groups,
                Some(&to_judge),
                &mut compared,
                &mut compare_warnings,
                progress,
            );
        }
    }
    warnings.extend(compare_warnings);
    drop(run_dir);
    let groups = texts.groups;
    let jobs = compiled.iter().filter(|c| !c.cached).count();
    let cached = compiled.len() - jobs;
    let compile_ms = ms(compile_time);

    // one result per variant, in the order of the request
    let mut results: Vec<VariantResult> = Vec::with_capacity(count);
    for (i, variant) in request.variants.iter().enumerate() {
        let name = describe(i + 1, variant.label.as_deref());
        let mut result = match &errors[i] {
            Some(error) => VariantResult::unchecked("error", format!("{name}: {error}")),
            None => {
                let g = confirmed[i].unwrap_or(ranked[i]);
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
        result.shrunk = shrink_state[i].clone();
        result.confirmed_on_full = confirmed[i].is_some();
        results.push(result);
    }
    results.sort_by_key(VariantResult::rank);
    // the confirmation compile ran inside the compare phase; it counts as compile time
    let compare_ms = ms(compare_started
        .elapsed()
        .saturating_sub(compile_time.saturating_sub(compile_first)));

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
                "shrink_checks": checks.len(),
                "confirmed": confirmed.iter().flatten().count(),
            },
        }),
    ))
}
