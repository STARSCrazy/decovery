//! Attempts (design 6): what `build` records per compared function and variant, and the `history` tool that reads
//! them back.
//!
//! Every function a full or file build compares gets one attempt with origin `build`; every variant of
//! `build {variants}` one with origin `variant` (whole file) or `function` (`function_source`), labelled with the
//! variant's label. A build that repeats the function's last attempt (same body, context, profile, flags and
//! original bytes) appends nothing, so an unchanged source does not grow the store. Identical attempts and the best
//! compared one of each call per function are archived (`cache/archive/`); the others are recorded without.

use std::cell::OnceCell;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Mutex;

use decovery_core::{
    Address, AttemptOrigin, AttemptRecord, DEFAULT_ATTEMPT_BUDGET, Workspace, append_attempts,
    archive_load, archive_save, attempt_budget, attempt_distance, read_attempts,
};
use decovery_toolchain::{Profile, definitions, tool_dir, tool_fingerprint};
use serde_json::{Map, Value, json};

use super::legacy::function_of;
use crate::{Budget, FacadeError, Response, Session, store_handle};

/// Attempts `history` lists inline by default.
pub const DEFAULT_HISTORY_LIMIT: usize = 20;
/// Actor of the bench harness's own builds: left out of the default view, like from the budget.
const HARNESS_ACTOR: &str = "bench-harness";
/// The environment variable that names the actor of every attempt and call of this process (the bench sets
/// `bench:<run-id>`); it wins over [`set_actor`].
pub const ACTOR_ENV: &str = "DECOVERY_ACTOR";

static ACTOR: Mutex<Option<String>> = Mutex::new(None);

/// Sets who calls the facade in this process (`cli`, `mcp`); the MCP server and the CLI set it once at start.
pub fn set_actor(actor: &str) {
    *ACTOR.lock().unwrap_or_else(|p| p.into_inner()) = Some(actor.to_string());
}

/// The actor of this process: `DECOVERY_ACTOR` when set, else what [`set_actor`] set, else `library`.
pub fn actor() -> String {
    if let Ok(actor) = std::env::var(ACTOR_ENV)
        && !actor.trim().is_empty()
    {
        return actor.trim().to_string();
    }
    ACTOR
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .unwrap_or_else(|| "library".to_string())
}

/// How a build records its attempts when the caller is not the agent itself: the bridge's `search` records its
/// candidate with origin `search` and a label of its own and skips the current source it ranks it against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RecordAs {
    /// Replaces the origin of every recorded attempt.
    pub(crate) origin: Option<AttemptOrigin>,
    /// Replaces the label of every recorded attempt.
    pub(crate) label: Option<String>,
    /// Variants with these labels are not recorded.
    pub(crate) skip_labels: Vec<String>,
    /// Added to every recorded attempt.
    pub(crate) extra: Map<String, Value>,
}

impl RecordAs {
    /// Whether a variant labelled `label` is recorded.
    pub(crate) fn records(&self, label: Option<&str>) -> bool {
        !label.is_some_and(|l| self.skip_labels.iter().any(|s| s == l))
    }

    /// Applies origin, label and extra to `record`.
    pub(crate) fn apply(&self, record: &mut AttemptRecord) {
        if let Some(origin) = self.origin {
            record.origin = origin;
        }
        if let Some(label) = &self.label {
            record.label = Some(label.clone());
        }
        for (k, v) in &self.extra {
            record.extra.insert(k.clone(), v.clone());
        }
    }
}

/// An attempt of this call and what to archive with it.
pub(crate) struct Tried {
    pub(crate) record: AttemptRecord,
    /// The archive files (`function.c`, `module.c`, `objects/<name>`, `comparison.txt`, `messages/<n>.txt`).
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    /// Archive this attempt (identical, or the best compared one of its function in this call).
    pub(crate) archive: bool,
}

/// What every attempt of one source shares: its file, the text it is judged on and the compile inputs.
pub(crate) struct AttemptSource<'a> {
    /// Name in `src/`.
    pub(crate) file: &'a str,
    /// The whole file text, LF line ends.
    pub(crate) text: &'a str,
    pub(crate) profile: &'a str,
    pub(crate) flags: &'a str,
    /// blake3 (hex) of the staged headers by DOS name.
    pub(crate) headers: &'a BTreeMap<String, String>,
    /// The tool fingerprint ([`fingerprint_of`]).
    pub(crate) fingerprint: &'a str,
    /// The definitions of `text` by name, read once for all functions of the source.
    spans: OnceCell<HashMap<String, Vec<(usize, usize)>>>,
}

/// The tool fingerprint of `profile` in its directory, empty when the directory cannot be found.
pub(crate) fn fingerprint_of(ws: &Workspace, profile: &Profile) -> String {
    decovery_core::read_user_config()
        .ok()
        .and_then(|user| tool_dir(profile, ws.config.rebuild.as_ref(), &user, &ws.root).ok())
        .and_then(|dir| tool_fingerprint(profile, &dir).ok())
        .unwrap_or_default()
}

/// blake3 hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

impl<'a> AttemptSource<'a> {
    pub(crate) fn new(
        file: &'a str,
        text: &'a str,
        profile: &'a str,
        flags: &'a str,
        headers: &'a BTreeMap<String, String>,
        fingerprint: &'a str,
    ) -> Self {
        AttemptSource {
            file,
            text,
            profile,
            flags,
            headers,
            fingerprint,
            spans: OnceCell::new(),
        }
    }

    /// The text span of the only definition of `name` in the source.
    fn span(&self, name: &str) -> Option<(usize, usize)> {
        let spans = self.spans.get_or_init(|| {
            let mut spans: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
            for d in definitions(self.text) {
                spans.entry(d.name).or_default().push((d.start, d.end));
            }
            spans
        });
        match spans.get(name).map(Vec::as_slice) {
            Some([one]) => Some(*one),
            _ => None,
        }
    }

    /// A new attempt at `name` (`address`) in this source: hashes of the function's definition (the whole text when
    /// the source does not define it once) and of the rest of the file with the headers, profile, flags and tool
    /// fingerprint, the original bytes' hash, file, profile, flags and the actor of this process.
    pub(crate) fn attempt(
        &self,
        address: Address,
        name: &str,
        origin: AttemptOrigin,
        result: decovery_core::RebuildResult,
        original_hash: &str,
    ) -> AttemptRecord {
        let span = self.span(name);
        let body = span.map_or(self.text, |(start, end)| &self.text[start..end]);
        let mut context = blake3::Hasher::new();
        match span {
            Some((start, end)) => {
                context.update(&self.text.as_bytes()[..start]);
                context.update(b"\0");
                context.update(&self.text.as_bytes()[end..]);
            }
            None => {
                context.update(b"\0");
            }
        }
        for (header, hash) in self.headers {
            context.update(b"\0");
            context.update(header.as_bytes());
            context.update(b"=");
            context.update(hash.as_bytes());
        }
        for part in [self.profile, self.flags, self.fingerprint] {
            context.update(b"\0");
            context.update(part.as_bytes());
        }
        let mut r = AttemptRecord::new(address, name, origin, result);
        r.file = Some(self.file.to_string());
        r.actor = Some(actor());
        r.profile = self.profile.to_string();
        r.flags = self.flags.to_string();
        r.body_hash = format!("blake3:{}", hex(body.as_bytes()));
        r.context_hash = context.finalize().to_hex().to_string();
        r.original_hash = original_hash.to_string();
        r
    }

    /// The archive files of an attempt at `name`: its definition, the whole file, the object, the comparison and
    /// the compiler's message.
    pub(crate) fn files(
        &self,
        record: &AttemptRecord,
        object: Option<(&str, &[u8])>,
        message: Option<&str>,
    ) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        if let Some((start, end)) = self.span(&record.name) {
            files.insert(
                "function.c".to_string(),
                self.text.as_bytes()[start..end].to_vec(),
            );
        }
        let extension = self
            .file
            .rsplit_once('.')
            .map_or("c", |(_, e)| e)
            .to_ascii_lowercase();
        files.insert(format!("module.{extension}"), self.text.as_bytes().to_vec());
        if let Some((name, bytes)) = object {
            files.insert(
                format!("objects/{}", name.to_ascii_lowercase()),
                bytes.to_vec(),
            );
        }
        files.insert(
            "comparison.txt".to_string(),
            comparison_text(record).into_bytes(),
        );
        if let Some(message) = message.filter(|m| !m.trim().is_empty()) {
            files.insert(
                "messages/1.txt".to_string(),
                message.replace("\r\n", "\n").into_bytes(),
            );
        }
        files
    }
}

/// The comparison of an attempt as text (content only, no time: equal attempts archive once).
fn comparison_text(r: &AttemptRecord) -> String {
    let id = |v: Option<String>| v.unwrap_or_else(|| "-".into());
    let mut text = format!(
        "function: {} at {}\nresult: {}\nverdict: {}\ninstructions differing: {}\nbytes differing: {}\n",
        r.name,
        r.address,
        r.result.id(),
        id(r.verdict.map(|v| v.id().to_string())),
        id(r.instructions_differing.map(|n| n.to_string())),
        id(r.bytes_differing.map(|n| n.to_string())),
    );
    if !r.blockers.is_empty() {
        text.push_str(&format!("blockers: {}\n", r.blockers.join(", ")));
    }
    if !r.diagnosis.is_empty() {
        text.push_str(&format!("diagnosis: {}\n", r.diagnosis.join(", ")));
    }
    if let Some(message) = r.extra.get("message").and_then(Value::as_str) {
        text.push_str(&format!("message:\n{message}\n"));
    }
    text
}

/// Marks for archiving, per function, the identical attempts and the best compared other one.
pub(crate) fn mark_archived(tried: &mut [Tried]) {
    let mut best: HashMap<Address, (u64, usize)> = HashMap::new();
    for (i, t) in tried.iter_mut().enumerate() {
        match attempt_distance(&t.record) {
            Some(0) => t.archive = true,
            Some(d) => {
                let entry = best.entry(t.record.address).or_insert((d, i));
                if d < entry.0 {
                    *entry = (d, i);
                }
            }
            None => {}
        }
    }
    for (_, i) in best.into_values() {
        tried[i].archive = true;
    }
}

/// Records the attempts of one call (outside the workspace lock): an attempt equal to its function's last one is
/// dropped, the others are archived as marked and appended. Returns warnings (a store that cannot be written does
/// not fail the build, whose results are already recorded).
pub(crate) fn record_attempts(root: &Path, tried: Vec<Tried>) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut last: HashMap<Address, Option<AttemptRecord>> = HashMap::new();
    let mut records = Vec::new();
    for mut t in tried {
        let previous = last.entry(t.record.address).or_insert_with(|| {
            read_attempts(root, t.record.address)
                .ok()
                .and_then(|(mut records, _)| records.pop())
        });
        if previous.as_ref().is_some_and(|p| p.same_attempt(&t.record)) {
            continue;
        }
        if t.archive {
            let r = &t.record;
            let meta = json!({
                "address": r.address,
                "name": r.name,
                "file": r.file,
                "profile": r.profile,
                "flags": r.flags,
                "body_hash": r.body_hash,
                "context_hash": r.context_hash,
                "original_hash": r.original_hash,
            });
            match archive_save(root, &meta, &t.files) {
                Ok(id) => t.record.archive = Some(id),
                Err(e) => warnings.push(format!("{}: attempt not archived: {e}", r.name)),
            }
        }
        *previous = Some(t.record.clone());
        records.push(t.record);
    }
    if let Err(e) = append_attempts(root, &records) {
        warnings.push(format!("attempts not recorded: {e}"));
    }
    warnings
}

// -- the history tool ------------------------------------------------------------------------------------------

fn attempt_json(r: &AttemptRecord) -> Value {
    json!({
        "time": r.time,
        "origin": r.origin,
        "label": r.label,
        "actor": r.actor,
        "verdict": r.verdict,
        "result": r.result,
        "instructions_differing": r.instructions_differing,
        "bytes_differing": r.bytes_differing,
        "blockers": r.blockers,
        "archive": r.archive,
    })
}

fn limit_of(ws: &Workspace) -> u32 {
    ws.config
        .rebuild
        .as_ref()
        .and_then(|r| r.attempt_budget)
        .unwrap_or(DEFAULT_ATTEMPT_BUDGET)
}

/// The attempts of the function `target` (name or address): the newest `limit` first, the best one, the attempt
/// budget and the failures grouped by their first line. When there are more attempts than listed, or the listed
/// ones exceed `budget`, all of them go into a handle. The bench harness's own builds are left out.
pub fn history(
    root: &Path,
    target: &str,
    limit: usize,
    budget: Budget,
) -> Result<Response, FacadeError> {
    let session = Session::open(root)?;
    let function = function_of(&session, target)?;
    let (all, warnings) = read_attempts(root, function.address)?;
    let records: Vec<AttemptRecord> = all
        .into_iter()
        .filter(|r| r.actor.as_deref() != Some(HARNESS_ACTOR))
        .collect();
    let spent = attempt_budget(&records, limit_of(&session.workspace));

    let best = records
        .iter()
        .filter_map(|r| Some((attempt_distance(r)?, r)))
        .min_by_key(|(d, _)| *d);
    let best_text = match best {
        Some((0, _)) => "identical".to_string(),
        Some((u64::MAX, _)) => "differs".to_string(),
        Some((d, _)) => format!("{d} instructions differ"),
        None => "none compared".to_string(),
    };
    let parked = spent.parked() && !records.is_empty();

    let mut failures: Vec<(String, u32)> = Vec::new();
    for r in records
        .iter()
        .filter(|r| r.result == decovery_core::RebuildResult::Error)
    {
        let first = r
            .extra
            .get("message")
            .and_then(Value::as_str)
            .and_then(|m| m.lines().next())
            .unwrap_or("error")
            .to_string();
        match failures.iter_mut().find(|(m, _)| *m == first) {
            Some((_, n)) => *n += 1,
            None => failures.push((first, 1)),
        }
    }
    failures.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let newest: Vec<&AttemptRecord> = records.iter().rev().collect();
    let mut shown = Vec::new();
    let mut used = 0usize;
    for r in newest.iter().take(limit) {
        let v = attempt_json(r);
        let n = v.to_string().len();
        if used + n > budget.chars {
            break;
        }
        used += n;
        shown.push(v);
    }
    let mut handles = Vec::new();
    let mut summary = format!(
        "{}: {} attempts, best {best_text}, {}",
        function.name,
        records.len(),
        if parked { "parked" } else { "not parked" }
    );
    if shown.len() < records.len() {
        let text: String = newest
            .iter()
            .map(|r| format!("{}\n", attempt_json(r)))
            .collect();
        let mut handle = store_handle(root, "history-attempts", &text)?;
        handle.description = format!(
            "all {} attempts of {}, newest first, one JSON object per line",
            records.len(),
            function.name
        );
        summary.push_str(&format!("; all attempts: detail {}", handle.id));
        handles.push(handle);
    }
    let mut response = Response::new(
        summary,
        json!({
            "function": {"address": function.address.to_string(), "name": function.name},
            "attempts": shown,
            "attempts_total": records.len(),
            "best": best.map(|(d, r)| json!({
                "distance": d,
                "time": r.time,
                "archive": r.archive,
            })),
            "attempt_budget": {
                "own": spent.own,
                "since_progress": spent.since_progress,
                "limit": spent.limit,
                "parked": parked,
            },
            "failures": failures
                .iter()
                .map(|(message, count)| json!({"message": message, "count": count}))
                .collect::<Vec<_>>(),
            "warnings": warnings,
        }),
    );
    response.handles = handles;
    Ok(response)
}

/// The archived attempt `id` of the function `target`: its `function.c` and `comparison.txt` (a text over
/// `budget` goes into a handle).
pub fn history_archive(
    root: &Path,
    target: &str,
    id: &str,
    budget: Budget,
) -> Result<Response, FacadeError> {
    let session = Session::open(root)?;
    let function = function_of(&session, target)?;
    let entry = archive_load(root, id)?;
    if entry.meta["address"] != json!(function.address) {
        return Err(FacadeError::Invalid(format!(
            "archive entry {id} is not an attempt at {}",
            function.name
        )));
    }
    let mut handles = Vec::new();
    let mut text_of = |name: &str| -> Result<Value, FacadeError> {
        let Some(bytes) = entry.files.get(name) else {
            return Ok(Value::Null);
        };
        let text = String::from_utf8_lossy(bytes).into_owned();
        if text.chars().count() <= budget.chars {
            return Ok(json!(text));
        }
        let mut handle = store_handle(root, "history-archive", &text)?;
        handle.description = format!("{name} of archived attempt {id}");
        let shown: String = text.chars().take(budget.chars).collect();
        let marked = format!("{shown}… truncated; full text: detail {}\n", handle.id);
        handles.push(handle);
        Ok(json!(marked))
    };
    let function_c = text_of("function.c")?;
    let comparison = text_of("comparison.txt")?;
    let mut response = Response::new(
        format!("{}: archived attempt {id}", function.name),
        json!({
            "function": {"address": function.address.to_string(), "name": function.name},
            "archive": id,
            "meta": entry.meta,
            "files": entry.files.keys().collect::<Vec<_>>(),
            "function_c": function_c,
            "comparison": comparison,
        }),
    );
    response.handles = handles;
    Ok(response)
}
