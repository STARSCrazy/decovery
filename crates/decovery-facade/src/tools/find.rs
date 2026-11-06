//! `find`: lists and searches over functions, names, strings, generated code and cross references.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use decovery_core::{AccessKind, Address, AnalysisIndex, Confidence, RebuildResult};
use serde_json::{Value, json};

use crate::output::{FUNCTIONS_DIR, OUTPUT_DIR};
use crate::{Budget, FacadeError, Response, Session, resolve, store_handle};

/// Longest `text` of a code row.
const CODE_TEXT_CHARS: usize = 200;
/// Default number of rows.
pub const DEFAULT_LIMIT: usize = 100;
const OUTPUT_MISSING: &str = "output/ not generated; run `decovery show` or analyze";

/// What to search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FindWhat {
    Functions,
    Names,
    Strings,
    Code,
    Xrefs,
}

/// Restricts the function list; all given filters must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FunctionFilter {
    Named,
    Unnamed,
    Assumed,
    Confirmed,
    NotTried,
    Identical,
    Differs,
}

/// Order of the function list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum FunctionSort {
    /// By address.
    #[default]
    Address,
    /// Most distinct callers first.
    Callers,
    /// Largest first.
    Size,
}

/// A `find` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindQuery {
    pub what: FindWhat,
    /// Case-insensitive substring; `*` matches any run. For `Xrefs` the target (name or address).
    pub pattern: Option<String>,
    /// `Functions` only.
    pub filter: Vec<FunctionFilter>,
    /// `Functions` only.
    pub sort: FunctionSort,
    pub limit: usize,
}

impl FindQuery {
    /// A query for `what` without pattern or filters and the default limit.
    pub fn new(what: FindWhat) -> Self {
        FindQuery {
            what,
            pattern: None,
            filter: Vec::new(),
            sort: FunctionSort::Address,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// Runs `query`. Rows beyond `query.limit` or `budget` are cut from `data.items`; the full result is stored as
/// a handle of kind `find-results`.
pub fn find(session: &Session, query: &FindQuery, budget: Budget) -> Result<Response, FacadeError> {
    if query.what != FindWhat::Functions
        && (!query.filter.is_empty() || query.sort != FunctionSort::Address)
    {
        return Err(FacadeError::Invalid(
            "filters and sorting apply to functions only".into(),
        ));
    }
    let pattern = query.pattern.as_deref().map(Pattern::new);
    match query.what {
        FindWhat::Functions => finish(
            session,
            "functions",
            functions(session, query, pattern),
            query,
            budget,
        ),
        FindWhat::Names => finish(session, "names", names(session, pattern), query, budget),
        FindWhat::Strings => finish(session, "strings", strings(session, pattern), query, budget),
        FindWhat::Code => {
            let Some(pattern) = pattern else {
                return Err(FacadeError::Invalid("find code needs a pattern".into()));
            };
            match code(&session.workspace.root, &pattern) {
                Some(hits) => {
                    let mut response = finish(session, "code lines", hits.rows, query, budget)?;
                    if !hits.unreadable.is_empty() {
                        response.summary.push_str(&format!(
                            "; {} files could not be read",
                            hits.unreadable.len()
                        ));
                        response.data["unreadable"] = json!(hits.unreadable);
                    }
                    Ok(response)
                }
                None => Ok(Response::new(
                    OUTPUT_MISSING,
                    json!({ "total": 0, "items": [] }),
                )),
            }
        }
        FindWhat::Xrefs => {
            let Some(target) = query.pattern.as_deref() else {
                return Err(FacadeError::Invalid("find xrefs needs a target".into()));
            };
            xrefs(session, target, query.limit, budget)
        }
    }
}

struct Row {
    json: Value,
    line: String,
}

fn row(json: Value, cells: &[String]) -> Row {
    Row {
        json,
        line: cells
            .iter()
            .map(|c| {
                c.replace('\t', "\\t")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
            })
            .collect::<Vec<_>>()
            .join("\t"),
    }
}

fn finish(
    session: &Session,
    noun: &str,
    rows: Vec<Row>,
    query: &FindQuery,
    budget: Budget,
) -> Result<Response, FacadeError> {
    let total = rows.len();
    let mut used = 0usize;
    let mut shown = 0usize;
    for r in rows.iter().take(query.limit) {
        let n = r.json.to_string().chars().count();
        if used + n > budget.chars {
            break;
        }
        used += n;
        shown += 1;
    }
    let items: Vec<Value> = rows[..shown].iter().map(|r| r.json.clone()).collect();
    let mut handles = Vec::new();
    let summary = if shown < total {
        let text: String = rows.iter().map(|r| format!("{}\n", r.line)).collect();
        let mut handle = store_handle(&session.workspace.root, "find-results", &text)?;
        handle.description = format!("all {total} {noun}, one per line");
        let summary = format!("{shown} of {total} {noun}; full list: detail {}", handle.id);
        handles.push(handle);
        summary
    } else {
        format!("{total} {noun}")
    };
    let mut response = Response::new(summary, json!({ "total": total, "items": items }));
    response.handles = handles;
    Ok(response)
}

fn kebab_confidence(c: Confidence) -> &'static str {
    match c {
        Confidence::Confirmed => "confirmed",
        _ => "assumed",
    }
}

struct Entry {
    start: Address,
    name: String,
    size: u32,
    callers: usize,
    status: &'static str,
    rebuild: &'static str,
}

fn functions(session: &Session, query: &FindQuery, pattern: Option<Pattern>) -> Vec<Row> {
    let index = session.analysis.index();
    let rebuild: HashMap<Address, RebuildResult> = session
        .rebuild
        .iter()
        .map(|r| (r.address, r.effective_result()))
        .collect();
    let mut entries: Vec<Entry> = Vec::new();
    for f in &session.analysis.functions {
        let name = session.name_of(f.start).name;
        if pattern.as_ref().is_some_and(|p| !p.is_match(&name)) {
            continue;
        }
        let status = session
            .symbol_at(f.start)
            .map_or("unnamed", |s| kebab_confidence(s.confidence));
        let rebuild = match rebuild.get(&f.start) {
            None => "not-tried",
            Some(RebuildResult::Identical) => "identical",
            Some(RebuildResult::Differs) => "differs",
            Some(RebuildResult::Error) => "error",
            Some(_) => "other",
        };
        let keep = query.filter.iter().all(|flt| match flt {
            FunctionFilter::Named => status != "unnamed",
            FunctionFilter::Unnamed => status == "unnamed",
            FunctionFilter::Assumed => status == "assumed",
            FunctionFilter::Confirmed => status == "confirmed",
            FunctionFilter::NotTried => rebuild == "not-tried",
            FunctionFilter::Identical => rebuild == "identical",
            FunctionFilter::Differs => rebuild == "differs",
        });
        if !keep {
            continue;
        }
        entries.push(Entry {
            start: f.start,
            name,
            size: f.body_size,
            callers: distinct_callers(&index, f.start),
            status,
            rebuild,
        });
    }
    match query.sort {
        FunctionSort::Address => entries.sort_by_key(|e| e.start),
        FunctionSort::Callers => entries.sort_by_key(|e| (std::cmp::Reverse(e.callers), e.start)),
        FunctionSort::Size => entries.sort_by_key(|e| (std::cmp::Reverse(e.size), e.start)),
    }
    entries
        .into_iter()
        .map(|e| {
            row(
                json!({
                    "address": e.start.to_string(),
                    "name": e.name,
                    "size": e.size,
                    "callers": e.callers,
                    "status": e.status,
                    "rebuild": e.rebuild,
                }),
                &[
                    e.start.to_string(),
                    e.name,
                    e.size.to_string(),
                    e.callers.to_string(),
                    e.status.to_string(),
                    e.rebuild.to_string(),
                ],
            )
        })
        .collect()
}

pub(crate) fn distinct_callers(index: &AnalysisIndex<'_>, f: Address) -> usize {
    let mut callers: Vec<Address> = index.callers(f).iter().map(|e| e.caller).collect();
    callers.sort();
    callers.dedup();
    callers.len()
}

fn names(session: &Session, pattern: Option<Pattern>) -> Vec<Row> {
    let mut names: BTreeMap<Address, String> = BTreeMap::new();
    for s in &session.workspace.symbols {
        if s.confidence != Confidence::Refuted && !s.name.is_empty() {
            names.entry(s.address).or_insert_with(|| s.name.clone());
        }
    }
    for f in &session.analysis.functions {
        names.entry(f.start).or_insert_with(|| {
            f.provider_name
                .clone()
                .unwrap_or_else(|| session.name_of(f.start).name)
        });
    }
    names
        .into_iter()
        .filter(|(_, name)| pattern.as_ref().is_none_or(|p| p.is_match(name)))
        .map(|(at, name)| address_text_row(at, name))
        .collect()
}

fn strings(session: &Session, pattern: Option<Pattern>) -> Vec<Row> {
    let mut strings: Vec<_> = session.analysis.strings.iter().collect();
    strings.sort_by_key(|s| s.address);
    strings
        .into_iter()
        .filter(|s| pattern.as_ref().is_none_or(|p| p.is_match(&s.text)))
        .map(|s| address_text_row(s.address, s.text.clone()))
        .collect()
}

fn address_text_row(at: Address, text: String) -> Row {
    row(
        json!({ "address": at.to_string(), "text": text }),
        &[at.to_string(), text],
    )
}

/// Result of a code search: rows and the files that could not be read.
struct CodeHits {
    rows: Vec<Row>,
    unreadable: Vec<String>,
}

/// Matching lines of the generated function files; `None` when they were not generated. Files are read
/// lossily (invalid UTF-8 becomes U+FFFD); symbolic links and junctions are not followed.
fn code(root: &Path, pattern: &Pattern) -> Option<CodeHits> {
    let dir = root.join(OUTPUT_DIR).join(FUNCTIONS_DIR);
    if !dir.is_dir() {
        return None;
    }
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    collect_c_files(root, &dir, &mut files, &mut unreadable);
    files.sort();
    let mut rows = Vec::new();
    for (name, path) in files {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                unreadable.push(name);
                continue;
            }
        };
        let content = String::from_utf8_lossy(&bytes);
        for (i, line) in content.lines().enumerate() {
            if pattern.is_match(line) {
                let text: String = line.trim().chars().take(CODE_TEXT_CHARS).collect();
                let number = i + 1;
                rows.push(row(
                    json!({ "file": name, "line": number, "text": text }),
                    &[name.clone(), number.to_string(), text],
                ));
            }
        }
    }
    unreadable.sort();
    Some(CodeHits { rows, unreadable })
}

/// Collects `(relative path with '/', path)` of the `.c` files below `dir`; directories and files that
/// cannot be listed go to `unreadable`.
fn collect_c_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
    unreadable: &mut Vec<String>,
) {
    let relative = |p: &Path| {
        p.strip_prefix(root)
            .unwrap_or(p)
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => {
            unreadable.push(relative(dir));
            return;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else {
            unreadable.push(relative(dir));
            continue;
        };
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            unreadable.push(relative(&path));
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_c_files(root, &path, out, unreadable);
        } else if path.extension().is_some_and(|e| e == "c") {
            out.push((relative(&path), path));
        }
    }
}

// --- xrefs ---------------------------------------------------------------------------------------------

fn xrefs(
    session: &Session,
    target: &str,
    limit: usize,
    budget: Budget,
) -> Result<Response, FacadeError> {
    let (address, is_function) = match resolve(session, target) {
        Ok(r) => (r.function, true),
        Err(FacadeError::NotInFunction { address, .. }) => (address, false),
        Err(e) => return Err(e),
    };
    let index = session.analysis.index();
    let name = if is_function || session.symbol_at(address).is_some() {
        session.name_of(address).name
    } else {
        let short = crate::session::default_name(address);
        format!("DAT_{}", short.trim_start_matches("fun_").to_lowercase())
    };
    let site = |at: Address| site_text(session, &index, at);

    let mut callers: Vec<_> = index.callers(address).to_vec();
    callers.sort_by_key(|e| (e.caller, e.site));
    callers.dedup_by_key(|e| (e.caller, e.site));
    let called_by: Vec<Value> = callers
        .iter()
        .map(|e| {
            json!({
                "address": e.caller.to_string(),
                "name": session.name_of(e.caller).name,
                "site": site(e.site),
            })
        })
        .collect();
    let mut callees: Vec<_> = index.callees(address).to_vec();
    callees.sort_by_key(|e| (e.site, e.callee));
    callees.dedup_by_key(|e| (e.site, e.callee));
    let calls: Vec<Value> = callees
        .iter()
        .map(|e| {
            json!({
                "address": e.callee.to_string(),
                "name": session.name_of(e.callee).name,
                "site": site(e.site),
            })
        })
        .collect();
    let mut accesses: Vec<_> = session
        .analysis
        .data_accesses
        .iter()
        .filter(|a| a.address == address)
        .map(|a| (a.function, matches!(a.kind, AccessKind::Write)))
        .collect();
    accesses.sort();
    accesses.dedup();
    let accesses: Vec<Value> = accesses
        .into_iter()
        .map(|(f, write)| {
            json!({
                "function": f.to_string(),
                "name": session.name_of(f).name,
                "kind": if write { "write" } else { "read" },
            })
        })
        .collect();
    let mut strings: Vec<_> = index.strings_used_by(address);
    strings.extend(
        session
            .analysis
            .strings
            .iter()
            .filter(|s| s.address == address),
    );
    strings.sort_by_key(|s| s.address);
    strings.dedup_by_key(|s| s.address);
    let strings: Vec<Value> = strings
        .into_iter()
        .map(|s| json!({ "address": s.address.to_string(), "text": s.text }))
        .collect();

    let counts = (called_by.len(), calls.len(), accesses.len(), strings.len());
    let build = |n: usize| {
        let cut = |v: &[Value]| v[..v.len().min(n)].to_vec();
        json!({
            "address": address.to_string(),
            "name": name,
            "called_by": cut(&called_by),
            "calls": cut(&calls),
            "accesses": cut(&accesses),
            "strings": cut(&strings),
        })
    };
    let mut n = limit;
    let mut data = build(n);
    while data.to_string().chars().count() > budget.chars && n > 0 {
        n /= 2;
        data = build(n);
    }
    let longest = counts.0.max(counts.1).max(counts.2).max(counts.3);
    let mut summary = format!(
        "{name} at {address}: {} callers, {} calls, {} accesses, {} strings",
        counts.0, counts.1, counts.2, counts.3
    );
    let mut handles = Vec::new();
    if n < longest {
        let full = build(usize::MAX);
        let text = serde_json::to_string_pretty(&full)
            .map_err(|e| FacadeError::Invalid(format!("cannot serialize result: {e}")))?
            + "\n";
        let mut handle = store_handle(&session.workspace.root, "find-results", &text)?;
        handle.description = format!("all cross references of {name}");
        summary.push_str(&format!(
            "; first {n} of each list shown, full result: detail {}",
            handle.id
        ));
        handles.push(handle);
    }
    let mut response = Response::new(summary, data);
    response.handles = handles;
    Ok(response)
}

/// `<function>+0x<offset>` for a site inside an analyzed function, else the address.
fn site_text(session: &Session, index: &AnalysisIndex<'_>, at: Address) -> String {
    match index.function_containing(at) {
        Some(f) => format!(
            "{}+0x{:x}",
            session.name_of(f.start).name,
            offset_in(f.start, at)
        ),
        None => at.to_string(),
    }
}

fn offset_in(start: Address, at: Address) -> u64 {
    match (start, at) {
        (Address::Sel { off: a, .. }, Address::Sel { off: b, .. }) => {
            u64::from(b.saturating_sub(a))
        }
        _ => match (start.linear(), at.linear()) {
            (Some(a), Some(b)) => b.saturating_sub(a),
            _ => 0,
        },
    }
}

// --- pattern -------------------------------------------------------------------------------------------

/// Case-insensitive match where `*` stands for any run of characters. The pattern may match anywhere in the
/// text, with or without `*` (Decomp's `search`).
struct Pattern {
    parts: Vec<String>,
}

impl Pattern {
    fn new(pattern: &str) -> Self {
        Pattern {
            parts: pattern
                .to_lowercase()
                .split('*')
                .map(str::to_string)
                .collect(),
        }
    }

    fn is_match(&self, text: &str) -> bool {
        let text = text.to_lowercase();
        let mut window = text.as_str();
        for part in &self.parts {
            match window.find(part.as_str()) {
                Some(at) => window = &window[at + part.len()..],
                None => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::Pattern;

    fn m(pattern: &str, text: &str) -> bool {
        Pattern::new(pattern).is_match(text)
    }

    #[test]
    fn substring_without_star() {
        assert!(m("load", "game_LoadLevel"));
        assert!(m("", "anything"));
        assert!(!m("save", "game_LoadLevel"));
    }

    #[test]
    fn star_at_the_ends_is_redundant() {
        assert!(m("fun_*", "fun_0001"));
        assert!(m("*level", "game_LoadLevel2"));
        assert!(m("*", ""));
        assert!(m("*load*", "game_LoadLevel"));
    }

    #[test]
    fn pattern_with_star_matches_inside_text() {
        assert!(m("foo*bar", "x = foo(a) + bar;"));
        assert!(m("fun_*", "a_fun_1"));
        assert!(!m("foo*bar", "bar foo"));
    }

    #[test]
    fn star_in_the_middle_and_overlap() {
        assert!(m("a*c", "abc"));
        assert!(m("a*b*c", "a--b--c"));
        assert!(!m("a*b*c", "a--c--b"));
        assert!(!m("ab*ba", "aba"));
        assert!(m("ab*ba", "abba"));
        assert!(m("ab*ba", "xabbay"));
        assert!(m("a**c", "ac"));
    }

    #[test]
    fn case_is_ignored_for_non_ascii_too() {
        assert!(m("STRA\u{df}E", "die stra\u{df}e"));
        assert!(m("\u{c4}*", "\u{e4}rger"));
    }
}
