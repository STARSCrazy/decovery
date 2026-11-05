//! Function files: paths, rendering and (re)writing.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use decovery_core::{Address, Analysis, AnalyzedFunction, WorkspaceLock, write_atomic};

use super::{Change, Context, FUNCTIONS_DIR, OUTPUT_DIR, OutputReport, functions_dir, header};
use crate::resolve::in_segment;
use crate::{FacadeError, Session};

/// Body prefix Decomp wrote for failed decompilations; imported verbatim.
const FAILED_DE: &str = "/* Dekompilieren fehlgeschlagen: ";
const FAILED_EN: &str = "/* decompilation failed: ";
const NO_DISASSEMBLY_DE: &str = "/* Disassembly:\n(nicht verfügbar)\n*/";
const NO_DISASSEMBLY_EN: &str = "/* Disassembly:\n(not available)\n*/";

/// Header plus stored pseudo-C of the function starting at `start`.
pub fn render_function(session: &Session, start: Address) -> Result<String, FacadeError> {
    let cx = Context::new(session)?;
    let f = function(&cx, start)?;
    render(&cx, f)
}

/// Path of the function file, relative to the workspace root.
pub fn function_path(session: &Session, start: Address) -> PathBuf {
    relative_path(session, start, &session.name_of(start).name)
}

/// Writes the file of the single function starting at `start` (and removes other files of that address).
pub fn write_function(
    session: &Session,
    start: Address,
    _lock: &WorkspaceLock,
) -> Result<OutputReport, FacadeError> {
    let cx = Context::new(session)?;
    let mut report = OutputReport::default();
    emit_function(&cx, start, &mut report)?;
    Ok(report)
}

/// Regenerates every function file and the index files; removes files of addresses that are no functions.
pub fn write_all(session: &Session, _lock: &WorkspaceLock) -> Result<OutputReport, FacadeError> {
    let cx = Context::new(session)?;
    let report = write_every_function(&cx)?;
    super::indices::write_indices(&cx)?;
    Ok(report)
}

/// Regenerates the function files a change affects (port of Decomp's `_betroffene`) and the index files.
pub fn write_affected(
    session: &Session,
    change: &Change,
    _lock: &WorkspaceLock,
) -> Result<OutputReport, FacadeError> {
    let cx = Context::new(session)?;
    let root = &session.workspace.root;
    let mut report = OutputReport::default();
    match change {
        Change::Types | Change::References => {
            report = write_every_function(&cx)?;
        }
        Change::Renamed { at, old } => {
            if cx.index.function_at(*at).is_some() {
                let old_path = root.join(relative_path(session, *at, old));
                let new_path = root.join(relative_path(session, *at, &cx.display_name(*at)));
                if old_path != new_path && remove_file(&old_path)? {
                    report.removed += 1;
                }
            }
            for start in affected(&cx, *at, true) {
                emit_function(&cx, start, &mut report)?;
            }
        }
        Change::Symbol { at } => {
            for start in affected(&cx, *at, false) {
                emit_function(&cx, start, &mut report)?;
            }
        }
    }
    super::indices::write_indices(&cx)?;
    Ok(report)
}

/// Functions whose file shows something of `at`: the containing function, functions accessing `at` as a
/// global, and for a renamed function start also its callers and callees.
fn affected(cx: &Context<'_>, at: Address, renamed: bool) -> BTreeSet<Address> {
    let mut out = BTreeSet::new();
    if let Some(f) = cx.index.function_containing(at) {
        out.insert(f.start);
        if renamed && f.start == at {
            out.extend(cx.callers(at).iter().map(|e| e.caller));
            out.extend(cx.callees(at).iter().map(|e| e.callee));
        }
    }
    out.extend(
        cx.session
            .analysis
            .data_accesses
            .iter()
            .filter(|g| g.address == at)
            .map(|g| g.function),
    );
    out
}

fn function<'a>(cx: &Context<'a>, start: Address) -> Result<&'a AnalyzedFunction, FacadeError> {
    cx.index.function_at(start).ok_or_else(|| {
        FacadeError::Invalid(format!("{start} is not the start of an analyzed function"))
    })
}

fn render(cx: &Context<'_>, f: &AnalyzedFunction) -> Result<String, FacadeError> {
    Ok(cx.header(f) + &body(cx, f)?)
}

/// The stored pseudo-C; Decomp's German failure text is shown in English.
fn body(cx: &Context<'_>, f: &AnalyzedFunction) -> Result<String, FacadeError> {
    match Analysis::decompiled(&cx.session.workspace.root, f.start)? {
        Some(code) => match code.strip_prefix(FAILED_DE) {
            Some(rest) => Ok(format!(
                "{FAILED_EN}{}",
                rest.replacen(NO_DISASSEMBLY_DE, NO_DISASSEMBLY_EN, 1)
            )),
            None => Ok(code),
        },
        None => {
            let error = f.decompile_error.as_deref().unwrap_or("no pseudo-C stored");
            Ok(format!("{FAILED_EN}{} */\n", header::safe(error)))
        }
    }
}

/// `<address>_<name>.c`; a name that is no C identifier is replaced by the default name, so knowledge text
/// never reaches the file system as a path.
fn file_name(start: Address, name: &str) -> String {
    if super::is_identifier(name) {
        format!("{}_{name}.c", address_stem(start))
    } else {
        format!(
            "{}_{}.c",
            address_stem(start),
            crate::session::default_name(start)
        )
    }
}

fn address_stem(start: Address) -> String {
    start.to_string().replace(':', "_")
}

fn relative_path(session: &Session, start: Address, name: &str) -> PathBuf {
    Path::new(OUTPUT_DIR)
        .join(FUNCTIONS_DIR)
        .join(folder_for(session, start))
        .join(file_name(start, name))
}

/// Path relative to `output/` (used for links in `index.md`).
pub(crate) fn link_path(cx: &Context<'_>, start: Address) -> String {
    format!(
        "{FUNCTIONS_DIR}/{}/{}",
        folder_for(cx.session, start),
        file_name(start, &cx.display_name(start))
    )
}

/// `seg_XXXX` for real-mode addresses, else the configured segment containing `at`, else `unknown`.
fn folder_for(session: &Session, at: Address) -> String {
    if let Address::Seg { seg, .. } = at {
        return format!("seg_{seg:04X}");
    }
    session
        .workspace
        .config
        .target
        .segments
        .iter()
        .find(|s| in_segment(s, at))
        .map_or_else(|| "unknown".to_string(), |s| s.name.clone())
}

/// File offset of `at` if its segment has file bytes there (Decomp's `Speicherkarte.zu_datei`).
pub(crate) fn file_offset(session: &Session, at: Address) -> Option<u64> {
    let seg = session
        .workspace
        .config
        .target
        .segments
        .iter()
        .find(|s| in_segment(s, at))?;
    let base = seg.file_offset?;
    let delta = match (seg.start, at) {
        (Address::Sel { off: s, .. }, Address::Sel { off, .. }) => u64::from(off - s),
        (start, at) => at.linear()? - start.linear()?,
    };
    let in_file = seg.file_length.map_or(seg.length, |n| n.min(seg.length));
    (delta < in_file).then_some(base + delta)
}

fn write_every_function(cx: &Context<'_>) -> Result<OutputReport, FacadeError> {
    let mut report = OutputReport::default();
    let mut keep = HashSet::new();
    for f in cx.functions() {
        keep.insert(emit_function(cx, f.start, &mut report)?);
    }
    let dir = functions_dir(&cx.session.workspace.root);
    for path in c_files(&dir)? {
        if !keep.contains(&path) && remove_file(&path)? {
            report.removed += 1;
        }
    }
    Ok(report)
}

/// Writes one function file if its content changed, then removes other files of the same address in its folder.
fn emit_function(
    cx: &Context<'_>,
    start: Address,
    report: &mut OutputReport,
) -> Result<PathBuf, FacadeError> {
    let f = function(cx, start)?;
    let root = &cx.session.workspace.root;
    let path = root.join(relative_path(cx.session, start, &cx.display_name(start)));
    let text = render(cx, f)?;
    if write_if_changed(&path, &text)? {
        report.written += 1;
    }
    let prefix = format!("{}_", address_stem(start));
    if let Some(dir) = path.parent() {
        for other in c_files_in(dir)? {
            let is_same_address = other
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix));
            if is_same_address && other != path && remove_file(&other)? {
                report.removed += 1;
            }
        }
    }
    Ok(path)
}

/// Writes `text` atomically unless the file already holds exactly these bytes; `true` if written.
pub(crate) fn write_if_changed(path: &Path, text: &str) -> Result<bool, FacadeError> {
    if std::fs::read(path).is_ok_and(|old| old == text.as_bytes()) {
        return Ok(false);
    }
    write_atomic(path, text.as_bytes()).map_err(|source| FacadeError::Output {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

fn remove_file(path: &Path) -> Result<bool, FacadeError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(FacadeError::Output {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_dir(dir: &Path) -> Result<Vec<std::fs::DirEntry>, FacadeError> {
    let io = |source| FacadeError::Output {
        path: dir.to_path_buf(),
        source,
    };
    match std::fs::read_dir(dir) {
        Ok(entries) => entries.map(|e| e.map_err(io)).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(io(e)),
    }
}

/// `.c` files directly in `dir`.
fn c_files_in(dir: &Path) -> Result<Vec<PathBuf>, FacadeError> {
    Ok(read_dir(dir)?
        .into_iter()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "c"))
        .collect())
}

/// `.c` files in the segment folders below `dir`.
fn c_files(dir: &Path) -> Result<Vec<PathBuf>, FacadeError> {
    let mut out = Vec::new();
    for entry in read_dir(dir)? {
        let path = entry.path();
        if path.is_dir() {
            out.extend(c_files_in(&path)?);
        }
    }
    Ok(out)
}
