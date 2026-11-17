//! Content-addressed archive of attempts (design 6): every distinct attempt (definition, module text, objects,
//! comparison, messages) is stored once under `cache/archive/<id>/`.
//!
//! An entry is `manifest.json` plus `files/<relative posix path>`. The manifest is canonical JSON (sorted keys, no
//! spaces, UTF-8) of `{"format", "meta", "files": {name: {"blake3", "size"}}}`; the id is the blake3 hex of the
//! manifest bytes. `meta` is content only (address, name, file, profile, flags, hashes): no time and nothing per
//! call, so saving content that already exists is a no-op that returns the existing id. The time lives in the
//! attempt record.
//!
//! File names are free relative paths, so an entry holds several objects (`objects/<name>`) and several compiler
//! messages (`messages/<n>.txt`). Conventional names of a build: `function.c`, `module.c`, `comparison.txt`,
//! `objects/<name>`, `messages/<n>.txt`. Every entry's `meta` records `file` (the function's source file), so a
//! bench copy can exclude all entries of that file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::address::Address;
use crate::workspace::WorkspaceError;

/// Directory of the archive, relative to the workspace root.
pub const ARCHIVE_DIR: &str = "cache/archive";
/// Version marker of the manifest (the archive's counterpart of `schema = 1`).
pub const ARCHIVE_FORMAT: &str = "decovery-attempt-archive/1";
const MANIFEST: &str = "manifest.json";
const FILES: &str = "files";
const TMP_PREFIX: &str = ".tmp-";
const RENAME_TRIES: u32 = 20;
const RENAME_WAIT: Duration = Duration::from_millis(50);

/// One archived attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveEntry {
    pub id: String,
    pub meta: Value,
    pub files: BTreeMap<String, Vec<u8>>,
}

fn invalid(path: &Path, detail: impl Into<String>) -> WorkspaceError {
    WorkspaceError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, detail.into()),
    }
}

fn io_error(path: &Path, source: std::io::Error) -> WorkspaceError {
    WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn json_error(path: &Path, source: serde_json::Error) -> WorkspaceError {
    WorkspaceError::Json {
        path: path.to_path_buf(),
        source: Box::new(source),
    }
}

fn archive_root(root: &Path) -> PathBuf {
    root.join(ARCHIVE_DIR)
}

fn is_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn entry_dir(root: &Path, id: &str) -> Result<PathBuf, WorkspaceError> {
    if is_id(id) {
        Ok(archive_root(root).join(id))
    } else {
        Err(invalid(
            &archive_root(root),
            format!("not an archive id: {id:?}"),
        ))
    }
}

fn is_reserved(stem: &str) -> bool {
    let lower = stem.to_ascii_lowercase();
    matches!(lower.as_str(), "con" | "prn" | "aux" | "nul")
        || (lower.len() == 4
            && (lower.starts_with("com") || lower.starts_with("lpt"))
            && matches!(lower.as_bytes()[3], b'1'..=b'9'))
}

/// Checks one archive file name; the error names the rule that failed.
fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty name".into());
    }
    if name.contains('\\') {
        return Err("backslash".into());
    }
    for segment in name.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("empty, `.` or `..` segment".into());
        }
        if segment.ends_with('.') || segment.ends_with(' ') {
            return Err(format!("trailing dot or space in segment {segment:?}"));
        }
        if let Some(c) = segment
            .chars()
            .find(|c| c.is_control() || "<>:\"|?*".contains(*c))
        {
            return Err(format!("forbidden character {c:?} in segment {segment:?}"));
        }
        let stem = segment.split('.').next().unwrap_or(segment);
        if is_reserved(stem) {
            return Err(format!("reserved DOS name {stem:?}"));
        }
    }
    Ok(())
}

/// Checks all names: each valid, no case-insensitive collision, no name that is also a directory of another.
pub(crate) fn check_names<'a>(names: impl Iterator<Item = &'a String>) -> Result<(), String> {
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    let mut lowered: Vec<(String, &str)> = Vec::new();
    for name in names {
        check_name(name).map_err(|e| format!("bad file name {name:?}: {e}"))?;
        let lower = name.to_lowercase();
        if let Some(other) = seen.insert(lower.clone(), name) {
            return Err(format!("names differ only by case: {other:?} and {name:?}"));
        }
        let segments: Vec<&str> = lower.split('/').collect();
        let mut prefix = String::new();
        for segment in &segments[..segments.len() - 1] {
            prefix.push_str(segment);
            dirs.insert(prefix.clone());
            prefix.push('/');
        }
        lowered.push((lower, name));
    }
    for (lower, name) in lowered {
        if dirs.contains(&lower) {
            return Err(format!("{name:?} is both a file and a directory"));
        }
    }
    Ok(())
}

/// Canonical JSON: `serde_json` maps are sorted (no `preserve_order`), output compact, UTF-8.
fn canonical(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

fn manifest_value(meta: &Value, files: &BTreeMap<String, Vec<u8>>) -> Value {
    let listed: serde_json::Map<String, Value> = files
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                json!({"blake3": blake3::hash(bytes).to_hex().to_string(), "size": bytes.len()}),
            )
        })
        .collect();
    json!({"format": ARCHIVE_FORMAT, "meta": meta, "files": listed})
}

fn file_path(dir: &Path, name: &str) -> PathBuf {
    name.split('/')
        .fold(dir.join(FILES), |path, segment| path.join(segment))
}

/// Saves an attempt and returns its id. Saving content that already exists keeps the existing entry (verified).
pub fn archive_save(
    root: &Path,
    meta: &Value,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<String, WorkspaceError> {
    let base = archive_root(root);
    check_names(files.keys()).map_err(|e| invalid(&base, e))?;
    let manifest = canonical(&manifest_value(meta, files)).map_err(|e| json_error(&base, e))?;
    let id = blake3::hash(&manifest).to_hex().to_string();
    let dir = base.join(&id);
    if dir.exists() {
        archive_load(root, &id)?;
        return Ok(id);
    }
    std::fs::create_dir_all(&base).map_err(|e| io_error(&base, e))?;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = base.join(format!(
        "{TMP_PREFIX}{}-{nanos:x}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        std::fs::create_dir_all(tmp.join(FILES))?;
        for (name, bytes) in files {
            let path = file_path(&tmp, name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, bytes)?;
        }
        std::fs::write(tmp.join(MANIFEST), &manifest)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(io_error(&tmp, e));
    }
    let mut last = None;
    for attempt in 1..=RENAME_TRIES {
        match std::fs::rename(&tmp, &dir) {
            Ok(()) => return Ok(id),
            Err(e) => {
                if dir.exists() {
                    // Another writer stored the same content first.
                    let _ = std::fs::remove_dir_all(&tmp);
                    archive_load(root, &id)?;
                    return Ok(id);
                }
                last = Some(e);
                std::thread::sleep(RENAME_WAIT * attempt);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Err(io_error(
        &dir,
        last.unwrap_or_else(|| std::io::Error::other("rename failed")),
    ))
}

fn collect_files(
    dir: &Path,
    prefix: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), WorkspaceError> {
    for item in std::fs::read_dir(dir).map_err(|e| io_error(dir, e))? {
        let item = item.map_err(|e| io_error(dir, e))?;
        let name = item.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = item.file_type().map_err(|e| io_error(&item.path(), e))?;
        if kind.is_dir() {
            collect_files(&item.path(), &rel, out)?;
        } else {
            out.insert(rel);
        }
    }
    Ok(())
}

/// Loads an entry and verifies id, manifest hash, file set, sizes and hashes.
pub fn archive_load(root: &Path, id: &str) -> Result<ArchiveEntry, WorkspaceError> {
    let dir = entry_dir(root, id)?;
    let manifest_path = dir.join(MANIFEST);
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| io_error(&manifest_path, e))?;
    if blake3::hash(&manifest_bytes).to_hex().as_str() != id {
        return Err(invalid(
            &manifest_path,
            "manifest hash does not match the id",
        ));
    }
    let manifest: Value =
        serde_json::from_slice(&manifest_bytes).map_err(|e| json_error(&manifest_path, e))?;
    if manifest["format"] != ARCHIVE_FORMAT {
        return Err(invalid(
            &manifest_path,
            format!("unsupported format {}", manifest["format"]),
        ));
    }
    let listed = manifest["files"]
        .as_object()
        .ok_or_else(|| invalid(&manifest_path, "`files` is not an object"))?;
    let mut on_disk = BTreeSet::new();
    let files_dir = dir.join(FILES);
    if files_dir.is_dir() {
        collect_files(&files_dir, "", &mut on_disk)?;
    }
    if let Some(extra) = on_disk.iter().find(|k| !listed.contains_key(*k)) {
        return Err(invalid(
            &file_path(&dir, extra),
            "file is not in the manifest",
        ));
    }
    let mut files = BTreeMap::new();
    for (name, info) in listed {
        check_name(name)
            .map_err(|e| invalid(&manifest_path, format!("bad file name {name:?}: {e}")))?;
        let path = file_path(&dir, name);
        let bytes = std::fs::read(&path).map_err(|e| io_error(&path, e))?;
        if info["size"].as_u64() != Some(bytes.len() as u64) {
            return Err(invalid(&path, "size differs from the manifest"));
        }
        if info["blake3"].as_str() != Some(blake3::hash(&bytes).to_hex().as_str()) {
            return Err(invalid(&path, "hash differs from the manifest"));
        }
        files.insert(name.clone(), bytes);
    }
    Ok(ArchiveEntry {
        id: id.to_string(),
        meta: manifest["meta"].clone(),
        files,
    })
}

/// Ids of the entries whose `meta.address` equals `address` (manifests only, sorted; `.tmp-*` is ignored).
pub fn archive_ids_for(root: &Path, address: Address) -> Result<Vec<String>, WorkspaceError> {
    let base = archive_root(root);
    let entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error(&base, e)),
    };
    let wanted = serde_json::to_value(address).map_err(|e| json_error(&base, e))?;
    let mut ids = Vec::new();
    for item in entries {
        let item = item.map_err(|e| io_error(&base, e))?;
        let name = item.file_name().to_string_lossy().into_owned();
        if !is_id(&name) {
            continue;
        }
        let path = item.path().join(MANIFEST);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_error(&path, e)),
        };
        let manifest: Value = serde_json::from_slice(&bytes).map_err(|e| json_error(&path, e))?;
        if manifest["meta"]["address"] == wanted {
            ids.push(name);
        }
    }
    ids.sort();
    Ok(ids)
}

/// Removes an entry (only for bench copies); a missing entry is fine.
pub fn archive_remove(root: &Path, id: &str) -> Result<(), WorkspaceError> {
    let dir = entry_dir(root, id)?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error(&dir, e)),
    }
}
