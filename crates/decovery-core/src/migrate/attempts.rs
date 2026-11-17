//! Import Decomp's attempt memory and verified immutable archive without modifying the source.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{MigrateError, io, translate_address};
use crate::{
    Address, AttemptOrigin, AttemptRecord, RebuildResult, append_attempts, archive_save,
    read_attempts, read_rebuild,
};

/// Counts and diagnostics of an idempotent attempt-memory import.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AttemptMigrationReport {
    pub schema: u32,
    pub attempts: usize,
    pub archive_entries: usize,
    pub already_present: usize,
    pub skipped_lines: usize,
    pub skipped_archives: usize,
    /// Skipped lines or archive entries, with their path and line/byte position.
    pub skipped: Vec<String>,
    /// Non-fatal issues where the attempt itself was retained, or damage in existing destination shards.
    pub warnings: Vec<String>,
}

#[derive(Deserialize)]
struct LegacyAttempt {
    #[serde(rename = "adresse")]
    address: String,
    name: String,
    #[serde(rename = "rumpf_hash")]
    body_hash: String,
    #[serde(rename = "kontext_hash")]
    context_hash: String,
    #[serde(rename = "profil")]
    profile: String,
    #[serde(rename = "optionen")]
    flags: String,
    original_hash: String,
    #[serde(rename = "ergebnis")]
    result: String,
    #[serde(default, rename = "befehle_abweichend")]
    instructions_differing: Option<u32>,
    #[serde(default, rename = "bytes_abweichend")]
    bytes_differing: Option<u32>,
    #[serde(default, rename = "diagnose")]
    diagnosis: Vec<String>,
    #[serde(default, rename = "beschriftung")]
    label: String,
    #[serde(default, rename = "zeit")]
    time: String,
    #[serde(default, rename = "umformung")]
    transform: String,
    #[serde(default, rename = "archiv_id")]
    archive: String,
    #[serde(default, rename = "pruefung")]
    check: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Imports into an existing destination directory. The source (including its archive) is only read.
pub fn migrate_attempts(from: &Path, to: &Path) -> Result<AttemptMigrationReport, MigrateError> {
    let source = from.canonicalize().map_err(|e| io(from, e))?;
    let destination = to.canonicalize().map_err(|e| io(to, e))?;
    if destination.starts_with(&source) {
        return Err(MigrateError::Invalid {
            key: "destination".into(),
            value: "must be outside the source workspace".into(),
        });
    }
    if source.starts_with(destination.join("cache/legacy")) {
        return Err(MigrateError::Invalid {
            key: "source".into(),
            value: "the bridge shadow is not an attempt-memory source".into(),
        });
    }
    let lock_dir = destination.join("cache/migration/attempts");
    std::fs::create_dir_all(&lock_dir).map_err(|e| io(&lock_dir, e))?;
    let _lock = crate::attempts::lock_dir(&lock_dir)?;
    let mut report = AttemptMigrationReport {
        schema: 1,
        ..Default::default()
    };
    let archives = import_archives(&source, &destination, &mut report)?;
    let path = source.join("cache/nachbau/versuche.jsonl");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(io(&path, e)),
    };
    let file_by_address: HashMap<_, _> = read_rebuild(&destination)?
        .into_iter()
        .filter_map(|r| Some((r.address, r.file?)))
        .collect();
    let mut existing: HashMap<Address, HashSet<String>> = HashMap::new();
    let mut records = Vec::new();
    let mut offset = None;
    for (index, line) in bytes.split(|b| *b == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let place = format!("{}:{}", path.display(), index + 1);
        let parsed = match serde_json::from_slice::<LegacyAttempt>(line) {
            Ok(parsed) => parsed,
            Err(e) => {
                report.skipped_lines += 1;
                report.skipped.push(format!("{place}: {e}"));
                continue;
            }
        };
        let Some(address) = translate_address(&parsed.address) else {
            report.skipped_lines += 1;
            report
                .skipped
                .push(format!("{place}: unsupported address {}", parsed.address));
            continue;
        };
        if let std::collections::hash_map::Entry::Vacant(entry) = existing.entry(address) {
            let (previous, warnings) = read_attempts(&destination, address)?;
            report.warnings.extend(warnings);
            entry.insert(
                previous
                    .iter()
                    .filter_map(|r| r.extra.get("decomp_line")?.as_str().map(str::to_string))
                    .collect(),
            );
        }
        let key = blake3::hash(line).to_hex().to_string();
        let seen = existing.entry(address).or_default();
        if seen.contains(&key) {
            report.already_present += 1;
            continue;
        }
        let local_offset = match offset {
            Some(value) => value,
            None => {
                let value = current_offset()?;
                offset = Some(value);
                value
            }
        };
        if !parsed.archive.is_empty() && !archives.contains_key(&parsed.archive) {
            report.warnings.push(format!(
                "{place}: archive {} unavailable; attempt retained as evidence",
                parsed.archive
            ));
        }
        match convert_attempt(parsed, address, local_offset, &archives, &file_by_address) {
            Ok(mut record) => {
                record.extra.insert("decomp_line".into(), json!(key));
                seen.insert(key);
                records.push(record);
            }
            Err(reason) => {
                report.skipped_lines += 1;
                report.skipped.push(format!("{place}: {reason}"));
            }
        }
    }
    append_attempts(&destination, &records)?;
    report.attempts = records.len();
    Ok(report)
}

fn hash(text: &str) -> Result<String, String> {
    let (kind, value) = text
        .strip_prefix("sha256-text-v2-")
        .map_or(("decomp-sha256", text), |v| ("decomp-sha256-text-v2", v));
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid legacy hash {text:?}"));
    }
    Ok(format!("{kind}:{}", value.to_ascii_lowercase()))
}

fn convert_attempt(
    old: LegacyAttempt,
    address: Address,
    offset: i32,
    archives: &HashMap<String, (String, Option<String>)>,
    files: &HashMap<Address, String>,
) -> Result<AttemptRecord, String> {
    let result = match old.result.as_str() {
        "identisch" => RebuildResult::Identical,
        "abweichend" => RebuildResult::Differs,
        "fehler" => RebuildResult::Error,
        _ => return Err(format!("unsupported result {:?}", old.result)),
    };
    let automatic_label = old.label == "aktuell"
        || old.label.starts_with("Reihenfolge ")
        || old.label.contains("(Zeile ")
        || old.label.contains(" statt ");
    let origin = match old.transform.as_str() {
        "hand" => AttemptOrigin::Function,
        "" if !automatic_label => AttemptOrigin::Build,
        _ => AttemptOrigin::Variant,
    };
    let mut record = AttemptRecord::new(address, old.name, origin, result);
    record.time = if old.time.is_empty() {
        crate::now_utc()
    } else {
        to_utc(&old.time, offset)?
    };
    record.actor = Some("migrate".into());
    record.body_hash = hash(&old.body_hash)?;
    record.context_hash = hash(&old.context_hash)?;
    record.original_hash = hash(&old.original_hash)?;
    record.profile = old.profile;
    record.flags = old.flags;
    record.instructions_differing = old.instructions_differing;
    record.bytes_differing = old.bytes_differing;
    record.label = (!old.label.is_empty()).then_some(old.label);
    record.diagnosis = old
        .diagnosis
        .iter()
        .map(|id| {
            super::knowledge::DIAGNOSES
                .iter()
                .find(|(source, _)| source == id)
                .map_or("other", |(_, english)| *english)
                .to_string()
        })
        .collect();
    record.file = files.get(&address).cloned();
    if let Some((id, file)) = archives.get(&old.archive) {
        record.archive = Some(id.clone());
        if file.is_some() {
            record.file = file.clone();
        }
    }
    record
        .extra
        .insert("decomp_result".into(), json!(old.result));
    record.extra.insert("decomp_time".into(), json!(old.time));
    record
        .extra
        .insert("decomp_utc_offset_seconds".into(), json!(offset));
    record
        .extra
        .insert("decomp_diagnosis".into(), json!(old.diagnosis));
    if !old.archive.is_empty() {
        record
            .extra
            .insert("decomp_archive".into(), json!(old.archive));
    }
    if !old.check.is_empty() {
        record.extra.insert("decomp_check".into(), json!(old.check));
    }
    if !old.transform.is_empty() {
        record
            .extra
            .insert("transform".into(), json!(old.transform));
    }
    if !old.extra.is_empty() {
        record
            .extra
            .insert("decomp".into(), Value::Object(old.extra));
    }
    // No verdict: the imported result is Decomp's evidence, not a comparison by decovery.
    Ok(record)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn unlinked(path: &Path) -> Result<std::fs::Metadata, String> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("{}: byte 0: {e}", path.display()))?;
    if meta.file_type().is_symlink() || std::fs::read_link(path).is_ok() {
        return Err(format!(
            "{}: byte 0: links are not allowed in an archive entry",
            path.display()
        ));
    }
    Ok(meta)
}

fn disk_files(
    root: &Path,
    prefix: &str,
    depth: usize,
    found: &mut BTreeSet<String>,
) -> Result<(), String> {
    if depth > 128 {
        return Err(format!(
            "{}: byte 0: archive directory nesting exceeds 128",
            root.display()
        ));
    }
    unlinked(root)?;
    for entry in std::fs::read_dir(root).map_err(|e| format!("{}: byte 0: {e}", root.display()))? {
        let entry = entry.map_err(|e| format!("{}: byte 0: {e}", root.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{}: byte 0: non-UTF-8 name", root.display()))?;
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let meta = unlinked(&entry.path())?;
        if meta.is_dir() {
            disk_files(&entry.path(), &relative, depth + 1, found)?;
        } else if meta.is_file() {
            found.insert(relative);
        } else {
            return Err(format!(
                "{}: byte 0: not a regular file",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

struct LegacyArchive {
    meta: Map<String, Value>,
    files: BTreeMap<String, Vec<u8>>,
}

fn source_names<'a>(names: impl Iterator<Item = &'a String>) -> Result<(), String> {
    let names: Vec<_> = names.collect();
    crate::archive::check_names(names.iter().copied())?;
    let mut spellings = BTreeMap::new();
    for name in names {
        let mut prefix = String::new();
        for component in name.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if let Some(previous) = spellings.insert(prefix.to_lowercase(), prefix.clone())
                && previous != prefix
            {
                return Err(format!(
                    "conflicting archive path spellings: {previous:?} and {prefix:?}"
                ));
            }
        }
    }
    Ok(())
}

fn load_archive(base: &Path, id: &str) -> Result<LegacyArchive, String> {
    let dir = base.join(id);
    unlinked(&dir)?;
    let path = dir.join("manifest.json");
    unlinked(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: byte 0: {e}", path.display()))?;
    let invalid = |message: &str| format!("{}: byte 0: {message}", path.display());
    if sha256(&bytes) != id {
        return Err(invalid("manifest SHA-256 differs from archive id"));
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let fields = value
        .as_object()
        .ok_or_else(|| invalid("manifest is not an object"))?;
    if fields.len() != 3 || value["format"] != "decomp-versuchsarchiv/1" {
        return Err(invalid("unsupported archive manifest"));
    }
    let meta = value["meta"]
        .as_object()
        .ok_or_else(|| invalid("meta is not an object"))?
        .clone();
    let listed = value["dateien"]
        .as_object()
        .ok_or_else(|| invalid("file list is not an object"))?;
    source_names(listed.keys()).map_err(|e| invalid(&e))?;
    let mut found = BTreeSet::new();
    disk_files(&dir.join("dateien"), "", 0, &mut found)?;
    if found != listed.keys().cloned().collect() {
        return Err(invalid("file set differs from manifest"));
    }
    let mut files = BTreeMap::new();
    for (name, info) in listed {
        let path = dir.join("dateien").join(name);
        let invalid_file = |message: &str| format!("{}: byte 0: {message}", path.display());
        let info = info
            .as_object()
            .filter(|o| o.len() == 2)
            .ok_or_else(|| invalid_file("invalid file descriptor"))?;
        let expected = info
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .ok_or_else(|| invalid_file("invalid SHA-256"))?;
        let size = info
            .get("groesse")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_file("invalid size"))?;
        let bytes = std::fs::read(&path).map_err(|e| invalid_file(&e.to_string()))?;
        if bytes.len() as u64 != size || sha256(&bytes) != expected {
            return Err(invalid_file("file size or SHA-256 differs"));
        }
        files.insert(name.clone(), bytes);
    }
    Ok(LegacyArchive { meta, files })
}

fn import_archives(
    source: &Path,
    destination: &Path,
    report: &mut AttemptMigrationReport,
) -> Result<HashMap<String, (String, Option<String>)>, MigrateError> {
    let base = source.join("cache/nachbau/archiv");
    let entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(io(&base, e)),
    };
    let mut pending = BTreeMap::new();
    let mut ids = Vec::new();
    for entry in entries {
        ids.push(
            entry
                .map_err(|e| io(&base, e))?
                .file_name()
                .to_string_lossy()
                .into_owned(),
        );
    }
    ids.sort();
    for id in ids.into_iter().filter(|id| valid_id(id)) {
        match load_archive(&base, &id) {
            Ok(entry) => {
                pending.insert(id, entry);
            }
            Err(reason) => {
                report.skipped_archives += 1;
                report.skipped.push(reason);
            }
        }
    }
    let mut converted: HashMap<String, (String, Option<String>)> = HashMap::new();
    let archive_dir = destination.join(crate::ARCHIVE_DIR);
    let mut known_ids: BTreeSet<String> = match std::fs::read_dir(&archive_dir) {
        Ok(entries) => entries
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()
            .map_err(|e| io(&archive_dir, e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => return Err(io(&archive_dir, e)),
    };
    while !pending.is_empty() {
        let ready: Vec<_> = pending
            .iter()
            .filter(|(_, entry)| {
                entry
                    .meta
                    .get("vorgaenger")
                    .and_then(Value::as_str)
                    .is_none_or(|id| !pending.contains_key(id))
            })
            .map(|(id, _)| id.clone())
            .collect();
        if ready.is_empty() {
            for id in pending.keys() {
                report.skipped_archives += 1;
                report.skipped.push(format!(
                    "{}/{}: byte 0: cyclic archive predecessors",
                    base.display(),
                    id
                ));
            }
            break;
        }
        for old_id in ready {
            let Some(entry) = pending.remove(&old_id) else {
                continue;
            };
            let mut meta = Map::new();
            let mut unknown = Map::new();
            let mut unsupported = false;
            for (key, value) in entry.meta {
                let english = match key.as_str() {
                    "adresse" => {
                        if let Some(address) = value.as_str().and_then(translate_address) {
                            meta.insert("address".into(), json!(address));
                        } else {
                            report.skipped.push(format!(
                                "{}/{old_id}: byte 0: unsupported archive address {value}",
                                base.display()
                            ));
                            unsupported = true;
                        }
                        continue;
                    }
                    "vorgaenger" => {
                        if let Some((id, _)) = value.as_str().and_then(|id| converted.get(id)) {
                            meta.insert("predecessor".into(), json!(id));
                        } else if value.as_str().is_some_and(|s| !s.is_empty()) {
                            unknown.insert("predecessor".into(), value);
                        }
                        continue;
                    }
                    "funktion" => "name",
                    "datei" => "file",
                    "profil" => "profile",
                    "optionen" => "flags",
                    "messung" => "measurement",
                    "pruefung" => "check",
                    "beschriftung" => "label",
                    _ => {
                        unknown.insert(key, value);
                        continue;
                    }
                };
                meta.insert(english.into(), value);
            }
            if unsupported {
                report.skipped_archives += 1;
                continue;
            }
            meta.entry("file").or_insert(Value::Null);
            if !unknown.is_empty() {
                meta.insert("decomp".into(), Value::Object(unknown));
            }
            let objects = entry
                .files
                .keys()
                .filter(|n| n.starts_with("obj/") && n.ends_with(".obj"))
                .count();
            let files: BTreeMap<_, _> = entry
                .files
                .into_iter()
                .map(|(name, bytes)| {
                    let english = match name.as_str() {
                        "funktion.c" => "function.c".into(),
                        "modul.c" => "module.c".into(),
                        "vergleich.txt" => "comparison.txt".into(),
                        _ if name.starts_with("obj/") => {
                            if objects == 1 && name.ends_with(".obj") {
                                "object.obj".into()
                            } else {
                                name.replacen("obj/", "objects/", 1)
                            }
                        }
                        _ if name.starts_with("eingabe/") => name.replacen("eingabe/", "input/", 1),
                        _ if name.starts_with("meldungen/") => {
                            name.replacen("meldungen/", "messages/", 1)
                        }
                        _ => format!("decomp/{name}"),
                    };
                    (english, bytes)
                })
                .collect();
            let meta = Value::Object(meta);
            let file = meta["file"].as_str().map(str::to_string);
            let id = archive_save(destination, &meta, &files)?;
            if known_ids.insert(id.clone()) {
                report.archive_entries += 1;
            }
            converted.insert(old_id, (id, file));
        }
    }
    Ok(converted)
}

fn current_offset() -> Result<i32, MigrateError> {
    #[cfg(windows)]
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[int][DateTimeOffset]::Now.Offset.TotalSeconds",
        ])
        .output();
    #[cfg(not(windows))]
    let output = Command::new("date").arg("+%z").output();
    let invalid = |value: String| MigrateError::Invalid {
        key: "migration UTC offset".into(),
        value,
    };
    let output = output.map_err(|e| invalid(e.to_string()))?;
    if !output.status.success() {
        return Err(invalid(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    #[cfg(windows)]
    let offset = text
        .trim()
        .parse::<i32>()
        .map_err(|e| invalid(e.to_string()))?;
    #[cfg(not(windows))]
    let offset = {
        let text = text.trim();
        if text.len() != 5 || !text.is_ascii() {
            return Err(invalid(text.into()));
        }
        let hours = text[1..3]
            .parse::<i32>()
            .map_err(|e| invalid(e.to_string()))?;
        let minutes = text[3..5]
            .parse::<i32>()
            .map_err(|e| invalid(e.to_string()))?;
        if !matches!(&text[..1], "+" | "-") || hours > 23 || minutes > 59 {
            return Err(invalid(text.into()));
        }
        (hours * 3600 + minutes * 60) * if text.starts_with('-') { -1 } else { 1 }
    };
    if !(-86_400..=86_400).contains(&offset) {
        return Err(invalid(offset.to_string()));
    }
    Ok(offset)
}

fn to_utc(text: &str, offset: i32) -> Result<String, String> {
    let invalid = || format!("invalid local timestamp {text:?}");
    if !text.is_ascii() || !(text.len() == 19 || (text.len() == 20 && text.ends_with('Z'))) {
        return Err(invalid());
    }
    let b = text.as_bytes();
    if b[..19]
        .iter()
        .enumerate()
        .any(|(i, b)| !matches!(i, 4 | 7 | 10 | 13 | 16) && !b.is_ascii_digit())
    {
        return Err(invalid());
    }
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return Err(invalid());
    }
    let number = |start, end| text[start..end].parse::<i64>().map_err(|_| invalid());
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
        || hour < 0
        || minute < 0
        || second < 0
    {
        return Err(invalid());
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let days =
        era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5 + day - 1 - 719_468;
    if crate::analysis::civil_from_days(days) != (year, month, day) {
        return Err(invalid());
    }
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second
        - if text.ends_with('Z') {
            0
        } else {
            i64::from(offset)
        };
    let (year, month, day) = crate::analysis::civil_from_days(seconds.div_euclid(86_400));
    if !(1..=9999).contains(&year) {
        return Err(invalid());
    }
    let rest = seconds.rem_euclid(86_400);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn archive_directory_spellings_must_not_collide() {
        let names = ["Input/a.h".to_string(), "input/b.h".to_string()];
        assert!(super::source_names(names.iter()).is_err());
        let names = ["input/a.h".to_string(), "input/b.h".to_string()];
        assert!(super::source_names(names.iter()).is_ok());
    }

    #[test]
    fn local_times_use_the_migration_offset_and_cross_date_boundaries() {
        assert_eq!(
            super::to_utc("2026-01-01T00:15:02", 3600).unwrap(),
            "2025-12-31T23:15:02Z"
        );
        assert_eq!(
            super::to_utc("2024-03-01T00:15:00", 3600).unwrap(),
            "2024-02-29T23:15:00Z"
        );
        assert_eq!(
            super::to_utc("2026-11-17T12:00:00Z", 3600).unwrap(),
            "2026-11-17T12:00:00Z"
        );
        for text in [
            "2026-02-29T00:00:00",
            "2026-01-01T25:00:00",
            "later",
            "éééééééééé",
        ] {
            assert!(super::to_utc(text, 3600).is_err(), "{text}");
        }
    }
}
