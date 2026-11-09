//! Typed views of `knowledge/rebuild.toml`, `knowledge/rebuild-program.toml` and `knowledge/references.toml` as
//! migrate writes them.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

use crate::address::Address;
use crate::knowledge::ClaimSource;
use crate::store::{WorkspaceLock, write_atomic};
use crate::workspace::{SCHEMA, WorkspaceError};

/// Path of the rebuild records relative to the workspace root.
pub const REBUILD_FILE: &str = "knowledge/rebuild.toml";
/// Path of the program record (the last `link`) relative to the workspace root.
pub const REBUILD_PROGRAM_FILE: &str = "knowledge/rebuild-program.toml";
/// Path of the reference records relative to the workspace root.
pub const REFERENCES_FILE: &str = "knowledge/references.toml";

/// Outcome of rebuilding one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RebuildResult {
    Identical,
    Differs,
    Error,
    /// A value this version does not know; kept so the record is not lost.
    ///
    /// Not written back; writers refuse it.
    #[serde(other)]
    Other,
}

/// decovery's verdict on a rebuilt function (design 4); set only by decovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum VerdictId {
    Identical,
    Equivalent,
    Differs,
    Unchecked,
    /// A value this version does not know; kept so the record is not lost.
    ///
    /// Not written back; writers refuse it.
    #[serde(other)]
    Other,
}

impl VerdictId {
    /// The serialized id.
    pub fn id(self) -> &'static str {
        match self {
            VerdictId::Identical => "identical",
            VerdictId::Equivalent => "equivalent",
            VerdictId::Differs => "differs",
            VerdictId::Unchecked => "unchecked",
            VerdictId::Other => "other",
        }
    }
}

impl RebuildResult {
    /// The serialized id.
    pub fn id(self) -> &'static str {
        match self {
            RebuildResult::Identical => "identical",
            RebuildResult::Differs => "differs",
            RebuildResult::Error => "error",
            RebuildResult::Other => "other",
        }
    }
}

/// Why a rebuilt function is not identical, as stored: a kebab-case kind (`bytes-differ`, `wrong-absolute-ref`,
/// `inline-assembly`, ...), the offset in the function and a count where the kind has them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BlockerRecord {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

impl BlockerRecord {
    pub fn new(kind: impl Into<String>, at: Option<u32>, count: Option<u32>) -> Self {
        BlockerRecord {
            kind: kind.into(),
            at,
            count,
        }
    }
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The last rebuild of one function.
///
/// `result` is Decomp's byte rule, `verdict` and `blockers` are decovery's. Zero metrics are not written. Keys this
/// version does not know are kept in `extra` and written back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RebuildRecord {
    pub address: Address,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    pub result: RebuildResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<VerdictId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<BlockerRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub equal: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gaps: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub differing: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refs_ok: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refs_wrong: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refs_unchecked: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub instructions_differing: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub padding_bytes: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub alignment: u32,
    #[serde(
        default,
        deserialize_with = "number_or_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub first_difference: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnoses: Vec<String>,
    /// blake3 of the function's bytes in the object, 16 hex characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// The last equivalence check (`[function.equivalence]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equivalence: Option<Equivalence>,
    /// Keys this version does not know.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl RebuildRecord {
    /// The state shown in counts and filters: decovery's verdict when the record has one (equivalent counts as
    /// differing, its bytes differ; unchecked as an error), else Decomp's result. `Other` for unknown values.
    pub fn effective_result(&self) -> RebuildResult {
        match self.verdict {
            Some(VerdictId::Identical) => RebuildResult::Identical,
            Some(VerdictId::Equivalent | VerdictId::Differs) => RebuildResult::Differs,
            Some(VerdictId::Unchecked) => RebuildResult::Error,
            Some(VerdictId::Other) => RebuildResult::Other,
            None => self.result,
        }
    }

    /// A record with only address, name and result set.
    pub fn new(address: Address, name: impl Into<String>, result: RebuildResult) -> Self {
        RebuildRecord {
            address,
            name: name.into(),
            file: None,
            compiler: None,
            flags: None,
            result,
            verdict: None,
            blockers: Vec::new(),
            message: None,
            bytes: 0,
            equal: 0,
            gaps: 0,
            differing: 0,
            refs_ok: 0,
            refs_wrong: 0,
            refs_unchecked: 0,
            instructions_differing: 0,
            padding_bytes: 0,
            alignment: 0,
            first_difference: None,
            diagnoses: Vec::new(),
            code_hash: None,
            date: None,
            equivalence: None,
            extra: toml::Table::new(),
        }
    }
}

/// The last equivalence check of a rebuilt function. The fields shown in output are typed; the others (reasons,
/// code, case counts by kind) are kept in `extra`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Equivalence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, rename = "static", skip_serializing_if = "Option::is_none")]
    pub static_check: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cases: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// `first_difference` is an integer in practice, but the schema allows text (`"12"`, `"0x0C"`).
fn number_or_text<'de, D: Deserializer<'de>, T: TryFrom<u64>>(d: D) -> Result<Option<T>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Number(u64),
        Text(String),
    }
    let n = match Option::<Raw>::deserialize(d)? {
        None => return Ok(None),
        Some(Raw::Number(n)) => n,
        Some(Raw::Text(t)) => {
            let t = t.trim();
            match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => t.parse(),
            }
            .map_err(serde::de::Error::custom)?
        }
    };
    T::try_from(n)
        .map(Some)
        .map_err(|_| serde::de::Error::custom(format!("{n} is out of range")))
}

/// How a reference transfers control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReferenceKind {
    Jump,
    Call,
    /// A value this version does not know; kept so the record is not lost.
    ///
    /// Not written back; writers refuse it.
    #[serde(other)]
    Other,
}

/// A reference from one address to another that analysis alone cannot see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Reference {
    pub from: Address,
    pub to: Address,
    pub kind: ReferenceKind,
    #[serde(default)]
    pub source: Option<ClaimSource>,
    #[serde(default)]
    pub evidence: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RebuildFile {
    schema: u32,
    #[serde(default)]
    function: Vec<RebuildRecord>,
}

#[derive(Deserialize)]
struct ReferencesFile {
    schema: u32,
    #[serde(default)]
    reference: Vec<Reference>,
}

/// Reads `knowledge/rebuild.toml`; empty when the file does not exist.
pub fn read_rebuild(root: &Path) -> Result<Vec<RebuildRecord>, WorkspaceError> {
    let path = root.join(REBUILD_FILE);
    Ok(read_optional::<RebuildFile>(&path, |f| f.schema)?
        .map(|f| f.function)
        .unwrap_or_default())
}

/// Reads `knowledge/references.toml`; empty when the file does not exist.
pub fn read_references(root: &Path) -> Result<Vec<Reference>, WorkspaceError> {
    let path = root.join(REFERENCES_FILE);
    Ok(read_optional::<ReferencesFile>(&path, |f| f.schema)?
        .map(|f| f.reference)
        .unwrap_or_default())
}

/// Writes `knowledge/rebuild.toml`: records sorted by address (stable), LF line ends, deterministic. Refuses a
/// record with an unknown result or verdict.
pub fn save_rebuild(
    root: &Path,
    records: &[RebuildRecord],
    _lock: &WorkspaceLock,
) -> Result<(), WorkspaceError> {
    let path = root.join(REBUILD_FILE);
    for r in records {
        let unknown = [
            (r.result == RebuildResult::Other).then_some("result"),
            (r.verdict == Some(VerdictId::Other)).then_some("verdict"),
        ];
        if let Some(field) = unknown.into_iter().flatten().next() {
            return Err(WorkspaceError::UnknownValue {
                file: path,
                detail: format!("rebuild record at {} has an unknown {field}", r.address),
            });
        }
    }
    let mut function = records.to_vec();
    function.sort_by_key(|r| r.address);
    let text = toml::to_string(&RebuildFile {
        schema: SCHEMA,
        function,
    })
    .map_err(|e| WorkspaceError::Io {
        path: path.clone(),
        source: std::io::Error::other(e),
    })?;
    write_atomic(&path, text.as_bytes()).map_err(|source| WorkspaceError::Io { path, source })
}

/// Merges the records of a build into the stored ones. Records of `built_files` are replaced by `new`; with `all`
/// (every source was built), records of files not in `existing_files` are dropped. A new record keeps the old
/// record's `equivalence` when its `code_hash` equals the old one or the old record has none, and the old
/// record's unknown keys. Sorted by address.
pub fn merge_rebuild(
    old: Vec<RebuildRecord>,
    new: Vec<RebuildRecord>,
    built_files: &[String],
    all: bool,
    existing_files: &[String],
) -> Vec<RebuildRecord> {
    let listed =
        |file: &Option<String>, list: &[String]| file.as_ref().is_some_and(|f| list.contains(f));
    let mut previous: BTreeMap<Address, RebuildRecord> = BTreeMap::new();
    let mut merged: BTreeMap<Address, RebuildRecord> = BTreeMap::new();
    for r in old {
        let replaced = listed(&r.file, built_files);
        let vanished = all && !listed(&r.file, existing_files);
        if !replaced && !vanished {
            merged.insert(r.address, r.clone());
        }
        previous.entry(r.address).or_insert(r);
    }
    for mut r in new {
        if let Some(before) = previous.get(&r.address) {
            if r.equivalence.is_none()
                && (before.code_hash.is_none() || before.code_hash == r.code_hash)
            {
                r.equivalence = before.equivalence.clone();
            }
            for (key, value) in &before.extra {
                r.extra.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
        merged.insert(r.address, r);
    }
    merged.into_values().collect()
}

/// Bytes of the original image by origin (Decomp's `anteile`): each byte counts once, for the first of c (rebuilt
/// identical from C), library, assembly, other functions; the rest is data and gaps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Shares {
    #[serde(default)]
    pub c: u64,
    #[serde(default)]
    pub library: u64,
    #[serde(default)]
    pub assembly: u64,
    #[serde(default)]
    pub other_functions: u64,
    #[serde(default)]
    pub rest: u64,
}

/// Rebuilt functions used in a linked program (LE: inserted into the original image).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Used {
    #[serde(default)]
    pub functions: u64,
    #[serde(default)]
    pub bytes: u64,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

/// The last `link`: the whole program against the original file (`[program]` in `knowledge/rebuild-program.toml`).
/// `first_difference` is a file offset. Keys this version does not know are kept in `extra` and written back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProgramRecord {
    pub result: RebuildResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub original_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub rebuilt_bytes: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub differing: u64,
    #[serde(
        default,
        deserialize_with = "number_or_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub first_difference: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnosis: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares: Option<Shares>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<Used>,
    /// Keys this version does not know.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl ProgramRecord {
    /// A record with only the result set.
    pub fn new(result: RebuildResult) -> Self {
        ProgramRecord {
            result,
            compiler: None,
            original_bytes: 0,
            rebuilt_bytes: 0,
            differing: 0,
            first_difference: None,
            message: None,
            date: None,
            diagnosis: Vec::new(),
            shares: None,
            used: None,
            extra: toml::Table::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ProgramFile {
    schema: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    program: Option<ProgramRecord>,
}

/// Reads `knowledge/rebuild-program.toml`; `None` when the file or its `[program]` does not exist.
pub fn read_program_record(root: &Path) -> Result<Option<ProgramRecord>, WorkspaceError> {
    let path = root.join(REBUILD_PROGRAM_FILE);
    Ok(read_optional::<ProgramFile>(&path, |f| f.schema)?.and_then(|f| f.program))
}

/// Writes `knowledge/rebuild-program.toml` atomically and deterministically (LF line ends). Refuses a record with
/// an unknown result.
pub fn save_program_record(
    root: &Path,
    record: &ProgramRecord,
    _lock: &WorkspaceLock,
) -> Result<(), WorkspaceError> {
    let path = root.join(REBUILD_PROGRAM_FILE);
    if record.result == RebuildResult::Other {
        return Err(WorkspaceError::UnknownValue {
            file: path,
            detail: "program record has an unknown result".into(),
        });
    }
    let text = toml::to_string(&ProgramFile {
        schema: SCHEMA,
        program: Some(record.clone()),
    })
    .map_err(|e| WorkspaceError::Io {
        path: path.clone(),
        source: std::io::Error::other(e),
    })?;
    write_atomic(&path, text.as_bytes()).map_err(|source| WorkspaceError::Io { path, source })
}

fn read_optional<T: for<'de> Deserialize<'de>>(
    path: &Path,
    schema: impl Fn(&T) -> u32,
) -> Result<Option<T>, WorkspaceError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(WorkspaceError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let file: T = toml::from_str(&text).map_err(|source| WorkspaceError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if schema(&file) != SCHEMA {
        return Err(WorkspaceError::Schema {
            path: path.to_path_buf(),
            found: schema(&file),
        });
    }
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_with(file: &str, text: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("knowledge")).unwrap();
        std::fs::write(dir.path().join(file), text).unwrap();
        dir
    }

    #[test]
    fn reads_rebuild_records() {
        let dir = root_with(
            REBUILD_FILE,
            r#"schema = 1

[[function]]
address = "flat:00010010"
name = "choose"
file = "main.c"
compiler = "watcom-9.5"
flags = "-ox"
result = "differs"
bytes = 448
equal = 360
gaps = 88
differing = 2
refs_ok = 7
refs_wrong = 1
refs_unchecked = 3
instructions_differing = 4
padding_bytes = 2
alignment = 16
first_difference = 12
diagnoses = ["operand-swap", "constant"]
date = "2026-10-30"
[function.equivalence]
verdict = "unchecked"

[[function]]
address = "flat:00010400"
name = "tiny"
result = "identical"
"#,
        );
        let records = read_rebuild(dir.path()).unwrap();
        assert_eq!(records.len(), 2);
        let r = &records[0];
        assert_eq!(r.address, Address::Flat(0x10010));
        assert_eq!(r.result, RebuildResult::Differs);
        assert_eq!(r.file.as_deref(), Some("main.c"));
        assert_eq!((r.bytes, r.equal, r.gaps, r.differing), (448, 360, 88, 2));
        assert_eq!((r.refs_ok, r.refs_wrong, r.refs_unchecked), (7, 1, 3));
        assert_eq!(
            (r.instructions_differing, r.padding_bytes, r.alignment),
            (4, 2, 16)
        );
        assert_eq!(r.first_difference, Some(12));
        assert_eq!(r.diagnoses, ["operand-swap", "constant"]);
        assert_eq!(r.date.as_deref(), Some("2026-10-30"));
        let e = r.equivalence.as_ref().unwrap();
        assert_eq!(e.verdict.as_deref(), Some("unchecked"));
        assert_eq!((e.static_check.as_deref(), e.cases), (None, None));
        let t = &records[1];
        assert_eq!(t.result, RebuildResult::Identical);
        assert_eq!((t.bytes, t.first_difference), (0, None));
        assert!(t.diagnoses.is_empty() && t.file.is_none() && t.message.is_none());
        assert!(t.equivalence.is_none());
    }

    #[test]
    fn reads_references() {
        let dir = root_with(
            REFERENCES_FILE,
            r#"schema = 1

[[reference]]
from = "flat:00010379"
to = "seg:0010:0020"
kind = "jump"
source = "runtime"
evidence = "seen 16x"

[[reference]]
from = "flat:00010379"
to = "flat:000103FC"
kind = "call"
"#,
        );
        let refs = read_references(dir.path()).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].kind, ReferenceKind::Jump);
        assert_eq!(
            refs[0].to,
            Address::Seg {
                seg: 0x10,
                off: 0x20
            }
        );
        assert_eq!(refs[0].source, Some(ClaimSource::Runtime));
        assert_eq!(refs[0].evidence.as_deref(), Some("seen 16x"));
        assert_eq!(refs[1].kind, ReferenceKind::Call);
        assert_eq!(refs[1].source, None);
    }

    #[test]
    fn rebuild_record_with_unknown_result_is_read() {
        let dir = root_with(
            REBUILD_FILE,
            r#"schema = 1

[[function]]
address = "flat:00010010"
name = "a"
result = "identical"

[[function]]
address = "flat:00010020"
name = "b"
result = "exploded"

[[function]]
address = "flat:00010030"
name = "c"
result = "differs"
"#,
        );
        let records = read_rebuild(dir.path()).unwrap();
        let results: Vec<_> = records.iter().map(|r| r.result).collect();
        assert_eq!(
            results,
            [
                RebuildResult::Identical,
                RebuildResult::Other,
                RebuildResult::Differs
            ]
        );
        assert_eq!(records[1].name, "b");
    }

    #[test]
    fn reference_with_unknown_kind_and_source_is_read() {
        let dir = root_with(
            REFERENCES_FILE,
            r#"schema = 1

[[reference]]
from = "flat:00000001"
to = "flat:00000002"
kind = "table"
source = "oracle"

[[reference]]
from = "flat:00000003"
to = "flat:00000004"
kind = "call"
source = "human"
"#,
        );
        let refs = read_references(dir.path()).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].kind, ReferenceKind::Other);
        assert_eq!(refs[0].source, Some(ClaimSource::Other));
        assert_eq!(refs[1].kind, ReferenceKind::Call);
        assert_eq!(refs[1].source, Some(ClaimSource::Human));
    }

    #[test]
    fn absent_files_read_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_rebuild(dir.path()).unwrap().is_empty());
        assert!(read_references(dir.path()).unwrap().is_empty());
    }

    fn lock(dir: &Path) -> WorkspaceLock {
        std::fs::write(
            dir.join(crate::workspace::CONFIG_FILE),
            "schema = 1\n[target]\nfile = \"t.exe\"\nsha256 = \"00\"\nformat = \"mz\"\nprocessor = \"x86\"\n",
        )
        .unwrap();
        crate::Workspace::open(dir)
            .unwrap()
            .lock(std::time::Duration::from_secs(1))
            .unwrap()
    }

    fn record(at: u32, file: &str, result: RebuildResult) -> RebuildRecord {
        let mut r = RebuildRecord::new(Address::Flat(at), format!("f{at:x}"), result);
        r.file = Some(file.to_string());
        r
    }

    const WITH_UNKNOWN_KEYS: &str = r#"schema = 1

[[function]]
address = "flat:00010010"
name = "a"
file = "main.c"
result = "differs"
verdict = "differs"
bytes = 12
differing = 2
first_difference = "0x4"
future_key = "kept"

[[function.blockers]]
kind = "bytes-differ"
count = 2

[function.equivalence]
verdict = "equivalent_tested"
reasons = ["same calls"]
code = "abc"
"#;

    #[test]
    fn save_round_trip_is_byte_stable_and_keeps_unknown_keys() {
        let dir = root_with(REBUILD_FILE, WITH_UNKNOWN_KEYS);
        let lock = lock(dir.path());
        let records = read_rebuild(dir.path()).unwrap();
        assert_eq!(records[0].extra["future_key"].as_str(), Some("kept"));
        assert_eq!(records[0].first_difference, Some(4));
        assert_eq!(records[0].verdict, Some(VerdictId::Differs));
        assert_eq!(
            records[0].blockers,
            [BlockerRecord::new("bytes-differ", None, Some(2))]
        );
        let eq = records[0].equivalence.as_ref().unwrap();
        assert_eq!(eq.extra["code"].as_str(), Some("abc"));
        save_rebuild(dir.path(), &records, &lock).unwrap();
        let first = std::fs::read_to_string(dir.path().join(REBUILD_FILE)).unwrap();
        assert!(first.contains("future_key = \"kept\""), "{first}");
        assert!(first.contains("first_difference = 4"), "{first}");
        assert!(first.contains("reasons = [\"same calls\"]"), "{first}");
        assert!(!first.contains("equal = 0") && !first.contains('\r'));
        let again = read_rebuild(dir.path()).unwrap();
        assert_eq!(again, records);
        save_rebuild(dir.path(), &again, &lock).unwrap();
        let second = std::fs::read_to_string(dir.path().join(REBUILD_FILE)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn save_refuses_unknown_result() {
        let dir = tempfile::tempdir().unwrap();
        let lock = lock(dir.path());
        let r = record(0x10, "a.c", RebuildResult::Other);
        let err = save_rebuild(dir.path(), &[r], &lock).unwrap_err();
        assert!(matches!(err, WorkspaceError::UnknownValue { .. }), "{err}");
    }

    #[test]
    fn merge_replaces_built_files_and_keeps_others() {
        let old = vec![
            record(0x10, "a.c", RebuildResult::Identical),
            record(0x20, "a.c", RebuildResult::Identical),
            record(0x30, "b.c", RebuildResult::Differs),
            record(0x40, "gone.c", RebuildResult::Differs),
        ];
        let new = vec![record(0x10, "a.c", RebuildResult::Differs)];
        let files = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let merged = merge_rebuild(old.clone(), new.clone(), &files(&["a.c"]), false, &[]);
        let at: Vec<_> = merged.iter().map(|r| (r.address, r.result)).collect();
        assert_eq!(
            at,
            [
                (Address::Flat(0x10), RebuildResult::Differs),
                (Address::Flat(0x30), RebuildResult::Differs),
                (Address::Flat(0x40), RebuildResult::Differs),
            ]
        );
        let all = merge_rebuild(
            old,
            new,
            &files(&["a.c", "b.c"]),
            true,
            &files(&["a.c", "b.c"]),
        );
        let at: Vec<_> = all.iter().map(|r| r.address).collect();
        assert_eq!(at, [Address::Flat(0x10)]);
    }

    #[test]
    fn merge_keeps_equivalence_only_for_same_code() {
        let mut before = record(0x10, "a.c", RebuildResult::Differs);
        before.equivalence = Some(Equivalence {
            verdict: Some("equivalent_tested".into()),
            ..Equivalence::default()
        });
        before.extra.insert("note".into(), "x".into());
        let files = ["a.c".to_string()];
        let mut same = record(0x10, "a.c", RebuildResult::Differs);
        same.code_hash = Some("11".into());
        // the old record has no code hash: kept
        let merged = merge_rebuild(vec![before.clone()], vec![same.clone()], &files, false, &[]);
        assert!(merged[0].equivalence.is_some());
        assert_eq!(merged[0].extra["note"].as_str(), Some("x"));
        before.code_hash = Some("11".into());
        let merged = merge_rebuild(vec![before.clone()], vec![same.clone()], &files, false, &[]);
        assert!(merged[0].equivalence.is_some());
        same.code_hash = Some("22".into());
        let merged = merge_rebuild(vec![before], vec![same], &files, false, &[]);
        assert!(merged[0].equivalence.is_none());
    }
}
