//! Typed views of `knowledge/rebuild.toml` and `knowledge/references.toml` as migrate writes them.

use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

use crate::address::Address;
use crate::knowledge::ClaimSource;
use crate::workspace::{SCHEMA, WorkspaceError};

/// Path of the rebuild records relative to the workspace root.
pub const REBUILD_FILE: &str = "knowledge/rebuild.toml";
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
    #[serde(other)]
    Other,
}

/// The last rebuild of one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RebuildRecord {
    pub address: Address,
    pub name: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub compiler: Option<String>,
    #[serde(default)]
    pub flags: Option<String>,
    pub result: RebuildResult,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub bytes: u32,
    #[serde(default)]
    pub equal: u32,
    #[serde(default)]
    pub gaps: u32,
    #[serde(default)]
    pub differing: u32,
    #[serde(default)]
    pub refs_ok: u32,
    #[serde(default)]
    pub refs_wrong: u32,
    #[serde(default)]
    pub refs_unchecked: u32,
    #[serde(default)]
    pub instructions_differing: u32,
    #[serde(default)]
    pub padding_bytes: u32,
    #[serde(default)]
    pub alignment: u32,
    #[serde(default, deserialize_with = "number_or_text")]
    pub first_difference: Option<u32>,
    #[serde(default)]
    pub diagnoses: Vec<String>,
    #[serde(default)]
    pub date: Option<String>,
}

/// `first_difference` is an integer in practice, but the schema allows text (`"12"`, `"0x0C"`).
fn number_or_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Number(u32),
        Text(String),
    }
    match Option::<Raw>::deserialize(d)? {
        None => Ok(None),
        Some(Raw::Number(n)) => Ok(Some(n)),
        Some(Raw::Text(t)) => {
            let t = t.trim();
            let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => t.parse(),
            };
            parsed.map(Some).map_err(serde::de::Error::custom)
        }
    }
}

/// How a reference transfers control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReferenceKind {
    Jump,
    Call,
    /// A value this version does not know; kept so the record is not lost.
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

#[derive(Deserialize)]
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
        let t = &records[1];
        assert_eq!(t.result, RebuildResult::Identical);
        assert_eq!((t.bytes, t.first_difference), (0, None));
        assert!(t.diagnoses.is_empty() && t.file.is_none() && t.message.is_none());
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
}
