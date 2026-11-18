//! Decompiler metadata stored next to a function's pseudo-C (`decompiler/decompile` v2, optional fields): per
//! C line the instruction ranges it came from, the signature and the variables. A function decompiled by an
//! older plugin has no metadata; every field is optional.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::store::{WorkspaceLock, write_atomic};
use crate::workspace::WorkspaceError;

const DECOMPILED_DIR: &str = "knowledge/analysis/decompiled";

/// Inclusive instruction address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: Address,
    pub end: Address,
}

/// One pseudo-C line (1-based into the stored `.c` text) and the ranges it came from (may be empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRanges {
    pub line: u32,
    #[serde(default)]
    pub ranges: Vec<AddressRange>,
}

/// A parameter or local of the decompiled function; every field may be missing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variable {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_use: Option<Address>,
}

/// The decompiler's prototype of the function.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<Variable>>,
}

impl Signature {
    /// `__cdecl int (int count [register:AX], ...)`; missing parts are left out.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for part in [&self.calling_convention, &self.return_type]
            .into_iter()
            .flatten()
        {
            out.push_str(part);
            out.push(' ');
        }
        let parameters: Vec<String> = self
            .parameters
            .iter()
            .flatten()
            .map(|p| {
                let mut s = [&p.data_type, &p.name]
                    .into_iter()
                    .flatten()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
                if let Some(storage) = &p.storage {
                    if !s.is_empty() {
                        s.push(' ');
                    }
                    s.push_str(&format!("[{storage}]"));
                }
                if s.is_empty() { "?".to_string() } else { s }
            })
            .collect();
        match &self.parameters {
            Some(_) => out.push_str(&format!("({})", parameters.join(", "))),
            None => out.push_str("(?)"),
        }
        out
    }
}

/// The metadata of one decompiled function.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<Vec<LineRanges>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<Variable>>,
}

/// Where an address lies within the line map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineHit {
    pub line: u32,
    /// `true`: inside a range of the line; `false`: the nearest mapped instruction before it.
    pub exact: bool,
}

/// Comparable position of an address; addresses of different kinds or static segments never compare.
fn position(a: Address) -> (u8, u32, u64) {
    match a {
        Address::Flat(x) => (0, 0, u64::from(x)),
        Address::Seg { .. } => (1, 0, a.linear().unwrap_or(0)),
        Address::Sel { segment, off } => (2, u32::from(segment), u64::from(off)),
    }
}

impl DecompileInfo {
    /// `true` when nothing is known.
    pub fn is_empty(&self) -> bool {
        self.lines.is_none() && self.signature.is_none() && self.variables.is_none()
    }

    /// The C line whose range holds `at`; otherwise the line of the nearest mapped range ending before `at`
    /// (frame setup and temporaries are often unmapped). Ties go to the lower line number.
    pub fn line_of(&self, at: Address) -> Option<LineHit> {
        let (kind, group, pos) = position(at);
        let mut before: Option<(u64, u32)> = None;
        for l in self.lines.iter().flatten() {
            for r in &l.ranges {
                let (sk, sg, start) = position(r.start);
                let (ek, eg, end) = position(r.end);
                if (sk, sg) != (kind, group) || (ek, eg) != (kind, group) || start > end {
                    continue;
                }
                if (start..=end).contains(&pos) {
                    return Some(LineHit {
                        line: l.line,
                        exact: true,
                    });
                }
                if end < pos
                    && before.is_none_or(|(e, line)| end > e || (end == e && l.line < line))
                {
                    before = Some((end, l.line));
                }
            }
        }
        before.map(|(_, line)| LineHit { line, exact: false })
    }

    /// The metadata stored for the function at `start`; `None` when there is none (or it cannot be read as
    /// metadata, which callers treat the same: an older plugin wrote no file).
    pub fn load(root: &Path, start: Address) -> Result<Option<DecompileInfo>, WorkspaceError> {
        let path = info_path(root, start);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(WorkspaceError::Io { path, source: e }),
        }
    }

    /// Stores the metadata of the function at `start`; empty metadata removes a stale file instead.
    pub fn save(
        &self,
        root: &Path,
        start: Address,
        _lock: &WorkspaceLock,
    ) -> Result<(), WorkspaceError> {
        let path = info_path(root, start);
        if self.is_empty() {
            return match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(WorkspaceError::Io { path, source: e }),
            };
        }
        let mut text = serde_json::to_string_pretty(self).map_err(|e| WorkspaceError::Io {
            path: path.clone(),
            source: std::io::Error::other(e),
        })?;
        text.push('\n');
        write_atomic(&path, text.as_bytes()).map_err(|e| WorkspaceError::Io { path, source: e })
    }
}

/// `knowledge/analysis/decompiled/<address>.json`, next to the `.c` file.
pub fn info_path(root: &Path, start: Address) -> PathBuf {
    root.join(DECOMPILED_DIR)
        .join(format!("{}.json", start.to_string().replace(':', "_")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(off: u16) -> Address {
        Address::Seg { seg: 0x1000, off }
    }

    fn info() -> DecompileInfo {
        let range = |a, b| AddressRange {
            start: seg(a),
            end: seg(b),
        };
        DecompileInfo {
            lines: Some(vec![
                LineRanges {
                    line: 1,
                    ranges: vec![],
                },
                LineRanges {
                    line: 3,
                    ranges: vec![range(0x14, 0x17)],
                },
                LineRanges {
                    line: 4,
                    ranges: vec![range(0x20, 0x22), range(0x30, 0x31)],
                },
            ]),
            ..DecompileInfo::default()
        }
    }

    #[test]
    fn inside_a_range_is_exact() {
        let hit = info().line_of(seg(0x21)).unwrap();
        assert_eq!(
            hit,
            LineHit {
                line: 4,
                exact: true
            }
        );
        assert_eq!(info().line_of(seg(0x30)).unwrap().line, 4);
    }

    #[test]
    fn unmapped_takes_the_nearest_mapped_before() {
        assert_eq!(
            info().line_of(seg(0x1A)),
            Some(LineHit {
                line: 3,
                exact: false
            })
        );
        assert_eq!(info().line_of(seg(0x40)).unwrap().line, 4);
    }

    #[test]
    fn before_every_range_or_other_kind_is_none() {
        assert_eq!(info().line_of(seg(0x10)), None);
        assert_eq!(info().line_of(Address::Flat(0x10021)), None);
        assert_eq!(DecompileInfo::default().line_of(seg(0x21)), None);
    }

    #[test]
    fn decodes_the_plugin_shape_and_tolerates_missing_fields() {
        let v: DecompileInfo = serde_json::from_str(
            r#"{"lines":[{"line":4,"ranges":[{"start":"seg:1000:0010","end":"seg:1000:0015"}]}],
                "signature":{"calling_convention":"__cdecl","return_type":"int",
                  "parameters":[{"name":"count","type":"int","storage":"register:AX"}]},
                "variables":[{"name":"saved","storage":"stack:-4","first_use":"seg:1000:0014"}]}"#,
        )
        .unwrap();
        assert_eq!(v.line_of(seg(0x12)).unwrap().line, 4);
        assert_eq!(
            v.signature.as_ref().unwrap().text(),
            "__cdecl int (int count [register:AX])"
        );
        assert_eq!(v.variables.unwrap()[0].first_use, Some(seg(0x14)));
        let empty: DecompileInfo = serde_json::from_str("{}").unwrap();
        assert!(empty.is_empty());
        assert_eq!(Signature::default().text(), "(?)");
    }
}
