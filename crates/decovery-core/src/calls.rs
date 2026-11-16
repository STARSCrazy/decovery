//! The tool-call log: one line per MCP tool call and per CLI command, kept per month under `cache/calls/`.
//!
//! No tool the agent sees reads it; the bench derives its usage counts from it and the parity documents count
//! bridge use from it (ADR 0008 step 3).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::analysis::now_utc;
use crate::attempts::lock_dir;
use crate::workspace::{SCHEMA, WorkspaceError};

/// Directory of the call log, relative to the workspace root.
pub const CALLS_DIR: &str = "cache/calls";

/// One tool call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CallRecord {
    pub schema: u32,
    /// RFC 3339 UTC, to the second: when the call started.
    pub time: String,
    /// The MCP tool or CLI command (`build`, `search`, `history`, ...).
    pub tool: String,
    /// The deep operation, search strategy or check (`registers`, `chain`, `equivalence`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// The function or symbol the call is about, as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Wall time of the call.
    pub seconds: f64,
    /// `ok`, `error`, `refused` (the call was not run: bad parameters, unknown tool, a limit) or `cancelled`.
    pub outcome: String,
    /// `cli`, `mcp` or the value of `DECOVERY_ACTOR`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Builds the call ran: 1 for a build, the number of variants for a build with variants, 0 otherwise.
    #[serde(default)]
    pub builds: u32,
    /// Searches the call ran (Decomp's search through the bridge).
    #[serde(default)]
    pub searches: u32,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl CallRecord {
    /// A record of `tool` started now with outcome `ok`; fill the rest.
    pub fn new(tool: impl Into<String>) -> Self {
        CallRecord {
            schema: SCHEMA,
            time: now_utc(),
            tool: tool.into(),
            operation: None,
            target: None,
            seconds: 0.0,
            outcome: "ok".into(),
            actor: None,
            builds: 0,
            searches: 0,
            extra: serde_json::Map::new(),
        }
    }
}

/// The month file of a record time (`2026-11-17T08:15:02Z` → `cache/calls/2026-11.jsonl`).
fn month_path(root: &Path, time: &str) -> PathBuf {
    let month = time.get(..7).filter(|m| {
        m.len() == 7 && m.as_bytes()[4] == b'-' && m.bytes().filter(u8::is_ascii_digit).count() == 6
    });
    root.join(CALLS_DIR)
        .join(format!("{}.jsonl", month.unwrap_or("unknown")))
}

/// Appends `record` to `cache/calls/<yyyy-mm>.jsonl` (the month of its time) under the lock `cache/calls/.lock`.
pub fn append_call(root: &Path, record: &CallRecord) -> Result<(), WorkspaceError> {
    let dir = root.join(CALLS_DIR);
    std::fs::create_dir_all(&dir).map_err(|source| WorkspaceError::Io {
        path: dir.clone(),
        source,
    })?;
    let path = month_path(root, &record.time);
    let mut line = serde_json::to_string(record).map_err(|e| WorkspaceError::Json {
        path: path.clone(),
        source: Box::new(e),
    })?;
    line.push('\n');
    let _lock = lock_dir(&dir)?;
    let io = |source| WorkspaceError::Io {
        path: path.clone(),
        source,
    };
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .map_err(io)?;
    file.write_all(line.as_bytes()).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_go_to_their_month_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut record = CallRecord::new("build");
        record.time = "2026-11-17T08:15:02Z".into();
        record.builds = 3;
        record
            .extra
            .insert("future".into(), serde_json::json!(true));
        append_call(dir.path(), &record).unwrap();
        append_call(dir.path(), &record).unwrap();
        let text =
            std::fs::read_to_string(dir.path().join(CALLS_DIR).join("2026-11.jsonl")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let back: CallRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(back, record);
        assert_eq!(back.schema, 1);
    }

    #[test]
    fn a_malformed_time_goes_to_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let mut record = CallRecord::new("status");
        record.time = "later".into();
        append_call(dir.path(), &record).unwrap();
        assert!(dir.path().join(CALLS_DIR).join("unknown.jsonl").is_file());
    }
}
