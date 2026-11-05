//! The answer envelope shared by all tools: a summary, structured data and handles to bulky content.

use std::path::{Path, PathBuf};

use decovery_core::write_atomic;
use serde::Serialize;

use crate::FacadeError;

/// Directory of stored handle contents, relative to the workspace root.
pub const HANDLES_DIR: &str = "cache/handles";

/// What every tool returns.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Response {
    /// One line telling the outcome.
    pub summary: String,
    /// Structured result; shape depends on the tool.
    pub data: serde_json::Value,
    /// Stored content that did not fit the budget; page it with `detail`.
    pub handles: Vec<Handle>,
}

impl Response {
    pub fn new(summary: impl Into<String>, data: serde_json::Value) -> Self {
        Response {
            summary: summary.into(),
            data,
            handles: Vec::new(),
        }
    }
}

/// Reference to content stored under `cache/handles/<id>.txt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Handle {
    /// `h_` plus 12 hex characters of the blake3 hash of the content.
    pub id: String,
    pub kind: String,
    /// Size in bytes.
    pub size: u64,
    pub description: String,
}

/// How many characters of data a response may carry inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub chars: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget { chars: 8000 }
    }
}

/// Stores `content` as a handle (same content, same id) and returns it; the description is empty.
pub fn store_handle(root: &Path, kind: &str, content: &str) -> Result<Handle, FacadeError> {
    let hash = blake3::hash(content.as_bytes()).to_hex();
    let id = format!("h_{}", &hash.as_str()[..12]);
    let path = handle_path(root, &id);
    write_atomic(&path, content.as_bytes()).map_err(|source| FacadeError::Output {
        path: path.clone(),
        source,
    })?;
    Ok(Handle {
        id,
        kind: kind.to_string(),
        size: content.len() as u64,
        description: String::new(),
    })
}

/// `true` for `h_` plus 12 lowercase hex characters.
pub(crate) fn is_handle_id(id: &str) -> bool {
    id.strip_prefix("h_").is_some_and(|hex| {
        hex.len() == 12
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) fn handle_path(root: &Path, id: &str) -> PathBuf {
    root.join(HANDLES_DIR).join(format!("{id}.txt"))
}
