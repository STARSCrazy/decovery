//! `detail`: pages the content of a handle.

use std::path::Path;

use serde_json::json;

use crate::response::{handle_path, is_handle_id};
use crate::{FacadeError, Response};

/// Returns `limit` characters of the handle's content starting at character `offset`.
pub fn detail(
    root: &Path,
    handle: &str,
    offset: usize,
    limit: usize,
) -> Result<Response, FacadeError> {
    if !is_handle_id(handle) {
        return Err(FacadeError::NotFound(handle.to_string()));
    }
    let path = handle_path(root, handle);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FacadeError::NotFound(handle.to_string()));
        }
        Err(source) => return Err(FacadeError::Output { path, source }),
    };
    let total = content.chars().count();
    let offset = offset.min(total);
    let text: String = content.chars().skip(offset).take(limit).collect();
    let end = offset + text.chars().count();
    Ok(Response::new(
        format!("chars {offset}..{end} of {total}"),
        json!({
            "handle": handle,
            "offset": offset,
            "limit": limit,
            "total": total,
            "text": text,
        }),
    ))
}
