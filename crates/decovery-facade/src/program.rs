//! Loading the target program of a workspace.

use std::path::{Path, PathBuf};

use decovery_core::{Program, TargetFormat, Workspace};

use crate::FacadeError;

/// Path as given when it exists, otherwise relative to the workspace root.
fn locate(path: &Path, root: &Path) -> PathBuf {
    if path.is_absolute() || path.exists() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// Loads the target of `ws`. LE only for now.
pub fn load(ws: &Workspace) -> Result<Program, FacadeError> {
    if ws.config.target.format != TargetFormat::Le {
        return Err(FacadeError::Invalid(format!(
            "target format {:?} is not supported yet; phase 0 reads LE only",
            ws.config.target.format
        )));
    }
    let file = locate(Path::new(&ws.config.target.file), &ws.root);
    let bytes = std::fs::read(&file)
        .map_err(|e| FacadeError::Invalid(format!("cannot read target {}: {e}", file.display())))?;
    decovery_loaders::load_le(&bytes)
        .map(|image| image.program)
        .map_err(|e| FacadeError::Invalid(format!("cannot load target {}: {e}", file.display())))
}
