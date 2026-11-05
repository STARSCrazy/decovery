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

/// Loads the target of `ws`, dispatching on its format.
pub fn load(ws: &Workspace) -> Result<Program, FacadeError> {
    let format = ws.config.target.format;
    let file = locate(Path::new(&ws.config.target.file), &ws.root);
    let bytes = std::fs::read(&file)
        .map_err(|e| FacadeError::Invalid(format!("cannot read target {}: {e}", file.display())))?;
    let loaded = match format {
        TargetFormat::Le => decovery_loaders::load_le(&bytes).map(|image| image.program),
        TargetFormat::Mz => decovery_loaders::load_mz(&bytes).map(|image| image.program),
        TargetFormat::Com => decovery_loaders::load_com(&bytes),
        _ => {
            return Err(FacadeError::Invalid(format!(
                "target format {format:?} is not supported yet"
            )));
        }
    };
    loaded.map_err(|e| FacadeError::Invalid(format!("cannot load target {}: {e}", file.display())))
}
