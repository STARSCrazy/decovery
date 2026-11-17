//! Reproducible agent benchmarks over solution-free workspace copies.

mod copy;
mod legacy_view;
mod suite;

pub use copy::{TaskCopy, copies_dir, prepare_copy};
pub use suite::{StartPoint, Suite, SuiteTask, TaskDefaults, ToolSet, read_suite};

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BenchError {
    #[error("{}: {reason}", path.display())]
    Suite { path: PathBuf, reason: String },
    #[error("task {task}: {reason}")]
    Copy { task: String, reason: String },
    #[error("task {task}: {reason}")]
    Driver { task: String, reason: String },
    #[error("{0}")]
    Facade(#[from] decovery_facade::FacadeError),
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl From<decovery_core::WorkspaceError> for BenchError {
    fn from(error: decovery_core::WorkspaceError) -> Self {
        Self::Facade(decovery_facade::FacadeError::from(error))
    }
}

pub(crate) fn io(path: &Path, source: std::io::Error) -> BenchError {
    BenchError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Canonical paths written into external tool configs use ordinary Windows spelling, matching pathlib.
pub(crate) fn canonical(path: &Path) -> Result<PathBuf, BenchError> {
    let path = path.canonicalize().map_err(|e| io(path, e))?;
    #[cfg(windows)]
    if let Some(text) = path.to_str() {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{rest}")));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(rest));
        }
    }
    Ok(path)
}
