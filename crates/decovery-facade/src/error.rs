//! Errors of the facade.

use std::path::PathBuf;

use decovery_core::{Address, WorkspaceError};

/// Why a facade operation failed. Every variant maps to exit code 2 at the CLI.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FacadeError {
    #[error("{0}")]
    Workspace(WorkspaceError),
    #[error("no analysis for this target; run `decovery analyze`")]
    NoAnalysis,
    #[error(
        "the analysis belongs to another target (analysis sha256 {found}, workspace target {expected}); run `decovery analyze`"
    )]
    AnalysisOfOtherTarget { expected: String, found: String },
    #[error("no function or symbol named {0}")]
    NotFound(String),
    #[error("unknown handle {0}")]
    UnknownHandle(String),
    #[error("{address} is in no function{}", nearest_text(nearest))]
    NotInFunction {
        address: Address,
        nearest: Option<(Address, String)>,
    },
    #[error("{0} is outside the memory map")]
    OutsideMap(Address),
    #[error("{0}")]
    Invalid(String),
    #[error("plugin error: {0}")]
    Plugin(String),
    #[error("workspace is locked by pid {pid}")]
    Locked { pid: u32 },
    #[error("cannot write {}: {source}", path.display())]
    Output {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn nearest_text(nearest: &Option<(Address, String)>) -> String {
    match nearest {
        Some((at, name)) => format!(" (nearest: {name} at {at})"),
        None => String::new(),
    }
}

impl FacadeError {
    /// Process exit code for this error.
    pub fn exit_code(&self) -> u8 {
        2
    }
}

impl From<WorkspaceError> for FacadeError {
    fn from(e: WorkspaceError) -> Self {
        match e {
            WorkspaceError::Locked { pid } => FacadeError::Locked { pid },
            other => FacadeError::Workspace(other),
        }
    }
}
