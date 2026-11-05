//! Errors of the toolchain crate.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolchainError {
    #[error("unknown compiler profile `{0}`")]
    UnknownProfile(String),
    #[error(
        "no tool directory for profile `{profile}`; run `decovery setup toolchain {profile} <dir>` or set `tool_dir` in [rebuild]"
    )]
    NoToolDir { profile: String },
    #[error("tool directory of profile `{profile}` does not exist: {}", path.display())]
    ToolDirMissing { profile: String, path: PathBuf },
    #[error("the workspace has no [rebuild] compiler")]
    NoRebuildConfig,
    #[error("{0}")]
    Invalid(String),
    #[error("cannot read {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}
