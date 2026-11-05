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
    #[error("{name}: source names must match [a-z0-9_-]{{1,8}}.(c|h|s|asm)")]
    InvalidSourceName { name: String },
    #[error("{file}:{line}: character U+{ch:04X} does not exist in code page 437")]
    NotCp437 { file: String, line: u32, ch: u32 },
    #[error("{0}")]
    Invalid(String),
    #[error("cannot read {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}
