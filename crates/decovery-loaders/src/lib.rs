//! Executable format loaders: turn file bytes into a [`decovery_core::Program`].

pub mod le;
pub mod mz;

pub use le::{LeHeader, LeImage, RawFixup, load_le};
pub use mz::{MzHeader, MzImage, load_com, load_mz, mz_image_range, parse_mz_header};

/// Why a file could not be loaded. Offsets are byte offsets into the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The input ends before `needed` bytes starting at `offset`.
    #[error("input truncated: {needed} bytes needed at offset {offset:#x}")]
    Truncated { offset: u64, needed: usize },
    /// A magic number is missing at `offset`.
    #[error("bad magic at offset {offset:#x}")]
    BadMagic { offset: u64 },
    /// The file is inconsistent or uses something this loader does not handle.
    #[error("unsupported or inconsistent file: {0}")]
    Unsupported(String),
}
