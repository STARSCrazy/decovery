//! Executable format loaders: turn file bytes into a [`decovery_core::Program`].

pub mod le;
pub mod mz;
pub mod overlay;

pub use le::{
    FIXUP_BLOCK, LeHeader, LeImage, LeObject, RawFixup, fixup_processing_order, load_le,
    processing_order,
};
pub use mz::{MzHeader, MzImage, load_com, load_mz, mz_image_range, parse_mz_header};
pub use overlay::{
    OVERLAY_HEADER, OVERLAY_MAGIC, Overlay, OverlayHeader, aztec_data_segment, find_overlay_loader,
    read_overlay, read_overlays,
};

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
    /// A field at `offset` has a value the format does not allow.
    #[error("malformed field at offset {offset:#x}: {detail}")]
    Malformed { offset: u64, detail: String },
    /// The file is inconsistent or uses something this loader does not handle.
    #[error("unsupported or inconsistent file: {0}")]
    Unsupported(String),
}
