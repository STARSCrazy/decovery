//! Core model of decovery: addresses, programs, knowledge and workspaces.

pub mod address;
pub mod knowledge;
pub mod migrate;
pub mod program;
pub mod records;
pub mod store;
pub mod workspace;

pub use address::{Address, AddressError, AddressInput};
pub use knowledge::{
    ClaimSource, Confidence, LineComment, LocalVariable, RefutedClaim, Symbol, SymbolKind,
    SymbolsFile,
};
pub use migrate::{MigrateError, MigrationReport, migrate_decomp};
pub use program::{
    ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
pub use records::{
    RebuildRecord, RebuildResult, Reference, ReferenceKind, read_rebuild, read_references,
};
pub use store::{WorkspaceLock, write_atomic};
pub use workspace::{
    AnalysisConfig, DetectedFact, LinkConfig, OutputConfig, RebuildConfig, RuntimeBase,
    RuntimeConfig, SegmentConfig, TargetConfig, TargetFormat, UnpackedConfig, Workspace,
    WorkspaceConfig, WorkspaceError,
};
