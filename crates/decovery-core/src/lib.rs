//! Core model of decovery: addresses, programs, knowledge and workspaces.

pub mod address;
pub mod knowledge;
pub mod migrate;
pub mod program;
pub mod workspace;

pub use address::{Address, AddressError, AddressInput};
pub use knowledge::{
    ClaimSource, Confidence, LineComment, LocalVariable, RefutedClaim, Symbol, SymbolKind,
};
pub use migrate::{MigrateError, MigrationReport, migrate_decomp};
pub use program::{
    ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
pub use workspace::{
    AnalysisConfig, DetectedFact, LinkConfig, OutputConfig, RebuildConfig, RuntimeBase,
    RuntimeConfig, SegmentConfig, TargetConfig, TargetFormat, UnpackedConfig, Workspace,
    WorkspaceConfig, WorkspaceError,
};
