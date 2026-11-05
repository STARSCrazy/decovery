//! Core model of decovery: addresses, programs, knowledge and workspaces.

pub mod address;
pub mod analysis;
pub mod knowledge;
pub mod migrate;
pub mod program;
pub mod records;
pub mod store;
pub mod user_config;
pub mod workspace;

pub use address::{Address, AddressError, AddressInput};
pub use analysis::{
    ANALYSIS_DIR, AccessKind, Analysis, AnalysisIndex, AnalyzedFunction, CallEdge, DataAccess,
    Provider, StringItem, knowledge_hash, today,
};
pub use knowledge::{
    ClaimSource, Confidence, LineComment, LocalVariable, RefutedClaim, Symbol, SymbolKind,
    SymbolsFile,
};
pub use migrate::{MigrateError, MigrationReport, migrate_decomp};
pub use program::{
    ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
pub use records::{
    Equivalence, RebuildRecord, RebuildResult, Reference, ReferenceKind, read_rebuild,
    read_references,
};
pub use store::{WorkspaceLock, write_atomic};
pub use user_config::{
    UserConfig, plugin_config, read_user_config, read_user_config_file, user_config_path,
};
pub use workspace::{
    AnalysisConfig, DetectedFact, LinkConfig, OutputConfig, PluginConfig, RebuildConfig,
    RuntimeBase, RuntimeConfig, SegmentConfig, TargetConfig, TargetFormat, UnpackedConfig,
    Workspace, WorkspaceConfig, WorkspaceError,
};
