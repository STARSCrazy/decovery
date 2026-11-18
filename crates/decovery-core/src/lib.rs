//! Core model of decovery: addresses, programs, knowledge and workspaces.

pub mod address;
pub mod analysis;
pub mod archive;
pub mod attempts;
pub mod bench;
pub mod calls;
pub mod decompile_info;
pub mod jobs;
pub mod knowledge;
pub mod migrate;
pub mod program;
pub mod records;
pub mod store;
pub mod user_config;
pub mod workspace;

pub use address::{
    Address, AddressError, AddressInput, OVERLAY_NAME_MAX, OverlayName, address_key,
};
pub use analysis::{
    ANALYSIS_DIR, AccessKind, Analysis, AnalysisIndex, AnalyzedFunction, CallEdge, DataAccess,
    Provider, StringItem, knowledge_hash, now_utc, today,
};
pub use archive::{
    ARCHIVE_DIR, ARCHIVE_FORMAT, ArchiveEntry, archive_ids_for, archive_load, archive_remove,
    archive_save,
};
pub use attempts::{
    ATTEMPTS_DIR, AttemptBudget, AttemptOrigin, AttemptRecord, DEFAULT_ATTEMPT_BUDGET,
    append_attempts, attempt_budget, attempt_distance, distance_of, read_attempts,
};
pub use bench::{BenchLimits, BenchUsage};
pub use calls::{CALLS_DIR, CallRecord, append_call};
pub use decompile_info::{AddressRange, DecompileInfo, LineHit, LineRanges, Signature, Variable};
pub use jobs::{
    JOBS_DIR, JobLease, JobProgress, JobRecord, JobState, job_cancel_requested, job_create,
    job_create_leased, job_lease, job_list, job_load, job_request_cancel, job_save,
};
pub use knowledge::{
    ClaimSource, Confidence, LineComment, LocalVariable, RefutedClaim, Symbol, SymbolKind,
    SymbolsFile,
};
pub use migrate::{
    AttemptMigrationReport, MigrateError, MigrationReport, migrate_attempts, migrate_decomp,
};
pub use program::{
    ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};
pub use records::{
    BlockerRecord, Equivalence, ProgramRecord, RebuildRecord, RebuildResult, Reference,
    ReferenceKind, Shares, Used, VerdictId, merge_rebuild, read_program_record, read_rebuild,
    read_references, save_program_record, save_rebuild,
};
pub use store::{WorkspaceLock, write_atomic};
pub use user_config::{
    UserConfig, plugin_config, read_user_config, read_user_config_file, user_config_path,
};
pub use workspace::{
    AnalysisConfig, DetectedFact, LegacyConfig, LinkConfig, OutputConfig, OverlayConfig,
    PluginConfig, RebuildConfig, RuntimeBase, RuntimeConfig, SegmentConfig, TargetConfig,
    TargetFormat, UnpackedConfig, Workspace, WorkspaceConfig, WorkspaceError,
};
