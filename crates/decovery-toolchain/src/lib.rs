//! Compiler profiles, tool directories and the rebuild settings of a workspace.

mod build;
mod cache;
mod cheat;
mod cp437;
mod error;
mod profile;
mod runner;
mod schedule;
mod staging;

pub use build::{
    CompilePlan, CompiledFile, DEFAULT_TIMEOUT_S, compile, compile_planned, is_job_not_run,
    plan_compile, tool_fingerprint,
};
pub use cache::{OBJECT_CACHE_DIR, ObjectCache};
pub use cheat::{CheatFinding, CheatKind, find_cheats};
pub use runner::{
    JobOutcome, JobStatus, Mount, NativeRunner, PluginRunner, RunJob, RunRequest, Runner,
    RunnerError, open_runners, run_with_fallback,
};
pub use schedule::{JobSlots, SlotGuard, default_jobs, global_slots, set_global_jobs};
pub use staging::{SourceSet, find_sources, stage, stage_text, to_dos_bytes};

pub use error::ToolchainError;
pub use profile::{
    AssemblerSpec, LinkerSpec, ObjectFormat, Profile, profile, profiles, rebuild_profile, tool_dir,
};
