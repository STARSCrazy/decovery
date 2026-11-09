//! Compiler profiles, tool directories and the rebuild settings of a workspace.

mod build;
mod cache;
mod cheat;
mod cp437;
mod error;
mod le_link;
mod link;
mod profile;
mod runner;
mod schedule;
mod shrink;
mod staging;

pub use build::{
    CompilePlan, CompiledFile, DEFAULT_TIMEOUT_S, SourceJob, compile, compile_planned,
    is_job_not_run, plan_compile, tool_fingerprint,
};
pub use cache::{OBJECT_CACHE_DIR, ObjectCache};
pub use cheat::{CheatFinding, CheatKind, find_cheats};
pub use cp437::decode as from_cp437;
pub use le_link::{
    Insert, LE_DEFAULT_MODULE, LE_DEFAULT_STACK, LE_OBJECT_FILE, LE_RESPONSE_STEM, LE_START_SYMBOL,
    LE_STUB_FILE, SegmentPlan, build_insert, le_linker, le_module, link_le, module_name,
    response_file, segment_plan, usable_inserts,
};
pub use link::{DEFAULT_STARTUP, Linked, link};
pub use runner::{
    JobOutcome, JobStatus, Mount, NativeRunner, PluginRunner, RunJob, RunRequest, Runner,
    RunnerError, open_runners, run_with_fallback, run_with_fallback_reporting,
};
pub use schedule::{JobSlots, SlotGuard, default_jobs, global_slots, set_global_jobs};
pub use shrink::{Definition, Shrunk, definitions, shrink, splice_function};
pub use staging::{SourceSet, find_sources, stage, stage_text, to_dos_bytes};

pub use error::ToolchainError;
pub use profile::{
    AssemblerSpec, LinkerSpec, ObjectFormat, Profile, profile, profiles, rebuild_profile, tool_dir,
};
