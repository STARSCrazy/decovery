//! Compiler profiles, tool directories and the rebuild settings of a workspace.

mod assemble;
mod build;
mod cache;
mod cheat;
mod cp437;
mod error;
mod le_link;
mod link;
mod map;
mod profile;
mod runner;
mod schedule;
mod shrink;
mod staging;

pub use assemble::{AssembleError, BUILTIN_ASSEMBLER, assemble_listing};
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
pub use link::{DEFAULT_STARTUP, Linked, link, run_whole_link, startup_object};
pub use map::{LinkMap, MapPublic, MapSegment, parse_tlink_map};
pub use runner::{
    JobOutcome, JobStatus, JobTimes, Mount, NativeRunner, PluginRunner, RunJob, RunRequest, Runner,
    RunnerError, open_runners, run_with_fallback, run_with_fallback_reporting,
};
pub use schedule::{
    JobSlots, JobSpan, SlotGuard, Throughput, default_jobs, global_slots, set_global_jobs,
    throughput,
};
pub use shrink::{Definition, Shrunk, definitions, shrink, splice_function};
pub use staging::{
    BUILD_ONLY_MARKERS, SourceSet, find_sources, is_build_only, stage, stage_text, to_dos_bytes,
};

pub use error::ToolchainError;
pub use profile::{
    AssemblerSpec, LinkerSpec, LiteralSpec, MapFormat, MapSpec, ObjectFormat, Profile, SearchSpec,
    WholeLinkLine, assembler_profile, profile, profiles, rebuild_profile, tool_dir,
};
