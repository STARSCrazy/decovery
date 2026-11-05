//! Compiler profiles, tool directories and the rebuild settings of a workspace.

mod cheat;
mod cp437;
mod error;
mod profile;
mod runner;
mod staging;

pub use cheat::{CheatFinding, CheatKind, find_cheats};
pub use runner::{
    JobOutcome, JobStatus, Mount, NativeRunner, PluginRunner, RunJob, RunRequest, Runner,
    RunnerError, open_runners, run_with_fallback,
};
pub use staging::{SourceSet, find_sources, stage, stage_text, to_dos_bytes};

pub use error::ToolchainError;
pub use profile::{
    AssemblerSpec, LinkerSpec, ObjectFormat, Profile, profile, profiles, rebuild_profile, tool_dir,
};
