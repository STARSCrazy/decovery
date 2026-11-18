//! The operations behind the CLI subcommands and MCP tools.

mod analyze;
mod annotate;
mod build;
mod detail;
mod diagnose;
mod find;
mod history;
mod job;
mod legacy;
mod link;
mod link_symbols;
mod show;
mod status;
mod variants;

pub use analyze::{AnalyzeOptions, analyze, analyze_with_user_plugins, program_description};
pub use annotate::{AnnotateAction, Annotation, annotate};
pub use build::{BuildRequest, OBJECT_FORMAT, OBJECTS_DIR, RUNS_DIR, SOURCE_DIR, build};
pub use detail::detail;
pub use diagnose::diagnose_tool as diagnose;
pub use find::{
    DEFAULT_LIMIT, DEFAULT_SIMILAR_LIMIT, FindQuery, FindWhat, FunctionFilter, FunctionSort, find,
};
pub use history::{ACTOR_ENV, DEFAULT_HISTORY_LIMIT, actor, history, history_archive, set_actor};
pub use job::{JobAction, job_tool};
pub use legacy::{
    LEGACY_PLUGIN, LegacyCall, LegacyOperation, LegacyOptions, SHADOW_DIR, diagnose_deep,
    keep_legacy_plugin, search, verify,
};
pub use link::link;
pub use show::show;
pub use status::status;
pub use variants::{MAX_VARIANTS, Variant};
