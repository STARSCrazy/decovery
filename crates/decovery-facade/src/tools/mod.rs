//! The operations behind the CLI subcommands and MCP tools.

mod analyze;
mod annotate;
mod build;
mod detail;
mod diagnose;
mod find;
mod link;
mod show;
mod status;
mod variants;

pub use analyze::{AnalyzeOptions, analyze, analyze_with_user_plugins, program_description};
pub use annotate::{AnnotateAction, Annotation, annotate};
pub use build::{BuildRequest, OBJECT_FORMAT, OBJECTS_DIR, RUNS_DIR, SOURCE_DIR, build};
pub use detail::detail;
pub use diagnose::diagnose_tool as diagnose;
pub use find::{DEFAULT_LIMIT, FindQuery, FindWhat, FunctionFilter, FunctionSort, find};
pub use link::link;
pub use show::show;
pub use status::status;
pub use variants::{MAX_VARIANTS, Variant};
