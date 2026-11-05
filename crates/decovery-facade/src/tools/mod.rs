//! The operations behind the CLI subcommands and MCP tools.

mod analyze;
mod annotate;
mod detail;
mod find;
mod show;
mod status;

pub use analyze::{AnalyzeOptions, analyze, analyze_with_user_plugins, program_description};
pub use annotate::{AnnotateAction, Annotation, annotate};
pub use detail::detail;
pub use find::{DEFAULT_LIMIT, FindQuery, FindWhat, FunctionFilter, FunctionSort, find};
pub use show::show;
pub use status::status;
