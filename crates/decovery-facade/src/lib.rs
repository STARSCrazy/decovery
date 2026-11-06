//! Shared operations of decovery: sessions, target resolution and the layers built on them.

mod error;
pub mod output;
pub mod plugins;
pub mod program;
mod resolve;
pub mod response;
mod session;
pub mod tools;

pub use decovery_plugin::Progress;
pub use error::FacadeError;
pub use output::{
    Change, OutputReport, StatusCounts, function_path, render_function, status_counts,
    write_affected, write_all,
};
pub use resolve::{Resolved, resolve};
pub use response::{Budget, Handle, Response, store_handle};
pub use session::{DisplayName, KnowledgeView, Session};
pub use tools::{
    AnalyzeOptions, AnnotateAction, Annotation, BuildRequest, DEFAULT_LIMIT, FindQuery, FindWhat,
    FunctionFilter, FunctionSort, Variant, analyze, analyze_with_user_plugins, annotate, build,
    detail, find, program_description, show, status,
};
