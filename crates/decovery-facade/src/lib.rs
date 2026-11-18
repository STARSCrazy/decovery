//! Shared operations of decovery: sessions, target resolution and the layers built on them.

mod control;
mod error;
mod exemplars;
pub mod output;
pub mod plugins;
pub mod program;
mod resolve;
pub mod response;
mod session;
pub mod tools;

pub use control::Control;
pub use decovery_plugin::{CancelToken, Progress};
pub use error::FacadeError;
pub use exemplars::{EXEMPLARS_FILE, Exemplar, ExemplarIndex, LSH_ALL, exemplar_index};
pub use output::{
    Change, OutputReport, StatusCounts, function_path, render_function, status_counts,
    write_affected, write_all,
};
pub use resolve::{Resolved, resolve};
pub use response::{Budget, Handle, Response, store_handle};
pub use session::{DisplayName, KnowledgeView, Session};
pub use tools::{
    ACTOR_ENV, AnalyzeOptions, AnnotateAction, Annotation, BuildRequest, DEFAULT_HISTORY_LIMIT,
    DEFAULT_LIMIT, DEFAULT_SIMILAR_LIMIT, FindQuery, FindWhat, FunctionFilter, FunctionSort,
    LegacyCall, LegacyOperation, LegacyOptions, Variant, actor, analyze, analyze_with_user_plugins,
    annotate, build, detail, diagnose, diagnose_deep, find, history, history_archive,
    keep_legacy_plugin, link, program_description, search, set_actor, show, status, verify,
};
