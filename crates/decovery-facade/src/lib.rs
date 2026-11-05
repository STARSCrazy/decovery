//! Shared operations of decovery: sessions, target resolution and the layers built on them.

mod error;
pub mod output;
pub mod program;
mod resolve;
mod session;

pub use error::FacadeError;
pub use output::{
    Change, OutputReport, StatusCounts, function_path, render_function, status_counts,
    write_affected, write_all,
};
pub use resolve::{Resolved, resolve};
pub use session::{DisplayName, Session};
