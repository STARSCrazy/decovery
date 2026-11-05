//! Shared operations of decovery: sessions, target resolution and the layers built on them.

mod error;
pub mod program;
mod resolve;
mod session;

pub use error::FacadeError;
pub use resolve::{Resolved, resolve};
pub use session::{DisplayName, Session};
