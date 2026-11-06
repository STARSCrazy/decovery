//! The decovery plugin protocol (JSON-RPC 2.0 over stdio, newline-delimited) and a host for it.
//!
//! See `docs/plugin-protocol.md` and `schemas/plugin-protocol.schema.json` for the wire contract.

mod host;
pub mod protocol;

pub use host::{CallOptions, CancelToken, PluginError, PluginHost};
pub use protocol::{Blob, BlobError, Limits, PROTOCOL, PluginInfo, Progress};
