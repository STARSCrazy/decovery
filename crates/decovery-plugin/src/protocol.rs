//! Wire types of the plugin protocol.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Protocol identifier sent in `initialize` and expected in its result.
pub const PROTOCOL: &str = "decovery-plugin/1";

/// Blobs below this size travel inline (base64), larger ones by path and hash.
pub const INLINE_LIMIT: usize = 64 * 1024;

/// Method not found (standard JSON-RPC).
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Capability not supported by the plugin.
pub const CAPABILITY_NOT_SUPPORTED: i64 = -32001;
/// Request was cancelled.
pub const CANCELLED: i64 = -32002;

/// What a plugin reports in its `initialize` result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginInfo {
    /// Plugin name.
    pub name: String,
    /// Plugin version.
    pub version: String,
    /// Protocol identifier, e.g. `decovery-plugin/1`.
    pub protocol: String,
    /// Capability name to capability version.
    pub capabilities: BTreeMap<String, u32>,
}

/// A `$/progress` notification.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct Progress {
    /// Units done so far.
    pub done: u64,
    /// Total units, when known.
    #[serde(default)]
    pub total: Option<u64>,
    /// Free-text status.
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct WireInfo {
    pub name: String,
    pub version: String,
    pub protocol: String,
    pub capabilities: BTreeMap<String, WireCapability>,
}

#[derive(Deserialize)]
pub(crate) struct WireCapability {
    pub version: u32,
}

impl From<WireInfo> for PluginInfo {
    fn from(w: WireInfo) -> Self {
        PluginInfo {
            name: w.name,
            version: w.version,
            protocol: w.protocol,
            capabilities: w
                .capabilities
                .into_iter()
                .map(|(k, v)| (k, v.version))
                .collect(),
        }
    }
}

/// A binary payload: inline below [`INLINE_LIMIT`], otherwise a file with its blake3 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Blob {
    /// Bytes carried in the message.
    Inline(Vec<u8>),
    /// Bytes in a file readable by both sides.
    File {
        /// Absolute path.
        path: PathBuf,
        /// Lowercase hex blake3 of the file contents (64 digits).
        blake3: String,
    },
}

/// Invalid blob.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobError {
    /// Payload too large to inline.
    #[error("{0} bytes exceed the inline limit of 65536; use a file blob")]
    TooLarge(usize),
    /// Not valid base64.
    #[error("invalid base64 at offset {0}")]
    Base64(usize),
    /// Path is not absolute.
    #[error("blob path must be absolute")]
    RelativePath,
    /// Hash is not 64 lowercase hex digits.
    #[error("blake3 must be 64 lowercase hex digits")]
    BadHash,
}

impl Blob {
    /// Inline blob; errors when `bytes` is 64 KiB or more.
    pub fn inline(bytes: &[u8]) -> Result<Self, BlobError> {
        if bytes.len() >= INLINE_LIMIT {
            return Err(BlobError::TooLarge(bytes.len()));
        }
        Ok(Blob::Inline(bytes.to_vec()))
    }

    /// File blob; the path must be absolute and the hash 64 lowercase hex digits.
    pub fn file(path: PathBuf, blake3: String) -> Result<Self, BlobError> {
        if !path.is_absolute() {
            return Err(BlobError::RelativePath);
        }
        let hex_ok = blake3.len() == 64
            && blake3
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return Err(BlobError::BadHash);
        }
        Ok(Blob::File { path, blake3 })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum WireBlob {
    Inline { inline_base64: String },
    File { blob: WireFile },
}

#[derive(Serialize, Deserialize)]
struct WireFile {
    path: PathBuf,
    blake3: String,
}

impl Serialize for Blob {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Blob::Inline(b) => WireBlob::Inline {
                inline_base64: base64_encode(b),
            },
            Blob::File { path, blake3 } => WireBlob::File {
                blob: WireFile {
                    path: path.clone(),
                    blake3: blake3.clone(),
                },
            },
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match WireBlob::deserialize(d)? {
            WireBlob::Inline { inline_base64 } => {
                let bytes = base64_decode(&inline_base64).map_err(serde::de::Error::custom)?;
                Blob::inline(&bytes).map_err(serde::de::Error::custom)
            }
            WireBlob::File { blob } => {
                Blob::file(blob.path, blob.blake3).map_err(serde::de::Error::custom)
            }
        }
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_decode(text: &str) -> Result<Vec<u8>, BlobError> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(BlobError::Base64(bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (ci, chunk) in bytes.chunks(4).enumerate() {
        let last = (ci + 1) * 4 == bytes.len();
        let mut n = 0u32;
        let mut pad = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' && last && i >= 2 {
                pad += 1;
                0
            } else if pad > 0 {
                return Err(BlobError::Base64(ci * 4 + i));
            } else {
                B64.iter()
                    .position(|&x| x == c)
                    .ok_or(BlobError::Base64(ci * 4 + i))? as u32
            };
            n = (n << 6) | v;
        }
        let triple = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&triple[..3 - pad]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_all_tail_lengths() {
        for len in 0..10u8 {
            let data: Vec<u8> = (0..len).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(base64_decode(&base64_encode(&data)).unwrap(), data);
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert!(base64_decode("TW*=").is_err());
    }

    #[test]
    fn inline_limit_is_enforced() {
        assert!(Blob::inline(&vec![0; INLINE_LIMIT - 1]).is_ok());
        assert_eq!(
            Blob::inline(&vec![0; INLINE_LIMIT]),
            Err(BlobError::TooLarge(INLINE_LIMIT))
        );
    }

    #[test]
    fn blob_wire_forms() {
        let v = serde_json::to_value(Blob::inline(b"Ma").unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"inline_base64": "TWE="}));
        assert_eq!(
            serde_json::from_value::<Blob>(v).unwrap(),
            Blob::Inline(b"Ma".to_vec())
        );

        let hash = "0".repeat(64);
        let path = std::env::temp_dir().join("x.bin");
        let blob = Blob::file(path.clone(), hash.clone()).unwrap();
        let v = serde_json::to_value(&blob).unwrap();
        assert_eq!(v["blob"]["blake3"], hash);
        assert_eq!(serde_json::from_value::<Blob>(v).unwrap(), blob);

        assert_eq!(
            Blob::file("rel/x".into(), hash),
            Err(BlobError::RelativePath)
        );
        assert_eq!(Blob::file(path, "AB".into()), Err(BlobError::BadHash));
    }
}
