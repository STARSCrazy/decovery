//! Knowledge model: symbols with claims, as stored in `knowledge/symbols.toml`.

use serde::{Deserialize, Serialize};

use crate::address::Address;

/// How sure a claim is. Precedence is `confirmed` > `assumed`; refuted claims are kept with history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Confidence {
    Confirmed,
    Assumed,
    Refuted,
}

/// Where a claim comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ClaimSource {
    Human,
    Signature,
    Runtime,
    Similarity,
    Analysis,
    Agent,
    Import,
}

/// What a symbol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SymbolKind {
    Function,
    Global,
    Label,
    /// A kind this version does not know; kept so the symbol is not lost.
    Other,
}

/// A claim that was refuted earlier, kept as history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RefutedClaim {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ClaimSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A named local variable or parameter of a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LocalVariable {
    /// Location text such as `stack:-0x14`, `param:1` or `reg:ax`.
    pub place: String,
    pub name: String,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
}

/// A comment attached to one instruction address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LineComment {
    pub address: Address,
    pub text: String,
    pub source: ClaimSource,
}

/// A function, global or label with its claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Symbol {
    pub address: Address,
    pub kind: SymbolKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub source: ClaimSource,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refuted: Vec<RefutedClaim>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locals: Vec<LocalVariable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_comments: Vec<LineComment>,
}

impl Symbol {
    /// A symbol with the given address, kind and name; claim fields default to `human` / `assumed`.
    pub fn new(address: Address, kind: SymbolKind, name: impl Into<String>) -> Self {
        Symbol {
            address,
            kind,
            name: name.into(),
            signature: None,
            comment: None,
            source: ClaimSource::Human,
            confidence: Confidence::Assumed,
            evidence: None,
            refuted: Vec::new(),
            data_type: None,
            size: None,
            library: None,
            locals: Vec::new(),
            line_comments: Vec::new(),
        }
    }
}

/// On-disk form of `knowledge/symbols.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SymbolsFile {
    pub schema: u32,
    #[serde(default, rename = "symbol")]
    pub symbols: Vec<Symbol>,
}
