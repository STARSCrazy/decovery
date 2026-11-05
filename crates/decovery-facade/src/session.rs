//! A workspace opened together with its analysis.

use std::path::Path;

use decovery_core::{
    Address, Analysis, Confidence, Provider, RebuildRecord, Symbol, Workspace, read_rebuild,
};

use crate::FacadeError;

/// Workspace, analysis and rebuild records, loaded once.
pub struct Session {
    pub workspace: Workspace,
    pub analysis: Analysis,
    pub rebuild: Vec<RebuildRecord>,
}

/// The name shown for an address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisplayName {
    pub name: String,
    /// `true` for the generated `fun_XXXXXXXX` name.
    pub is_default: bool,
}

impl Session {
    /// Opens the workspace; fails if there is no analysis of this target.
    pub fn open(root: &Path) -> Result<Session, FacadeError> {
        let workspace = Workspace::open(root)?;
        let analysis = Analysis::load(root)?.ok_or(FacadeError::NoAnalysis)?;
        check_target(&workspace, &analysis)?;
        let rebuild = read_rebuild(root)?;
        Ok(Session {
            workspace,
            analysis,
            rebuild,
        })
    }

    /// Opens the workspace for `analyze` and `annotate`: without a stored analysis the analysis is empty.
    pub fn open_without_analysis(root: &Path) -> Result<Session, FacadeError> {
        let workspace = Workspace::open(root)?;
        let analysis = match Analysis::load(root)? {
            Some(analysis) => {
                check_target(&workspace, &analysis)?;
                analysis
            }
            None => Analysis::new(
                Provider::new("none", ""),
                workspace.config.target.sha256.clone(),
                "",
                "",
            ),
        };
        let rebuild = read_rebuild(root)?;
        Ok(Session {
            workspace,
            analysis,
            rebuild,
        })
    }

    /// Active symbol name at `at`, else the default name.
    pub fn name_of(&self, at: Address) -> DisplayName {
        match self.symbol_at(at) {
            Some(symbol) => DisplayName {
                name: symbol.name.clone(),
                is_default: false,
            },
            None => DisplayName {
                name: default_name(at),
                is_default: true,
            },
        }
    }

    /// The active (not refuted) symbol with a name at exactly `at`.
    pub fn symbol_at(&self, at: Address) -> Option<&Symbol> {
        self.workspace
            .symbols
            .iter()
            .find(|s| s.address == at && s.confidence != Confidence::Refuted && !s.name.is_empty())
    }
}

fn check_target(workspace: &Workspace, analysis: &Analysis) -> Result<(), FacadeError> {
    if analysis.target_sha256 == workspace.config.target.sha256 {
        Ok(())
    } else {
        Err(FacadeError::AnalysisOfOtherTarget {
            expected: workspace.config.target.sha256.clone(),
            found: analysis.target_sha256.clone(),
        })
    }
}

/// Decomp's `standardname`: `fun_` plus the address text without its prefix, `:` as `_`
/// (`fun_0001A2B0`, `fun_1234_0010`, `fun_0007_00001234`).
pub(crate) fn default_name(at: Address) -> String {
    let text = at.to_string();
    let short = text.split_once(':').map_or(text.as_str(), |(_, rest)| rest);
    format!("fun_{}", short.replace(':', "_"))
}

/// The address a default name stands for (inverse of [`default_name`]).
pub(crate) fn parse_default_name(name: &str) -> Option<Address> {
    let rest = name.strip_prefix("fun_")?;
    let hex = |t: &str, n: usize| {
        (t.len() == n && t.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| u32::from_str_radix(t, 16).ok())
            .flatten()
    };
    let parts: Vec<&str> = rest.split('_').collect();
    match parts.as_slice() {
        [a] => Some(Address::Flat(hex(a, 8)?)),
        [s, o] if o.len() == 4 => Some(Address::Seg {
            seg: u16::try_from(hex(s, 4)?).ok()?,
            off: u16::try_from(hex(o, 4)?).ok()?,
        }),
        [s, o] => Some(Address::Sel {
            segment: u16::try_from(hex(s, 4)?).ok()?,
            off: hex(o, 8)?,
        }),
        _ => None,
    }
}
