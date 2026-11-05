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

/// `fun_` plus eight uppercase hex digits for flat addresses; other forms use their text with `_` for `:`.
fn default_name(at: Address) -> String {
    match at {
        Address::Flat(a) => format!("fun_{a:08X}"),
        other => format!("fun_{}", other.to_string().replace(':', "_")),
    }
}
