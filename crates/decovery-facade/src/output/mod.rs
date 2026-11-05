//! Generated output: one `.c` file per function with a header, plus index files (port of Decomp's `ausgabe/`).
//!
//! Layout below the workspace root: `output/functions/<segment>/<address>_<name>.c`, `output/index.md`,
//! `output/calls.json`, `output/strings.md`, `output/globals.md`, `output/status.json`.

mod files;
mod header;
mod indices;

use std::collections::HashMap;
use std::path::PathBuf;

use decovery_core::{
    AccessKind, Address, AnalysisIndex, AnalyzedFunction, CallEdge, Confidence, DataAccess,
    RebuildRecord, Symbol, knowledge_hash,
};

use crate::{FacadeError, Session};

pub use files::{function_path, render_function, write_affected, write_all};
pub use indices::{StatusCounts, status_counts};

/// Directory of all generated output, relative to the workspace root.
pub const OUTPUT_DIR: &str = "output";
/// Directory of the function files below [`OUTPUT_DIR`].
pub const FUNCTIONS_DIR: &str = "functions";

/// What changed in the knowledge, to decide which function files to regenerate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// The symbol at `at` was renamed from `old`.
    Renamed { at: Address, old: String },
    /// Another claim of the symbol at `at` changed (comment, signature, confidence, …).
    Symbol { at: Address },
    /// `types.h` changed.
    Types,
    /// `references.toml` changed.
    References,
}

/// How many function files were written and how many stale ones removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutputReport {
    /// Function files whose content changed (unchanged files are not rewritten).
    pub written: u32,
    /// Function files removed (renamed or no longer a function).
    pub removed: u32,
}

/// Lookups shared by all files rendered in one run.
pub(crate) struct Context<'a> {
    session: &'a Session,
    index: AnalysisIndex<'a>,
    /// Active (not refuted) symbol per address; a named one wins over an unnamed one.
    symbols: HashMap<Address, &'a Symbol>,
    rebuild: HashMap<Address, &'a RebuildRecord>,
    stale: bool,
}

impl<'a> Context<'a> {
    pub(crate) fn new(session: &'a Session) -> Result<Self, FacadeError> {
        let mut symbols: HashMap<Address, &Symbol> = HashMap::new();
        for s in &session.workspace.symbols {
            if s.confidence == Confidence::Refuted {
                continue;
            }
            let slot = symbols.entry(s.address).or_insert(s);
            if slot.name.is_empty() && !s.name.is_empty() {
                *slot = s;
            }
        }
        let rebuild = session.rebuild.iter().map(|r| (r.address, r)).collect();
        let stale = analysis_stale(session)?;
        Ok(Context {
            session,
            index: session.analysis.index(),
            symbols,
            rebuild,
            stale,
        })
    }

    /// The active symbol at `at` with a name.
    fn named(&self, at: Address) -> Option<&'a Symbol> {
        self.symbols
            .get(&at)
            .copied()
            .filter(|s| !s.name.is_empty())
    }

    /// Knowledge name, else the default name (Decomp's `anzeigename`).
    fn display_name(&self, at: Address) -> String {
        match self.named(at) {
            Some(s) => s.name.clone(),
            None => crate::session::default_name(at),
        }
    }

    /// Functions in start order.
    fn functions(&self) -> Vec<&'a AnalyzedFunction> {
        let mut functions: Vec<_> = self.session.analysis.functions.iter().collect();
        functions.sort_by_key(|f| f.start);
        functions
    }

    /// All call edges in Decomp's order: by caller, site, callee; duplicates dropped.
    fn calls(&self) -> Vec<&'a CallEdge> {
        let mut calls: Vec<_> = self.session.analysis.calls.iter().collect();
        sort_edges(&mut calls);
        calls
    }

    /// Edges calling `f`, by caller then site.
    fn callers(&self, f: Address) -> Vec<&'a CallEdge> {
        let mut edges = self.index.callers(f).to_vec();
        sort_edges(&mut edges);
        edges
    }

    /// Edges from `f`, by site then callee.
    fn callees(&self, f: Address) -> Vec<&'a CallEdge> {
        let mut edges = self.index.callees(f).to_vec();
        sort_edges(&mut edges);
        edges
    }

    /// Data accesses of `f` by variable, reads before writes; duplicates dropped.
    fn accesses(&self, f: Address) -> Vec<&'a DataAccess> {
        let mut accesses = self.index.accesses_of(f).to_vec();
        sort_accesses(&mut accesses);
        accesses
    }

    fn header(&self, f: &AnalyzedFunction) -> String {
        let callers = header::per_partner(self.callers(f.start).iter().map(|e| e.caller), |a| {
            self.display_name(a)
        });
        let callees = header::per_partner(self.callees(f.start).iter().map(|e| e.callee), |a| {
            self.display_name(a)
        });
        let strings = self
            .index
            .strings_used_by(f.start)
            .iter()
            .map(|s| header::string_entry(s.address, &s.text))
            .collect();
        let globals = self
            .accesses(f.start)
            .iter()
            .map(|g| {
                let mut entry = format!("{} {}", access_word(g.kind), g.address);
                if let Some(s) = self.named(g.address) {
                    entry.push(' ');
                    entry.push_str(&s.name);
                }
                entry
            })
            .collect();
        header::header(&header::HeaderData {
            function: f,
            file_offset: files::file_offset(self.session, f.start),
            name: self.display_name(f.start),
            symbol: self.symbols.get(&f.start).copied(),
            callers,
            callees,
            strings,
            globals,
            rebuild: self.rebuild.get(&f.start).copied(),
        })
    }
}

/// `true` when the analysis was made with other knowledge than the current one (R17: reported in
/// `index.md`, `status.json` and by `show`/`status`, not in function files).
pub fn analysis_stale(session: &Session) -> Result<bool, FacadeError> {
    Ok(session.analysis.knowledge_hash != knowledge_hash(&session.workspace.root)?)
}

/// Whether a name can be used as part of a file name (`[A-Za-z_][A-Za-z0-9_]*`).
pub(crate) fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn access_word(kind: AccessKind) -> &'static str {
    match kind {
        AccessKind::Read => "reads",
        _ => "writes",
    }
}

fn access_rank(kind: AccessKind) -> u8 {
    match kind {
        AccessKind::Read => 0,
        _ => 1,
    }
}

fn sort_edges(edges: &mut Vec<&CallEdge>) {
    edges.sort_by_key(|e| (e.caller, e.site, e.callee));
    edges.dedup_by_key(|e| (e.caller, e.site, e.callee));
}

fn sort_accesses(accesses: &mut Vec<&DataAccess>) {
    accesses.sort_by_key(|g| (g.function, g.address, access_rank(g.kind)));
    accesses.dedup_by_key(|g| (g.function, g.address, access_rank(g.kind)));
}

/// `output/functions` below `root`.
fn functions_dir(root: &std::path::Path) -> PathBuf {
    root.join(OUTPUT_DIR).join(FUNCTIONS_DIR)
}
