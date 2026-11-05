//! `decovery compare`: one rebuilt function of an object file against the original in a decovery workspace.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use decovery_core::{Address, Confidence, SymbolKind, Workspace};
use decovery_diff::{
    Blocker, CompareOptions, Comparison, Decoration, NameAt, SymbolView, Verdict, compare,
};
use decovery_objects::{functions, read_omf};
use serde_json::{Value, json};

/// What `decovery compare` was asked to do.
pub struct Request {
    pub workspace: PathBuf,
    pub object: PathBuf,
    pub function: String,
    pub length: Option<u32>,
    pub padding: bool,
}

/// Result of a successful comparison, ready to print.
pub struct Outcome {
    pub function: String,
    pub address: Address,
    pub original_len: Option<u32>,
    pub comparison: Comparison,
}

/// Active (not refuted) names of the workspace's knowledge, by address.
pub struct Knowledge {
    by_address: BTreeMap<Address, String>,
}

impl Knowledge {
    pub fn from_workspace(ws: &Workspace) -> Self {
        let by_address = ws
            .symbols
            .iter()
            .filter(|s| s.confidence != Confidence::Refuted && !s.name.is_empty())
            .map(|s| (s.address, s.name.clone()))
            .collect();
        Knowledge { by_address }
    }
}

impl SymbolView for Knowledge {
    fn name_at(&self, at: Address) -> Option<NameAt> {
        match self.by_address.get(&at) {
            Some(n) => Some(NameAt::new(n.clone(), false)),
            None => match at {
                Address::Flat(a) => Some(NameAt::new(format!("fun_{a:08X}"), true)),
                _ => None,
            },
        }
    }

    fn address_of(&self, name: &str) -> Option<Address> {
        self.by_address
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(&a, _)| a)
    }
}

/// `path` as given when it exists, otherwise relative to the workspace root.
fn resolve(path: &Path, root: &Path) -> PathBuf {
    if path.is_absolute() || path.exists() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// Runs the comparison. Errors are messages for the user.
pub fn run(request: &Request) -> Result<Outcome, String> {
    let ws = Workspace::open(&request.workspace)
        .map_err(|e| format!("cannot open workspace {}: {e}", request.workspace.display()))?;
    let knowledge = Knowledge::from_workspace(&ws);
    let symbol = ws
        .symbols
        .iter()
        .filter(|s| s.confidence != Confidence::Refuted)
        .find(|s| s.name == request.function && s.kind == SymbolKind::Function)
        .ok_or_else(|| format!("no function named {} in the knowledge", request.function))?;
    let address = symbol.address;
    let original_len = request
        .length
        .or_else(|| symbol.size.and_then(|s| u32::try_from(s).ok()));

    let object_path = resolve(&request.object, &ws.root);
    let bytes = std::fs::read(&object_path)
        .map_err(|e| format!("cannot read object {}: {e}", object_path.display()))?;
    let file_name = object_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let object = read_omf(&bytes, &file_name)
        .map_err(|e| format!("cannot read object {}: {e}", object_path.display()))?;

    let decoration = Decoration::watcom();
    let view = object
        .modules
        .iter()
        .flat_map(functions)
        .find(|f| decoration.undecorate(f.name) == request.function)
        .ok_or_else(|| {
            format!(
                "function {} is not in {}",
                request.function,
                object_path.display()
            )
        })?;

    let program = decovery_facade::program::load(&ws).map_err(|e| e.to_string())?;
    let options = CompareOptions::new(request.padding, original_len);
    let comparison = compare(&view, address, &program, &knowledge, &decoration, &options);
    Ok(Outcome {
        function: request.function.clone(),
        address,
        original_len,
        comparison,
    })
}

fn verdict_name(v: &Verdict) -> &'static str {
    match v {
        Verdict::Identical => "identical",
        Verdict::Equivalent { .. } => "equivalent",
        Verdict::Differs => "differs",
        Verdict::Unchecked => "unchecked",
        _ => "unknown",
    }
}

fn blocker_json(b: &Blocker) -> Value {
    match *b {
        Blocker::BytesDiffer { count } => json!({"kind": "bytes_differ", "count": count}),
        Blocker::UncheckedRef { at } => json!({"kind": "unchecked_ref", "at": at}),
        Blocker::WrongAbsoluteRef { at } => json!({"kind": "wrong_absolute_ref", "at": at}),
        Blocker::WrongRelativeRef { at } => json!({"kind": "wrong_relative_ref", "at": at}),
        Blocker::InstructionsDiffer { count } => {
            json!({"kind": "instructions_differ", "count": count})
        }
        Blocker::OriginalUnavailable => json!({"kind": "original_unavailable"}),
        _ => json!({"kind": "unknown"}),
    }
}

fn blocker_text(b: &Blocker) -> String {
    match *b {
        Blocker::BytesDiffer { count } => format!("{count} bytes differ"),
        Blocker::UncheckedRef { at } => format!("reference at +{at:#x} cannot be checked"),
        Blocker::WrongAbsoluteRef { at } => {
            format!("absolute reference at +{at:#x} has another target")
        }
        Blocker::WrongRelativeRef { at } => {
            format!("relative reference at +{at:#x} has another target")
        }
        Blocker::InstructionsDiffer { count } => format!("{count} instructions differ"),
        Blocker::OriginalUnavailable => "original bytes are not in the program".to_string(),
        _ => format!("{b:?}"),
    }
}

impl Outcome {
    pub fn identical(&self) -> bool {
        self.comparison.verdict == Verdict::Identical
    }

    pub fn to_json(&self) -> Value {
        let m = &self.comparison.metrics;
        json!({
            "function": self.function,
            "address": self.address.to_string(),
            "original_len": self.original_len,
            "verdict": verdict_name(&self.comparison.verdict),
            "blockers": self.comparison.blockers.iter().map(blocker_json).collect::<Vec<_>>(),
            "metrics": {
                "bytes": m.bytes,
                "equal": m.equal,
                "gaps": m.gaps,
                "padding": m.padding,
                "differing": m.differing,
                "refs_ok": m.refs_ok,
                "refs_wrong": m.refs_wrong,
                "refs_unchecked": m.refs_unchecked,
                "instructions_differing": m.instructions_differing,
                "first_difference": m.first_difference,
            },
        })
    }

    pub fn to_text(&self) -> String {
        let m = &self.comparison.metrics;
        let mut out = format!(
            "{} at {}: {}\n",
            self.function,
            self.address,
            verdict_name(&self.comparison.verdict)
        );
        for b in &self.comparison.blockers {
            out.push_str(&format!("  - {}\n", blocker_text(b)));
        }
        out.push_str(&format!(
            "  bytes {}, equal {}, gaps {}, padding {}, differing {}; refs ok {}, wrong {}, unchecked {}; \
             instructions differing {}\n",
            m.bytes,
            m.equal,
            m.gaps,
            m.padding,
            m.differing,
            m.refs_ok,
            m.refs_wrong,
            m.refs_unchecked,
            m.instructions_differing
        ));
        if self.original_len.is_none() {
            out.push_str(
                "  note: length of the original function unknown (no symbol size, no --length)\n",
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn knowledge(entries: &[(u32, &str)]) -> Knowledge {
        Knowledge {
            by_address: entries
                .iter()
                .map(|&(a, n)| (Address::Flat(a), n.to_string()))
                .collect(),
        }
    }

    #[test]
    fn known_address_has_its_name() {
        let k = knowledge(&[(0x10010, "main_")]);
        assert_eq!(
            k.name_at(Address::Flat(0x10010)),
            Some(NameAt::new("main_", false))
        );
        assert_eq!(k.address_of("main_"), Some(Address::Flat(0x10010)));
    }

    #[test]
    fn unknown_flat_address_gets_default_name() {
        let k = knowledge(&[]);
        assert_eq!(
            k.name_at(Address::Flat(0x2A)),
            Some(NameAt::new("fun_0000002A", true))
        );
        assert_eq!(k.address_of("fun_0000002A"), None);
    }

    #[test]
    fn missing_relative_path_falls_back_to_workspace_root() {
        let root = Path::new("some/workspace");
        assert_eq!(
            resolve(Path::new("does/not/exist.obj"), root),
            root.join("does/not/exist.obj")
        );
    }
}
