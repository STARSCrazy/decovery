//! `decovery compare`: one rebuilt function of an object file against the original in a decovery workspace.

use std::path::{Path, PathBuf};

use decovery_core::{Address, Analysis, Confidence, Workspace, read_rebuild};
use decovery_diff::{
    Blocker, CompareOptions, Comparison, Decoration, Verdict, compare, compare_with_gaps,
};
use decovery_facade::KnowledgeView;
use decovery_objects::{ObjectFormat, functions, read_object};
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
    /// `differs near C line N: <text>` from the analyzer's line map of the original, when it has one.
    pub near: Option<String>,
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
    let analysis = Analysis::load(&ws.root)
        .map_err(|e| format!("cannot read the analysis of {}: {e}", ws.root.display()))?;
    let knowledge = KnowledgeView::new(&ws, analysis.as_ref());
    let rebuild = read_rebuild(&ws.root).map_err(|e| {
        format!(
            "cannot read the rebuild records of {}: {e}",
            ws.root.display()
        )
    })?;
    let target = request.function.trim();
    // an address (`flat:`, `seg:`, `ovl:`), else a name: exact first, then rebuild records and overlay-qualified
    // names (`<OVERLAY>_<name>`), else a default name `fun_…`
    let address = if target.contains(':') {
        target
            .parse::<Address>()
            .map_err(|e| format!("{target}: {e}"))?
    } else {
        decovery_facade::function_by_name(&ws, analysis.as_ref(), &rebuild, target)
            .map_err(|e| e.to_string())?
            .or_else(|| decovery_facade::parse_default_name(target))
            .ok_or_else(|| format!("no function named {target} in the knowledge"))?
    };
    let symbol = ws
        .symbols
        .iter()
        .filter(|s| s.confidence != Confidence::Refuted && !s.name.is_empty())
        .find(|s| s.address == address);
    let original_len = request
        .length
        .or_else(|| {
            symbol
                .and_then(|s| s.size)
                .and_then(|s| u32::try_from(s).ok())
        })
        .or_else(|| {
            let index = analysis.as_ref()?.index();
            let f = index.function_at(address)?;
            u32::try_from(f.end.bytes_from(f.start)?.checked_add(1)?).ok()
        });
    // the names the rebuilt function may carry in the object: as asked, the rebuild record's, the symbol's, and
    // the symbol's without its overlay prefix
    let mut names: Vec<String> = vec![target.to_string()];
    names.extend(
        rebuild
            .iter()
            .filter(|r| r.address == address)
            .map(|r| r.name.clone()),
    );
    if let Some(s) = symbol {
        names.push(s.name.clone());
        if let Some(stripped) = address
            .overlay()
            .and_then(|o| s.name.strip_prefix(o.as_str()))
            .and_then(|n| n.strip_prefix('_'))
        {
            names.push(stripped.to_string());
        }
    }
    let shown = symbol.map_or_else(|| target.to_string(), |s| s.name.clone());

    let object_path = resolve(&request.object, &ws.root);
    let bytes = std::fs::read(&object_path)
        .map_err(|e| format!("cannot read object {}: {e}", object_path.display()))?;
    let file_name = object_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let profile = ws
        .config
        .rebuild
        .as_ref()
        .and_then(|r| r.compiler.as_deref())
        .and_then(|id| decovery_toolchain::profile(id).ok());
    let format = profile
        .as_ref()
        .map_or(ObjectFormat::Omf, |p| p.object_format);
    let object = read_object(format, &bytes, &file_name)
        .map_err(|e| format!("cannot read object {}: {e}", object_path.display()))?;
    let decoration = profile.map_or_else(Decoration::watcom, |p| p.decoration);
    let view = object
        .modules
        .iter()
        .flat_map(functions)
        .find(|f| {
            let name = decoration.undecorate(f.name);
            names.iter().any(|n| n == name || n == f.name)
        })
        .ok_or_else(|| format!("function {shown} is not in {}", object_path.display()))?;

    let program = decovery_facade::program::load(&ws).map_err(|e| e.to_string())?;
    let options = CompareOptions::new(request.padding, original_len);
    let comparison = if format == ObjectFormat::Aztec {
        // no linker (phase 4): object against image, relocated fields are link gaps, as `build` compares
        let image = program.read(address, view.code().len()).unwrap_or(&[]);
        compare_with_gaps(&view, image, address)
    } else {
        compare(&view, address, &program, &knowledge, &decoration, &options)
    };
    let near = match (&comparison.verdict, comparison.metrics.first_difference) {
        (Verdict::Differs, Some(offset)) => {
            decovery_facade::differs_near(&ws.root, address, offset)
        }
        _ => None,
    };
    Ok(Outcome {
        near,
        function: shown,
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
            "near": self.near,
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
        if let Some(near) = &self.near {
            out.push_str(&format!("  {near}\n"));
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

    #[test]
    fn missing_relative_path_falls_back_to_workspace_root() {
        let root = Path::new("some/workspace");
        assert_eq!(
            resolve(Path::new("does/not/exist.obj"), root),
            root.join("does/not/exist.obj")
        );
    }
}
