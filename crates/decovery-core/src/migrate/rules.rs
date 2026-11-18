//! Decomp's compiler knowledge (`compilerwissen/*.toml` at the root of the Decomp repository) becomes workspace
//! knowledge: the rules for the workspace's compiler are written to `knowledge/compiler-rules.toml` with English
//! keys and ids; their texts stay in German and are counted as untranslated.

use std::path::{Path, PathBuf};

use toml::{Table, Value};

use super::decomp_format::{rules, values};
use super::{Ctx, MigrateError, Tbl, io, read};

/// Workspace file the rules are written to.
pub(super) const FILE: &str = "knowledge/compiler-rules.toml";

/// The `compilerwissen/` directory of the Decomp repository holding `from`, if any.
fn knowledge_dir(from: &Path) -> Option<PathBuf> {
    let from = std::path::absolute(from).ok()?;
    from.ancestors()
        .map(|a| a.join(rules::DIR))
        .find(|d| d.is_dir())
}

fn status(text: &str) -> Option<&'static str> {
    Some(match text {
        values::CONFIDENCE_CONFIRMED => "confirmed",
        values::CONFIDENCE_ASSUMED => "assumed",
        values::CONFIDENCE_REFUTED => "refuted",
        _ => return None,
    })
}

/// The rules of `compiler` as the text of [`FILE`], or `None` when there is no compiler knowledge for it.
pub(super) fn convert(
    from: &Path,
    compiler: Option<&str>,
    cx: &mut Ctx,
) -> Result<Option<String>, MigrateError> {
    let (Some(compiler), Some(dir)) = (compiler, knowledge_dir(from)) else {
        return Ok(None);
    };
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| io(&dir, e))? {
        let path = entry.map_err(|e| io(&dir, e))?.path();
        if path.extension().is_some_and(|x| x == "toml") && path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();
    let mut out = Vec::new();
    let mut sources = Vec::new();
    for path in paths {
        let text = read(&path)?;
        let mut table: Table = toml::from_str(&text).map_err(|source| MigrateError::Parse {
            path: path.clone(),
            source: Box::new(source),
        })?;
        let Some(Value::Array(items)) = table.remove(rules::RULE) else {
            continue;
        };
        let before = out.len();
        for item in items {
            let applies = item
                .get(rules::COMPILER)
                .and_then(Value::as_array)
                .is_some_and(|c| c.iter().any(|v| v.as_str() == Some(compiler)));
            if !applies {
                continue;
            }
            if let Some(t) = Tbl::new(item, rules::RULE, cx) {
                out.push(Value::Table(convert_rule(t, cx)));
            }
        }
        if out.len() > before {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            sources.push(format!("{}/{name}", rules::DIR));
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    let mut root = Table::new();
    root.insert("rule".into(), Value::Array(out));
    let body = toml::to_string(&root).map_err(|source| MigrateError::Serialize {
        path: PathBuf::from(FILE),
        source: Box::new(source),
    })?;
    Ok(Some(format!(
        "# Compiler rules for {compiler}, migrated from Decomp ({}); texts are in German.\n\n{body}",
        sources.join(", ")
    )))
}

fn convert_rule(mut t: Tbl, cx: &mut Ctx) -> Table {
    let mut r = Table::new();
    if let Some(id) = t.string("id", cx) {
        r.insert("id".into(), Value::String(id));
    }
    let compilers = t.strings(rules::COMPILER, cx);
    r.insert(
        "compilers".into(),
        Value::Array(compilers.into_iter().map(Value::String).collect()),
    );
    if let Some(s) = t.string("status", cx) {
        let mapped = status(&s).map(str::to_string).unwrap_or_else(|| {
            cx.unmapped.insert(format!("{}.status={s}", rules::RULE));
            s
        });
        r.insert("status".into(), Value::String(mapped));
    }
    for (decomp, english) in [("text", "text"), (rules::SUGGESTION, "suggestion")] {
        if let Some(s) = t.text(decomp, cx) {
            r.insert(english.into(), Value::String(s));
        }
    }
    let no_help = t.strings(rules::DOES_NOT_HELP, cx);
    cx.texts += u32::try_from(no_help.len()).unwrap_or(u32::MAX);
    r.insert(
        "does_not_help".into(),
        Value::Array(no_help.into_iter().map(Value::String).collect()),
    );
    let mut evidence = Vec::new();
    for mut e in t.tables(rules::EVIDENCE, cx) {
        let mut out = Table::new();
        for (decomp, english, free) in [
            (rules::TARGET, "target", false),
            (rules::FUNCTION, "function", true),
            (rules::DATE, "date", false),
            (rules::RESULT, "result", true),
        ] {
            let v = if free {
                e.text(decomp, cx)
            } else {
                e.string(decomp, cx)
            };
            if let Some(v) = v {
                out.insert(english.into(), Value::String(v));
            }
        }
        e.finish(cx);
        evidence.push(Value::Table(out));
    }
    if !evidence.is_empty() {
        r.insert("evidence".into(), Value::Array(evidence));
    }
    t.finish(cx);
    r
}
