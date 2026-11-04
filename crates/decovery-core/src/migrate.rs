//! Migration of a Decomp workspace (German schema) into a decovery workspace.
//!
//! Every key or value that has no mapping ends up in [`MigrationReport::unmapped`]; nothing is dropped
//! silently. Free text (comments, evidence, notes) is copied unchanged and counted in
//! [`MigrationReport::untranslated_texts`].

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use toml::Value;

use crate::address::Address;
use crate::knowledge::{
    ClaimSource, Confidence, LineComment, LocalVariable, RefutedClaim, Symbol, SymbolKind,
    SymbolsFile,
};
use crate::workspace::{
    AnalysisConfig, CONFIG_FILE, DetectedFact, LinkConfig, OutputConfig, RebuildConfig,
    RuntimeBase, RuntimeConfig, SCHEMA, SYMBOLS_FILE, SegmentConfig, TargetConfig, TargetFormat,
    UnpackedConfig, WorkspaceConfig,
};

/// Result of a migration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MigrationReport {
    /// Files written, relative to the target directory.
    pub converted: Vec<PathBuf>,
    /// Dotted Decomp key paths (or `key=value` for unknown enum values, or file names) that were not mapped.
    pub unmapped: Vec<String>,
    /// Number of free-text fields copied unchanged (still in the source language).
    pub untranslated_texts: u32,
}

/// Errors that stop a migration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MigrateError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{}: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("missing required key `{0}`")]
    Missing(String),
    #[error("invalid value for `{key}`: {value}")]
    Invalid { key: String, value: String },
    #[error("unsupported target format `{0}`")]
    UnsupportedFormat(String),
    #[error("{} already contains a workspace", .0.display())]
    TargetExists(PathBuf),
    #[error("cannot write {}: {source}", path.display())]
    Serialize {
        path: PathBuf,
        source: Box<toml::ser::Error>,
    },
}

#[derive(Default)]
struct Ctx {
    unmapped: BTreeSet<String>,
    texts: u32,
}

/// A TOML table whose keys are consumed one by one; leftovers are reported as unmapped.
struct Tbl {
    path: String,
    map: toml::Table,
}

impl Tbl {
    fn new(value: Value, path: &str, cx: &mut Ctx) -> Option<Tbl> {
        match value {
            Value::Table(map) => Some(Tbl {
                path: path.to_string(),
                map,
            }),
            _ => {
                cx.unmapped.insert(format!("{path} (expected a table)"));
                None
            }
        }
    }

    fn key(&self, k: &str) -> String {
        if self.path.is_empty() {
            k.to_string()
        } else {
            format!("{}.{k}", self.path)
        }
    }

    fn mismatch(&self, k: &str, expected: &str, cx: &mut Ctx) {
        cx.unmapped
            .insert(format!("{} (expected {expected})", self.key(k)));
    }

    fn string(&mut self, k: &str, cx: &mut Ctx) -> Option<String> {
        match self.map.remove(k)? {
            Value::String(s) => Some(s),
            _ => {
                self.mismatch(k, "a string", cx);
                None
            }
        }
    }

    /// Free text: a string that is copied unchanged and counted.
    fn text(&mut self, k: &str, cx: &mut Ctx) -> Option<String> {
        let s = self.string(k, cx)?;
        cx.texts += 1;
        Some(s)
    }

    fn uint(&mut self, k: &str, cx: &mut Ctx) -> Option<u64> {
        match self.map.remove(k)? {
            Value::Integer(i) if i >= 0 => Some(i as u64),
            _ => {
                self.mismatch(k, "a non-negative integer", cx);
                None
            }
        }
    }

    fn boolean(&mut self, k: &str, cx: &mut Ctx) -> Option<bool> {
        match self.map.remove(k)? {
            Value::Boolean(b) => Some(b),
            _ => {
                self.mismatch(k, "a boolean", cx);
                None
            }
        }
    }

    fn strings(&mut self, k: &str, cx: &mut Ctx) -> Vec<String> {
        let Some(v) = self.map.remove(k) else {
            return Vec::new();
        };
        let Value::Array(items) = v else {
            self.mismatch(k, "an array of strings", cx);
            return Vec::new();
        };
        let mut out = Vec::new();
        for item in items {
            match item {
                Value::String(s) => out.push(s),
                _ => self.mismatch(k, "an array of strings", cx),
            }
        }
        out
    }

    fn table(&mut self, k: &str, cx: &mut Ctx) -> Option<Tbl> {
        let v = self.map.remove(k)?;
        let path = self.key(k);
        Tbl::new(v, &path, cx)
    }

    fn tables(&mut self, k: &str, cx: &mut Ctx) -> Vec<Tbl> {
        let Some(v) = self.map.remove(k) else {
            return Vec::new();
        };
        let path = self.key(k);
        match v {
            Value::Array(items) => items
                .into_iter()
                .filter_map(|i| Tbl::new(i, &path, cx))
                .collect(),
            _ => {
                self.mismatch(k, "an array of tables", cx);
                Vec::new()
            }
        }
    }

    fn require_string(&mut self, k: &str, cx: &mut Ctx) -> Result<String, MigrateError> {
        let missing = !self.map.contains_key(k);
        match self.string(k, cx) {
            Some(s) => Ok(s),
            None if missing => Err(MigrateError::Missing(self.key(k))),
            None => Err(MigrateError::Invalid {
                key: self.key(k),
                value: "not a string".into(),
            }),
        }
    }

    fn require_uint(&mut self, k: &str, cx: &mut Ctx) -> Result<u64, MigrateError> {
        let missing = !self.map.contains_key(k);
        match self.uint(k, cx) {
            Some(n) => Ok(n),
            None if missing => Err(MigrateError::Missing(self.key(k))),
            None => Err(MigrateError::Invalid {
                key: self.key(k),
                value: "not a non-negative integer".into(),
            }),
        }
    }

    fn finish(self, cx: &mut Ctx) {
        for k in self.map.keys() {
            cx.unmapped.insert(self.key(k));
        }
    }
}

/// Translates a Decomp address (`va:X`, `rel:S:O`) or an already canonical one.
fn translate_address(text: &str) -> Option<Address> {
    if let Some(hex) = text.strip_prefix("va:") {
        return Some(Address::Flat(u32::from_str_radix(hex, 16).ok()?));
    }
    if let Some(rest) = text.strip_prefix("rel:") {
        let (seg, off) = rest.split_once(':')?;
        return Some(Address::Seg {
            seg: u16::from_str_radix(seg, 16).ok()?,
            off: u16::from_str_radix(off, 16).ok()?,
        });
    }
    text.parse().ok()
}

fn require_address(key: &str, text: &str) -> Result<Address, MigrateError> {
    translate_address(text).ok_or_else(|| MigrateError::Invalid {
        key: key.to_string(),
        value: text.to_string(),
    })
}

fn map_source(text: &str) -> Option<ClaimSource> {
    Some(match text {
        "mensch" => ClaimSource::Human,
        "ki" => ClaimSource::Agent,
        "signatur" => ClaimSource::Signature,
        "laufzeit" => ClaimSource::Runtime,
        "aehnlich" => ClaimSource::Similarity,
        "import" => ClaimSource::Import,
        "engine" => ClaimSource::Analysis,
        _ => return None,
    })
}

fn map_confidence(text: &str) -> Option<Confidence> {
    Some(match text {
        "belegt" => Confidence::Confirmed,
        "vermutet" => Confidence::Assumed,
        "widerlegt" => Confidence::Refuted,
        _ => return None,
    })
}

fn map_kind(text: &str) -> Option<SymbolKind> {
    Some(match text {
        "funktion" => SymbolKind::Function,
        "global" | "variable" => SymbolKind::Global,
        "marke" | "label" => SymbolKind::Label,
        _ => return None,
    })
}

fn map_detected_kind(text: &str) -> Option<&'static str> {
    Some(match text {
        "format" => "format",
        "packer" => "packer",
        "extender" => "extender",
        "compiler" => "compiler",
        "aufrufart" => "calling-convention",
        _ => return None,
    })
}

fn find_date(text: &str) -> Option<String> {
    let b = text.as_bytes();
    (0..b.len().saturating_sub(9)).find_map(|i| {
        let w = &b[i..i + 10];
        let ok = w.iter().enumerate().all(|(j, c)| match j {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        });
        ok.then(|| text[i..i + 10].to_string())
    })
}

/// Parses `"<name>: … (<source>, <confidence>; … YYYY-MM-DD …)"`; anything that does not fit goes to `note`.
fn parse_refuted(text: &str) -> RefutedClaim {
    let (name, rest) = match text.split_once(": ") {
        Some((n, r))
            if !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') =>
        {
            (n.to_string(), r.trim())
        }
        _ => (String::new(), text.trim()),
    };
    let mut claim = RefutedClaim {
        name,
        source: None,
        confidence: None,
        evidence: None,
        date: None,
        note: None,
    };
    let parsed = rest.strip_suffix(')').and_then(|body| {
        let open = body.rfind('(')?;
        let inner = &body[open + 1..];
        let (head, tail) = inner.split_once(';')?;
        let (source, confidence) = head.split_once(',')?;
        let source = map_source(source.trim())?;
        let confidence = map_confidence(confidence.trim())?;
        Some((body[..open].trim(), source, confidence, tail.trim()))
    });
    match parsed {
        Some((evidence, source, confidence, tail)) => {
            claim.source = Some(source);
            claim.confidence = Some(confidence);
            claim.evidence = (!evidence.is_empty()).then(|| evidence.to_string());
            claim.date = find_date(tail);
            claim.note = (!tail.is_empty()).then(|| tail.to_string());
        }
        None => {
            claim.date = rest
                .strip_suffix(')')
                .and_then(|b| b.rfind('(').map(|o| &b[o..]))
                .and_then(find_date);
            claim.note = Some(rest.to_string());
        }
    }
    claim
}

/// Migrates the Decomp workspace at `from` into `to` (created if missing).
pub fn migrate_decomp(from: &Path, to: &Path) -> Result<MigrationReport, MigrateError> {
    let mut cx = Ctx::default();
    let config_text = read(&from.join("decomp.toml"))?;
    let table: toml::Table =
        toml::from_str(&config_text).map_err(|source| MigrateError::Parse {
            path: from.join("decomp.toml"),
            source: Box::new(source),
        })?;
    let config = convert_config(table, &mut cx)?;

    let wissen = from.join("wissen");
    let mut symbols = Vec::new();
    let symbols_src = wissen.join("symbole.toml");
    if symbols_src.is_file() {
        let text = read(&symbols_src)?;
        let table: toml::Table = toml::from_str(&text).map_err(|source| MigrateError::Parse {
            path: symbols_src.clone(),
            source: Box::new(source),
        })?;
        symbols = convert_symbols(table, &mut cx)?;
    }
    let types = read_optional(&wissen.join("typen.h"))?;
    let notes = read_optional(&wissen.join("notizen.md"))?;

    report_leftover_files(from, &mut cx)?;

    let config_path = to.join(CONFIG_FILE);
    if config_path.exists() {
        return Err(MigrateError::TargetExists(to.to_path_buf()));
    }
    let knowledge = to.join("knowledge");
    create_dir(&knowledge)?;
    let config_toml = toml::to_string(&config).map_err(|source| MigrateError::Serialize {
        path: config_path.clone(),
        source: Box::new(source),
    })?;
    let symbols_toml = toml::to_string(&SymbolsFile {
        schema: SCHEMA,
        symbols,
    })
    .map_err(|source| MigrateError::Serialize {
        path: to.join(SYMBOLS_FILE),
        source: Box::new(source),
    })?;
    let mut converted = Vec::new();
    for (rel, content) in [
        (CONFIG_FILE, config_toml),
        (SYMBOLS_FILE, symbols_toml),
        ("knowledge/types.h", types),
        ("knowledge/notes.md", notes),
    ] {
        write(&to.join(rel), &content)?;
        converted.push(PathBuf::from(rel));
    }
    Ok(MigrationReport {
        converted,
        unmapped: cx.unmapped.into_iter().collect(),
        untranslated_texts: cx.texts,
    })
}

fn io(path: &Path, source: std::io::Error) -> MigrateError {
    MigrateError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn read(path: &Path) -> Result<String, MigrateError> {
    std::fs::read_to_string(path).map_err(|e| io(path, e))
}

fn read_optional(path: &Path) -> Result<String, MigrateError> {
    if path.is_file() {
        read(path)
    } else {
        Ok(String::new())
    }
}

fn create_dir(path: &Path) -> Result<(), MigrateError> {
    std::fs::create_dir_all(path).map_err(|e| io(path, e))
}

fn write(path: &Path, content: &str) -> Result<(), MigrateError> {
    std::fs::write(path, content).map_err(|e| io(path, e))
}

/// Files and folders of the Decomp workspace that have no counterpart are listed, not ignored.
fn report_leftover_files(from: &Path, cx: &mut Ctx) -> Result<(), MigrateError> {
    const ROOT_KNOWN: [&str; 6] = [
        "decomp.toml",
        "wissen",
        "ausgabe",
        "cache",
        ".gitignore",
        ".git",
    ];
    const WISSEN_KNOWN: [&str; 3] = ["symbole.toml", "typen.h", "notizen.md"];
    for (dir, known, prefix) in [
        (from.to_path_buf(), &ROOT_KNOWN[..], ""),
        (from.join("wissen"), &WISSEN_KNOWN[..], "wissen/"),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.map_err(|e| io(&dir, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !known.contains(&name.as_str()) {
                cx.unmapped.insert(format!("file:{prefix}{name}"));
            }
        }
    }
    Ok(())
}

fn convert_config(table: toml::Table, cx: &mut Ctx) -> Result<WorkspaceConfig, MigrateError> {
    let mut root = Tbl {
        path: String::new(),
        map: table,
    };
    let mut ziel = root
        .table("ziel", cx)
        .ok_or_else(|| MigrateError::Missing("ziel".into()))?;
    let file = ziel.require_string("datei", cx)?;
    let sha256 = ziel.require_string("sha256", cx)?;
    let format_text = ziel.require_string("format", cx)?;
    let format = match format_text.as_str() {
        "mz" => TargetFormat::Mz,
        "com" => TargetFormat::Com,
        "le" => TargetFormat::Le,
        "flach32" => TargetFormat::Flat32,
        _ => return Err(MigrateError::UnsupportedFormat(format_text)),
    };
    let processor = ziel.require_string("prozessor", cx)?;
    let mut segments = Vec::new();
    for mut s in ziel.tables("segment", cx) {
        let name = s.require_string("name", cx)?;
        let start_text = s.require_string("start", cx)?;
        let start = require_address(&s.key("start"), &start_text)?;
        let length = s.require_uint("laenge", cx)?;
        let file_offset = s.uint("datei_offset", cx);
        let file_length = s.uint("datei_laenge", cx);
        let permissions = s.string("rechte", cx).unwrap_or_else(|| "rwx".into());
        if permissions.is_empty() || !permissions.chars().all(|c| matches!(c, 'r' | 'w' | 'x')) {
            cx.unmapped
                .insert(format!("{}={permissions}", s.key("rechte")));
        }
        s.finish(cx);
        segments.push(SegmentConfig {
            name,
            start,
            length,
            file_offset,
            file_length,
            permissions,
        });
    }
    ziel.finish(cx);
    let target = TargetConfig {
        file,
        sha256,
        format,
        processor,
        segments,
    };

    let mut analysis = AnalysisConfig::default();
    if let Some(mut a) = root.table("analyse", cx) {
        analysis.prologues = a.strings("prologe", cx);
        analysis.calling_convention = a.string("aufrufart", cx);
        a.finish(cx);
    }

    let mut output = OutputConfig::default();
    if let Some(mut a) = root.table("ausgabe", cx) {
        if let Some(v) = a.boolean("versionieren", cx) {
            output.versioned = v;
        }
        a.finish(cx);
    }

    let mut detected = Vec::new();
    for mut e in root.tables("erkennung", cx) {
        let kind_text = e.require_string("art", cx)?;
        let kind = map_detected_kind(&kind_text)
            .map(str::to_string)
            .unwrap_or_else(|| {
                cx.unmapped.insert(format!("erkennung.art={kind_text}"));
                kind_text.clone()
            });
        let value = match e.map.remove("wert") {
            None => None,
            Some(Value::String(s)) => Some(s),
            Some(Value::Integer(i)) => Some(i.to_string()),
            Some(Value::Boolean(b)) => Some(b.to_string()),
            Some(_) => {
                e.mismatch("wert", "a scalar", cx);
                None
            }
        };
        let conf_text = e.string("sicherheit", cx);
        let confidence = match conf_text.as_deref() {
            None => Confidence::Assumed,
            Some(t) => map_confidence(t).unwrap_or_else(|| {
                cx.unmapped.insert(format!("erkennung.sicherheit={t}"));
                Confidence::Assumed
            }),
        };
        let evidence = e.text("beleg", cx);
        let source = e.string("quelle", cx).map(|q| match q.as_str() {
            "gepackt" => "packed".to_string(),
            _ => {
                cx.unmapped.insert(format!("erkennung.quelle={q}"));
                q
            }
        });
        e.finish(cx);
        detected.push(DetectedFact {
            kind,
            value,
            confidence,
            evidence,
            source,
        });
    }

    let unpacked = match root.table("entpackt", cx) {
        Some(mut u) => {
            let packer = u.require_string("packer", cx)?;
            let sha = u.require_string("sha256", cx)?;
            let entry_text = u.require_string("einsprung", cx)?;
            let entry = require_address("entpackt.einsprung", &entry_text)?;
            u.finish(cx);
            Some(UnpackedConfig {
                packer,
                sha256: sha,
                entry,
            })
        }
        None => None,
    };

    let runtime = match root.table("laufzeit", cx) {
        Some(mut l) => {
            let mut bases = Vec::new();
            for mut b in l.tables("basis", cx) {
                let segment = b.require_string("segment", cx)?;
                let text = b.require_string("basis_linear", cx)?;
                let digits = text
                    .strip_prefix("0x")
                    .or_else(|| text.strip_prefix("0X"))
                    .unwrap_or(&text);
                let linear_base =
                    u32::from_str_radix(digits, 16).map_err(|_| MigrateError::Invalid {
                        key: b.key("basis_linear"),
                        value: text.clone(),
                    })?;
                b.finish(cx);
                bases.push(RuntimeBase {
                    segment,
                    linear_base,
                });
            }
            l.finish(cx);
            Some(RuntimeConfig { bases })
        }
        None => None,
    };

    let rebuild = match root.table("nachbau", cx) {
        Some(mut n) => {
            let mut r = RebuildConfig {
                compiler: n.string("compiler", cx),
                flags: n.string("optionen", cx),
                link: None,
            };
            if let Some(mut l) = n.table("linken", cx) {
                r.link = Some(LinkConfig {
                    profile: l.string("profil", cx),
                    libraries: l.strings("bibliotheken", cx),
                    flags: l.string("optionen", cx),
                    startup: l.string("start", cx),
                });
                l.finish(cx);
            }
            n.finish(cx);
            Some(r)
        }
        None => None,
    };

    root.finish(cx);
    Ok(WorkspaceConfig {
        schema: SCHEMA,
        target,
        analysis,
        output,
        rebuild,
        runtime,
        unpacked,
        detected,
    })
}

fn convert_symbols(table: toml::Table, cx: &mut Ctx) -> Result<Vec<Symbol>, MigrateError> {
    let mut root = Tbl {
        path: String::new(),
        map: table,
    };
    let mut symbols = Vec::new();
    for mut s in root.tables("symbol", cx) {
        symbols.push(convert_symbol(&mut s, cx)?);
        s.finish(cx);
    }
    root.finish(cx);
    symbols.sort_by_key(|s| s.address);
    Ok(symbols)
}

fn convert_symbol(s: &mut Tbl, cx: &mut Ctx) -> Result<Symbol, MigrateError> {
    let addr_text = s.require_string("adresse", cx)?;
    let address = require_address("symbol.adresse", &addr_text)?;
    let kind = match s.string("art", cx) {
        None => SymbolKind::Function,
        Some(t) => map_kind(&t).unwrap_or_else(|| {
            cx.unmapped.insert(format!("symbol.art={t}"));
            SymbolKind::Other
        }),
    };
    let name = s.string("name", cx).unwrap_or_default();
    let mut symbol = Symbol::new(address, kind, name);
    symbol.signature = s.string("signatur", cx);
    symbol.comment = s.text("kommentar", cx);
    symbol.source = match s.string("quelle", cx) {
        None => ClaimSource::Human,
        Some(t) => map_source(&t).unwrap_or_else(|| {
            cx.unmapped.insert(format!("symbol.quelle={t}"));
            ClaimSource::Import
        }),
    };
    symbol.confidence = match s.string("sicherheit", cx) {
        None => Confidence::Assumed,
        Some(t) => map_confidence(&t).unwrap_or_else(|| {
            cx.unmapped.insert(format!("symbol.sicherheit={t}"));
            Confidence::Assumed
        }),
    };
    symbol.evidence = s.text("beleg", cx);
    for text in s.strings("widerlegt_frueher", cx) {
        cx.texts += 1;
        symbol.refuted.push(parse_refuted(&text));
    }
    symbol.data_type = s.string("typ", cx);
    symbol.size = s.uint("groesse", cx);
    symbol.library = s.string("bibliothek", cx);
    for mut l in s.tables("lokal", cx) {
        let place = l.require_string("platz", cx)?;
        let name = l.require_string("name", cx)?;
        let data_type = l.string("typ", cx);
        l.finish(cx);
        symbol.locals.push(LocalVariable {
            place,
            name,
            data_type,
        });
    }
    for mut c in s.tables("zeilenkommentar", cx) {
        let at = c.require_string("adresse", cx)?;
        let address = require_address("symbol.zeilenkommentar.adresse", &at)?;
        let text = match c.text("text", cx) {
            Some(t) => t,
            None => return Err(MigrateError::Missing(c.key("text"))),
        };
        let source = match c.string("quelle", cx) {
            None => ClaimSource::Human,
            Some(t) => map_source(&t).unwrap_or_else(|| {
                cx.unmapped
                    .insert(format!("symbol.zeilenkommentar.quelle={t}"));
                ClaimSource::Import
            }),
        };
        c.finish(cx);
        symbol.line_comments.push(LineComment {
            address,
            text,
            source,
        });
    }
    Ok(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;

    const MINIMAL: &str = r#"
[ziel]
datei = "bin/PROGRAM.EXE"
sha256 = "ab12"
format = "le"
prozessor = "x86:LE:32:default"
segment = [
    { name = "obj1", start = "va:00010000", laenge = 4096, datei_offset = 512, datei_laenge = 4000, rechte = "rx" },
]

[analyse]
prologe = ["5589E5"]
aufrufart = "__watcall"

[ausgabe]
versionieren = false

[[erkennung]]
art = "compiler"
wert = "watcom"
sicherheit = "vermutet"
beleg = "Muster im Startcode"

[laufzeit]
basis = [{ segment = "obj1", basis_linear = "0x001B3000" }]

[nachbau]
compiler = "watcom-9.5"
optionen = "-ox"

[nachbau.linken]
profil = "watcom-10.6"
"#;

    fn setup(config: &str, symbols: Option<&str>) -> (tempfile::TempDir, tempfile::TempDir) {
        let from = tempfile::tempdir().unwrap();
        let to = tempfile::tempdir().unwrap();
        std::fs::write(from.path().join("decomp.toml"), config).unwrap();
        if let Some(s) = symbols {
            std::fs::create_dir(from.path().join("wissen")).unwrap();
            std::fs::write(from.path().join("wissen/symbole.toml"), s).unwrap();
        }
        (from, to)
    }

    #[test]
    fn migrates_minimal_decomp_toml() {
        let (from, to) = setup(MINIMAL, None);
        let report = migrate_decomp(from.path(), to.path()).unwrap();
        assert!(report.unmapped.is_empty(), "{:?}", report.unmapped);
        assert_eq!(report.untranslated_texts, 1);
        let ws = Workspace::open(to.path()).unwrap();
        let c = &ws.config;
        assert_eq!(c.schema, 1);
        assert_eq!(c.target.file, "bin/PROGRAM.EXE");
        assert_eq!(c.target.format, TargetFormat::Le);
        let seg = &c.target.segments[0];
        assert_eq!(seg.start, Address::Flat(0x10000));
        assert_eq!(
            (seg.length, seg.file_offset, seg.file_length),
            (4096, Some(512), Some(4000))
        );
        assert_eq!(seg.permissions, "rx");
        assert_eq!(c.analysis.prologues, ["5589E5"]);
        assert_eq!(c.analysis.calling_convention.as_deref(), Some("__watcall"));
        assert!(!c.output.versioned);
        assert_eq!(c.detected[0].kind, "compiler");
        assert_eq!(c.detected[0].confidence, Confidence::Assumed);
        assert_eq!(c.runtime.as_ref().unwrap().bases[0].linear_base, 0x1B3000);
        let r = c.rebuild.as_ref().unwrap();
        assert_eq!(r.flags.as_deref(), Some("-ox"));
        assert_eq!(
            r.link.as_ref().unwrap().profile.as_deref(),
            Some("watcom-10.6")
        );
        let written = std::fs::read_to_string(to.path().join("knowledge/symbols.toml")).unwrap();
        assert!(written.contains("schema = 1"));
        assert!(to.path().join("knowledge/types.h").is_file());
        assert!(to.path().join("knowledge/notes.md").is_file());
    }

    #[test]
    fn maps_symbol_keys_and_values() {
        let symbols = r#"
[[symbol]]
adresse = "va:00010010"
art = "funktion"
name = "choose_music"
signatur = "void __cdecl choose_music(void)"
kommentar = "Waehlt die Musik."
quelle = "ki"
sicherheit = "belegt"
beleg = "Laufzeit"
groesse = 12
lokal = [{ platz = "stack:-0x14", name = "mode" }]

[[symbol]]
adresse = "rel:1234:0010"
art = "variable"
name = "counter"
quelle = "aehnlich"
sicherheit = "vermutet"

[[symbol]]
adresse = "va:00020000"
art = "marke"
quelle = "engine"
sicherheit = "belegt"

[[symbol]]
adresse = "va:00030000"
art = "zauber"
foo = 1
"#;
        let (from, to) = setup(MINIMAL, Some(symbols));
        let report = migrate_decomp(from.path(), to.path()).unwrap();
        assert_eq!(report.unmapped, ["symbol.art=zauber", "symbol.foo"]);
        let ws = Workspace::open(to.path()).unwrap();
        assert_eq!(ws.symbols.len(), 4);
        let f = &ws.symbols[0];
        assert_eq!(f.address, Address::Flat(0x10010));
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(f.source, ClaimSource::Agent);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.comment.as_deref(), Some("Waehlt die Musik."));
        assert_eq!(f.evidence.as_deref(), Some("Laufzeit"));
        assert_eq!(f.size, Some(12));
        assert_eq!(f.locals[0].place, "stack:-0x14");
        let g = ws
            .symbols
            .iter()
            .find(|s| {
                s.address
                    == Address::Seg {
                        seg: 0x1234,
                        off: 0x10,
                    }
            })
            .unwrap();
        assert_eq!(g.kind, SymbolKind::Global);
        assert_eq!(g.source, ClaimSource::Similarity);
        let l = ws
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Label)
            .unwrap();
        assert_eq!(l.source, ClaimSource::Analysis);
        assert!(ws.symbols.iter().any(|s| s.kind == SymbolKind::Other));
    }

    #[test]
    fn parses_refuted_history_entry() {
        let c = parse_refuted(
            "alter_name: ersetzt durch new_name (ki, vermutet; Abgabe 2026-10-18, ohne Sperre)",
        );
        assert_eq!(c.name, "alter_name");
        assert_eq!(c.source, Some(ClaimSource::Agent));
        assert_eq!(c.confidence, Some(Confidence::Assumed));
        assert_eq!(c.date.as_deref(), Some("2026-10-18"));
        assert_eq!(c.evidence.as_deref(), Some("ersetzt durch new_name"));
        assert_eq!(c.note.as_deref(), Some("Abgabe 2026-10-18, ohne Sperre"));
    }

    #[test]
    fn unparsable_refuted_entry_goes_to_note() {
        let c = parse_refuted("foo_bar: Kein Anheben, sondern Ausloesen (Pruefer 2026-10-15)");
        assert_eq!(c.name, "foo_bar");
        assert_eq!(c.source, None);
        assert_eq!(c.date.as_deref(), Some("2026-10-15"));
        assert_eq!(
            c.note.as_deref(),
            Some("Kein Anheben, sondern Ausloesen (Pruefer 2026-10-15)")
        );
        let d = parse_refuted("irgendein freier Text");
        assert_eq!(d.name, "");
        assert_eq!(d.note.as_deref(), Some("irgendein freier Text"));
    }

    #[test]
    fn unknown_key_is_reported() {
        let config = MINIMAL.replace("[ziel]\n", "[ziel]\nfoo = 1\n");
        let (from, to) = setup(&config, None);
        let report = migrate_decomp(from.path(), to.path()).unwrap();
        assert_eq!(report.unmapped, ["ziel.foo"]);
    }

    #[test]
    fn leftover_files_are_reported() {
        let (from, to) = setup(MINIMAL, Some(""));
        std::fs::write(from.path().join("wissen/verweise.toml"), "").unwrap();
        let report = migrate_decomp(from.path(), to.path()).unwrap();
        assert_eq!(report.unmapped, ["file:wissen/verweise.toml"]);
    }

    #[test]
    fn refuses_existing_workspace() {
        let (from, to) = setup(MINIMAL, None);
        migrate_decomp(from.path(), to.path()).unwrap();
        assert!(matches!(
            migrate_decomp(from.path(), to.path()),
            Err(MigrateError::TargetExists(_))
        ));
    }

    #[test]
    fn workspace_open_reads_config() {
        let (from, to) = setup(MINIMAL, None);
        migrate_decomp(from.path(), to.path()).unwrap();
        let ws = Workspace::open(to.path()).unwrap();
        assert_eq!(ws.root, to.path());
        assert!(ws.symbols.is_empty());
        std::fs::write(to.path().join("decovery.toml"), "schema = 2\n").unwrap();
        assert!(matches!(
            Workspace::open(to.path()),
            Err(crate::workspace::WorkspaceError::Parse { .. })
                | Err(crate::workspace::WorkspaceError::Schema { .. })
        ));
    }
}
