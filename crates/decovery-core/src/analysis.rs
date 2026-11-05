//! Analysis store: provider results kept in `knowledge/analysis/` (ADR 0005).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::records::REFERENCES_FILE;
use crate::store::{TYPES_FILE, WorkspaceLock, write_atomic};
use crate::workspace::{SCHEMA, SYMBOLS_FILE, WorkspaceError};

/// Directory below the workspace root that holds the analysis.
pub const ANALYSIS_DIR: &str = "knowledge/analysis";
const ANALYSIS_FILE: &str = "knowledge/analysis/analysis.json";
const DECOMPILED_DIR: &str = "knowledge/analysis/decompiled";

/// The tool that produced an analysis (`ghidra`, `decomp-import`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Provider {
    pub name: String,
    pub version: String,
}

impl Provider {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Provider {
            name: name.into(),
            version: version.into(),
        }
    }
}

/// A function found by the provider. `end` is inclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AnalyzedFunction {
    pub start: Address,
    pub end: Address,
    pub body_size: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decompile_error: Option<String>,
}

impl AnalyzedFunction {
    pub fn new(start: Address, end: Address, body_size: u32) -> Self {
        AnalyzedFunction {
            start,
            end,
            body_size,
            provider_name: None,
            decompile_error: None,
        }
    }
}

/// One call instruction: `site` lies inside `caller` and targets `callee`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CallEdge {
    pub site: Address,
    pub caller: Address,
    pub callee: Address,
}

impl CallEdge {
    pub fn new(site: Address, caller: Address, callee: Address) -> Self {
        CallEdge {
            site,
            caller,
            callee,
        }
    }
}

/// A string literal and the functions that use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StringItem {
    pub address: Address,
    pub text: String,
    pub users: Vec<Address>,
}

impl StringItem {
    pub fn new(address: Address, text: impl Into<String>, users: Vec<Address>) -> Self {
        StringItem {
            address,
            text: text.into(),
            users,
        }
    }
}

/// Whether a function reads or writes a data address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AccessKind {
    Read,
    Write,
}

/// One data access of a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DataAccess {
    pub function: Address,
    pub address: Address,
    pub kind: AccessKind,
}

impl DataAccess {
    pub fn new(function: Address, address: Address, kind: AccessKind) -> Self {
        DataAccess {
            function,
            address,
            kind,
        }
    }
}

/// Provider results for one target (`knowledge/analysis/analysis.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Analysis {
    pub schema: u32,
    pub provider: Provider,
    pub target_sha256: String,
    pub knowledge_hash: String,
    pub created: String,
    pub functions: Vec<AnalyzedFunction>,
    pub calls: Vec<CallEdge>,
    pub strings: Vec<StringItem>,
    pub data_accesses: Vec<DataAccess>,
}

fn io_error(path: &Path, source: std::io::Error) -> WorkspaceError {
    WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl Analysis {
    /// An analysis without results; fill the public vectors, then `save`.
    pub fn new(
        provider: Provider,
        target_sha256: impl Into<String>,
        knowledge_hash: impl Into<String>,
        created: impl Into<String>,
    ) -> Self {
        Analysis {
            schema: SCHEMA,
            provider,
            target_sha256: target_sha256.into(),
            knowledge_hash: knowledge_hash.into(),
            created: created.into(),
            functions: Vec::new(),
            calls: Vec::new(),
            strings: Vec::new(),
            data_accesses: Vec::new(),
        }
    }

    /// Reads `knowledge/analysis/analysis.json`; `None` if the file is absent.
    pub fn load(root: &Path) -> Result<Option<Analysis>, WorkspaceError> {
        let path = root.join(ANALYSIS_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(&path, e)),
        };
        let analysis: Analysis = serde_json::from_str(&text).map_err(|e| WorkspaceError::Json {
            path: path.clone(),
            source: Box::new(e),
        })?;
        if analysis.schema != SCHEMA {
            return Err(WorkspaceError::Schema {
                path,
                found: analysis.schema,
            });
        }
        Ok(Some(analysis))
    }

    /// Writes `analysis.json` atomically: functions by start, calls by site, strings by address.
    pub fn save(&self, root: &Path, _lock: &WorkspaceLock) -> Result<(), WorkspaceError> {
        let path = root.join(ANALYSIS_FILE);
        let mut sorted = self.clone();
        sorted.functions.sort_by_key(|f| f.start);
        sorted.calls.sort_by_key(|c| c.site);
        sorted.strings.sort_by_key(|s| s.address);
        let mut text = serde_json::to_string_pretty(&sorted).map_err(|e| WorkspaceError::Json {
            path: path.clone(),
            source: Box::new(e),
        })?;
        text.push('\n');
        write_atomic(&path, text.as_bytes()).map_err(|e| io_error(&path, e))
    }

    /// The pseudo-C stored for the function at `start`, if any.
    pub fn decompiled(root: &Path, start: Address) -> Result<Option<String>, WorkspaceError> {
        let path = decompiled_path(root, start);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&path, e)),
        }
    }

    /// Stores pseudo-C for the function at `start` as the provider printed it.
    pub fn save_decompiled(
        root: &Path,
        start: Address,
        code: &str,
        _lock: &WorkspaceLock,
    ) -> Result<(), WorkspaceError> {
        let path = decompiled_path(root, start);
        write_atomic(&path, code.as_bytes()).map_err(|e| io_error(&path, e))
    }

    /// Removes the stored pseudo-C of every function not in `keep`; returns how many files were removed.
    /// Files whose name is no address are left alone.
    pub fn remove_decompiled_except(
        root: &Path,
        keep: &std::collections::HashSet<Address>,
        _lock: &WorkspaceLock,
    ) -> Result<u32, WorkspaceError> {
        let dir = root.join(DECOMPILED_DIR);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(io_error(&dir, e)),
        };
        let mut removed = 0;
        for entry in entries {
            let path = entry.map_err(|e| io_error(&dir, e))?.path();
            let start = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".c"))
                .and_then(|stem| stem.replace('_', ":").parse::<Address>().ok());
            if let Some(start) = start
                && !keep.contains(&start)
                && path.is_file()
            {
                std::fs::remove_file(&path).map_err(|e| io_error(&path, e))?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Lookup tables over this analysis, built once.
    pub fn index(&self) -> AnalysisIndex<'_> {
        let mut functions: Vec<&AnalyzedFunction> = self.functions.iter().collect();
        functions.sort_by_key(|f| f.start);
        let mut calls: Vec<&CallEdge> = self.calls.iter().collect();
        calls.sort_by_key(|c| c.site);
        let mut callers: HashMap<Address, Vec<&CallEdge>> = HashMap::new();
        let mut callees: HashMap<Address, Vec<&CallEdge>> = HashMap::new();
        for edge in calls {
            callers.entry(edge.callee).or_default().push(edge);
            callees.entry(edge.caller).or_default().push(edge);
        }
        let mut strings: HashMap<Address, Vec<&StringItem>> = HashMap::new();
        let mut items: Vec<&StringItem> = self.strings.iter().collect();
        items.sort_by_key(|s| s.address);
        for item in items {
            for user in &item.users {
                let list = strings.entry(*user).or_default();
                if list.last().is_none_or(|last| !std::ptr::eq(*last, item)) {
                    list.push(item);
                }
            }
        }
        let mut accesses: HashMap<Address, Vec<&DataAccess>> = HashMap::new();
        for access in &self.data_accesses {
            accesses.entry(access.function).or_default().push(access);
        }
        AnalysisIndex {
            functions,
            callers,
            callees,
            strings,
            accesses,
        }
    }
}

/// Lookup tables over an [`Analysis`].
pub struct AnalysisIndex<'a> {
    functions: Vec<&'a AnalyzedFunction>,
    callers: HashMap<Address, Vec<&'a CallEdge>>,
    callees: HashMap<Address, Vec<&'a CallEdge>>,
    strings: HashMap<Address, Vec<&'a StringItem>>,
    accesses: HashMap<Address, Vec<&'a DataAccess>>,
}

impl<'a> AnalysisIndex<'a> {
    /// The function whose `start..=end` contains `at`.
    pub fn function_containing(&self, at: Address) -> Option<&'a AnalyzedFunction> {
        let after = self.functions.partition_point(|f| f.start <= at);
        let candidate = *self.functions.get(after.checked_sub(1)?)?;
        (at <= candidate.end).then_some(candidate)
    }

    /// The function starting exactly at `start`.
    pub fn function_at(&self, start: Address) -> Option<&'a AnalyzedFunction> {
        let i = self.functions.partition_point(|f| f.start < start);
        self.functions.get(i).copied().filter(|f| f.start == start)
    }

    /// Call edges whose callee is `f`, by site.
    pub fn callers(&self, f: Address) -> &[&'a CallEdge] {
        self.callers.get(&f).map_or(&[], Vec::as_slice)
    }

    /// Call edges whose caller is `f`, by site.
    pub fn callees(&self, f: Address) -> &[&'a CallEdge] {
        self.callees.get(&f).map_or(&[], Vec::as_slice)
    }

    /// Strings used by `f`, in address order.
    pub fn strings_used_by(&self, f: Address) -> Vec<&'a StringItem> {
        self.strings.get(&f).cloned().unwrap_or_default()
    }

    /// Data accesses of `f`, in stored order.
    pub fn accesses_of(&self, f: Address) -> &[&'a DataAccess] {
        self.accesses.get(&f).map_or(&[], Vec::as_slice)
    }
}

/// Today's date (UTC) as `YYYY-MM-DD`; the `created` date of an analysis and the date of history entries.
pub fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400) as i64;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// blake3 (hex) over `symbols.toml`, `types.h` and `references.toml`.
///
/// Each file contributes its name, a presence byte and its length-prefixed content, in that fixed order.
pub fn knowledge_hash(root: &Path) -> Result<String, WorkspaceError> {
    let mut hasher = blake3::Hasher::new();
    for name in [SYMBOLS_FILE, TYPES_FILE, REFERENCES_FILE] {
        let path = root.join(name);
        let content = match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(&path, e)),
        };
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        match content {
            Some(bytes) => {
                hasher.update(&[1]);
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(&bytes);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn decompiled_path(root: &Path, start: Address) -> PathBuf {
    root.join(DECOMPILED_DIR)
        .join(format!("{}.c", start.to_string().replace(':', "_")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{Symbol, SymbolKind};
    use crate::workspace::{CONFIG_FILE, TargetConfig, TargetFormat, Workspace, WorkspaceConfig};
    use std::time::Duration;

    fn workspace(dir: &Path, symbols: Vec<Symbol>) -> Workspace {
        let config = WorkspaceConfig {
            schema: SCHEMA,
            target: TargetConfig {
                file: "t.exe".into(),
                sha256: "00".into(),
                format: TargetFormat::Flat32,
                processor: "x86".into(),
                segments: Vec::new(),
            },
            analysis: Default::default(),
            output: Default::default(),
            rebuild: None,
            runtime: None,
            unpacked: None,
            detected: Vec::new(),
            plugins: Default::default(),
        };
        std::fs::write(dir.join(CONFIG_FILE), toml::to_string(&config).unwrap()).unwrap();
        Workspace {
            root: dir.to_path_buf(),
            config,
            symbols,
        }
    }

    fn flat(a: u32) -> Address {
        Address::Flat(a)
    }

    fn sample() -> Analysis {
        let mut a = Analysis::new(
            Provider::new("ghidra", "11.3"),
            "ab".repeat(32),
            "cd".repeat(32),
            "2026-11-05",
        );
        let mut f2 = AnalyzedFunction::new(flat(0x10100), flat(0x1017F), 128);
        f2.provider_name = Some("FUN_00010100".into());
        let mut f1 = AnalyzedFunction::new(flat(0x10010), flat(0x100FF), 240);
        f1.decompile_error = Some("timeout".into());
        // stored unsorted on purpose; save sorts
        a.functions = vec![f2, f1];
        a.calls = vec![
            CallEdge::new(flat(0x10120), flat(0x10100), flat(0x10010)),
            CallEdge::new(flat(0x10020), flat(0x10010), flat(0x10100)),
            CallEdge::new(flat(0x10030), flat(0x10010), flat(0x10100)),
        ];
        a.strings = vec![
            StringItem::new(flat(0x20040), "world", vec![flat(0x10100)]),
            StringItem::new(flat(0x20000), "hello", vec![flat(0x10010), flat(0x10100)]),
        ];
        a.data_accesses = vec![
            DataAccess::new(flat(0x10010), flat(0x30000), AccessKind::Write),
            DataAccess::new(flat(0x10010), flat(0x30004), AccessKind::Read),
            DataAccess::new(flat(0x10100), flat(0x30000), AccessKind::Read),
        ];
        a
    }

    #[test]
    fn analysis_round_trip_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        let lock = ws.lock(Duration::ZERO).unwrap();
        assert!(Analysis::load(dir.path()).unwrap().is_none());
        sample().save(dir.path(), &lock).unwrap();
        let path = dir.path().join(ANALYSIS_FILE);
        let first = std::fs::read(&path).unwrap();
        assert_eq!(first.last(), Some(&b'\n'));
        assert!(!first.contains(&b'\r'));
        let loaded = Analysis::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.functions[0].start, flat(0x10010));
        assert_eq!(loaded.calls[0].site, flat(0x10020));
        assert_eq!(loaded.strings[0].text, "hello");
        loaded.save(dir.path(), &lock).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), first);
        assert!(
            !dir.path()
                .join("knowledge/analysis/analysis.json.tmp")
                .exists()
        );
    }

    #[test]
    fn function_containing_finds_inner_address() {
        let a = sample();
        let index = a.index();
        let f = index.function_containing(flat(0x10050)).unwrap();
        assert_eq!(f.start, flat(0x10010));
        assert_eq!(
            index.function_containing(flat(0x10010)).unwrap().start,
            flat(0x10010)
        );
        assert_eq!(
            index.function_containing(flat(0x100FF)).unwrap().start,
            flat(0x10010)
        );
        assert_eq!(
            index.function_containing(flat(0x1017F)).unwrap().start,
            flat(0x10100)
        );
        assert_eq!(index.function_at(flat(0x10100)).unwrap().body_size, 128);
        assert!(index.function_at(flat(0x10101)).is_none());
    }

    #[test]
    fn function_containing_between_functions_is_none() {
        let mut a = sample();
        a.functions = vec![
            AnalyzedFunction::new(flat(0x10010), flat(0x10050), 64),
            AnalyzedFunction::new(flat(0x10100), flat(0x1017F), 128),
        ];
        let index = a.index();
        assert!(index.function_containing(flat(0x10051)).is_none());
        assert!(index.function_containing(flat(0x100FF)).is_none());
        assert!(index.function_containing(flat(0x10000)).is_none());
        assert!(index.function_containing(flat(0x10180)).is_none());
    }

    #[test]
    fn callers_and_callees_are_grouped() {
        let a = sample();
        let index = a.index();
        let callees = index.callees(flat(0x10010));
        assert_eq!(callees.len(), 2);
        assert_eq!(callees[0].site, flat(0x10020));
        assert_eq!(callees[1].site, flat(0x10030));
        let callers = index.callers(flat(0x10010));
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].caller, flat(0x10100));
        assert_eq!(index.callers(flat(0x10100)).len(), 2);
        assert!(index.callers(flat(0x99999)).is_empty());
        let strings = index.strings_used_by(flat(0x10100));
        let texts: Vec<&str> = strings.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, ["hello", "world"]);
        let accesses = index.accesses_of(flat(0x10010));
        assert_eq!(accesses.len(), 2);
        assert_eq!(accesses[0].kind, AccessKind::Write);
        assert!(index.accesses_of(flat(0x99999)).is_empty());
    }

    #[test]
    fn decompiled_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        let lock = ws.lock(Duration::ZERO).unwrap();
        assert!(
            Analysis::decompiled(dir.path(), flat(0x10010))
                .unwrap()
                .is_none()
        );
        let code = "int f(void)\n{\n  return 1;\n}\n";
        Analysis::save_decompiled(dir.path(), flat(0x10010), code, &lock).unwrap();
        let file = dir
            .path()
            .join("knowledge/analysis/decompiled/flat_00010010.c");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), code);
        assert_eq!(
            Analysis::decompiled(dir.path(), flat(0x10010))
                .unwrap()
                .as_deref(),
            Some(code)
        );
    }

    #[test]
    fn remove_decompiled_except_keeps_listed_and_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        let lock = ws.lock(Duration::ZERO).unwrap();
        let none = std::collections::HashSet::new();
        assert_eq!(
            Analysis::remove_decompiled_except(dir.path(), &none, &lock).unwrap(),
            0
        );
        for a in [0x10010, 0x10100] {
            Analysis::save_decompiled(dir.path(), flat(a), "x\n", &lock).unwrap();
        }
        let seg = Address::Seg {
            seg: 0x1234,
            off: 0x10,
        };
        Analysis::save_decompiled(dir.path(), seg, "x\n", &lock).unwrap();
        let foreign = dir.path().join(DECOMPILED_DIR).join("notes.c");
        std::fs::write(&foreign, "keep").unwrap();
        let keep = [flat(0x10100)].into_iter().collect();
        assert_eq!(
            Analysis::remove_decompiled_except(dir.path(), &keep, &lock).unwrap(),
            2
        );
        assert!(
            Analysis::decompiled(dir.path(), flat(0x10010))
                .unwrap()
                .is_none()
        );
        assert!(Analysis::decompiled(dir.path(), seg).unwrap().is_none());
        assert!(
            Analysis::decompiled(dir.path(), flat(0x10100))
                .unwrap()
                .is_some()
        );
        assert!(foreign.is_file());
    }

    #[test]
    fn knowledge_hash_changes_with_symbols() {
        let dir = tempfile::tempdir().unwrap();
        let mut ws = workspace(dir.path(), Vec::new());
        let lock = ws.lock(Duration::ZERO).unwrap();
        let empty = knowledge_hash(dir.path()).unwrap();
        assert_eq!(empty, knowledge_hash(dir.path()).unwrap());
        ws.symbols = vec![Symbol::new(flat(0x10010), SymbolKind::Function, "choose")];
        ws.save_symbols(&lock).unwrap();
        let one = knowledge_hash(dir.path()).unwrap();
        assert_ne!(empty, one);
        assert_eq!(one.len(), 64);
        ws.symbols = vec![Symbol::new(flat(0x10010), SymbolKind::Function, "pick")];
        ws.save_symbols(&lock).unwrap();
        assert_ne!(one, knowledge_hash(dir.path()).unwrap());
    }
}
