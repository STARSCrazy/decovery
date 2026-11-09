//! Writing the workspace back: atomic file writes and the workspace lock.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::knowledge::{ClaimSource, Symbol, SymbolsFile};
use crate::workspace::{SCHEMA, SYMBOLS_FILE, Workspace, WorkspaceError};

/// Path of the types header relative to the workspace root.
pub const TYPES_FILE: &str = "knowledge/types.h";
/// Path of the lock file relative to the workspace root.
pub const LOCK_FILE: &str = "cache/workspace.lock";
/// Pid of the lock holder. Kept beside the lock file because on Windows a locked file cannot be read
/// through another handle.
const PID_FILE: &str = "cache/workspace.lock.pid";
const POLL: Duration = Duration::from_millis(50);

/// Writes `bytes` to `<path>.tmp` and renames it over `path`, creating parent directories.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    let result = (|| {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Exclusive write access to a workspace. The OS lock is released when this is dropped or the process dies.
#[derive(Debug)]
pub struct WorkspaceLock {
    _file: File,
}

fn io_error(path: &Path, source: std::io::Error) -> WorkspaceError {
    WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl Workspace {
    /// Takes the workspace lock, retrying until `wait` has passed; then fails with `Locked { pid }`.
    pub fn lock(&self, wait: Duration) -> Result<WorkspaceLock, WorkspaceError> {
        let path = self.root.join(LOCK_FILE);
        let pid_path = self.root.join(PID_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| io_error(&path, e))?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => {
                    if start.elapsed() >= wait {
                        let pid = std::fs::read_to_string(&pid_path)
                            .ok()
                            .and_then(|t| t.trim().parse().ok())
                            .unwrap_or(0);
                        return Err(WorkspaceError::Locked { pid });
                    }
                    std::thread::sleep(POLL.min(wait.saturating_sub(start.elapsed())));
                }
                Err(TryLockError::Error(e)) => return Err(io_error(&path, e)),
            }
        }
        let pid = std::process::id().to_string();
        write_atomic(&pid_path, pid.as_bytes()).map_err(|e| io_error(&pid_path, e))?;
        // Best effort: the holder's own handle may write its pid into the lock file itself.
        let mut handle = &file;
        let _ = file
            .set_len(0)
            .and_then(|()| handle.write_all(pid.as_bytes()));
        Ok(WorkspaceLock { _file: file })
    }

    /// Writes `knowledge/symbols.toml` from `self.symbols`, sorted by address, then kind.
    pub fn save_symbols(&self, _lock: &WorkspaceLock) -> Result<(), WorkspaceError> {
        let path = self.root.join(SYMBOLS_FILE);
        for s in &self.symbols {
            let unknown = [
                (s.source == ClaimSource::Other).then_some("source"),
                s.refuted
                    .iter()
                    .any(|r| r.source == Some(ClaimSource::Other))
                    .then_some("refuted source"),
                s.line_comments
                    .iter()
                    .any(|c| c.source == ClaimSource::Other)
                    .then_some("line comment source"),
            ];
            if let Some(field) = unknown.into_iter().flatten().next() {
                return Err(WorkspaceError::UnknownValue {
                    file: path,
                    detail: format!("symbol at {} has an unknown {field}", s.address),
                });
            }
        }
        let text = SymbolsFile::new(self.symbols.clone())
            .to_toml()
            .map_err(|e| io_error(&path, std::io::Error::other(e)))?;
        write_atomic(&path, text.as_bytes()).map_err(|e| io_error(&path, e))
    }

    /// Adds symbols to `knowledge/symbols.toml` as it is on disk now (read under `lock`, so claims written since
    /// this workspace was opened are seen): `decide` gets the current symbols and returns the ones to add. Nothing
    /// is written when it returns none. The file is written like [`Workspace::save_symbols`] (atomic, sorted,
    /// `schema = 1`, unknown keys kept) and `self.symbols` becomes its content. Returns the added symbols.
    pub fn add_symbols(
        &mut self,
        decide: impl FnOnce(&[Symbol]) -> Vec<Symbol>,
        lock: &WorkspaceLock,
    ) -> Result<Vec<Symbol>, WorkspaceError> {
        let path = self.root.join(SYMBOLS_FILE);
        let current = match std::fs::read_to_string(&path) {
            Ok(text) => {
                let file: SymbolsFile =
                    toml::from_str(&text).map_err(|source| WorkspaceError::Parse {
                        path: path.clone(),
                        source: Box::new(source),
                    })?;
                if file.schema != SCHEMA {
                    return Err(WorkspaceError::Schema {
                        path,
                        found: file.schema,
                    });
                }
                file.symbols
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io_error(&path, e)),
        };
        let added = decide(&current);
        if added.is_empty() {
            self.symbols = current;
            return Ok(added);
        }
        let before = std::mem::replace(&mut self.symbols, current);
        self.symbols.extend(added.iter().cloned());
        let saved = self.save_symbols(lock);
        if saved.is_err() {
            self.symbols = before;
        }
        saved.map(|()| added)
    }

    /// Content of `knowledge/types.h`; empty when the file does not exist.
    pub fn types_h(&self) -> Result<String, WorkspaceError> {
        let path = self.root.join(TYPES_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(io_error(&path, e)),
        }
    }

    /// Replaces `knowledge/types.h`.
    pub fn save_types_h(&self, text: &str, _lock: &WorkspaceLock) -> Result<(), WorkspaceError> {
        let path = self.root.join(TYPES_FILE);
        write_atomic(&path, text.as_bytes()).map_err(|e| io_error(&path, e))
    }
}

impl SymbolsFile {
    /// A file with the current schema and `symbols` sorted by address, then kind (stable).
    pub fn new(mut symbols: Vec<Symbol>) -> Self {
        symbols.sort_by_key(|s| (s.address, s.kind));
        SymbolsFile {
            schema: SCHEMA,
            symbols,
        }
    }

    /// The one serialization of `symbols.toml`: deterministic, LF line endings.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::knowledge::{
        ClaimSource, Confidence, LineComment, LocalVariable, RefutedClaim, SymbolKind,
    };
    use crate::workspace::{CONFIG_FILE, TargetConfig, TargetFormat, WorkspaceConfig};
    use std::sync::Arc;

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

    fn full_symbol() -> Symbol {
        let mut s = Symbol::new(Address::Flat(0x10010), SymbolKind::Function, "choose");
        s.signature = Some("int choose(int a)".into());
        s.comment = Some("picks".into());
        s.source = ClaimSource::Agent;
        s.confidence = Confidence::Confirmed;
        s.evidence = Some("seen".into());
        s.refuted = vec![RefutedClaim {
            name: "old".into(),
            source: Some(ClaimSource::Human),
            confidence: Some(Confidence::Refuted),
            evidence: Some("no".into()),
            date: Some("2026-01-01".into()),
            note: Some("n".into()),
        }];
        s.data_type = Some("int".into());
        s.size = Some(12);
        s.library = Some("libc".into());
        s.locals = vec![LocalVariable {
            place: "stack:-0x14".into(),
            name: "i".into(),
            data_type: Some("int".into()),
        }];
        s.line_comments = vec![LineComment {
            address: Address::Flat(0x10014),
            text: "loop".into(),
            source: ClaimSource::Human,
        }];
        s
    }

    #[test]
    fn symbols_round_trip_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), vec![full_symbol()]);
        let lock = ws.lock(Duration::from_secs(1)).unwrap();
        ws.save_symbols(&lock).unwrap();
        let first = std::fs::read(dir.path().join(SYMBOLS_FILE)).unwrap();
        let reopened = Workspace::open(dir.path()).unwrap();
        assert_eq!(reopened.symbols, ws.symbols);
        reopened.save_symbols(&lock).unwrap();
        let second = std::fs::read(dir.path().join(SYMBOLS_FILE)).unwrap();
        assert_eq!(first, second);
        assert!(!first.contains(&b'\r'));
    }

    #[test]
    fn save_refuses_unknown_source_and_keeps_file() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        let path = dir.path().join(SYMBOLS_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let text = "schema = 1

[[symbol]]
address = \"flat:00010010\"
kind = \"function\"
name = \"f\"
source = \"oracle\"
confidence = \"assumed\"
";
        std::fs::write(&path, text).unwrap();
        let ws = Workspace::open(&ws.root).unwrap();
        assert_eq!(ws.symbols[0].source, ClaimSource::Other);
        let lock = ws.lock(Duration::from_secs(1)).unwrap();
        let err = ws.save_symbols(&lock).unwrap_err();
        assert!(matches!(err, WorkspaceError::UnknownValue { .. }), "{err}");
        assert!(err.to_string().contains("flat:00010010"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn unknown_symbol_keys_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        let path = dir.path().join(SYMBOLS_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "schema = 1

[[symbol]]
address = \"flat:00010010\"
kind = \"function\"
name = \"f\"
             source = \"human\"
confidence = \"assumed\"
future_key = \"kept\"
",
        )
        .unwrap();
        let ws = Workspace::open(&ws.root).unwrap();
        assert_eq!(ws.symbols[0].extra["future_key"].as_str(), Some("kept"));
        let lock = ws.lock(Duration::from_secs(1)).unwrap();
        ws.save_symbols(&lock).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("future_key = \"kept\""), "{text}");
    }

    #[test]
    fn add_symbols_reads_the_file_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let sym = |a, n| Symbol::new(Address::Flat(a), SymbolKind::Global, n);
        let mut ws = workspace(dir.path(), vec![sym(0x20, "on_disk")]);
        let lock = ws.lock(Duration::from_secs(1)).unwrap();
        ws.save_symbols(&lock).unwrap();
        // a stale in-memory view: the file is what counts
        ws.symbols.clear();
        let path = dir.path().join(SYMBOLS_FILE);
        let before = std::fs::read(&path).unwrap();
        let none = ws
            .add_symbols(
                |current| {
                    assert_eq!(current.len(), 1);
                    Vec::new()
                },
                &lock,
            )
            .unwrap();
        assert!(none.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let added = ws.add_symbols(|_| vec![sym(0x10, "new")], &lock).unwrap();
        assert_eq!(added.len(), 1);
        let names: Vec<_> = Workspace::open(dir.path())
            .unwrap()
            .symbols
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["new", "on_disk"]);
        assert_eq!(ws.symbols.len(), 2);
    }

    #[test]
    fn save_sorts_by_address() {
        let dir = tempfile::tempdir().unwrap();
        let sym = |a, k, n| Symbol::new(Address::Flat(a), k, n);
        let ws = workspace(
            dir.path(),
            vec![
                sym(0x30, SymbolKind::Function, "c"),
                sym(0x10, SymbolKind::Label, "b"),
                sym(0x10, SymbolKind::Function, "a"),
            ],
        );
        let lock = ws.lock(Duration::from_secs(1)).unwrap();
        ws.save_symbols(&lock).unwrap();
        let names: Vec<_> = Workspace::open(dir.path())
            .unwrap()
            .symbols
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["a", "b", "c"]);
    }

    #[test]
    fn write_atomic_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("f.txt");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["f.txt"]);
    }

    #[test]
    fn types_h_round_trip_and_absent() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        assert_eq!(ws.types_h().unwrap(), "");
        let lock = ws.lock(Duration::from_secs(1)).unwrap();
        ws.save_types_h("typedef int x;\n", &lock).unwrap();
        assert_eq!(ws.types_h().unwrap(), "typedef int x;\n");
    }

    #[test]
    fn second_writer_waits_for_lock() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Arc::new(workspace(dir.path(), Vec::new()));
        let held = ws.lock(Duration::from_secs(1)).unwrap();
        let other = Arc::clone(&ws);
        let started = Instant::now();
        let handle = std::thread::spawn(move || other.lock(Duration::from_secs(10)).map(|_| ()));
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
        handle.join().unwrap().unwrap();
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[test]
    fn lock_times_out_with_pid() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        let _held = ws.lock(Duration::from_secs(1)).unwrap();
        match ws.lock(Duration::from_millis(100)) {
            Err(WorkspaceError::Locked { pid }) => assert_eq!(pid, std::process::id()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn stale_lock_of_dead_process_is_taken_over() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Vec::new());
        std::fs::create_dir_all(dir.path().join("cache")).unwrap();
        std::fs::write(dir.path().join(LOCK_FILE), u32::MAX.to_string()).unwrap();
        std::fs::write(dir.path().join(PID_FILE), u32::MAX.to_string()).unwrap();
        let _lock = ws.lock(Duration::from_millis(100)).unwrap();
        let pid = std::fs::read_to_string(dir.path().join(PID_FILE)).unwrap();
        assert_eq!(pid, std::process::id().to_string());
    }
}
