//! Attempt records: one line per build of a function, kept per function under `cache/attempts/` (design 6).
//!
//! The archive of attempts is the base of `history`, the parked filter, the migration of Decomp's memory and the
//! bench. Records are appended under one lock; a function's shard is a JSON-lines file named by [`address_key`].

use std::collections::{BTreeMap, HashSet};
use std::fs::{OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::address::{Address, address_key};
use crate::analysis::now_utc;
use crate::records::{RebuildResult, VerdictId};
use crate::workspace::{SCHEMA, WorkspaceError};

/// Directory of the attempt shards, relative to the workspace root.
pub const ATTEMPTS_DIR: &str = "cache/attempts";
/// Own attempts without progress after which a function is parked (`[rebuild] attempt_budget` overrides).
pub const DEFAULT_ATTEMPT_BUDGET: u32 = 30;
const LOCK_NAME: &str = ".lock";
const LOCK_WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(20);
/// Actor of the bench harness's own builds; they never count toward the budget (the agent must not be charged).
const HARNESS_ACTOR: &str = "bench-harness";

/// Where an attempt came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AttemptOrigin {
    /// A build of the function's current source.
    Build,
    /// A variant text supplied by the caller (an agent's own rewrite). Automatic variants are `Search`.
    Variant,
    /// A build driven from a whole-function call.
    Function,
    /// An automatic search (transformations, permuter, ...).
    Search,
    /// A bench harness build.
    Bench,
    /// Imported from another tool's memory.
    Migrate,
}

/// One attempt to rebuild a function.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttemptRecord {
    pub schema: u32,
    /// RFC 3339 UTC, to the second.
    pub time: String,
    pub address: Address,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub origin: AttemptOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Who made the attempt: `cli`, `mcp` (the agent's callers), `bench-harness`, `bench:<run-id>` or `migrate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub profile: String,
    pub flags: String,
    /// `<algo>:<hex>` of the function's definition text with LF line ends; native records write `blake3:<hex>`,
    /// migrated ones keep the algorithm of their source (`decomp-sha256:...`).
    pub body_hash: String,
    /// blake3 hex over the rest of the file, the headers and the tool fingerprint.
    pub context_hash: String,
    /// blake3 hex of the original function bytes.
    pub original_hash: String,
    pub result: RebuildResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<VerdictId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions_differing: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_differing: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnosis: Vec<String>,
    /// Name of the archived source of this attempt, when one was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AttemptRecord {
    /// A record at the current time with the optional parts empty; fill the public fields that are known.
    pub fn new(
        address: Address,
        name: impl Into<String>,
        origin: AttemptOrigin,
        result: RebuildResult,
    ) -> Self {
        AttemptRecord {
            schema: SCHEMA,
            time: now_utc(),
            address,
            name: name.into(),
            file: None,
            origin,
            label: None,
            actor: None,
            profile: String::new(),
            flags: String::new(),
            body_hash: String::new(),
            context_hash: String::new(),
            original_hash: String::new(),
            result,
            verdict: None,
            instructions_differing: None,
            bytes_differing: None,
            blockers: Vec::new(),
            diagnosis: Vec::new(),
            archive: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Whether `other` is the same attempt: the same function, body, context, profile, flags and original bytes
    /// (Decomp's `Versuch.schluessel`). A build of an unchanged source repeats its last attempt and is not appended.
    pub fn same_attempt(&self, other: &AttemptRecord) -> bool {
        self.address == other.address
            && self.body_hash == other.body_hash
            && self.context_hash == other.context_hash
            && self.profile == other.profile
            && self.flags == other.flags
            && self.original_hash == other.original_hash
    }

    /// Whether this attempt is one of the agent's own and counts toward the budget: origin `build` or `function`,
    /// and `variant` only when a caller (`cli`, `mcp`, `bench:<run-id>`) supplied it; `search`, `bench` and `migrate` never count,
    /// nor does anything made by the bench harness itself.
    pub fn counts_toward_budget(&self) -> bool {
        let actor = self.actor.as_deref();
        if actor == Some(HARNESS_ACTOR) {
            return false;
        }
        match self.origin {
            AttemptOrigin::Build | AttemptOrigin::Function => true,
            AttemptOrigin::Variant => {
                actor.is_some_and(|a| matches!(a, "cli" | "mcp") || a.starts_with("bench:"))
            }
            AttemptOrigin::Search | AttemptOrigin::Bench | AttemptOrigin::Migrate => false,
        }
    }
}

fn io_error(path: &Path, source: std::io::Error) -> WorkspaceError {
    WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn shard_path(root: &Path, address: Address) -> PathBuf {
    root.join(ATTEMPTS_DIR)
        .join(format!("{}.jsonl", address_key(address)))
}

/// Takes the append lock `<dir>/.lock` (an OS file lock, waits up to 10 s); it is held until the file is dropped.
/// `dir` must exist.
pub(crate) fn lock_dir(dir: &Path) -> Result<std::fs::File, WorkspaceError> {
    let lock_path = dir.join(LOCK_NAME);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| io_error(&lock_path, e))?;
    let start = Instant::now();
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(lock),
            Err(TryLockError::WouldBlock) => {
                if start.elapsed() >= LOCK_WAIT {
                    return Err(WorkspaceError::Locked { pid: 0 });
                }
                std::thread::sleep(POLL);
            }
            Err(TryLockError::Error(e)) => return Err(io_error(&lock_path, e)),
        }
    }
}

/// Appends `records` to the shards of their functions. Takes the lock `cache/attempts/.lock` (waits up to 10 s)
/// and writes each shard's new lines with one `write_all`.
pub fn append_attempts(root: &Path, records: &[AttemptRecord]) -> Result<(), WorkspaceError> {
    if records.is_empty() {
        return Ok(());
    }
    let dir = root.join(ATTEMPTS_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
    let mut shards: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
    for record in records {
        let line = serde_json::to_string(record).map_err(|e| WorkspaceError::Json {
            path: shard_path(root, record.address),
            source: Box::new(e),
        })?;
        let buffer = shards.entry(record.address).or_default();
        buffer.extend_from_slice(line.as_bytes());
        buffer.push(b'\n');
    }
    let _lock = lock_dir(&dir)?;
    for (address, mut bytes) in shards {
        let path = shard_path(root, address);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|e| io_error(&path, e))?;
        // A torn last line (a crash mid-write) must not swallow the first new record.
        let length = file.metadata().map_err(|e| io_error(&path, e))?.len();
        if length > 0 {
            let mut last = [0u8; 1];
            file.seek(SeekFrom::End(-1))
                .and_then(|_| file.read_exact(&mut last))
                .map_err(|e| io_error(&path, e))?;
            if last[0] != b'\n' {
                bytes.insert(0, b'\n');
            }
        }
        file.write_all(&bytes).map_err(|e| io_error(&path, e))?;
    }
    Ok(())
}

/// Reads the attempts of one function, oldest first, and warnings for lines that could not be read (the file and
/// line are named). A missing shard is an empty list.
pub fn read_attempts(
    root: &Path,
    address: Address,
) -> Result<(Vec<AttemptRecord>, Vec<String>), WorkspaceError> {
    let path = shard_path(root, address);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(io_error(&path, e)),
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let place = format!("{}:{}", path.display(), index + 1);
        match serde_json::from_str::<AttemptRecord>(line) {
            Ok(record) if record.schema == SCHEMA => records.push(record),
            Ok(record) => warnings.push(format!(
                "{place}: skipped, unsupported schema {} (expected {SCHEMA})",
                record.schema
            )),
            Err(e) => warnings.push(format!("{place}: skipped, {e}")),
        }
    }
    Ok((records, warnings))
}

/// How far a compared attempt is from identical: 0 identical, else the instructions that differ (the largest
/// number when that count is unknown). A non-identical result with zero differing instructions has distance 1:
/// reference blockers can remain, and only identical has distance 0.
/// `None` when the attempt was not compared (`error` or an unknown value).
///
/// This is the one meaning of "better" in decovery: smaller is better, `None` is worse than any number.
pub fn distance_of(
    result: RebuildResult,
    verdict: Option<VerdictId>,
    instructions_differing: Option<u32>,
) -> Option<u64> {
    let compared = match verdict {
        Some(VerdictId::Identical) => return Some(0),
        Some(VerdictId::Equivalent | VerdictId::Differs) => true,
        Some(VerdictId::Unchecked | VerdictId::Other) => false,
        None => match result {
            RebuildResult::Identical => return Some(0),
            RebuildResult::Differs => true,
            RebuildResult::Error | RebuildResult::Other => false,
        },
    };
    compared.then(|| instructions_differing.map_or(u64::MAX, |n| u64::from(n).max(1)))
}

/// [`distance_of`] for an attempt record.
pub fn attempt_distance(r: &AttemptRecord) -> Option<u64> {
    // Imported identical findings are evidence until decovery actually judges the source.
    if r.verdict.is_none()
        && r.result == RebuildResult::Identical
        && r.extra.contains_key("decomp_result")
    {
        return Some(
            r.instructions_differing
                .map_or(u64::MAX, |n| u64::from(n).max(1)),
        );
    }
    distance_of(r.result, r.verdict, r.instructions_differing)
}

/// Where a function stands against its attempt budget.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttemptBudget {
    /// Own attempts counted (distinct bodies, compared).
    pub own: u32,
    /// Own attempts since the best distance last improved.
    pub since_progress: u32,
    /// The best distance so far.
    pub best: Option<u64>,
    pub limit: u32,
}

impl AttemptBudget {
    /// Not identical, and the limit of attempts without progress is reached.
    pub fn parked(&self) -> bool {
        self.best != Some(0) && self.since_progress >= self.limit
    }
}

/// The budget of a function from its attempts (oldest first). Counted are own attempts
/// ([`AttemptRecord::counts_toward_budget`]) that were compared, each `body_hash` once; a new best distance resets
/// `since_progress`, any other attempt adds one.
pub fn attempt_budget(records: &[AttemptRecord], limit: u32) -> AttemptBudget {
    let mut seen = HashSet::new();
    let mut budget = AttemptBudget {
        own: 0,
        since_progress: 0,
        best: None,
        limit,
    };
    for record in records {
        let Some(distance) = attempt_distance(record) else {
            continue;
        };
        // A judged automated search can solve the function without spending the agent's own budget.
        if record.actor.as_deref() != Some(HARNESS_ACTOR) && distance == 0 {
            budget.best = Some(0);
            budget.since_progress = 0;
        }
        if !record.counts_toward_budget() || !seen.insert(record.body_hash.as_str()) {
            continue;
        }
        budget.own += 1;
        if distance == 0 {
            continue;
        }
        if budget.best.is_none_or(|best| distance < best) {
            budget.best = Some(distance);
            budget.since_progress = 0;
        } else {
            budget.since_progress += 1;
        }
    }
    budget
}
