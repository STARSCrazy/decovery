//! The exemplar index: identical functions from C sources whose instruction forms, MinHash sketches and source
//! let an agent learn the compiler's idioms from the program itself (design 5.12 item 2, plan decision 3).
//!
//! The index is cache data in [`EXEMPLARS_FILE`]. [`exemplar_index`] loads it, compares its members with the
//! rebuild records (adds new identical functions, drops the others) and saves it when it changed; a changed
//! target (`target_sha256`) or a damaged file rebuilds it from scratch. Only new members are decoded. A query
//! ranks the candidates sharing an LSH band key with the target (all members up to [`LSH_ALL`]) with Decomp's
//! ranking ([`decovery_diff::rank`]). Works without the analysis provider and without the bridge: the forms come
//! from the original bytes of the analysed function range.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use decovery_core::{
    Address, ClaimSource, RebuildRecord, RebuildResult, TargetFormat, Workspace, write_atomic,
};
use decovery_diff::{
    HASHES, Ranked, Stretch, coarse_forms, instruction_forms, lsh_keys, minhash, rank,
};
use decovery_toolchain::{definitions, find_sources, rebuild_profile};
use serde::{Deserialize, Serialize};

use crate::{FacadeError, Session};

/// The index file, relative to the workspace root.
pub const EXEMPLARS_FILE: &str = "cache/exemplars/index.json";
/// Up to this many members every member is a candidate; above it only those sharing an LSH band key.
pub const LSH_ALL: usize = 2000;
const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexFile {
    schema: u32,
    target_sha256: String,
    /// Interned instruction forms (normalised and coarse); entries refer to them by position.
    forms: Vec<String>,
    entries: Vec<Entry>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    address: Address,
    /// Last address of the analysed range the forms were decoded from; a changed range re-decodes the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    end: Option<Address>,
    name: String,
    file: String,
    #[serde(default)]
    flags: String,
    forms: Vec<u32>,
    coarse: Vec<u32>,
    minhash: Vec<u64>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// The loaded index with its LSH buckets.
pub struct ExemplarIndex {
    file: IndexFile,
    ids: HashMap<String, u32>,
    buckets: HashMap<u64, Vec<usize>>,
}

/// A similar identical function.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Exemplar {
    pub address: Address,
    pub name: String,
    /// The source file in `src/`.
    pub file: String,
    pub flags: String,
    pub similarity: f64,
    pub coverage: f64,
    pub score: f64,
    /// Only numbers and addresses differ (the coarse forms are equal).
    pub twin: bool,
    /// Instruction indices (inclusive) into the padding-free sequences of the target and the exemplar.
    pub stretches: Vec<Stretch>,
    /// The definition from `src/`; `None` when the file no longer defines it.
    pub source: Option<String>,
}

impl Exemplar {
    /// "similarity 0.91, coverage 0.88, twin; shared stretches 0-24↔3-27".
    pub fn reason(&self) -> String {
        let mut text = format!(
            "similarity {:.2}, coverage {:.2}",
            self.similarity, self.coverage
        );
        if self.twin {
            text.push_str(", twin");
        }
        if !self.stretches.is_empty() {
            let stretches: Vec<String> = self
                .stretches
                .iter()
                .map(|s| {
                    format!(
                        "{}-{}\u{2194}{}-{}",
                        s.target.0, s.target.1, s.candidate.0, s.candidate.1
                    )
                })
                .collect();
            text.push_str(&format!("; shared stretches {}", stretches.join(", ")));
        }
        text
    }
}

/// Loads the index of `session`'s workspace, refreshes it from the rebuild records and saves it when it changed.
pub fn exemplar_index(session: &Session) -> Result<ExemplarIndex, FacadeError> {
    let root = &session.workspace.root;
    let path = root.join(EXEMPLARS_FILE);
    let sha = &session.workspace.config.target.sha256;
    let existed = path.exists();
    let loaded = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<IndexFile>(&bytes).ok())
        .filter(|f| f.schema == SCHEMA && &f.target_sha256 == sha && valid(f));
    let mut changed = existed && loaded.is_none();
    let mut file = loaded.unwrap_or_else(|| IndexFile {
        schema: SCHEMA,
        target_sha256: sha.clone(),
        forms: Vec::new(),
        entries: Vec::new(),
        extra: serde_json::Map::new(),
    });

    let members = members(session);
    let analysed = session.analysis.index();
    let before = file.entries.len();
    // a member whose analysed range changed is dropped here and decoded again below
    file.entries.retain(|e| {
        members.contains_key(&e.address)
            && e.end.is_some()
            && analysed.function_at(e.address).map(|f| f.end) == e.end
    });
    changed |= file.entries.len() != before;
    for entry in &mut file.entries {
        let record = members[&entry.address];
        let file_name = record.file.clone().unwrap_or_default();
        let flags = record.flags.clone().unwrap_or_default();
        if entry.name != record.name || entry.file != file_name || entry.flags != flags {
            entry.name = record.name.clone();
            entry.file = file_name;
            entry.flags = flags;
            changed = true;
        }
    }
    let known: BTreeSet<Address> = file.entries.iter().map(|e| e.address).collect();
    let new: Vec<&RebuildRecord> = members
        .values()
        .copied()
        .filter(|r| !known.contains(&r.address))
        .collect();
    let mut ids: HashMap<String, u32> = intern_table(&file.forms);
    if !new.is_empty() {
        let program = crate::program::load(&session.workspace)?;
        let bits = bits(&session.workspace);
        let index = session.analysis.index();
        for record in new {
            let Some(code) = index
                .function_at(record.address)
                .and_then(|f| original_code(&program, f.start, f.end))
            else {
                continue;
            };
            let base = record.address.linear().unwrap_or(0);
            let forms = intern(
                &instruction_forms(code, bits, base),
                &mut ids,
                &mut file.forms,
            );
            let coarse = intern(&coarse_forms(code, bits, base), &mut ids, &mut file.forms);
            let end = index.function_at(record.address).map(|f| f.end);
            file.entries.push(Entry {
                address: record.address,
                end,
                name: record.name.clone(),
                file: record.file.clone().unwrap_or_default(),
                flags: record.flags.clone().unwrap_or_default(),
                minhash: minhash(&forms).to_vec(),
                forms,
                coarse,
                extra: serde_json::Map::new(),
            });
            changed = true;
        }
        file.entries.sort_by_key(|e| e.address);
    }
    if changed {
        let text = serde_json::to_string(&file).map_err(|e| {
            FacadeError::Invalid(format!("cannot serialize the exemplar index: {e}"))
        })?;
        write_atomic(&path, text.as_bytes())
            .map_err(|source| FacadeError::Output { path, source })?;
    }
    Ok(ExemplarIndex::new(file, ids))
}

impl ExemplarIndex {
    fn new(file: IndexFile, ids: HashMap<String, u32>) -> Self {
        let mut buckets: HashMap<u64, Vec<usize>> = HashMap::new();
        for (k, entry) in file.entries.iter().enumerate() {
            let Ok(sketch) = <[u64; HASHES]>::try_from(entry.minhash.as_slice()) else {
                continue;
            };
            for key in lsh_keys(&sketch) {
                let bucket = buckets.entry(key).or_default();
                if bucket.last() != Some(&k) {
                    bucket.push(k);
                }
            }
        }
        ExemplarIndex { file, ids, buckets }
    }

    /// An index over bare sequences (forms equal coarse forms), members at `flat:<position>`; not saved. For
    /// measurements of the lookup.
    pub fn from_sequences(sequences: &[Vec<u32>]) -> Self {
        let entries = sequences
            .iter()
            .enumerate()
            .map(|(k, forms)| Entry {
                address: Address::Flat(u32::try_from(k).unwrap_or(u32::MAX)),
                end: None,
                name: format!("member_{k}"),
                file: String::new(),
                flags: String::new(),
                forms: forms.clone(),
                coarse: forms.clone(),
                minhash: minhash(forms).to_vec(),
                extra: serde_json::Map::new(),
            })
            .collect();
        let file = IndexFile {
            schema: SCHEMA,
            target_sha256: String::new(),
            forms: Vec::new(),
            entries,
            extra: serde_json::Map::new(),
        };
        ExemplarIndex::new(file, HashMap::new())
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.file.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.file.entries.is_empty()
    }

    /// Whether the function at `address` is a member.
    pub fn contains(&self, address: Address) -> bool {
        self.file.entries.iter().any(|e| e.address == address)
    }

    /// Positions of the members that are candidates for `forms`: all up to [`LSH_ALL`] members, else those
    /// sharing an LSH band key; ascending.
    pub fn candidates(&self, forms: &[u32]) -> Vec<usize> {
        if self.len() <= LSH_ALL {
            return (0..self.len()).collect();
        }
        let mut found: BTreeSet<usize> = BTreeSet::new();
        for key in lsh_keys(&minhash(forms)) {
            if let Some(bucket) = self.buckets.get(&key) {
                found.extend(bucket);
            }
        }
        found.into_iter().collect()
    }

    /// The best `top` candidates for the interned sequences, without the member at `exclude`; `candidate` is the
    /// member's position.
    pub fn rank_forms(
        &self,
        forms: &[u32],
        coarse: &[u32],
        exclude: Option<Address>,
        top: usize,
    ) -> Vec<Ranked> {
        let positions: Vec<usize> = self
            .candidates(forms)
            .into_iter()
            .filter(|&k| Some(self.file.entries[k].address) != exclude)
            .collect();
        let pairs: Vec<(&[u32], &[u32])> = positions
            .iter()
            .map(|&k| {
                let e = &self.file.entries[k];
                (e.forms.as_slice(), e.coarse.as_slice())
            })
            .collect();
        let mut ranked = rank(forms, coarse, &pairs, top);
        for r in &mut ranked {
            r.candidate = positions[r.candidate];
        }
        ranked
    }

    /// The `top` identical functions most similar to the analysed function starting at `target` (never itself),
    /// each with its current definition from `src/`.
    pub fn similar(
        &self,
        session: &Session,
        target: Address,
        top: usize,
    ) -> Result<Vec<Exemplar>, FacadeError> {
        if self.is_empty() || top == 0 {
            return Ok(Vec::new());
        }
        let index = session.analysis.index();
        let function = index.function_at(target).ok_or_else(|| {
            FacadeError::Invalid(format!("{target} is not the start of an analysed function"))
        })?;
        let program = crate::program::load(&session.workspace)?;
        let code = original_code(&program, function.start, function.end).ok_or_else(|| {
            FacadeError::Invalid(format!(
                "the original bytes of the function at {target} are not in the program"
            ))
        })?;
        let bits = bits(&session.workspace);
        let base = target.linear().unwrap_or(0);
        let mut local = HashMap::new();
        let forms = self.lookup(&instruction_forms(code, bits, base), &mut local);
        let coarse = self.lookup(&coarse_forms(code, bits, base), &mut local);
        let root = &session.workspace.root;
        Ok(self
            .rank_forms(&forms, &coarse, Some(target), top)
            .into_iter()
            .map(|r| {
                let e = &self.file.entries[r.candidate];
                Exemplar {
                    address: e.address,
                    name: e.name.clone(),
                    file: e.file.clone(),
                    flags: e.flags.clone(),
                    similarity: r.similarity,
                    coverage: r.coverage,
                    score: r.score,
                    twin: r.twin,
                    stretches: r.stretches,
                    source: definition_in(root, &e.file, &e.name),
                }
            })
            .collect())
    }

    /// Ids of `strings` in the table; a form the table lacks gets an id of its own beyond the table.
    fn lookup(&self, strings: &[String], local: &mut HashMap<String, u32>) -> Vec<u32> {
        let base = u32::try_from(self.file.forms.len()).unwrap_or(u32::MAX);
        strings
            .iter()
            .map(|s| match self.ids.get(s) {
                Some(&id) => id,
                None => {
                    let next = base.saturating_add(u32::try_from(local.len()).unwrap_or(u32::MAX));
                    *local.entry(s.clone()).or_insert(next)
                }
            })
            .collect()
    }
}

/// Every id of an entry points into the table and every sketch has [`HASHES`] values.
fn valid(file: &IndexFile) -> bool {
    let n = file.forms.len();
    file.entries.iter().all(|e| {
        e.minhash.len() == HASHES && e.forms.iter().chain(&e.coarse).all(|&id| (id as usize) < n)
    })
}

fn intern_table(forms: &[String]) -> HashMap<String, u32> {
    forms
        .iter()
        .enumerate()
        .map(|(k, s)| (s.clone(), u32::try_from(k).unwrap_or(u32::MAX)))
        .collect()
}

fn intern(strings: &[String], ids: &mut HashMap<String, u32>, table: &mut Vec<String>) -> Vec<u32> {
    strings
        .iter()
        .map(|s| {
            *ids.entry(s.clone()).or_insert_with(|| {
                table.push(s.clone());
                u32::try_from(table.len() - 1).unwrap_or(u32::MAX)
            })
        })
        .collect()
}

/// The identical functions from C sources that are not library-classified and have an analysed range.
fn members(session: &Session) -> BTreeMap<Address, &RebuildRecord> {
    let index = session.analysis.index();
    session
        .rebuild
        .iter()
        .filter(|r| {
            r.effective_result() == RebuildResult::Identical && r.instructions_differing == 0
        })
        .filter(|r| r.file.as_deref().is_some_and(|f| !is_assembler_source(f)))
        .filter(|r| !is_library(session, r.address))
        .filter(|r| index.function_at(r.address).is_some())
        .map(|r| (r.address, r))
        .collect()
}

fn is_library(session: &Session, at: Address) -> bool {
    session.symbol_at(at).is_some_and(|s| {
        s.source == ClaimSource::Signature || s.library.as_deref().is_some_and(|l| !l.is_empty())
    })
}

pub(crate) fn is_assembler_source(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.ends_with(".asm") || lower.ends_with(".s")
}

/// Instruction width of the code: the rebuild profile's, else by target format.
fn bits(ws: &Workspace) -> u32 {
    rebuild_profile(ws).map_or_else(
        |_| match ws.config.target.format {
            TargetFormat::Le | TargetFormat::Flat32 => 32,
            _ => 16,
        },
        |(profile, _)| u32::from(profile.bits),
    )
}

/// The original bytes from `start` through `end` (inclusive).
fn original_code(program: &decovery_core::Program, start: Address, end: Address) -> Option<&[u8]> {
    let len = end.linear()?.checked_sub(start.linear()?)?.checked_add(1)?;
    program.read(start, usize::try_from(len).ok()?)
}

/// The definition of `name` in the source `file` of `src/` (searched like `build` finds sources).
pub(crate) fn definition_in(root: &Path, file: &str, name: &str) -> Option<String> {
    let set = find_sources(&root.join(crate::tools::SOURCE_DIR), &[]).ok()?;
    let path = set
        .sources
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == file))?;
    let text = String::from_utf8_lossy(&std::fs::read(path).ok()?).into_owned();
    definitions(&text)
        .into_iter()
        .find(|d| d.name == name)
        .map(|d| text[d.start..d.end].to_string())
}

/// The current definition of the function at `start` in `src/`: in the file its rebuild record names, else the
/// first C source (in `build`'s order) defining its name. `(file, text)`.
pub(crate) fn current_source(session: &Session, start: Address) -> Option<(String, String)> {
    let root = &session.workspace.root;
    let name = session.name_of(start).name;
    let recorded = session
        .rebuild
        .iter()
        .find(|r| r.address == start)
        .and_then(|r| r.file.clone())
        .filter(|f| !is_assembler_source(f));
    if let Some(file) = recorded
        && let Some(text) = definition_in(root, &file, &name)
    {
        return Some((file, text));
    }
    let set = find_sources(&root.join(crate::tools::SOURCE_DIR), &[]).ok()?;
    set.sources.iter().find_map(|path| {
        let file = path.file_name()?.to_string_lossy().into_owned();
        if !file.to_ascii_lowercase().ends_with(".c") {
            return None;
        }
        let text = String::from_utf8_lossy(&std::fs::read(path).ok()?).into_owned();
        definitions(&text)
            .into_iter()
            .find(|d| d.name == name)
            .map(|d| (file, text[d.start..d.end].to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_names_twin_and_stretches() {
        let mut stretches =
            decovery_diff::shared_stretches(&[1, 2, 3, 4, 5, 6, 7], &[9, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(stretches.len(), 1);
        let exemplar = Exemplar {
            address: Address::Flat(0x10),
            name: "f".into(),
            file: "f.c".into(),
            flags: String::new(),
            similarity: 0.91,
            coverage: 0.875,
            score: 0.8925,
            twin: true,
            stretches: vec![stretches.remove(0)],
            source: None,
        };
        assert_eq!(
            exemplar.reason(),
            "similarity 0.91, coverage 0.88, twin; shared stretches 0-6\u{2194}1-7"
        );
    }
}
