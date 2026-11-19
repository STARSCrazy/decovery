//! Library members in `build` and `compare` (ADR 0016): the members of the configured Aztec libraries that the
//! program contains, placed at the knowledge's functions and compared like other Aztec objects (relocated fields
//! are link gaps).
//!
//! A member belongs to the program when one of its code symbols names a knowledge function (by the object name,
//! its undecorated form or the overlay-qualified knowledge name `<OVERLAY>_<name>`), or when its whole code section
//! matches the original at a knowledge function that no source rebuilds (every byte outside a relocated field
//! equal, at least [`MIN_MATCHED_BYTES`] of them, or fewer when it exactly fills the room behind a placed member).
//! Each knowledge function that starts inside a placed member is
//! one compared function: it runs to the next knowledge function in the member or the member's end.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use decovery_core::{
    Address, Analysis, Confidence, Program, RebuildRecord, SymbolKind, Workspace, read_user_config,
};
use decovery_diff::{Comparison, Decoration, SymbolView, compare_with_gaps};
use decovery_objects::{
    AztecLibraryMember, FunctionView, ObjectFormat, SectionKind, read_aztec_library,
};
use decovery_toolchain::{Profile, tool_dir};
use serde_json::{Value, json};

use crate::KnowledgeView;

/// A member found only by its bytes needs at least this many bytes outside relocated fields: shorter code (a lone
/// `ret`) matches too many places, so it is placed only where it fills the room between a placed member and the
/// next function exactly.
pub const MIN_MATCHED_BYTES: u32 = 6;

/// A configured library (or library object) with its members.
pub struct LibraryFile {
    /// The file name as configured (`C.LIB`, `OVLD.O`).
    pub label: String,
    /// The file is a library (members are named `C.LIB(member)`), not a single object.
    pub is_library: bool,
    pub members: Vec<AztecLibraryMember>,
}

impl LibraryFile {
    /// Reads a library or single object of the Aztec format. Errors name the file and the byte offset.
    pub fn read(path: &Path, label: &str) -> Result<LibraryFile, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        LibraryFile::from_bytes(&bytes, label)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))
    }

    /// A library or single object from its bytes.
    pub fn from_bytes(
        bytes: &[u8],
        label: &str,
    ) -> Result<LibraryFile, decovery_objects::ObjectError> {
        let members = read_aztec_library(bytes, label)?;
        let is_library = bytes.get(..2) == Some(&[0x62, 0xEC][..]);
        Ok(LibraryFile {
            label: label.to_string(),
            is_library,
            members,
        })
    }

    /// The source name of a member as records name it: `C.LIB(strcmp)`, or `OVLD.O` for a single object.
    pub fn source_of(&self, member: &AztecLibraryMember) -> String {
        if self.is_library {
            format!("{}({})", self.label, member.name)
        } else {
            self.label.clone()
        }
    }
}

/// How a member was placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// One of its code symbols names the knowledge function there.
    Name(String),
    /// Its code matches the original there.
    Bytes,
}

/// A member placed in the original: its code section starts at `base`.
pub struct MemberPlacement<'m> {
    pub file: &'m LibraryFile,
    pub member: &'m AztecLibraryMember,
    pub section: u32,
    pub base: Address,
    pub len: u32,
    pub anchor: Anchor,
    /// Every byte outside a relocated field equals the original.
    pub matches: bool,
}

/// One compared function of a placed member.
pub struct MemberFunction<'m> {
    pub at: Address,
    pub view: FunctionView<'m>,
    /// The member's code symbol at the function's start, when it has one.
    pub symbol: Option<&'m str>,
}

/// The knowledge's functions: their starts, and their addresses by every name a library symbol may match.
pub struct KnowledgeFunctions {
    pub starts: BTreeSet<Address>,
    by_name: BTreeMap<String, Vec<Address>>,
}

impl KnowledgeFunctions {
    /// The active function symbols of the knowledge and the analysis' function starts.
    pub fn new(ws: &Workspace, analysis: Option<&Analysis>) -> KnowledgeFunctions {
        let mut starts = BTreeSet::new();
        let mut by_name: BTreeMap<String, Vec<Address>> = BTreeMap::new();
        for s in &ws.symbols {
            if s.kind != SymbolKind::Function
                || s.confidence == Confidence::Refuted
                || s.name.is_empty()
            {
                continue;
            }
            starts.insert(s.address);
            by_name.entry(s.name.clone()).or_default().push(s.address);
            // an overlay function named `<OVERLAY>_<name>` (the overlay's copy of a library function)
            if let Some(rest) = s.address.overlay().and_then(|o| {
                s.name
                    .get(..o.as_str().len())
                    .filter(|p| p.eq_ignore_ascii_case(o.as_str()))
                    .and_then(|_| s.name[o.as_str().len()..].strip_prefix('_'))
            }) {
                by_name.entry(rest.to_string()).or_default().push(s.address);
            }
        }
        if let Some(a) = analysis {
            starts.extend(a.functions.iter().map(|f| f.start));
        }
        KnowledgeFunctions { starts, by_name }
    }

    fn named(&self, name: &str) -> &[Address] {
        self.by_name.get(name).map_or(&[], Vec::as_slice)
    }
}

/// The paths of the configured libraries and library objects: a bare file name lies in the toolchain's `LIB`
/// directory, a path is relative to the workspace root.
pub fn library_paths(ws: &Workspace, profile: &Profile) -> Result<Vec<(String, PathBuf)>, String> {
    let Some(rebuild) = ws.config.rebuild.as_ref() else {
        return Ok(Vec::new());
    };
    let names: Vec<&String> = rebuild
        .libraries
        .iter()
        .chain(&rebuild.library_objects)
        .collect();
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let mut lib_dir: Option<PathBuf> = None;
    let mut out = Vec::new();
    for name in names {
        let path = if name.contains(['/', '\\']) {
            ws.root.join(name)
        } else {
            if lib_dir.is_none() {
                let user = read_user_config().map_err(|e| e.to_string())?;
                let dir = tool_dir(profile, Some(rebuild), &user, &ws.root)
                    .map_err(|e| format!("no library directory: {e}"))?;
                lib_dir = Some(dir.join("LIB"));
            }
            lib_dir.as_ref().map_or_else(PathBuf::new, |d| d.join(name))
        };
        let label = Path::new(name)
            .file_name()
            .map_or_else(|| name.clone(), |n| n.to_string_lossy().into_owned());
        out.push((label, path));
    }
    Ok(out)
}

/// The configured libraries, read; a library that cannot be read is a warning.
pub fn load_libraries(
    ws: &Workspace,
    profile: &Profile,
    warnings: &mut Vec<String>,
) -> Vec<LibraryFile> {
    if profile.object_format != ObjectFormat::Aztec {
        return Vec::new();
    }
    let paths = match library_paths(ws, profile) {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!("libraries not compared: {e}"));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for (label, path) in paths {
        match LibraryFile::read(&path, &label) {
            Ok(file) => out.push(file),
            Err(e) => warnings.push(format!("library not compared: {e}")),
        }
    }
    out
}

/// The member's code section with its relocated bytes: index, bytes, gap mask.
fn code_section(member: &AztecLibraryMember) -> Option<(u32, FunctionView<'_>)> {
    let module = &member.module;
    let (index, section) = module
        .sections
        .iter()
        .enumerate()
        .find(|(_, s)| s.kind == SectionKind::Code && !s.data.is_empty())?;
    let len = u32::try_from(section.data.len()).ok()?;
    Some((
        index as u32,
        FunctionView {
            name: &member.name,
            module,
            section: index as u32,
            start: 0,
            len,
        },
    ))
}

/// Bytes outside relocated fields that equal the original at `base`, and whether all of them do. `None` when the
/// original has no bytes there.
fn match_at(
    view: &FunctionView<'_>,
    gaps: &BTreeSet<u32>,
    program: &Program,
    base: Address,
) -> Option<(u32, bool)> {
    let code = view.code();
    let image = program.read(base, code.len())?;
    let mut equal = 0u32;
    let mut all = true;
    for (k, (&a, &b)) in code.iter().zip(image).enumerate() {
        if gaps.contains(&(k as u32)) {
            continue;
        }
        if a == b {
            equal += 1;
        } else {
            all = false;
        }
    }
    Some((equal, all))
}

fn within(x: Address, base: Address, len: u32) -> bool {
    x.bytes_from(base).is_some_and(|d| d < u64::from(len))
}

/// The names a knowledge function may carry for a library code symbol: the symbol, its undecorated form.
fn names_of<'s>(symbol: &'s str, decoration: &Decoration) -> Vec<&'s str> {
    let mut names = vec![symbol];
    let c = decoration.undecorate(symbol);
    if c != symbol {
        names.push(c);
    }
    names
}

/// Places the members of `libraries` in the original. `taken` are the function starts the sources rebuild: a
/// member is not placed over one of them. Name anchors win over byte anchors, matching over differing ones, longer
/// members over shorter; members never overlap.
pub fn place_members<'m>(
    libraries: &'m [LibraryFile],
    functions: &KnowledgeFunctions,
    program: &Program,
    decoration: &Decoration,
    taken: &BTreeSet<Address>,
) -> Vec<MemberPlacement<'m>> {
    let free: Vec<Address> = functions
        .starts
        .iter()
        .copied()
        .filter(|a| !taken.contains(a))
        .collect();
    let mut candidates: Vec<(usize, MemberPlacement<'m>, u32)> = Vec::new();
    let mut order = 0usize;
    for file in libraries {
        for member in &file.members {
            order += 1;
            let Some((section, view)) = code_section(member) else {
                continue;
            };
            let gaps = view.gaps();
            let symbols: Vec<(&str, u32)> = member
                .module
                .symbols
                .iter()
                .filter(|s| s.section == section)
                .map(|s| (s.name.as_str(), s.offset))
                .collect();
            let mut tried: BTreeSet<Address> = BTreeSet::new();
            let mut consider = |base: Address, anchor: Anchor, candidates: &mut Vec<_>| {
                if !tried.insert(base) {
                    return;
                }
                // a source rebuilds a function inside: not this member
                if taken.iter().any(|&t| within(t, base, view.len)) {
                    return;
                }
                let Some((equal, matches)) = match_at(&view, &gaps, program, base) else {
                    return;
                };
                if anchor == Anchor::Bytes && (!matches || equal == 0) {
                    return;
                }
                candidates.push((
                    order,
                    MemberPlacement {
                        file,
                        member,
                        section,
                        base,
                        len: view.len,
                        anchor,
                        matches,
                    },
                    equal,
                ));
            };
            for &(name, offset) in &symbols {
                for n in names_of(name, decoration) {
                    for &at in functions.named(n) {
                        if let Ok(base) = at.offset_by(-i64::from(offset)) {
                            consider(base, Anchor::Name(name.to_string()), &mut candidates);
                        }
                    }
                }
            }
            for &(_, offset) in &symbols {
                for &at in &free {
                    if let Ok(base) = at.offset_by(-i64::from(offset)) {
                        consider(base, Anchor::Bytes, &mut candidates);
                    }
                }
            }
        }
    }
    candidates.sort_by(|(oa, a, ea), (ob, b, eb)| {
        b.matches
            .cmp(&a.matches)
            .then_with(|| {
                matches!(b.anchor, Anchor::Name(_)).cmp(&matches!(a.anchor, Anchor::Name(_)))
            })
            .then(eb.cmp(ea))
            .then(oa.cmp(ob))
            .then(a.base.cmp(&b.base))
    });
    let overlaps = |placed: &[MemberPlacement<'m>], c: &MemberPlacement<'m>| {
        placed
            .iter()
            .any(|p| within(c.base, p.base, p.len) || within(p.base, c.base, c.len))
    };
    let mut placed: Vec<MemberPlacement<'m>> = Vec::new();
    let mut short: Vec<MemberPlacement<'m>> = Vec::new();
    for (_, c, equal) in candidates {
        if c.anchor == Anchor::Bytes && equal < MIN_MATCHED_BYTES {
            short.push(c);
        } else if !overlaps(&placed, &c) {
            placed.push(c);
        }
    }
    // a short member is placed only where it fills the room between a placed member and the next function
    // exactly, and no other member's code fits there
    loop {
        let mut added = false;
        let mut k = 0;
        while k < short.len() {
            let c = &short[k];
            let after_member = placed
                .iter()
                .any(|p| c.base.bytes_from(p.base) == Some(u64::from(p.len)));
            let end = c.base.offset_by(i64::from(c.len)).ok();
            let next = functions
                .starts
                .range(c.base..)
                .find(|&&a| a != c.base)
                .copied();
            let fills =
                end.is_some() && (end == next || placed.iter().any(|p| Some(p.base) == end));
            let code = code_section(c.member).map(|(_, v)| v.code());
            let unique = short
                .iter()
                .filter(|o| o.base == c.base)
                .all(|o| code_section(o.member).map(|(_, v)| v.code()) == code);
            if after_member && fills && unique && !overlaps(&placed, c) {
                let c = short.swap_remove(k);
                short.retain(|o| o.base != c.base);
                placed.push(c);
                added = true;
                k = 0;
            } else {
                k += 1;
            }
        }
        if !added {
            break;
        }
    }
    placed.sort_by_key(|p| p.base);
    placed
}

/// The compared functions of a placed member: one per knowledge function starting inside it.
pub fn member_functions<'m>(
    placement: &MemberPlacement<'m>,
    functions: &KnowledgeFunctions,
) -> Vec<MemberFunction<'m>> {
    let starts: Vec<(Address, u32)> = functions
        .starts
        .range(placement.base..)
        .map_while(|&a| {
            a.bytes_from(placement.base)
                .filter(|&d| d < u64::from(placement.len))
                .map(|d| (a, d as u32))
        })
        .collect();
    let module = &placement.member.module;
    starts
        .iter()
        .enumerate()
        .map(|(k, &(at, offset))| {
            let end = starts.get(k + 1).map_or(placement.len, |&(_, o)| o);
            let symbol = module
                .symbols
                .iter()
                .find(|s| s.section == placement.section && s.offset == offset)
                .map(|s| s.name.as_str());
            MemberFunction {
                at,
                view: FunctionView {
                    name: symbol.unwrap_or(&placement.member.name),
                    module,
                    section: placement.section,
                    start: offset,
                    len: end - offset,
                },
                symbol,
            }
        })
        .collect()
}

/// Compares a member function against the original with its relocated fields as link gaps.
pub fn compare_member_function(f: &MemberFunction<'_>, program: &Program) -> Comparison {
    let image = program.read(f.at, f.view.code().len()).unwrap_or(&[]);
    compare_with_gaps(&f.view, image, f.at)
}

/// The outcome of the library comparison of a build.
pub(super) struct LibraryOutcome {
    pub(super) records: Vec<RebuildRecord>,
    /// The source names of the records (`C.LIB(strcmp)`), for merging the records.
    pub(super) files: Vec<String>,
    pub(super) report: Option<Value>,
    pub(super) summary: Option<String>,
}

/// Places and compares the configured library members (`build`, ADR 0016). `taken` are the function starts the
/// sources rebuilt in this build.
pub(super) fn compare_libraries(
    ws: &Workspace,
    analysis: Option<&Analysis>,
    profile: &Profile,
    program: &Program,
    taken: &BTreeSet<Address>,
    date: &str,
    warnings: &mut Vec<String>,
) -> LibraryOutcome {
    let mut outcome = LibraryOutcome {
        records: Vec::new(),
        files: Vec::new(),
        report: None,
        summary: None,
    };
    let libraries = load_libraries(ws, profile, warnings);
    if libraries.is_empty() {
        return outcome;
    }
    let functions = KnowledgeFunctions::new(ws, analysis);
    let knowledge = KnowledgeView::new(ws, analysis);
    let placed = place_members(&libraries, &functions, program, &profile.decoration, taken);
    let mut members = Vec::new();
    let mut identical = 0usize;
    for p in &placed {
        let source = p.file.source_of(p.member);
        let mut names = Vec::new();
        for f in member_functions(p, &functions) {
            let c = compare_member_function(&f, program);
            let label = knowledge
                .name_at(f.at)
                .map_or_else(|| f.view.name.to_string(), |n| n.name);
            let mut r = super::build::comparison_record(f.at, &label, &c, date);
            r.file = Some(source.clone());
            r.compiler = Some(profile.id.clone());
            r.flags = Some(String::new());
            r.code_hash = Some(blake3::hash(f.view.code()).to_hex()[..16].to_string());
            if let Some(symbol) = f.symbol {
                r.extra.insert("symbol".into(), symbol.into());
            }
            if r.verdict == Some(decovery_core::VerdictId::Identical) {
                identical += 1;
            }
            names.push(label);
            outcome.records.push(r);
        }
        if !outcome.files.contains(&source) {
            outcome.files.push(source.clone());
        }
        members.push(json!({
            "source": source,
            "address": p.base.to_string(),
            "bytes": p.len,
            "anchor": match &p.anchor {
                Anchor::Name(n) => format!("name {n}"),
                Anchor::Bytes => "bytes".to_string(),
            },
            "functions": names,
        }));
    }
    // knowledge functions neither a source nor a library member rebuilt
    let covered: BTreeSet<Address> = outcome.records.iter().map(|r| r.address).collect();
    let remaining: Vec<String> = functions
        .starts
        .iter()
        .filter(|a| !taken.contains(a) && !covered.contains(a))
        .map(|&a| {
            knowledge
                .name_at(a)
                .map_or_else(|| a.to_string(), |n| format!("{} ({a})", n.name))
        })
        .collect();
    let total = outcome.records.len();
    let mut summary = format!("library: {identical} of {total} functions identical");
    if total > identical {
        let differing: Vec<&str> = outcome
            .records
            .iter()
            .filter(|r| r.verdict != Some(decovery_core::VerdictId::Identical))
            .take(8)
            .map(|r| r.name.as_str())
            .collect();
        summary.push_str(&format!(" (not identical: {})", differing.join(", ")));
    }
    if !remaining.is_empty() {
        summary.push_str(&format!(
            "; {} functions rebuilt by neither a source nor a library",
            remaining.len()
        ));
    }
    outcome.report = Some(json!({
        "libraries": libraries.iter().map(|l| json!({
            "file": l.label,
            "members": l.members.len(),
        })).collect::<Vec<_>>(),
        "functions": total,
        "identical": identical,
        "members": members,
        "remaining": remaining.iter().take(50).collect::<Vec<_>>(),
        "remaining_total": remaining.len(),
    }));
    outcome.summary = Some(summary);
    outcome
}

/// A library function for `compare`: by an object symbol name of a member (`$csav`, `strcmp_`, `strcmp`), or the
/// function at `address` when a member placed in the original covers it. The member is placed as `build` places it.
pub fn library_function<'m>(
    ws: &Workspace,
    analysis: Option<&Analysis>,
    program: &Program,
    decoration: &Decoration,
    library: &'m LibraryFile,
    target: &str,
    address: Option<Address>,
) -> Option<MemberFunction<'m>> {
    let functions = KnowledgeFunctions::new(ws, analysis);
    let placed = place_members(
        std::slice::from_ref(library),
        &functions,
        program,
        decoration,
        &BTreeSet::new(),
    );
    let mut found = placed
        .iter()
        .flat_map(|p| member_functions(p, &functions))
        .collect::<Vec<_>>();
    if let Some(at) = address
        && let Some(k) = found.iter().position(|f| f.at == at)
    {
        return Some(found.swap_remove(k));
    }
    // the function holding the symbol (`$cret` lies inside the knowledge's `$csav` function)
    let k = found.iter().position(|f| {
        f.view.module.symbols.iter().any(|s| {
            s.section == f.view.section
                && s.offset >= f.view.start
                && s.offset < f.view.start + f.view.len
                && names_of(&s.name, decoration).contains(&target)
        })
    })?;
    Some(found.swap_remove(k))
}
