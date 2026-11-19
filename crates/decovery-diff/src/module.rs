//! Whole overlay modules against the overlay file (phase 4, Aztec C86): code, data, relocations and BSS.
//!
//! There is no linker step (plan decision 5). The objects of one overlay module are placed in source order: code
//! from `corg`, data from `dorg`, BSS from `dorg + dsize` (BSS follows the overlay's whole data). The module is the
//! front of the overlay: its code must end where the overlay's entry (`$ovbgn` of the runtime library, linked
//! behind the module) begins; the data the library adds behind the module's data and the code from the entry on
//! are not part of the module. Port of Decomp's module check (`tools/pruefe_wizardry7_overlay.py`).
//!
//! Every relocated field is resolved before the bytes are compared:
//! - targets inside the module (code, data and BSS symbols of any of its objects, unnamed positions) are computed
//!   from the placement and must equal the original field (`refs_ok` / `refs_wrong`);
//! - external names take their binding from the original fields (field less the object's number): the address most
//!   uses of a name lead to binds it (the first on a tie), every other use is a wrong reference;
//! - common symbols (uninitialised globals no object defines) are placed behind the objects' own BSS in the order
//!   of their first appearance (ADR 0013) and count into the BSS size;
//! - segment paragraphs and far pointers (the loader's CS/DS) are link gaps.
//!
//! The module is identical when code and data are byte-equal after that, every reference agrees, the code ends
//! at the entry and the BSS size equals the header's.

use std::collections::{BTreeMap, BTreeSet};

use decovery_core::RelocKind;
use decovery_loaders::Overlay;
use decovery_objects::{ObjectFile, ObjectModule, RefTarget, SectionKind};

use crate::{Blocker, Comparison, Metrics, Verdict};

/// Result of [`compare_overlay_module`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ModuleVerdict {
    /// Code from `corg`: metrics in bytes, blockers at offsets from `corg`.
    pub code: Comparison,
    /// Code size of the module in the original (entry − corg) and rebuilt.
    pub code_size: (u32, u32),
    pub data_equal: bool,
    /// Offsets (from `dorg`) of differing data bytes; a rebuilt data part longer than the overlay's data adds
    /// the offsets past its end.
    pub data_diffs: Vec<u32>,
    /// Data size of the overlay (module plus library part) and of the rebuilt module.
    pub data_size: (u32, u32),
    /// Rebuilt data bytes not compared: relocated fields that are link gaps (segment paragraphs, far pointers,
    /// targets the module cannot place).
    pub data_gaps: u32,
    /// BSS size: overlay header, rebuilt. BSS has no bytes: only its size and the references into it are checked.
    pub bss: (u16, u16),
    /// External names and the address the original binds them to (code offset for calls, DS offset for data).
    pub externals: BTreeMap<String, u16>,
    /// References whose binding disagrees with an earlier use of the same external name.
    pub ambiguous: Vec<String>,
    pub identical: bool,
    /// Every external name bound inside the original's BSS when the files give less BSS than the original (name,
    /// address); the BSS finding names only the first of them.
    pub bss_externals: Vec<(String, u16)>,
    /// The common symbols the layout placed behind the files' own BSS, in order.
    pub commons: Vec<Common>,
    /// The wrong code references (one per wrong-reference blocker, same order): what the original's field leads
    /// to and what the rebuild's symbol and addend give.
    pub wrong_refs: Vec<WrongRef>,
    /// Plain-language findings for a module that is not identical, most telling first: a code size that differs
    /// from the original (a partial module, or a shift whose later differences are likely consequences).
    pub findings: Vec<String>,
}

/// A relocated code field of the module whose value differs from the original's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WrongRef {
    /// Offset of the field from the code origin.
    pub at: u32,
    /// Address of the field.
    pub place: i64,
    /// The symbol the rebuild references (an unnamed section target: `<module> <section>`).
    pub symbol: String,
    /// The addend the rebuild adds to it.
    pub addend: i64,
    /// The address the original's field leads to (for a self-relative field: its target).
    pub original: i64,
    /// The address the rebuild's symbol plus addend gives.
    pub rebuilt: i64,
    pub relative: bool,
}

impl WrongRef {
    /// `symbol+addend: original A, rebuilt B`.
    pub fn text(&self) -> String {
        let expr = match self.addend {
            0 => self.symbol.clone(),
            k if k > 0 => format!("{}+{k}", self.symbol),
            k => format!("{}{k}", self.symbol),
        };
        format!(
            "{expr}: original {:04X}, rebuilt {:04X}",
            self.original & 0xFFFF,
            self.rebuilt & 0xFFFF
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Code,
    Data,
}

/// Where a section lies: the part of the overlay file holding its bytes (`None` for BSS) and its address.
type Base = (Option<Part>, i64);

/// Where each section of each module lies (`None`: a section kind the overlay has no place for).
struct Layout {
    bases: Vec<Vec<Option<Base>>>,
    code: Vec<u8>,
    data: Vec<u8>,
    bss: u32,
}

fn layout(modules: &[&ObjectModule], corg: i64, dorg: i64, bss_start: i64) -> Layout {
    let (mut code, mut data, mut bss) = (Vec::new(), Vec::new(), 0u32);
    let mut bases = Vec::new();
    for m in modules {
        let mut own = Vec::new();
        for s in &m.sections {
            own.push(match s.kind {
                SectionKind::Code => {
                    let at = corg + code.len() as i64;
                    code.extend(&s.data);
                    code.resize(
                        code.len() + (s.size as usize).saturating_sub(s.data.len()),
                        0,
                    );
                    Some((Some(Part::Code), at))
                }
                SectionKind::Data => {
                    // the Aztec linker starts every object's data on a word: after an object with an odd data
                    // size one zero byte follows (third target, VMAZE: 229 data bytes, then a pad byte)
                    if data.len() % 2 == 1 {
                        data.push(0);
                    }
                    let at = dorg + data.len() as i64;
                    data.extend(&s.data);
                    data.resize(
                        data.len() + (s.size as usize).saturating_sub(s.data.len()),
                        0,
                    );
                    Some((Some(Part::Data), at))
                }
                SectionKind::Bss => {
                    let at = bss_start + i64::from(bss);
                    bss = bss.saturating_add(s.size);
                    Some((None, at))
                }
                _ => None,
            });
        }
        bases.push(own);
    }
    Layout {
        bases,
        code,
        data,
        bss,
    }
}

/// Places the common symbols no module defines behind the modules' own BSS (ADR 0013): each name once, in the
/// order of its first appearance (objects in link order, each in symbol-table order), with the largest size any
/// object declares, without alignment. Returns the BSS size including them and the placed commons.
fn place_commons<'a>(
    modules: &[&'a ObjectModule],
    public: &mut BTreeMap<&'a str, i64>,
    bss_start: i64,
    own_bss: u32,
) -> (u32, Vec<Common>) {
    let mut order: Vec<&str> = Vec::new();
    let mut sizes: BTreeMap<&str, (u32, Vec<String>)> = BTreeMap::new();
    for m in modules {
        for (name, size) in &m.commons {
            if public.contains_key(name.as_str()) {
                continue;
            }
            let entry = sizes.entry(name.as_str()).or_insert_with(|| {
                order.push(name.as_str());
                (0, Vec::new())
            });
            entry.0 = entry.0.max(*size);
            if !entry.1.contains(&m.name) {
                entry.1.push(m.name.clone());
            }
        }
    }
    let mut bss = own_bss;
    let mut placed = Vec::new();
    for name in order {
        let address = bss_start + i64::from(bss);
        public.insert(name, address);
        let (size, declared_in) = &sizes[name];
        placed.push(Common {
            name: name.to_string(),
            size: *size,
            address,
            declared_in: declared_in.clone(),
        });
        bss = bss.saturating_add(*size);
    }
    (bss, placed)
}

/// A common symbol placed in the module's BSS: an uninitialised global or an `extern` declaration with a size
/// (`extern int x[3];`), which the compiler emits the same way and which counts into the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Common {
    pub name: String,
    /// The largest size any object declares.
    pub size: u32,
    pub address: i64,
    /// The objects declaring it.
    pub declared_in: Vec<String>,
}

/// One use of an external name: the address it binds the name to (the original field less the object's number).
struct ExternUse<'a> {
    name: &'a str,
    bound: i64,
    number: i64,
    orig: i64,
    place: i64,
    /// Offset of the field from the code origin (for the blocker).
    at: u32,
    code: bool,
    relative: bool,
}

fn read_field(bytes: &[u8], at: usize, width: usize) -> Option<i64> {
    let field = bytes.get(at..at.checked_add(width)?)?;
    Some(
        field
            .iter()
            .rev()
            .fold(0i64, |a, &b| (a << 8) | i64::from(b)),
    )
}

fn sign(value: i64, width: usize) -> i64 {
    let bits = 8 * width as u32;
    if bits < 64 && value >> (bits - 1) & 1 == 1 {
        value - (1i64 << bits)
    } else {
        value
    }
}

fn write_field(bytes: &mut [u8], at: usize, width: usize, value: i64) {
    if let Some(field) = bytes.get_mut(at..at + width) {
        for (k, b) in field.iter_mut().enumerate() {
            *b = (value >> (8 * k)) as u8;
        }
    }
}

/// Compares the module built from `objects` (in source order) with `overlay`.
pub fn compare_overlay_module(objects: &[&ObjectFile], overlay: &Overlay) -> ModuleVerdict {
    let h = overlay.header;
    let modules: Vec<&ObjectModule> = objects.iter().flat_map(|o| &o.modules).collect();
    let corg = i64::from(h.corg);
    let dorg = i64::from(h.dorg);
    let bss_start = dorg + i64::from(h.dsize);
    let Layout {
        bases,
        mut code,
        mut data,
        bss: own_bss,
    } = layout(&modules, corg, dorg, bss_start);

    // symbols: public ones for every module, local ones for their own
    let mut public: BTreeMap<&str, i64> = BTreeMap::new();
    for (mi, m) in modules.iter().enumerate() {
        for s in m.symbols.iter().filter(|s| s.public) {
            if let Some(Some((_, base))) = bases[mi].get(s.section as usize) {
                public
                    .entry(s.name.as_str())
                    .or_insert(base + i64::from(s.offset));
            }
        }
    }
    let (bss, commons) = place_commons(&modules, &mut public, bss_start, own_bss);

    let mut metrics = Metrics::default();
    let mut blockers = Vec::new();
    let mut externals: BTreeMap<String, u16> = BTreeMap::new();
    let mut ambiguous = Vec::new();
    let mut wrong_refs: Vec<WrongRef> = Vec::new();
    // the uses of external names, judged once every use is known
    let mut uses: Vec<ExternUse> = Vec::new();
    let mut gaps_code = BTreeSet::new();
    let mut gaps_data = BTreeSet::new();
    // every relocated code field: judged as a reference, never as differing bytes
    let mut fields_code = BTreeSet::new();
    for (mi, m) in modules.iter().enumerate() {
        for (si, s) in m.sections.iter().enumerate() {
            let Some(Some((Some(part), base))) = bases[mi].get(si).copied() else {
                continue;
            };
            let (origin, original, rebuilt) = match part {
                Part::Code => (corg, overlay.code.as_slice(), &mut code),
                Part::Data => (dorg, overlay.data.as_slice(), &mut data),
            };
            for r in &s.relocs {
                let width = usize::from(r.width);
                let place = base + i64::from(r.offset);
                let at = (place - origin) as usize;
                let end = place + i64::from(r.width);
                let mask = if width >= 8 {
                    -1
                } else {
                    (1i64 << (8 * width)) - 1
                };
                let stored = read_field(&s.data, r.offset as usize, width).unwrap_or(0);
                let orig = read_field(original, at, width);
                let gap = |rebuilt: &mut Vec<u8>, gaps: &mut BTreeSet<usize>| {
                    if let Some(o) = orig {
                        write_field(rebuilt, at, width, o);
                    }
                    gaps.extend(at..at + width);
                };
                if part == Part::Code {
                    fields_code.extend(at..at + width);
                }
                let gaps = match part {
                    Part::Code => &mut gaps_code,
                    Part::Data => &mut gaps_data,
                };
                if !matches!(r.kind, RelocKind::Absolute | RelocKind::Relative) {
                    gap(rebuilt, gaps);
                    continue;
                }
                let relative = r.kind == RelocKind::Relative;
                // the address the reference names inside the module, or the external name
                // what the rebuild names: the symbol and its addend
                let (symbol, addend) = match &r.target {
                    RefTarget::Symbol(n) => (n.clone(), sign(stored, width)),
                    RefTarget::Section { index, offset } => {
                        let at = i64::from(*offset) + if relative { 0 } else { stored };
                        match m
                            .symbols
                            .iter()
                            .find(|x| x.section == *index && i64::from(x.offset) == at)
                        {
                            Some(x) => (x.name.clone(), 0),
                            None => (
                                format!(
                                    "{} {}",
                                    m.name,
                                    m.sections
                                        .get(*index as usize)
                                        .map_or("?", |x| x.name.as_str())
                                ),
                                at,
                            ),
                        }
                    }
                    _ => (String::new(), 0),
                };
                let (internal, name): (Option<i64>, Option<&str>) = match &r.target {
                    RefTarget::Section { index, offset } => {
                        match bases[mi].get(*index as usize).copied().flatten() {
                            // a self-relative section target already holds the expression's number
                            Some((_, b)) if relative => (Some(b + i64::from(*offset)), None),
                            Some((_, b)) => (Some(b + i64::from(*offset) + stored), None),
                            None => (None, None),
                        }
                    }
                    RefTarget::Symbol(n) => {
                        let local = m
                            .symbols
                            .iter()
                            .find(|x| x.name == *n)
                            .and_then(|x| {
                                bases[mi]
                                    .get(x.section as usize)
                                    .copied()
                                    .flatten()
                                    .map(|(_, b)| b + i64::from(x.offset))
                            })
                            .or_else(|| public.get(n.as_str()).copied());
                        match local {
                            Some(a) => (Some(a + sign(stored, width)), None),
                            None => (None, Some(n.as_str())),
                        }
                    }
                    _ => (None, None),
                };
                let to_field = |target: i64| (if relative { target - end } else { target }) & mask;
                let Some(orig) = orig else {
                    // past the original's end: the size check reports it
                    if let Some(t) = internal {
                        write_field(rebuilt, at, width, to_field(t));
                    }
                    metrics.refs_unchecked += 1;
                    continue;
                };
                let wrong =
                    |blockers: &mut Vec<Blocker>, wrong_refs: &mut Vec<WrongRef>, t: i64| {
                        let at = (place - corg).max(0) as u32;
                        wrong_refs.push(WrongRef {
                            at,
                            place,
                            symbol: symbol.clone(),
                            addend,
                            original: if relative {
                                end + sign(orig, width)
                            } else {
                                orig
                            },
                            rebuilt: t,
                            relative,
                        });
                        blockers.push(if relative {
                            Blocker::WrongRelativeRef { at }
                        } else {
                            Blocker::WrongAbsoluteRef { at }
                        });
                    };
                match (internal, name) {
                    (Some(t), _) => {
                        let value = to_field(t);
                        write_field(rebuilt, at, width, value);
                        if value == orig {
                            metrics.refs_ok += 1;
                        } else {
                            metrics.refs_wrong += 1;
                            if part == Part::Code {
                                wrong(&mut blockers, &mut wrong_refs, t);
                            }
                        }
                    }
                    (None, Some(n)) => {
                        let number = sign(stored, width);
                        let field = if relative { sign(orig, width) } else { orig };
                        let bound =
                            ((if relative { end + field } else { field }) - number) & 0xFFFF;
                        uses.push(ExternUse {
                            name: n,
                            bound,
                            number,
                            orig,
                            place,
                            at: (place - corg).max(0) as u32,
                            code: part == Part::Code,
                            relative,
                        });
                        write_field(rebuilt, at, width, orig);
                    }
                    (None, None) => {
                        metrics.refs_unchecked += 1;
                        gap(rebuilt, gaps);
                    }
                }
            }
        }
    }

    // external names: the address most of a name's uses agree on binds it (the first such use on a tie); every
    // other use is a wrong reference
    let mut votes: BTreeMap<&str, Vec<(i64, u32)>> = BTreeMap::new();
    for u in &uses {
        let v = votes.entry(u.name).or_default();
        match v.iter_mut().find(|(b, _)| *b == u.bound) {
            Some((_, n)) => *n += 1,
            None => v.push((u.bound, 1)),
        }
    }
    for (name, v) in &votes {
        // max_by_key keeps the last maximum: search the reversed list for the first
        if let Some(&(b, _)) = v.iter().rev().max_by_key(|(_, n)| *n) {
            externals.insert((*name).to_string(), b as u16);
        }
    }
    for u in &uses {
        let b = i64::from(externals[u.name]);
        if u.bound == b {
            metrics.refs_ok += 1;
            continue;
        }
        metrics.refs_wrong += 1;
        let n = u.name;
        let expr = match u.number {
            0 => n.to_string(),
            k if k > 0 => format!("{n}+{k}"),
            k => format!("{n}{k}"),
        };
        ambiguous.push(format!(
            "{n}: bound at {b:04X} by its other uses; the field at {:04X} ({expr}) holds {:04X}, as if {n} were at {:04X}",
            u.place, u.orig, u.bound
        ));
        if u.code {
            wrong_refs.push(WrongRef {
                at: u.at,
                place: u.place,
                symbol: n.to_string(),
                addend: u.number,
                original: u.bound + u.number,
                rebuilt: b + u.number,
                relative: u.relative,
            });
            blockers.push(if u.relative {
                Blocker::WrongRelativeRef { at: u.at }
            } else {
                Blocker::WrongAbsoluteRef { at: u.at }
            });
        }
    }
    wrong_refs.sort_by_key(|w| w.at);
    blockers.sort_by_key(|b| match *b {
        Blocker::WrongRelativeRef { at } | Blocker::WrongAbsoluteRef { at } => at,
        _ => 0,
    });

    // code
    let code_size = (
        u32::from(h.entry.wrapping_sub(h.corg)),
        u32::try_from(code.len()).unwrap_or(u32::MAX),
    );
    metrics.bytes = code_size.1;
    metrics.gaps = gaps_code.len() as u32;
    for (k, &b) in code.iter().enumerate() {
        match overlay.code.get(k) {
            _ if gaps_code.contains(&k) => {}
            _ if fields_code.contains(&k) => metrics.equal += 1,
            Some(&o) if o == b => metrics.equal += 1,
            _ => {
                metrics.differing += 1;
                metrics.first_difference.get_or_insert(k as u32);
            }
        }
    }
    if metrics.differing > 0 {
        let compared = code.len().min(overlay.code.len());
        metrics.instructions_differing =
            crate::gaps::differing_instructions(&code[..compared], &overlay.code[..compared], 16);
        blockers.insert(
            0,
            Blocker::BytesDiffer {
                count: metrics.differing,
            },
        );
    }
    let code_ok = blockers.is_empty() && code_size.0 == code_size.1;
    let comparison = Comparison {
        verdict: if code_ok {
            Verdict::Identical
        } else {
            Verdict::Differs
        },
        blockers,
        metrics,
        diagnoses: Vec::new(),
    };

    // data
    let data_diffs: Vec<u32> = data
        .iter()
        .enumerate()
        .filter(|&(k, &b)| !gaps_data.contains(&k) && overlay.data.get(k) != Some(&b))
        .map(|(k, _)| k as u32)
        .collect();
    let data_equal = data_diffs.is_empty();
    let bss = (h.bss, u16::try_from(bss).unwrap_or(u16::MAX));
    let identical = code_ok && data_equal && bss.0 == bss.1 && ambiguous.is_empty();
    let mut findings = size_findings(code_size, comparison.metrics.first_difference);
    let bss_externals = if bss.0 > bss.1 {
        findings.push(bss_finding(bss, bss_start, &externals));
        let end = bss_start + i64::from(bss.0);
        externals
            .iter()
            .filter(|(_, a)| (bss_start..end).contains(&i64::from(**a)))
            .map(|(n, a)| (n.clone(), *a))
            .collect()
    } else {
        Vec::new()
    };
    findings.extend(externals.iter().filter_map(|(n, &a)| suffix_mismatch(n, a)));
    if bss.0 != bss.1 && !commons.is_empty() {
        findings.push(commons_finding(&commons));
    }
    ModuleVerdict {
        code: comparison,
        code_size,
        data_equal,
        data_diffs,
        data_size: (
            u32::from(h.dsize),
            u32::try_from(data.len()).unwrap_or(u32::MAX),
        ),
        bss,
        externals,
        ambiguous,
        wrong_refs,
        bss_externals,
        commons,
        identical,
        findings,
        data_gaps: u32::try_from(gaps_data.len()).unwrap_or(u32::MAX),
    }
}

/// Names the external names bound inside the original's BSS when the files give less BSS than the original: a
/// global the sources only declare `extern` is not placed by the linker (an undefined name without a size is no
/// common symbol), so its definition is missing from the module's files.
fn bss_finding(
    (original, rebuilt): (u16, u16),
    bss_start: i64,
    externals: &BTreeMap<String, u16>,
) -> String {
    let end = bss_start + i64::from(original);
    let range = format!("{bss_start:04X}..{end:04X}");
    let inside: Vec<&str> = externals
        .iter()
        .filter(|(_, a)| (bss_start..end).contains(&i64::from(**a)))
        .map(|(n, _)| n.as_str())
        .collect();
    let head = format!("BSS: {original} bytes in the original, {rebuilt} from the module's files;");
    if inside.is_empty() {
        return format!("{head} no external name is bound inside the original BSS ({range})");
    }
    const SHOWN: usize = 8;
    let n = inside.len();
    let more = if n > SHOWN {
        format!(" and {} more", n - SHOWN)
    } else {
        String::new()
    };
    let more = if more.is_empty() {
        more
    } else {
        format!("{more} (all with addresses: the module's bss_externals)")
    };
    format!(
        "{head} {n} external name{} bound inside the original BSS ({range}), defined in none of the files: {}{more}",
        if n == 1 { "" } else { "s" },
        inside[..n.min(SHOWN)].join(", ")
    )
}

/// Says which declared sizes the BSS layout counts: extern declarations with a size count like definitions.
fn commons_finding(commons: &[Common]) -> String {
    let total: u32 = commons.iter().map(|c| c.size).sum();
    let list: Vec<String> = commons
        .iter()
        .take(8)
        .map(|c| {
            format!(
                "{} {} byte{} at {:04X} ({})",
                c.name,
                c.size,
                if c.size == 1 { "" } else { "s" },
                c.address,
                c.declared_in.join(", ")
            )
        })
        .collect();
    let more = if commons.len() > 8 {
        format!(" and {} more", commons.len() - 8)
    } else {
        String::new()
    };
    format!(
        "BSS counts {total} bytes of commons (uninitialised globals and extern declarations with a size, such as          `extern int x[3];`): {}{more}",
        list.join(", ")
    )
}

/// An external name that ends in a four-digit hexadecimal address (`word_91b8`, `table_84aa`, `DAT_seg_9202`,
/// the compiler's trailing `_` aside) other than the one the original binds it to: the name was likely given
/// for another address, or the extern is used at the wrong one.
fn suffix_mismatch(name: &str, bound: u16) -> Option<String> {
    let base = name.strip_suffix('_').unwrap_or(name);
    let (_, suffix) = base.rsplit_once('_')?;
    if suffix.len() != 4
        || !suffix.chars().all(|c| c.is_ascii_hexdigit())
        || !suffix.chars().any(|c| c.is_ascii_digit())
    {
        return None;
    }
    let named = u16::from_str_radix(suffix, 16).ok()?;
    (named != bound).then(|| {
        format!(
            "{name}: bound at {bound:04X}, but its name says {named:04X}; check the extern's name or the address its uses give"
        )
    })
}

/// Findings from the code size (original, rebuilt) and the first real byte difference.
fn size_findings((original, rebuilt): (u32, u32), first_difference: Option<u32>) -> Vec<String> {
    let mut out = Vec::new();
    if original == rebuilt {
        return out;
    }
    let by = original.abs_diff(rebuilt);
    let unit = if by == 1 { "byte" } else { "bytes" };
    if rebuilt < original {
        out.push(format!(
            "module covers only 0x0000..0x{rebuilt:04X} of 0x0000..0x{original:04X} \
             (code {by} {unit} shorter: rebuilt {rebuilt}, original {original}); a partial module, or code missing"
        ));
    } else {
        out.push(format!(
            "module code is {by} {unit} longer than the original (rebuilt {rebuilt}, original {original})"
        ));
    }
    if let Some(x) = first_difference {
        out.push(format!(
            "first real difference at offset 0x{x:04X}; differences after offset 0x{x:04X} are likely consequences \
             of the size change"
        ));
    }
    out
}
