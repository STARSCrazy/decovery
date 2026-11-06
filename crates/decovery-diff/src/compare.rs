//! Byte and reference comparison (port of Decomp's `vergleiche`) plus decovery's verdict.

use std::collections::{BTreeMap, BTreeSet};

use decovery_core::{Address, Program, RelocKind, Relocation};
use decovery_objects::{FunctionView, ObjReloc, ObjectModule, RefTarget, functions};
use decovery_x86::{DecodeOptions, decode_detailed, internal_calls, padding_positions};
use rayon::prelude::*;

use crate::anchors::{Anchors, Condition, FLAT, Outcome, SectionKey, frame_name};
use crate::instructions::{self, Naming, Side};
use crate::{
    Blocker, CompareOptions, Comparison, Decoration, Metrics, ModuleComparison, ModuleOptions,
    NameAt, Placement, SymbolView, Verdict,
};

fn signed(bytes: &[u8]) -> i64 {
    let raw = bytes
        .iter()
        .rev()
        .fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let bits = 8 * bytes.len() as u32;
    if bits > 0 && bits < 64 && raw >> (bits - 1) != 0 {
        raw as i64 - (1i64 << bits)
    } else {
        raw as i64
    }
}

/// Numeric value of an address inside its space (flat: linear; segmented: offset).
fn base_of(at: Address) -> Option<u64> {
    match at {
        Address::Flat(a) => Some(u64::from(a)),
        Address::Seg { off, .. } => Some(u64::from(off)),
        _ => None,
    }
}

/// The address `value` in the space of `at`, wrapped like the field (Decomp's `_ziel`).
fn address_in_space(at: Address, value: i64) -> Option<Address> {
    match at {
        Address::Flat(_) => Some(Address::Flat(value as u32)),
        Address::Seg { seg, .. } => Some(Address::Seg {
            seg,
            off: value as u16,
        }),
        _ => None,
    }
}

fn same(a: Address, b: Address) -> bool {
    a == b || (a.linear().is_some() && a.linear() == b.linear())
}

/// The rebuilt function in Decomp's terms.
struct Rebuild<'a> {
    f: &'a FunctionView<'a>,
    /// Bytes as Decomp's reader produced them: own-section absolute fields it could name are zeroed.
    bytes: Vec<u8>,
    gaps: BTreeSet<u32>,
    relative: BTreeSet<u32>,
    refs: BTreeMap<u32, String>,
    addends: BTreeMap<u32, i64>,
    /// Section offset → name of the functions in the same section (a later name at one offset wins).
    internal: BTreeMap<u32, String>,
}

impl<'a> Rebuild<'a> {
    fn new(f: &'a FunctionView<'a>) -> Self {
        let section = f.module.sections.get(f.section as usize);
        let section_relocs: &[ObjReloc] = section.map_or(&[], |s| s.relocs.as_slice());
        let section_data: &[u8] = section.map_or(&[], |s| s.data.as_slice());
        let section_gaps: BTreeSet<u32> = section_relocs
            .iter()
            .flat_map(|r| r.offset..r.offset.saturating_add(u32::from(r.width)))
            .collect();
        let mut bytes = f.code().to_vec();
        for r in section_relocs {
            let RefTarget::Section { index, offset } = r.target else {
                continue;
            };
            if index != f.section || r.kind == RelocKind::Relative {
                continue;
            }
            let p = r.offset;
            let w = if (p..p.saturating_add(4)).all(|q| section_gaps.contains(&q)) {
                4
            } else {
                2
            };
            let field = section_data
                .get(p as usize..)
                .map_or(&[][..], |d| &d[..d.len().min(w as usize)]);
            let target = i64::from(offset) + signed(field);
            let named = f
                .module
                .symbols
                .iter()
                .any(|s| s.section == f.section && i64::from(s.offset) == target);
            if named {
                for q in p..p.saturating_add(w) {
                    if q >= f.start
                        && let Some(b) = bytes.get_mut((q - f.start) as usize)
                    {
                        *b = 0;
                    }
                }
            }
        }
        let mut internal = BTreeMap::new();
        for g in functions(f.module) {
            if g.section == f.section {
                internal.insert(g.start, g.name.to_string());
            }
        }
        Rebuild {
            f,
            bytes,
            gaps: f.gaps(),
            relative: f.relative_offsets(),
            refs: f
                .references()
                .into_iter()
                .map(|(o, n)| (o, n.to_string()))
                .collect(),
            addends: f.addends().into_iter().collect(),
            internal,
        }
    }

    /// Fixup-less `E8`/`E9` whose target is exactly another function of the same section (Decomp's
    /// `_interne_aufrufe`): field offset → name.
    fn internal_calls(&self, width: u32) -> BTreeMap<u32, String> {
        let bits = width * 8;
        internal_calls(&self.bytes, bits, u64::from(self.f.start))
            .into_iter()
            .filter(|&(field, target)| {
                let k = field - 1;
                !(k..field + width).any(|p| self.gaps.contains(&p))
                    && target != u64::from(self.f.start)
            })
            .filter_map(|(field, target)| {
                let t = u32::try_from(target).ok()?;
                self.internal.get(&t).map(|n| (field, n.clone()))
            })
            .collect()
    }
}

/// Whether `a` and `b`, the same function from two objects (a full and a shrunk source file), hold the same code
/// (Decomp's `gleich` in `nachbau/einzeln.py`): equal bytes outside fixup fields, equal named references with
/// their displacements, equal self-relative fields, and equal unnamed references into the own section relative to
/// the function start (jump tables). Calls the compiler resolved inside the object without a fixup count as named
/// references. Padding behind the function and a following function's jump table do not count: in a shrunk file
/// another function follows. Texts and other functions lie elsewhere there, so field contents are not compared.
pub fn same_code(a: &FunctionView<'_>, b: &FunctionView<'_>) -> bool {
    match (CodeCore::of(a), CodeCore::of(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// What [`same_code`] compares of one function.
#[derive(PartialEq, Eq)]
struct CodeCore {
    bytes: Vec<u8>,
    gaps: BTreeSet<u32>,
    refs: BTreeMap<u32, String>,
    relative: BTreeSet<u32>,
    addends: BTreeMap<u32, i64>,
    /// Unnamed own-section fixups: (field, target, self-relative), both relative to the function start.
    own: Vec<(i64, i64, bool)>,
}

impl CodeCore {
    fn of(f: &FunctionView<'_>) -> Option<Self> {
        let section = f.module.sections.get(f.section as usize)?;
        let bits = u32::from(section.bits);
        if bits != 16 && bits != 32 {
            return None;
        }
        let width = bits / 8;
        let rebuild = Rebuild::new(f);
        let mut refs = rebuild.refs.clone();
        let mut relative = rebuild.relative.clone();
        let mut gaps = rebuild.gaps.clone();
        for (field, name) in rebuild.internal_calls(width) {
            refs.insert(field, name);
            relative.insert(field);
            gaps.extend(field..field + width);
        }
        let end = decode_detailed(
            &rebuild.bytes,
            bits,
            0,
            &DecodeOptions::new(gaps.clone(), true),
        )
        .iter()
        .filter(|d| !d.is_padding())
        .map(|d| d.offset + d.len)
        .max()
        .unwrap_or(0);
        let bytes = rebuild
            .bytes
            .iter()
            .take(end as usize)
            .enumerate()
            .map(|(k, &b)| if gaps.contains(&(k as u32)) { 0 } else { b })
            .collect();
        let start = i64::from(f.start);
        let own = f
            .relocs()
            .filter(|r| r.offset - f.start < end)
            .filter_map(|r| {
                let RefTarget::Section { index, offset } = r.target else {
                    return None;
                };
                if index != f.section {
                    return None;
                }
                let field = section
                    .data
                    .get(r.offset as usize..)
                    .map_or(&[][..], |d| &d[..d.len().min(usize::from(r.width))]);
                let target = i64::from(offset) + signed(field);
                let named = f
                    .module
                    .symbols
                    .iter()
                    .any(|s| s.section == f.section && i64::from(s.offset) == target);
                (!named).then_some((
                    i64::from(r.offset) - start,
                    target - start,
                    r.kind == RelocKind::Relative,
                ))
            })
            .collect();
        Some(CodeCore {
            bytes,
            gaps: gaps.range(..end).copied().collect(),
            refs: refs.into_iter().filter(|&(k, _)| k < end).collect(),
            relative: relative.range(..end).copied().collect(),
            addends: rebuild
                .addends
                .into_iter()
                .filter(|&(k, _)| k < end)
                .collect(),
            own,
        })
    }
}

/// Decomp's `_fuellung`: 1–3 zeros where the original has `90` everywhere, or the last zero run (up to 7).
fn zero_padding(code: &[u8], original: &[u8], gaps: &BTreeSet<u32>) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let mut k = 0usize;
    while k < code.len() {
        if code[k] != 0 || gaps.contains(&(k as u32)) {
            k += 1;
            continue;
        }
        let mut end = k;
        while end < code.len() && code[end] == 0 && !gaps.contains(&(end as u32)) {
            end += 1;
        }
        let run = end - k;
        if (end == code.len() && run <= 7)
            || (run <= 3 && original[k..end].iter().all(|&b| b == 0x90))
        {
            out.extend(k as u32..end as u32);
        }
        k = end;
    }
    out
}

fn name_or_default(symbols: &dyn SymbolView, at: Address) -> NameAt {
    symbols
        .name_at(at)
        .unwrap_or_else(|| NameAt::new(String::new(), true))
}

/// Decomp's `nb_name`: the C name, or the raw name when only that is known (Watcom `-4s`: `_dos_setvect`).
fn rebuild_name(symbols: &dyn SymbolView, decoration: &Decoration, raw: &str) -> String {
    let c = decoration.undecorate(raw);
    if c != raw && symbols.address_of(c).is_none() && symbols.address_of(raw).is_some() {
        raw.to_string()
    } else {
        c.to_string()
    }
}

/// Decomp's `bekannt`: where the knowledge itself names `name`; a default name resolved by the view does not count.
fn known_address(symbols: &dyn SymbolView, name: &str) -> Option<Address> {
    symbols.address_of(name).filter(|&a| {
        symbols
            .name_at(a)
            .is_some_and(|n| !n.is_default && n.name == name)
    })
}

fn unchecked(bytes: u32, blocker: Option<Blocker>) -> Comparison {
    Comparison {
        verdict: Verdict::Unchecked,
        blockers: blocker.into_iter().collect(),
        metrics: Metrics {
            bytes,
            ..Metrics::default()
        },
    }
}

/// Compares the rebuilt function `f` with the original at `at`: [`compare_module`] with this one placement.
pub fn compare(
    f: &FunctionView,
    at: Address,
    program: &Program,
    symbols: &dyn SymbolView,
    decoration: &Decoration,
    options: &CompareOptions,
) -> Comparison {
    let placement = Placement::new(f.clone(), at, options.original_len);
    let module_options = ModuleOptions::new(options.padding, BTreeMap::new());
    let len = u32::try_from(f.code().len()).unwrap_or(u32::MAX);
    compare_module(
        std::slice::from_ref(&placement),
        program,
        symbols,
        decoration,
        &module_options,
    )
    .functions
    .pop()
    .unwrap_or_else(|| unchecked(len, None))
}

/// Compares every placement with its original. Anchors (ADR 0006) are established over all placements first,
/// then each function is judged. See the crate documentation for the rules.
pub fn compare_module(
    placements: &[Placement<'_>],
    program: &Program,
    symbols: &dyn SymbolView,
    decoration: &Decoration,
    options: &ModuleOptions,
) -> ModuleComparison {
    let mut modules: Vec<&ObjectModule> = Vec::new();
    let module_of = module_indices(placements, &mut modules);
    // both passes are per function and independent; rayon keeps the order
    let prepared: Vec<Prepared> = placements
        .par_iter()
        .zip(module_of.par_iter())
        .map(|(p, &module)| prepare(p, module, program, symbols, decoration, options.padding))
        .collect();
    let conditions = prepared
        .iter()
        .filter_map(|p| match p {
            Prepared::Pending { fields, .. } => Some(fields),
            Prepared::Done(_) => None,
        })
        .flatten()
        .filter_map(|field| match &field.outcome {
            Outcome::Anchored(c) => Some(c),
            Outcome::Decided(_) => None,
        })
        .flatten();
    let anchors = Anchors::collect(conditions, &modules, &options.frames, program);
    let functions = prepared
        .into_par_iter()
        .map(|p| p.finish(&anchors))
        .collect();
    ModuleComparison {
        functions,
        anchors: anchors.list(&modules),
        warnings: anchors.warnings.clone(),
    }
}

/// The index in `modules` of the module of each placement; modules not in `modules` yet are appended.
fn module_indices<'a>(
    placements: &[Placement<'a>],
    modules: &mut Vec<&'a ObjectModule>,
) -> Vec<usize> {
    placements
        .iter()
        .map(|p| {
            match modules
                .iter()
                .position(|m| std::ptr::eq(*m, p.function.module))
            {
                Some(i) => i,
                None => {
                    modules.push(p.function.module);
                    modules.len() - 1
                }
            }
        })
        .collect()
}

/// Placements prepared once for many comparisons that differ only in their own placements (a variant of one function
/// judged together with the unchanged functions of the other objects): the first pass of [`compare_module`] over
/// them, kept as what it contributes to the anchors. See [`compare_module_with`].
pub struct SharedFunctions<'a> {
    modules: Vec<&'a ObjectModule>,
    /// Where each placement is and what its fields ask of the anchors.
    entries: Vec<(Address, Vec<Condition>)>,
}

impl<'a> SharedFunctions<'a> {
    /// Runs the first pass over `placements`; `options` and the other arguments must be those of the comparisons
    /// they are used in.
    pub fn new(
        placements: &[Placement<'a>],
        program: &Program,
        symbols: &dyn SymbolView,
        decoration: &Decoration,
        options: &ModuleOptions,
    ) -> Self {
        let mut modules: Vec<&ObjectModule> = Vec::new();
        let module_of = module_indices(placements, &mut modules);
        let entries = placements
            .par_iter()
            .zip(module_of.par_iter())
            .map(|(p, &module)| {
                let conditions =
                    match prepare(p, module, program, symbols, decoration, options.padding) {
                        Prepared::Pending { fields, .. } => fields
                            .into_iter()
                            .filter_map(|f| match f.outcome {
                                Outcome::Anchored(c) => Some(c),
                                Outcome::Decided(_) => None,
                            })
                            .flatten()
                            .collect(),
                        Prepared::Done(_) => Vec::new(),
                    };
                (p.at, conditions)
            })
            .collect();
        SharedFunctions { modules, entries }
    }
}

/// [`compare_module`] over `own` together with `shared`: the anchors are agreed on by the fields of both, the result
/// holds the comparisons of `own` only (`ModuleComparison::functions` parallels `own`). A shared function at the
/// address of an own placement is left out, as [`compare_module`] would have placed only the first of two functions
/// at one address. The verdicts, blockers and metrics of the `own` functions are those of [`compare_module`] over
/// `own` followed by the shared placements; the shared functions are not prepared again.
pub fn compare_module_with(
    own: &[Placement<'_>],
    shared: &SharedFunctions<'_>,
    program: &Program,
    symbols: &dyn SymbolView,
    decoration: &Decoration,
    options: &ModuleOptions,
) -> ModuleComparison {
    // the shared modules come first, so their conditions can be used as they are
    let mut modules: Vec<&ObjectModule> = shared.modules.clone();
    let module_of = module_indices(own, &mut modules);
    let prepared: Vec<Prepared> = own
        .par_iter()
        .zip(module_of.par_iter())
        .map(|(p, &module)| prepare(p, module, program, symbols, decoration, options.padding))
        .collect();
    let own_at: BTreeSet<Address> = own.iter().map(|p| p.at).collect();
    let conditions = prepared
        .iter()
        .filter_map(|p| match p {
            Prepared::Pending { fields, .. } => Some(fields),
            Prepared::Done(_) => None,
        })
        .flatten()
        .filter_map(|field| match &field.outcome {
            Outcome::Anchored(c) => Some(c),
            Outcome::Decided(_) => None,
        })
        .flatten()
        .chain(
            shared
                .entries
                .iter()
                .filter(|(at, _)| !own_at.contains(at))
                .flat_map(|(_, conditions)| conditions.iter()),
        );
    let anchors = Anchors::collect(conditions, &modules, &options.frames, program);
    let functions = prepared
        .into_par_iter()
        .map(|p| p.finish(&anchors))
        .collect();
    ModuleComparison {
        functions,
        anchors: anchors.list(&modules),
        warnings: anchors.warnings.clone(),
    }
}

/// A relocated field of a function, classified in the first pass.
struct Field {
    outcome: Outcome,
    wrong: Blocker,
    unchecked: Blocker,
}

/// A function after the first pass: its metrics and fields, waiting for the anchors.
enum Prepared {
    Done(Comparison),
    Pending {
        metrics: Metrics,
        fields: Vec<Field>,
    },
}

impl Prepared {
    fn finish(self, anchors: &Anchors) -> Comparison {
        let (m, fields) = match self {
            Prepared::Done(c) => return c,
            Prepared::Pending { metrics, fields } => (metrics, fields),
        };
        let mut blockers = Vec::new();
        if m.differing > 0 {
            blockers.push(Blocker::BytesDiffer { count: m.differing });
        }
        blockers.extend(
            fields
                .iter()
                .filter_map(|f| anchors.judge(&f.outcome, f.wrong, f.unchecked)),
        );
        if m.instructions_differing > 0 {
            blockers.push(Blocker::InstructionsDiffer {
                count: m.instructions_differing,
            });
        }
        Comparison {
            verdict: if blockers.is_empty() {
                Verdict::Identical
            } else {
                Verdict::Differs
            },
            blockers,
            metrics: m,
        }
    }
}

/// First pass for one placement: Decomp's metrics and the classified fields. `module` indexes the modules of
/// the comparison.
fn prepare(
    placement: &Placement<'_>,
    module: usize,
    program: &Program,
    symbols: &dyn SymbolView,
    decoration: &Decoration,
    padding_option: bool,
) -> Prepared {
    let f = &placement.function;
    let at = placement.at;
    let rebuild = Rebuild::new(f);
    let n = rebuild.bytes.len();
    let len = n as u32;
    let bits = f
        .module
        .sections
        .get(f.section as usize)
        .map_or(0, |s| u32::from(s.bits));
    if bits != 16 && bits != 32 {
        return Prepared::Done(unchecked(len, None));
    }
    let Some(original) = program.read(at, n) else {
        return Prepared::Done(unchecked(len, Some(Blocker::OriginalUnavailable)));
    };
    let Some(base) = base_of(at) else {
        return Prepared::Done(unchecked(len, Some(Blocker::OriginalUnavailable)));
    };
    let width = bits / 8;
    let code = &rebuild.bytes;

    // --- Decomp's `vergleiche` ---
    let mut refs = rebuild.refs.clone();
    let mut relative = rebuild.relative.clone();
    let mut gaps = rebuild.gaps.clone();
    let inner = rebuild.internal_calls(width);
    for (&field, name) in &inner {
        refs.insert(field, name.clone());
        relative.insert(field);
        gaps.extend(field..field + width);
    }
    let mut padding = if padding_option {
        zero_padding(code, original, &gaps)
    } else {
        BTreeSet::new()
    };
    let original_padding = padding_positions(original, bits);
    padding.extend(
        padding_positions(code, bits)
            .into_iter()
            .filter(|k| !gaps.contains(k))
            .filter(|&k| {
                original[k as usize] == 0
                    || original_padding.contains(&k)
                    || placement.original_len.is_some_and(|l| k >= l)
            }),
    );
    if let Some(original_len) = placement.original_len
        && len > original_len
    {
        // The following Watcom jump table is no code; only the structured decoder finds alignment
        // instructions behind it at their real boundaries.
        let decoded = decode_detailed(code, bits, 0, &DecodeOptions::new(gaps.clone(), false));
        for d in decoded.iter().rev() {
            if !d.is_padding() || d.offset < original_len {
                break;
            }
            padding.extend(d.offset..d.offset + d.len);
        }
    }
    let mut m = Metrics {
        bytes: len,
        ..Metrics::default()
    };
    for (k, (&a, &b)) in code.iter().zip(original).enumerate() {
        let k = k as u32;
        if gaps.contains(&k) {
            m.gaps += 1;
        } else if padding.contains(&k) && a != b {
            m.padding += 1;
        } else if a == b {
            m.equal += 1;
        } else {
            m.differing += 1;
            m.first_difference.get_or_insert(k);
        }
    }
    for &field in &relative {
        let Some(raw) = refs.get(&field).filter(|_| field + width <= len) else {
            m.refs_unchecked += 1;
            continue;
        };
        let mut wanted = decoration.undecorate(raw).to_string();
        let value = signed(&original[field as usize..(field + width) as usize]);
        let Some(target) = address_in_space(at, base as i64 + i64::from(field + width) + value)
        else {
            m.refs_unchecked += 1;
            continue;
        };
        let found = name_or_default(symbols, target);
        if found.name == *raw && found.name != wanted {
            wanted = raw.clone();
        }
        let elsewhere = known_address(symbols, &wanted);
        if found.name == wanted {
            m.refs_ok += 1;
        } else if found.is_default && elsewhere.is_none_or(|e| same(e, target)) {
            // a default name in the original that the rebuild names: a naming hint, not an error
        } else {
            m.refs_wrong += 1;
        }
    }

    // --- Decomp's `_befehlsvergleich` ---
    let original_span = placement
        .original_len
        .and_then(|l| program.read(at, l as usize))
        .unwrap_or(original);
    let names: BTreeMap<u32, String> = rebuild
        .refs
        .iter()
        .map(|(&o, raw)| (o, rebuild_name(symbols, decoration, raw)))
        .collect();
    let section_start = u64::from(f.start);
    let rebuild_target = |t: u64| -> Option<String> {
        let t = u32::try_from(t).ok()?;
        rebuild
            .internal
            .get(&t)
            .map(|n| decoration.undecorate(n).to_string())
    };
    let original_name = |t: u64| -> Option<String> {
        let mask = if matches!(at, Address::Flat(_)) {
            0xFFFF_FFFF
        } else {
            0xFFFF
        };
        let target = address_in_space(at, (t & mask) as i64)?;
        symbols
            .name_at(target)
            .filter(|n| !n.is_default)
            .map(|n| n.name)
    };
    let data_names =
        |t: u64| -> Vec<(String, i64)> { original_name(t).map(|n| (n, 0)).into_iter().collect() };
    let flat = matches!(at, Address::Flat(_));
    let no_names = BTreeMap::new();
    let no_addends = BTreeMap::new();
    let no_gaps = BTreeSet::new();
    let rebuild_side = Side {
        code,
        base: section_start,
        gaps: &rebuild.gaps,
        naming: Naming {
            names: &names,
            addends: &rebuild.addends,
            target_name: &rebuild_target,
            data_names: None,
        },
    };
    let original_side = Side {
        code: original_span,
        base,
        gaps: &no_gaps,
        naming: Naming {
            names: &no_names,
            addends: &no_addends,
            target_name: &original_name,
            data_names: if flat { Some(&data_names) } else { None },
        },
    };
    let data_address = |name: &str| -> Option<u64> {
        if flat {
            known_address(symbols, name).and_then(|a| a.linear())
        } else {
            None
        }
    };
    m.instructions_differing = instructions::differing(
        &rebuild_side,
        &original_side,
        bits,
        padding_option,
        &data_address,
    );

    // --- decovery's fields ---
    // Fields inside padding behind the original's end (the following function's jump table) belong to the
    // next function, as in Decomp's byte comparison.
    let mut checks: Vec<(u32, Check)> = f
        .relocs()
        .map(|r| (r.offset - f.start, Check::Fixup(r)))
        .filter(|(o, _)| !padding.contains(o))
        .collect();
    checks.extend(inner.iter().map(|(&o, n)| (o, Check::Internal(n))));
    checks.sort_by_key(|&(o, _)| o);
    let site = Site {
        rebuild: &rebuild,
        at,
        base,
        original,
        program,
        symbols,
        decoration,
        width,
        bits,
        module,
    };
    let fields = checks
        .iter()
        .map(|(offset, check)| site.classify(*offset, check))
        .collect();
    Prepared::Pending { metrics: m, fields }
}

enum Check<'a> {
    Fixup(&'a ObjReloc),
    /// A fixup-less near call/jump to another function of the object.
    Internal(&'a str),
}

/// What a field's target resolves to in the original.
enum Target {
    Known(Address),
    /// An unnamed position `rel` (section offset + addend + content) in another section of the module.
    Unnamed {
        section: u32,
        rel: i64,
    },
    /// A position before the function start in its own section (32-bit): the function's jump table, whose
    /// distance to the function depends on the code before it, matches by its entries; anything else (an unnamed
    /// static) matches when the original has it at `same_distance`.
    OwnTable {
        table: u32,
        same_distance: Address,
    },
    /// No address can be determined (unknown symbol, group target).
    Unresolved,
    /// The target address overflows its space.
    Invalid,
}

/// The original's relocation whose field starts exactly at `at`.
fn relocation_at(program: &Program, at: Address) -> Option<&Relocation> {
    program
        .relocations_in(at, 1)
        .iter()
        .find(|r| same(r.at, at))
}

/// Everything about one placement that classifying its fields needs.
struct Site<'s> {
    rebuild: &'s Rebuild<'s>,
    at: Address,
    base: u64,
    original: &'s [u8],
    program: &'s Program,
    symbols: &'s dyn SymbolView,
    decoration: &'s Decoration,
    width: u32,
    bits: u32,
    module: usize,
}

impl Site<'_> {
    fn lookup(&self, raw: &str) -> Option<Address> {
        let c = self.decoration.undecorate(raw);
        self.symbols
            .address_of(c)
            .or_else(|| self.symbols.address_of(raw))
    }

    /// The target the rebuild means, in the original's address space.
    fn expected(&self, check: &Check<'_>, raw_field: &[u8]) -> Target {
        let f = self.rebuild.f;
        let r = match check {
            Check::Internal(name) => {
                return self.lookup(name).map_or(Target::Unresolved, Target::Known);
            }
            Check::Fixup(r) => r,
        };
        let content = signed(raw_field);
        match &r.target {
            RefTarget::Symbol(name) => {
                let Some(a) = self.lookup(name) else {
                    return Target::Unresolved;
                };
                a.offset_by(content.wrapping_add(r.addend))
                    .map_or(Target::Invalid, Target::Known)
            }
            RefTarget::Section {
                index,
                offset: base_offset,
            } if *index == f.section => {
                // A symbol start (static function) resolves through that symbol's address; a target behind
                // the function (entries of the following function's jump table) through the function
                // containing it; everything else, including the function's own jump table placed before
                // its start, through the function's own address.
                let target = i64::from(*base_offset) + content;
                let end = i64::from(f.start) + i64::from(f.len);
                let in_section = |s: &&decovery_objects::ObjSymbol| {
                    s.section == f.section && s.offset != f.start
                };
                let owner = f
                    .module
                    .symbols
                    .iter()
                    .filter(in_section)
                    .find(|s| i64::from(s.offset) == target)
                    .or_else(|| {
                        (target >= end)
                            .then(|| {
                                f.module
                                    .symbols
                                    .iter()
                                    .filter(in_section)
                                    .filter(|s| i64::from(s.offset) <= target)
                                    .max_by_key(|s| s.offset)
                            })
                            .flatten()
                    });
                if owner.is_none() && target < i64::from(f.start) && self.bits == 32 {
                    // before the function: its own jump table (checked entry by entry) or an unnamed static
                    // at the same distance as in the original
                    return match (
                        u32::try_from(target),
                        self.at.offset_by(target - i64::from(f.start)),
                    ) {
                        (Ok(table), Ok(same_distance)) => Target::OwnTable {
                            table,
                            same_distance,
                        },
                        _ => Target::Invalid,
                    };
                }
                let resolved = match owner {
                    Some(s) => self
                        .lookup(&s.name)
                        .and_then(|a| a.offset_by(target - i64::from(s.offset)).ok()),
                    None => self.at.offset_by(target - i64::from(f.start)).ok(),
                };
                resolved.map_or(Target::Unresolved, Target::Known)
            }
            RefTarget::Section {
                index,
                offset: base_offset,
            } => {
                let target = i64::from(*base_offset) + content;
                let name = f
                    .module
                    .symbols
                    .iter()
                    .find(|s| s.section == *index && i64::from(s.offset) == target)
                    .map(|s| s.name.as_str());
                match name {
                    Some(name) => self.lookup(name).map_or(Target::Unresolved, Target::Known),
                    None => Target::Unnamed {
                        section: *index,
                        rel: target + r.addend,
                    },
                }
            }
            _ => Target::Unresolved,
        }
    }

    /// decovery's rule for one relocated field at `offset` (relative to the function).
    fn classify(&self, offset: u32, check: &Check<'_>) -> Field {
        let (kind, field_width) = match check {
            Check::Fixup(r) => (r.kind, u32::from(r.width)),
            Check::Internal(_) => (RelocKind::Relative, self.width),
        };
        let wrong = match kind {
            RelocKind::Relative => Blocker::WrongRelativeRef { at: offset },
            _ => Blocker::WrongAbsoluteRef { at: offset },
        };
        let unchecked = Blocker::UncheckedRef { at: offset };
        Field {
            outcome: self.outcome(
                offset,
                check,
                kind,
                field_width,
                Outcome::Decided(Some(wrong)),
                Outcome::Decided(Some(unchecked)),
            ),
            wrong,
            unchecked,
        }
    }

    fn outcome(
        &self,
        offset: u32,
        check: &Check<'_>,
        kind: RelocKind,
        field_width: u32,
        wrong: Outcome,
        unchecked: Outcome,
    ) -> Outcome {
        let f = self.rebuild.f;
        let fixup = match check {
            Check::Fixup(r) => Some(*r),
            Check::Internal(_) => None,
        };
        let sixteen = self.bits == 16;

        // 16-bit selector: the original's MZ relocation against the frame anchor (ADR 0006 item 6).
        if let Some(r) = fixup
            && sixteen
            && kind == RelocKind::Selector
        {
            let Ok(field_at) = self.at.offset_by(i64::from(offset)) else {
                return wrong;
            };
            let Some(reloc) = relocation_at(self.program, field_at)
                .filter(|s| s.kind == RelocKind::Selector && s.width == 2)
            else {
                return wrong;
            };
            let Some(frame) = frame_name(f.module, r) else {
                return unchecked;
            };
            let Some(base) = reloc.target.linear() else {
                return wrong;
            };
            return Outcome::Anchored(vec![Condition::Segment {
                frame,
                base: base as i64,
            }]);
        }

        let raw_field = f
            .code()
            .get(offset as usize..(offset + field_width) as usize)
            .unwrap_or(&[]);
        let target = match self.expected(check, raw_field) {
            Target::Invalid => return wrong,
            Target::Unresolved => return unchecked,
            t => t,
        };
        let Ok(field_at) = self.at.offset_by(i64::from(offset)) else {
            return wrong;
        };
        let relocation = relocation_at(self.program, field_at);

        // 16-bit offset without a relocation in the original (MZ): anchors (ADR 0006 items 1-5).
        if let Some(r) = fixup
            && sixteen
            && relocation.is_none()
        {
            let far = kind == RelocKind::FarPointer && field_width == 4;
            if far || (kind == RelocKind::Absolute && field_width == 2) {
                return self.anchored_offset(offset, field_at, r, far, &target, wrong, unchecked);
            }
        }

        match target {
            Target::Known(expected) => {
                let ok = match (relocation, kind) {
                    (Some(r), _) => {
                        r.kind == kind
                            && u32::from(r.width) == field_width
                            && r.target
                                .offset_by(r.addend)
                                .is_ok_and(|t| same(t, expected))
                    }
                    (None, RelocKind::Relative) => {
                        let Some(value) = self.relative_target(offset, field_width) else {
                            return wrong;
                        };
                        address_in_space(self.at, value).is_some_and(|t| same(t, expected))
                    }
                    (None, _) => false,
                };
                if ok { Outcome::Decided(None) } else { wrong }
            }
            Target::OwnTable {
                table,
                same_distance,
            } => {
                let Some(original_table) = relocation
                    .filter(|r| r.kind == kind && u32::from(r.width) == field_width)
                    .and_then(|r| r.target.offset_by(r.addend).ok())
                else {
                    return wrong;
                };
                if same(original_table, same_distance) || self.table_matches(table, original_table)
                {
                    Outcome::Decided(None)
                } else {
                    wrong
                }
            }
            Target::Unnamed { section, rel } if self.bits == 32 => {
                // 32-bit: the section's linear position from the original's relocation (ADR 0006 item 7).
                let observed = match (relocation, kind) {
                    (Some(r), _) => {
                        if r.kind != kind || u32::from(r.width) != field_width {
                            return wrong;
                        }
                        r.target.offset_by(r.addend).ok().and_then(|t| t.linear())
                    }
                    (None, RelocKind::Relative) => self
                        .relative_target(offset, field_width)
                        .and_then(|v| address_in_space(self.at, v))
                        .and_then(|t| t.linear()),
                    (None, _) => None,
                };
                let Some(observed) = observed else {
                    return wrong;
                };
                Outcome::Anchored(vec![Condition::Section {
                    key: SectionKey {
                        frame: FLAT.to_string(),
                        module: self.module,
                        section,
                        flat: true,
                    },
                    rel,
                    candidate: observed as i64 - rel,
                }])
            }
            _ => unchecked,
        }
    }

    /// Whether the rebuild's jump table at section offset `table` (consecutive 4-byte absolute entries into the
    /// own section, up to the function start) and the original's table at `original` send every entry to the same
    /// offset relative to the function start. A table without entries does not match.
    fn table_matches(&self, table: u32, original: Address) -> bool {
        let f = self.rebuild.f;
        let Some(section) = f.module.sections.get(f.section as usize) else {
            return false;
        };
        let (Some(at), Some(table_at)) = (self.at.linear(), original.linear()) else {
            return false;
        };
        let mut entries = 0;
        let mut offset = table;
        while offset.saturating_add(4) <= f.start {
            let Some(entry) = section.relocs.iter().find(|r| {
                r.offset == offset
                    && r.width == 4
                    && r.kind == RelocKind::Absolute
                    && matches!(r.target, RefTarget::Section { index, .. } if index == f.section)
            }) else {
                break;
            };
            let RefTarget::Section { offset: base, .. } = entry.target else {
                break;
            };
            let Some(content) = section.data.get(offset as usize..offset as usize + 4) else {
                break;
            };
            let rebuilt = i64::from(base) + signed(content) - i64::from(f.start);
            let k = u64::from(offset - table);
            let Some(entry_at) = u32::try_from(table_at + k).ok().map(Address::Flat) else {
                return false;
            };
            let original_target = match relocation_at(self.program, entry_at) {
                Some(r) => r.target.offset_by(r.addend).ok().and_then(|t| t.linear()),
                None => self
                    .program
                    .read(entry_at, 4)
                    .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
            };
            match original_target {
                Some(t) if t as i64 - at as i64 == rebuilt => {}
                _ => return false,
            }
            entries += 1;
            offset += 4;
        }
        entries > 0
    }

    /// The original's target of a self-relative field read from its bytes, as a value in the address space.
    fn relative_target(&self, offset: u32, field_width: u32) -> Option<i64> {
        let field = self
            .original
            .get(offset as usize..(offset + field_width) as usize)?;
        Some(self.base as i64 + i64::from(offset + field_width) + signed(field))
    }

    /// A 16-bit offset (or the offset word of a 16:16 far pointer) without a relocation in the original.
    #[allow(clippy::too_many_arguments)]
    fn anchored_offset(
        &self,
        offset: u32,
        field_at: Address,
        r: &ObjReloc,
        far: bool,
        target: &Target,
        wrong: Outcome,
        unchecked: Outcome,
    ) -> Outcome {
        let Some(word) = self.original.get(offset as usize..offset as usize + 2) else {
            return wrong;
        };
        let observed = u16::from_le_bytes([word[0], word[1]]);
        let frame = frame_name(self.rebuild.f.module, r);
        let mut conditions = Vec::new();
        if far {
            let Some(segment) = field_at
                .offset_by(2)
                .ok()
                .and_then(|a| relocation_at(self.program, a))
                .filter(|s| s.kind == RelocKind::Selector && s.width == 2)
                .and_then(|s| s.target.linear())
            else {
                return wrong;
            };
            match &frame {
                Some(frame) => conditions.push(Condition::Segment {
                    frame: frame.clone(),
                    base: segment as i64,
                }),
                // No frame name: segment and offset give the linear address directly.
                None => {
                    return match target {
                        Target::Known(a) => match a.linear() {
                            Some(t) if t == segment + u64::from(observed) => Outcome::Decided(None),
                            Some(_) => wrong,
                            None => unchecked,
                        },
                        _ => unchecked,
                    };
                }
            }
        }
        let Some(frame) = frame else {
            return unchecked;
        };
        match *target {
            Target::Known(a) => {
                let Some(t) = a.linear() else {
                    return unchecked;
                };
                conditions.push(Condition::Frame {
                    frame,
                    target: t as i64,
                    candidate: t as i64 - i64::from(observed),
                });
            }
            Target::Unnamed { section, rel } => conditions.push(Condition::Section {
                key: SectionKey {
                    frame,
                    module: self.module,
                    section,
                    flat: false,
                },
                rel,
                candidate: i64::from(observed.wrapping_sub(rel as u16)),
            }),
            _ => return unchecked,
        }
        Outcome::Anchored(conditions)
    }
}
