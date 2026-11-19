//! The data of an Aztec C86 object of the main program (MZ, no link step) against the original image.
//!
//! The Aztec linker places the data of every object of the main program one behind the other in the data segment
//! (DS), each starting on a word. A rebuild compiles only some of the objects, so the position of one object's data
//! is not computed from the link order: it is read off the original. Every relocated code field of the object's
//! placed functions that names a position of its own data (an unnamed data position or one of its data symbols)
//! votes for the data start: the original field less the position inside the data. The start most fields agree on
//! is the anchor; without a unique majority the data stays unchecked. DS itself comes from the startup code
//! ([`aztec_data_segment`]) or the configured frame `DATA`.
//!
//! With the anchor the data bytes are compared with the original at DS:start. Relocated data fields that name the
//! object's own data or code are resolved and must equal the original; the others (external names, BSS, segment
//! paragraphs) are link gaps.

use std::collections::{BTreeMap, BTreeSet};

use decovery_core::{Address, Program, RelocKind};
use decovery_objects::{ObjectModule, RefTarget, SectionKind};

use crate::Placement;

/// The state of an object's data after [`compare_main_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataState {
    Equal,
    Differs,
    /// No anchor, or every byte a link gap: nothing was compared.
    Unchecked,
}

impl DataState {
    pub fn id(self) -> &'static str {
        match self {
            DataState::Equal => "equal",
            DataState::Differs => "differs",
            DataState::Unchecked => "unchecked",
        }
    }
}

/// Result of [`compare_main_data`] for one object module.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainData {
    pub module: String,
    /// The data segment (paragraph) the data was compared in.
    pub ds: u16,
    /// Start of the object's data in DS, when the votes agree.
    pub start: Option<u16>,
    /// Code fields voting for `start`, and those voting for another position.
    pub votes: u32,
    pub dissent: u32,
    /// Data bytes of the object.
    pub bytes: u32,
    /// Bytes not compared: relocated fields the comparison cannot place.
    pub gaps: u32,
    /// Relocated data fields resolved and equal / unequal to the original.
    pub refs_ok: u32,
    pub refs_wrong: u32,
    /// Offsets (from the object's data start) of differing bytes, wrong fields included.
    pub diffs: Vec<u32>,
    pub state: DataState,
    /// Plain-language findings, most telling first.
    pub findings: Vec<String>,
}

/// The data segment of an Aztec C86 program: the startup code loads it into a register with its first instruction
/// (`mov bp, <DS>` in the small model), a field the MZ loader relocates. `None` when the program does not start so.
pub fn aztec_data_segment(program: &Program) -> Option<u16> {
    let entry = *program.entry_points.first()?;
    let opcode = *program.read(entry, 1)?.first()?;
    if !(0xB8..=0xBF).contains(&opcode) {
        return None;
    }
    let field = entry.offset_by(1).ok()?.linear()?;
    program
        .relocations
        .iter()
        .find(|r| r.kind == RelocKind::Selector && r.width == 2 && r.at.linear() == Some(field))
        .and_then(|r| match r.target {
            Address::Seg { seg, .. } => Some(seg),
            _ => None,
        })
}

fn read_word(bytes: &[u8], at: usize) -> Option<i64> {
    let b = bytes.get(at..at.checked_add(2)?)?;
    Some(i64::from(u16::from_le_bytes([b[0], b[1]])))
}

fn original_byte(program: &Program, ds: u16, at: i64) -> Option<u8> {
    let off = u16::try_from(at).ok()?;
    program.read(Address::Seg { seg: ds, off }, 1).map(|b| b[0])
}

fn original_word(program: &Program, ds: u16, at: i64) -> Option<i64> {
    let lo = original_byte(program, ds, at)?;
    let hi = original_byte(program, ds, at + 1)?;
    Some(i64::from(u16::from_le_bytes([lo, hi])))
}

/// Compares the data section of `module` with the original in data segment `ds`. `placements` are the placed
/// functions (those of other modules are ignored): their code fields anchor the data. `None` when the module has no
/// data bytes.
pub fn compare_main_data(
    module: &ObjectModule,
    placements: &[Placement<'_>],
    program: &Program,
    ds: u16,
) -> Option<MainData> {
    let data_index = module
        .sections
        .iter()
        .position(|s| s.kind == SectionKind::Data && !s.data.is_empty())?;
    let data = &module.sections[data_index];
    let own: Vec<&Placement> = placements
        .iter()
        .filter(|p| std::ptr::eq(p.function.module, module))
        .collect();
    // the position inside the own data a field names (field content included), `None` for other targets
    let data_position = |target: &RefTarget, stored: i64| -> Option<i64> {
        match target {
            RefTarget::Section { index, offset } if *index as usize == data_index => {
                Some(i64::from(*offset) + stored)
            }
            RefTarget::Symbol(n) => module
                .symbols
                .iter()
                .find(|s| s.name == *n && s.section as usize == data_index)
                .map(|s| i64::from(s.offset) + i64::from(stored as i16)),
            _ => None,
        }
    };
    let mut tally: BTreeMap<i64, u32> = BTreeMap::new();
    // where the code section lies in its segment: (section index, segment, offset of the section start)
    let mut code_base: Option<(u32, u16, i64)> = None;
    for p in &own {
        let f = &p.function;
        let Address::Seg { seg, off } = p.at else {
            continue;
        };
        code_base.get_or_insert((f.section, seg, i64::from(off) - i64::from(f.start)));
        let code = f.code();
        for r in f.relocs() {
            if r.kind != RelocKind::Absolute || r.width != 2 {
                continue;
            }
            let at = (r.offset - f.start) as usize;
            let Some(stored) = read_word(code, at) else {
                continue;
            };
            let Some(position) = data_position(&r.target, stored) else {
                continue;
            };
            let Some(orig) =
                p.at.offset_by(at as i64)
                    .ok()
                    .and_then(|a| program.read(a, 2))
                    .and_then(|b| read_word(b, 0))
            else {
                continue;
            };
            *tally.entry((orig - position) & 0xFFFF).or_default() += 1;
        }
    }
    let total: u32 = tally.values().sum();
    let best = tally.iter().max_by_key(|(_, n)| **n).map(|(b, n)| (*b, *n));
    let start = best.filter(|&(_, n)| tally.values().filter(|&&m| m == n).count() == 1);
    let bytes = u32::try_from(data.data.len()).unwrap_or(u32::MAX);
    let mut out = MainData {
        module: module.name.clone(),
        ds,
        start: start.map(|(b, _)| b as u16),
        votes: start.map_or(0, |(_, n)| n),
        dissent: start.map_or(0, |(_, n)| total - n),
        bytes,
        gaps: 0,
        refs_ok: 0,
        refs_wrong: 0,
        diffs: Vec::new(),
        state: DataState::Unchecked,
        findings: Vec::new(),
    };
    let Some((base, _)) = start else {
        out.findings.push(if own.is_empty() {
            format!(
                "data ({bytes} bytes) not compared: none of the object's functions is placed in this build, so nothing names its place in DS {ds:04X}; build the files that use it together with it"
            )
        } else if total == 0 {
            format!(
                "data ({bytes} bytes) not compared: no code field of the built functions names it, so its place in \
                 DS {ds:04X} is unknown"
            )
        } else {
            format!(
                "data ({bytes} bytes) not compared: the code fields name {} different starts in DS {ds:04X} without \
                 a majority",
                tally.len()
            )
        });
        return Some(out);
    };
    if out.dissent > 0 {
        out.findings.push(format!(
            "{} of {total} code fields name another data start than {base:04X}: those references or the data \
             layout before them differ",
            out.dissent
        ));
    }
    if base % 2 == 1 {
        out.findings.push(format!(
            "data start {ds:04X}:{base:04X} is odd, but the Aztec linker starts every object's data on a word"
        ));
    }
    // relocated data fields
    let mut gaps: BTreeSet<usize> = BTreeSet::new();
    let mut fields: BTreeMap<usize, i64> = BTreeMap::new();
    for r in &data.relocs {
        let at = r.offset as usize;
        let span = at..at + usize::from(r.width);
        let stored = read_word(&data.data, at);
        let expected = match (r.kind, r.width, stored) {
            (RelocKind::Absolute, 2, Some(stored)) => data_position(&r.target, stored)
                .map(|p| base + p)
                .or_else(|| match (&r.target, code_base) {
                    (RefTarget::Section { index, offset }, Some((ci, _, cb))) if *index == ci => {
                        Some(cb + i64::from(*offset) + stored)
                    }
                    _ => None,
                }),
            _ => None,
        };
        match expected {
            Some(value) => {
                fields.insert(at, value & 0xFFFF);
            }
            None => gaps.extend(span),
        }
    }
    let mut diffs: BTreeSet<u32> = BTreeSet::new();
    let mut wrong_fields = Vec::new();
    for (&at, &value) in &fields {
        let orig = original_word(program, ds, base + at as i64);
        if orig == Some(value) {
            out.refs_ok += 1;
        } else {
            out.refs_wrong += 1;
            diffs.extend([at as u32, at as u32 + 1]);
            wrong_fields.push((at, value, orig));
        }
    }
    let field_bytes: BTreeSet<usize> = fields.keys().flat_map(|&a| [a, a + 1]).collect();
    let mut missing = 0u32;
    for (k, &b) in data.data.iter().enumerate() {
        if gaps.contains(&k) || field_bytes.contains(&k) {
            continue;
        }
        match original_byte(program, ds, base + k as i64) {
            Some(o) if o == b => {}
            Some(_) => {
                diffs.insert(k as u32);
            }
            None => {
                missing += 1;
                diffs.insert(k as u32);
            }
        }
    }
    out.gaps = u32::try_from(gaps.len()).unwrap_or(u32::MAX);
    out.diffs = diffs.into_iter().collect();
    out.state = if out.gaps >= bytes {
        DataState::Unchecked
    } else if out.diffs.is_empty() {
        DataState::Equal
    } else {
        DataState::Differs
    };
    if let Some(&first) = out.diffs.first() {
        let n = out.diffs.len();
        out.findings.insert(
            0,
            format!(
                "data differs in {n} byte{} of {bytes}, first at {ds:04X}:{:04X} (data +0x{first:X})",
                if n == 1 { "" } else { "s" },
                base + i64::from(first)
            ),
        );
    }
    for (at, value, orig) in wrong_fields.iter().take(4) {
        out.findings.push(format!(
            "data field at +0x{at:X} should hold {value:04X}, the original holds {}",
            orig.map_or_else(
                || "nothing (past the image)".to_string(),
                |o| format!("{o:04X}")
            )
        ));
    }
    if missing > 0 {
        out.findings.push(format!(
            "{missing} data bytes lie past the original image's initialised bytes"
        ));
    }
    Some(out)
}
