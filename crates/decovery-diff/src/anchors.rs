//! Reference anchors (ADR 0006): frame and section bases agreed on by the fields of all compared functions.

use std::collections::{BTreeMap, BTreeSet};

use decovery_core::{Address, Program};
use decovery_objects::{Frame, ObjReloc, ObjectModule, RefTarget, SectionKind};

use crate::{Anchor, AnchorSource, Blocker};

/// Frame of 32-bit section anchors: the flat model has one frame with base 0.
pub(crate) const FLAT: &str = "FLAT";

/// A section of one module inside one frame. `module` indexes the modules in order of first placement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SectionKey {
    pub frame: String,
    pub module: usize,
    pub section: u32,
    /// 32-bit: the frame base is 0 and `base` is linear.
    pub flat: bool,
}

/// One requirement a relocated field places on the anchors.
#[derive(Debug, Clone)]
pub(crate) enum Condition {
    /// The field's frame base, `target` (linear) minus the original's field, must be the frame anchor.
    Frame {
        frame: String,
        target: i64,
        candidate: i64,
    },
    /// The section's position proposed by the field (`rel` = section offset + addend + content) must be the
    /// section anchor, and the section's bytes must match there.
    Section {
        key: SectionKey,
        rel: i64,
        candidate: i64,
    },
    /// The original's segment (linear base) must be the frame anchor; it does not vote.
    Segment { frame: String, base: i64 },
}

/// How a field is judged: already decided, or by anchors.
#[derive(Debug, Clone)]
pub(crate) enum Outcome {
    Decided(Option<Blocker>),
    Anchored(Vec<Condition>),
}

/// The frame of `reloc` (ADR 0006 item 1); `None` when it cannot be named.
pub(crate) fn frame_name(module: &ObjectModule, reloc: &ObjReloc) -> Option<String> {
    let section_name = |i: u32| module.sections.get(i as usize).map(|s| s.name.clone());
    match &reloc.frame {
        Frame::Group(name) => Some(name.clone()),
        Frame::Section(i) => section_name(*i),
        Frame::Target | Frame::Unknown => match reloc.target {
            RefTarget::Section { index, .. } => module
                .group_of(index)
                .map(|g| g.name.clone())
                .or_else(|| section_name(index)),
            _ => None,
        },
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
struct Tally {
    base: i64,
    votes: u32,
    dissent: u32,
    source: AnchorSource,
}

/// Majority over distinct (target, candidate) pairs, ties to the lowest candidate; `fixed` overrides the winner.
fn tally(pairs: &BTreeSet<(i64, i64)>, fixed: Option<i64>) -> Option<Tally> {
    let mut counts: BTreeMap<i64, u32> = BTreeMap::new();
    for &(_, candidate) in pairs {
        *counts.entry(candidate).or_default() += 1;
    }
    let total = pairs.len() as u32;
    let (base, source) = match fixed {
        Some(base) => (base, AnchorSource::Config),
        None => {
            // BTreeMap iterates ascending; `max_by_key` keeps the last maximum, so compare on (count, -value).
            let (&base, _) = counts
                .iter()
                .max_by_key(|&(&value, &count)| (count, std::cmp::Reverse(value)))?;
            (base, AnchorSource::Consensus)
        }
    };
    let votes = counts.get(&base).copied().unwrap_or(0);
    Some(Tally {
        base,
        votes,
        dissent: total - votes,
        source,
    })
}

/// The address of linear `at` in the program's address space.
fn address_at(linear: i64, flat: bool) -> Option<Address> {
    if flat {
        return u32::try_from(linear).ok().map(Address::Flat);
    }
    let linear = u32::try_from(linear).ok()?;
    Some(Address::Seg {
        seg: u16::try_from(linear >> 4).ok()?,
        off: (linear & 0xF) as u16,
    })
}

/// Whether the item of `section` at `rel` differs from the original, the section lying at linear `section_at`. The
/// item reaches from `rel` to the next boundary: the next referenced offset (`referenced`), the next symbol of the
/// section, or the end of its initialised bytes. Fixup fields of the section are not compared.
fn item_differs(
    module: &ObjectModule,
    section: u32,
    rel: i64,
    referenced: &BTreeSet<i64>,
    section_at: i64,
    flat: bool,
    program: &Program,
) -> bool {
    let Some(s) = module.sections.get(section as usize) else {
        return true;
    };
    let len = s.data.len() as i64;
    if rel < 0 || rel >= len {
        return false;
    }
    let end = referenced
        .range(rel + 1..)
        .next()
        .copied()
        .into_iter()
        .chain(
            module
                .symbols
                .iter()
                .filter(|y| y.section == section && i64::from(y.offset) > rel)
                .map(|y| i64::from(y.offset)),
        )
        .fold(len, i64::min);
    let (start, end) = (rel as usize, end as usize);
    let gaps: BTreeSet<usize> = s
        .relocs
        .iter()
        .flat_map(|r| r.offset as usize..r.offset as usize + usize::from(r.width))
        .collect();
    let Some(original) =
        address_at(section_at + rel, flat).and_then(|a| program.read(a, end - start))
    else {
        return true;
    };
    s.data[start..end]
        .iter()
        .zip(original)
        .enumerate()
        .any(|(i, (a, b))| a != b && !gaps.contains(&(start + i)))
}

#[derive(Debug)]
struct SectionAnchor {
    tally: Tally,
    /// Referenced offsets (`rel`) whose item differs from the original.
    differing: BTreeSet<i64>,
}

/// All anchors of one module comparison.
#[derive(Debug, Default)]
pub(crate) struct Anchors {
    frames: BTreeMap<String, Tally>,
    sections: BTreeMap<SectionKey, SectionAnchor>,
    pub warnings: Vec<String>,
}

impl Anchors {
    /// Establishes the anchors from the conditions of all fields, the configured frames and the original.
    pub fn collect<'c>(
        conditions: impl IntoIterator<Item = &'c Condition>,
        modules: &[&ObjectModule],
        config: &BTreeMap<String, Address>,
        program: &Program,
    ) -> Anchors {
        let mut frame_votes: BTreeMap<String, BTreeSet<(i64, i64)>> = BTreeMap::new();
        let mut section_votes: BTreeMap<SectionKey, BTreeSet<(i64, i64)>> = BTreeMap::new();
        // Referenced offsets per (module, section), over all frames: the item boundaries.
        let mut referenced: BTreeMap<(usize, u32), BTreeSet<i64>> = BTreeMap::new();
        let mut section_rels: BTreeMap<SectionKey, BTreeSet<i64>> = BTreeMap::new();
        for condition in conditions {
            if let Condition::Section { key, rel, .. } = condition {
                referenced
                    .entry((key.module, key.section))
                    .or_default()
                    .insert(*rel);
                section_rels.entry(key.clone()).or_default().insert(*rel);
            }
            match condition {
                Condition::Frame {
                    frame,
                    target,
                    candidate,
                } if *candidate >= 0 => {
                    frame_votes
                        .entry(frame.clone())
                        .or_default()
                        .insert((*target, *candidate));
                }
                Condition::Section {
                    key,
                    rel,
                    candidate,
                } if *candidate >= 0 => {
                    section_votes
                        .entry(key.clone())
                        .or_default()
                        .insert((*rel, *candidate));
                }
                _ => {}
            }
        }
        let mut anchors = Anchors::default();
        for (name, address) in config {
            let Some(base) = address.linear() else {
                anchors.warnings.push(format!(
                    "frame {name}: configured address {address} has no linear form; ignored"
                ));
                continue;
            };
            let votes = frame_votes.remove(name).unwrap_or_default();
            if let Some(t) = tally(&votes, Some(base as i64)) {
                anchors.frames.insert(name.clone(), t);
            }
        }
        for (name, votes) in frame_votes {
            if let Some(t) = tally(&votes, None) {
                anchors.frames.insert(name, t);
            }
        }
        for (key, votes) in section_votes {
            let Some(t) = tally(&votes, None) else {
                continue;
            };
            let Some(module) = modules.get(key.module) else {
                continue;
            };
            let checked = module
                .sections
                .get(key.section as usize)
                .is_some_and(|s| s.kind == SectionKind::Data && !s.data.is_empty());
            let frame_base = if key.flat {
                Some(0)
            } else {
                anchors.frames.get(&key.frame).map(|f| f.base)
            };
            let rels = section_rels.remove(&key).unwrap_or_default();
            let differing = match (checked, frame_base) {
                (false, _) => BTreeSet::new(),
                (true, Some(frame)) => {
                    let bounds = referenced
                        .get(&(key.module, key.section))
                        .cloned()
                        .unwrap_or_default();
                    rels.into_iter()
                        .filter(|&rel| {
                            item_differs(
                                module,
                                key.section,
                                rel,
                                &bounds,
                                frame + t.base,
                                key.flat,
                                program,
                            )
                        })
                        .collect()
                }
                (true, None) => {
                    let section = &module.sections[key.section as usize].name;
                    anchors.warnings.push(format!(
                        "{}: section {section} is not compared with the original: frame {} has no anchor",
                        module.name, key.frame
                    ));
                    BTreeSet::new()
                }
            };
            anchors.sections.insert(
                key,
                SectionAnchor {
                    tally: t,
                    differing,
                },
            );
        }
        anchors
    }

    /// The blocker of a field: `wrong` if a condition fails, `unchecked` if one cannot be verified.
    pub fn judge(&self, outcome: &Outcome, wrong: Blocker, unchecked: Blocker) -> Option<Blocker> {
        let conditions = match outcome {
            Outcome::Decided(b) => return *b,
            Outcome::Anchored(c) => c,
        };
        let mut unverified = false;
        for condition in conditions {
            let ok = match condition {
                Condition::Frame {
                    frame, candidate, ..
                } => self.frames.get(frame).is_some_and(|f| f.base == *candidate),
                Condition::Section {
                    key,
                    rel,
                    candidate,
                } => self
                    .sections
                    .get(key)
                    .is_some_and(|s| s.tally.base == *candidate && !s.differing.contains(rel)),
                Condition::Segment { frame, base } => match self.frames.get(frame) {
                    Some(f) => f.base == *base,
                    None => {
                        unverified = true;
                        true
                    }
                },
            };
            if !ok {
                return Some(wrong);
            }
        }
        unverified.then_some(unchecked)
    }

    /// The anchors for the result: frames by name, then sections by frame, module and section.
    pub fn list(&self, modules: &[&ObjectModule]) -> Vec<Anchor> {
        let anchor = |frame: &str, section: Option<String>, t: &Tally| Anchor {
            frame: frame.to_string(),
            section,
            base: t.base as u64,
            votes: t.votes,
            dissent: t.dissent,
            source: t.source,
        };
        let mut out: Vec<Anchor> = self
            .frames
            .iter()
            .map(|(name, t)| anchor(name, None, t))
            .collect();
        for (key, s) in &self.sections {
            let name = modules
                .get(key.module)
                .and_then(|m| m.sections.get(key.section as usize))
                .map(|s| s.name.clone());
            out.push(anchor(&key.frame, name, &s.tally));
        }
        out
    }
}
