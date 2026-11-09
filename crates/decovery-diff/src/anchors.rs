//! Reference anchors (ADR 0006): frame and section bases agreed on by the fields of all compared functions.

use std::collections::{BTreeMap, BTreeSet};

use decovery_core::{Address, Program, RelocKind};
use decovery_objects::{Frame, ObjReloc, ObjectModule, RefTarget, SectionKind};

use crate::compare::relocation_at;
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
            RefTarget::Group(ref name) => Some(name.clone()),
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

impl Tally {
    /// Whether the votes alone carry the anchor (ADR 0006 item 4, amendment 2026-11-09): at least two distinct
    /// pairs agree and they outnumber the dissent. A lone pair proposes the base that makes it right; a tie
    /// names no base.
    fn agreed(&self) -> bool {
        self.votes >= 2 && self.votes > self.dissent
    }
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

/// The comparison of one referenced item with the original.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    Equal,
    Differs,
    /// No byte of the item could be compared: `rel` lies outside the section's initialised bytes, or the item
    /// consists of the section's own fixup fields.
    NotCompared,
}

/// How the item of `section` at `rel` compares with the original, the section lying at linear `section_at`. The
/// item reaches from `rel` to the next boundary: the next referenced offset (`referenced`), the next symbol of the
/// section, or the end of its initialised bytes; with `until_nul`, also its first zero byte (a C string ends
/// there, the bytes after it belong to unreferenced items). Fixup fields of the section are not compared.
#[allow(clippy::too_many_arguments)]
fn item_check(
    module: &ObjectModule,
    section: u32,
    rel: i64,
    referenced: &BTreeSet<i64>,
    section_at: i64,
    flat: bool,
    program: &Program,
    until_nul: bool,
) -> Item {
    let Some(s) = module.sections.get(section as usize) else {
        return Item::Differs;
    };
    let len = s.data.len() as i64;
    if rel < 0 || rel >= len {
        return Item::NotCompared;
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
    let (start, mut end) = (rel as usize, end as usize);
    if until_nul && let Some(nul) = s.data[start..end].iter().position(|&b| b == 0) {
        end = start + nul + 1;
    }
    let gaps: BTreeSet<usize> = s
        .relocs
        .iter()
        .flat_map(|r| r.offset as usize..r.offset as usize + usize::from(r.width))
        .collect();
    let Some(original) =
        address_at(section_at + rel, flat).and_then(|a| program.read(a, end - start))
    else {
        return Item::Differs;
    };
    let mut compared = false;
    for (i, (a, b)) in s.data[start..end].iter().zip(original).enumerate() {
        if gaps.contains(&(start + i)) {
            continue;
        }
        if a != b {
            return Item::Differs;
        }
        compared = true;
    }
    if compared {
        Item::Equal
    } else {
        Item::NotCompared
    }
}

#[derive(Debug)]
struct SectionAnchor {
    tally: Tally,
    /// Referenced offsets (`rel`) whose item differs from the original.
    differing: BTreeSet<i64>,
    /// A data section whose items cannot be compared because its frame has no anchor: its fields stay unchecked
    /// (ADR 0006 item 5, amendment 2026-11-09).
    uncompared: bool,
    /// The votes carry the anchor ([`Tally::agreed`]). Otherwise the section has no anchor: its fields are
    /// unchecked, except those in `wrong`.
    agreed: bool,
    /// Without an anchor: votes (rel, candidate) whose item differs from the original at the position the field
    /// itself names, so the field is wrong whatever the section's position.
    wrong: BTreeSet<(i64, i64)>,
    /// Dissenting (rel, candidate) pairs whose item equals the original at the candidate's position: the item
    /// exists unchanged, only at another offset of the section (data layout).
    moved: BTreeSet<(i64, i64)>,
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
        startup: &BTreeMap<String, Address>,
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
            if let Some(proven) = startup.get(name).and_then(|a| a.linear())
                && proven != base
            {
                anchors.warnings.push(format!(
                    "frame {name}: configured address {address} differs from the startup code's base {proven:#x}"
                ));
            }
            let votes = frame_votes.remove(name).unwrap_or_default();
            if let Some(t) = tally(&votes, Some(base as i64)) {
                anchors.frames.insert(name.clone(), t);
            }
        }
        // the bases proven by the startup code (ADR 0006 item 10), unless configured
        for (name, address) in startup {
            if anchors.frames.contains_key(name) {
                continue;
            }
            let Some(base) = address.linear() else {
                continue;
            };
            let votes = frame_votes.remove(name).unwrap_or_default();
            if let Some(mut t) = tally(&votes, Some(base as i64)) {
                t.source = AnchorSource::Startup;
                anchors.frames.insert(name.clone(), t);
            }
        }
        for (name, votes) in frame_votes {
            let Some(t) = tally(&votes, None) else {
                continue;
            };
            if t.agreed() {
                anchors.frames.insert(name, t);
            } else {
                let vote = |n: u32| if n == 1 { "vote" } else { "votes" };
                anchors.warnings.push(format!(
                    "frame {name}: no anchor, the best base {:#x} has {} {} against {} {}; its fields stay \
                     unchecked",
                    t.base,
                    t.votes,
                    vote(t.votes),
                    t.dissent,
                    vote(t.dissent)
                ));
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
            let bounds = referenced
                .get(&(key.module, key.section))
                .cloned()
                .unwrap_or_default();
            if !t.agreed() {
                // no anchor (item 4, amendment 2026-11-09): a lone vote or a tie names no position; equal bytes at
                // the field's own position can be another item with the same value
                let wrong = match (checked, frame_base) {
                    (true, Some(frame)) => votes
                        .iter()
                        .filter(|&&(rel, candidate)| {
                            item_check(
                                module,
                                key.section,
                                rel,
                                &bounds,
                                frame + candidate,
                                key.flat,
                                program,
                                false,
                            ) == Item::Differs
                        })
                        .copied()
                        .collect(),
                    _ => BTreeSet::new(),
                };
                let section = &module.sections[key.section as usize].name;
                let vote = |n: u32| if n == 1 { "vote" } else { "votes" };
                anchors.warnings.push(format!(
                    "{}: section {section} has no anchor in frame {}, the best position {:#x} has {} {} against {} \
                     {}; its fields stay unchecked",
                    module.name,
                    key.frame,
                    t.base,
                    t.votes,
                    vote(t.votes),
                    t.dissent,
                    vote(t.dissent)
                ));
                anchors.sections.insert(
                    key,
                    SectionAnchor {
                        tally: t,
                        differing: BTreeSet::new(),
                        moved: BTreeSet::new(),
                        uncompared: false,
                        agreed: false,
                        wrong,
                    },
                );
                continue;
            }
            let moved: BTreeSet<(i64, i64)> = match (checked, frame_base) {
                (true, Some(frame)) => votes
                    .iter()
                    .filter(|&&(_, candidate)| candidate != t.base)
                    .filter(|&&(rel, candidate)| {
                        item_check(
                            module,
                            key.section,
                            rel,
                            &bounds,
                            frame + candidate,
                            key.flat,
                            program,
                            true,
                        ) != Item::Differs
                    })
                    .copied()
                    .collect(),
                _ => BTreeSet::new(),
            };
            let differing = match (checked, frame_base) {
                (false, _) => BTreeSet::new(),
                (true, Some(frame)) => rels
                    .into_iter()
                    .filter(|&rel| {
                        item_check(
                            module,
                            key.section,
                            rel,
                            &bounds,
                            frame + t.base,
                            key.flat,
                            program,
                            false,
                        ) == Item::Differs
                    })
                    .collect(),
                (true, None) => {
                    let section = &module.sections[key.section as usize].name;
                    anchors.warnings.push(format!(
                        "{}: section {section} is not compared with the original: frame {} has no anchor",
                        module.name, key.frame
                    ));
                    BTreeSet::new()
                }
            };
            let uncompared = checked && frame_base.is_none();
            anchors.sections.insert(
                key,
                SectionAnchor {
                    tally: t,
                    differing,
                    moved,
                    uncompared,
                    agreed: true,
                    wrong: BTreeSet::new(),
                },
            );
        }
        anchors
    }

    /// The blocker of a field: `wrong` if a condition fails, [`Blocker::DataLayout`] if the only failure is an
    /// unchanged item at another section offset, `unchecked` if a condition cannot be verified.
    pub fn judge(&self, outcome: &Outcome, wrong: Blocker, unchecked: Blocker) -> Option<Blocker> {
        let conditions = match outcome {
            Outcome::Decided(b) => return *b,
            Outcome::Anchored(c) => c,
        };
        let mut unverified = false;
        let mut layout = false;
        // A far pointer (segment and offset of one field) into a frame without an anchor: the original's relocated
        // segment plus its offset word give the linear address, which must be the target's.
        let far = |name: &str| {
            let segment = conditions.iter().find_map(|c| match c {
                Condition::Segment { frame, base } if frame == name => Some(*base),
                _ => None,
            })?;
            conditions.iter().find_map(|c| match c {
                Condition::Frame {
                    frame, candidate, ..
                } if frame == name => Some(*candidate == segment),
                _ => None,
            })
        };
        for condition in conditions {
            if let Condition::Section {
                key,
                rel,
                candidate,
            } = condition
                && let Some(s) = self.sections.get(key)
                && !s.agreed
            {
                if s.wrong.contains(&(*rel, *candidate)) {
                    return Some(wrong);
                }
                unverified = true;
                continue;
            }
            if let Condition::Section {
                key,
                rel,
                candidate,
            } = condition
                && self.sections.get(key).is_some_and(|s| {
                    s.tally.base != *candidate && s.moved.contains(&(*rel, *candidate))
                })
            {
                layout = true;
                continue;
            }
            let ok = match condition {
                Condition::Frame {
                    frame, candidate, ..
                } => match (self.frames.get(frame), far(frame)) {
                    (Some(f), _) => f.base == *candidate,
                    (None, Some(linear)) => linear,
                    // no anchor (item 4): the field is not checked; a negative base is no base at all
                    (None, None) if *candidate >= 0 => {
                        unverified = true;
                        true
                    }
                    (None, None) => false,
                },
                Condition::Section {
                    key,
                    rel,
                    candidate,
                } => match self.sections.get(key) {
                    Some(s) if s.tally.base == *candidate && !s.differing.contains(rel) => {
                        // the offset agrees, but an item that cannot be compared is not checked
                        unverified |= s.uncompared;
                        true
                    }
                    _ => false,
                },
                Condition::Segment { frame, base } => match (self.frames.get(frame), far(frame)) {
                    (Some(f), _) => f.base == *base,
                    (None, Some(linear)) => linear,
                    (None, None) => {
                        unverified = true;
                        true
                    }
                },
            };
            if !ok {
                return Some(wrong);
            }
        }
        if layout {
            return Some(Blocker::DataLayout {
                at: wrong.at().unwrap_or(0),
            });
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
        for (key, s) in self.sections.iter().filter(|(_, s)| s.agreed) {
            let name = modules
                .get(key.module)
                .and_then(|m| m.sections.get(key.section as usize))
                .map(|s| s.name.clone());
            out.push(anchor(&key.frame, name, &s.tally));
        }
        out
    }
}

/// Frame bases proven by the program's startup code: [`startup_frames`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StartupFrames {
    /// Base of each frame named by a selector field of the startup code.
    pub frames: BTreeMap<String, Address>,
    /// Why the startup code gave no frames, or which frames it left out.
    pub warnings: Vec<String>,
}

/// The frame bases the startup object `startup` proves in `program` (ADR 0006 item 10). The object's start address
/// (OMF `MODEND`) is placed at the program's entry point; its code section must equal the original there outside
/// its own fixup fields, and each of its 16-bit selector fields must have a segment relocation of the original at
/// the same place. The original's segment value then is the base of the field's frame. A frame whose fields give
/// different values gets no base. Never fails: without a base the result says why.
pub fn startup_frames(startup: &ObjectModule, program: &Program) -> StartupFrames {
    let mut out = StartupFrames::default();
    let refuse = |out: &mut StartupFrames, why: String| {
        out.warnings.push(format!(
            "startup {}: {why}; no frame bases taken from it",
            startup.name
        ));
    };
    let Some((index, start)) = startup.start else {
        refuse(&mut out, "no start address".to_string());
        return out;
    };
    let Some(section) = startup
        .sections
        .get(index as usize)
        .filter(|s| s.kind == SectionKind::Code && s.bits == 16)
    else {
        refuse(
            &mut out,
            "the start is not in a 16-bit code section".to_string(),
        );
        return out;
    };
    let Some(&entry) = program.entry_points.first() else {
        refuse(&mut out, "the program has no entry point".to_string());
        return out;
    };
    let Ok(section_at) = entry.offset_by(-i64::from(start)) else {
        refuse(
            &mut out,
            format!("its start offset {start:#x} lies before the program entry {entry}"),
        );
        return out;
    };
    let Some(original) = program.read(section_at, section.data.len()) else {
        refuse(
            &mut out,
            format!(
                "its code ({} bytes) does not fit the program at {section_at}",
                section.data.len()
            ),
        );
        return out;
    };
    let gaps: BTreeSet<usize> = section
        .relocs
        .iter()
        .flat_map(|r| r.offset as usize..r.offset as usize + usize::from(r.width))
        .collect();
    let differing = section
        .data
        .iter()
        .zip(original)
        .enumerate()
        .filter(|&(i, (a, b))| a != b && !gaps.contains(&i))
        .count();
    if differing > 0 {
        refuse(
            &mut out,
            format!("{differing} bytes differ from the original at the program entry {entry}"),
        );
        return out;
    }
    let mut bases: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for r in section
        .relocs
        .iter()
        .filter(|r| r.kind == RelocKind::Selector && r.width == 2)
    {
        let Ok(field_at) = section_at.offset_by(i64::from(r.offset)) else {
            continue;
        };
        let Some(base) = relocation_at(program, field_at)
            .filter(|s| s.kind == RelocKind::Selector && s.width == 2)
            .and_then(|s| s.target.linear())
        else {
            refuse(
                &mut out,
                format!("the original has no segment relocation at {field_at}"),
            );
            return out;
        };
        if let Some(frame) = frame_name(startup, r) {
            bases.entry(frame).or_default().insert(base);
        }
    }
    for (frame, values) in bases {
        let mut values = values.into_iter();
        match (values.next(), values.next()) {
            (Some(base), None) => {
                if let Some(at) = address_at(base as i64, false) {
                    out.frames.insert(frame, at);
                }
            }
            _ => out.warnings.push(format!(
                "startup {}: its selector fields give frame {frame} different bases; none taken",
                startup.name
            )),
        }
    }
    out
}
