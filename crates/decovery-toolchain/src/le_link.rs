//! Linking an LE program (Watcom, DOS/4GW) with WLINK as one OMF module (port of Decomp's `nachbau/le_binden.py`):
//! the original bytes per object, one fixup per field in the original's processing order, and the rebuilt
//! functions inserted at their original places.
//!
//! The order of the fixups matters: WLINK writes a page's fixup records in blocks of at most 512 bytes, the newest
//! block first ([`decovery_loaders::fixup_processing_order`] reverses that), so the module hands them over in the
//! order WLINK processed them for the original.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use decovery_core::{Address, Workspace};
use decovery_diff::insert_code;
use decovery_loaders::{LeImage, LeObject, RawFixup, fixup_processing_order};
use decovery_objects::{FunctionView, WriteFixup, WriteFixupKind, WriteSegment, write_omf_module};
use decovery_plugin::{CancelToken, Progress};

use crate::link::{Linked, run_linker};
use crate::{Profile, Runner, ToolchainError};

/// The module handed to the linker, in the build directory.
pub const LE_OBJECT_FILE: &str = "NB.OBJ";
/// The original's MZ stub, in the build directory.
pub const LE_STUB_FILE: &str = "STUB.EXE";
/// Stem of the object and of the response file (`NB.LNK`).
pub const LE_RESPONSE_STEM: &str = "NB";
/// The public at the entry point.
pub const LE_START_SYMBOL: &str = "_cstart_";
/// Module name when the original's resident name is no DOS name.
pub const LE_DEFAULT_MODULE: &str = "REBUILD";
/// Stack size when `[rebuild.link] stack` is not set.
pub const LE_DEFAULT_STACK: u32 = 4096;
/// Name of the OMF module (`THEADR`).
const OMF_MODULE: &str = "decovery_rebuild";
/// Off32 source type of an LE fixup.
const OFF32: u8 = 0x07;

/// The linker's segments for the objects of an LE image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SegmentPlan {
    pub segments: Vec<WriteSegment>,
    /// Groups with their member segments (1-based).
    pub groups: Vec<(String, Vec<u32>)>,
    /// LE object → segment (1-based) that carries its file data and is the target of fixups into it.
    pub object_segment: BTreeMap<u32, u32>,
    /// LE object → bytes taken from the file.
    pub data_length: BTreeMap<u32, u32>,
}

/// 32-bit code → `_TEXT`, 16-bit code → `_TEXT16`, further code objects → `CODE<n>`; the auto data object →
/// `DGROUP` of `_DATA` (the file data), `_BSS` and `STACK` (ESP points at its end); every other object → `OBJ<n>`
/// (`FAR_DATA`), each in a group of its own when there are several (WLINK merges neighbours into one object
/// otherwise). `_BSS` and `STACK` are byte aligned: `_DATA` may have an odd length, the object must keep its size.
/// The data length of an object is its [`LeObject::file_length`]. `stack` must be positive and divisible by 4
/// and fit into the uninitialized rest of the auto data object.
pub fn segment_plan(
    objects: &[LeObject],
    auto_data: u32,
    stack: u32,
) -> Result<SegmentPlan, ToolchainError> {
    if stack == 0 || !stack.is_multiple_of(4) {
        return Err(ToolchainError::Invalid(format!(
            "[rebuild.link] stack = {stack}: expected a positive number divisible by 4"
        )));
    }
    let mut plan = SegmentPlan {
        segments: Vec::new(),
        groups: Vec::new(),
        object_segment: BTreeMap::new(),
        data_length: BTreeMap::new(),
    };
    let mut code_names: BTreeSet<String> = BTreeSet::new();
    let mut far: Vec<(u32, u32)> = Vec::new();
    for o in objects {
        let use32 = o.flags & 0x2000 != 0;
        plan.data_length.insert(o.number, o.file_length);
        let first = plan.segments.len() as u32 + 1;
        plan.object_segment.insert(o.number, first);
        if o.flags & 0x4 != 0 {
            let mut name = if use32 { "_TEXT" } else { "_TEXT16" }.to_string();
            if code_names.contains(&name) {
                name = format!("CODE{}", o.number);
            }
            code_names.insert(name.clone());
            plan.segments
                .push(WriteSegment::new(name, "CODE", o.size, use32));
        } else if o.number == auto_data {
            let rest = o.size.saturating_sub(o.file_length);
            if stack > rest {
                return Err(ToolchainError::Invalid(format!(
                    "[rebuild.link] stack = {stack} is larger than the uninitialized rest of object {} ({rest} bytes)",
                    o.number
                )));
            }
            plan.segments.extend([
                WriteSegment::new("_DATA", "DATA", o.file_length, use32),
                WriteSegment::new("_BSS", "BSS", rest - stack, use32).with_align(1),
                WriteSegment::new("STACK", "STACK", stack, use32)
                    .with_combine(5)
                    .with_align(1),
            ]);
            plan.groups
                .push(("DGROUP".to_string(), vec![first, first + 1, first + 2]));
        } else {
            plan.segments.push(WriteSegment::new(
                format!("OBJ{}", o.number),
                "FAR_DATA",
                o.size,
                use32,
            ));
            far.push((o.number, first));
        }
    }
    if far.len() > 1 {
        plan.groups
            .extend(far.iter().map(|&(n, s)| (format!("OBJ{n}G"), vec![s])));
    }
    Ok(plan)
}

/// A rebuilt function made ready for its original place.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Insert {
    pub name: String,
    /// 1-based LE object.
    pub object: u32,
    /// Start in the object.
    pub offset: u32,
    /// The finished bytes, fields filled in.
    pub bytes: Vec<u8>,
    /// (offset in the object, target object) of the off32 fixups.
    pub fixups: Vec<(u32, u32)>,
    /// Object offsets whose bytes and fixup come from the original (linker fields without a name).
    pub keep: BTreeSet<u32>,
}

fn object_at(objects: &[LeObject], va: u64) -> Option<&LeObject> {
    objects
        .iter()
        .find(|o| u64::from(o.base) <= va && va < u64::from(o.base) + u64::from(o.size))
}

fn plain(name: &str) -> &str {
    name.trim_matches('_')
}

/// Port of `einsatz_bauen`: the rebuilt function `f` made ready for its original address `at` of `image`. The
/// padding behind the function goes ([`insert_code`]); named references are resolved through `address_of`
/// (decorated public names; only flat addresses count): self-relative fields (near calls, also those the compiler
/// resolved inside the object) get the distance from the original place and must stay inside the object, absolute
/// fields the target's offset in its object (plus field content and fixup displacement) and an off32 fixup. A target
/// exactly at the end of one object counts as in that object. Fixup fields without a name keep the original's bytes
/// and fixups ([`Insert::keep`]). Returns why the function cannot be inserted otherwise.
pub fn build_insert(
    f: &FunctionView<'_>,
    at: Address,
    image: &LeImage,
    address_of: &dyn Fn(&str) -> Option<Address>,
) -> Result<Insert, String> {
    let Address::Flat(va) = at else {
        return Err(format!("{at} is not a flat address"));
    };
    let va = u64::from(va);
    let o = object_at(&image.objects, va).ok_or_else(|| format!("{va:#x} lies in no object"))?;
    let code = insert_code(f)
        .filter(|_| {
            f.module
                .sections
                .get(f.section as usize)
                .is_some_and(|s| s.bits == 32)
        })
        .ok_or_else(|| "not a 32-bit function".to_string())?;
    let start = va - u64::from(o.base);
    let mut bytes = code.bytes.clone();
    let mut references: BTreeMap<u32, &str> = code
        .references
        .iter()
        .map(|(&k, n)| (k, n.as_str()))
        .collect();
    let mut relative = code.relative.clone();
    for (&field, name) in &code.internal_calls {
        references.insert(field, name);
        relative.insert(field);
    }
    let mut targets: HashMap<&str, Option<u64>> = HashMap::new();
    let mut missing: Vec<&str> = Vec::new();
    for &name in references.values() {
        targets.entry(name).or_insert_with(|| {
            let t = match address_of(name) {
                Some(Address::Flat(t)) => Some(u64::from(t)),
                _ => None,
            };
            if t.is_none() {
                missing.push(plain(name));
            }
            t
        });
    }
    if !missing.is_empty() {
        return Err(missing
            .iter()
            .map(|n| format!("{n} not resolved"))
            .collect::<Vec<_>>()
            .join("; "));
    }
    let mut fixups = Vec::new();
    let mut covered: BTreeSet<u32> = BTreeSet::new();
    for (&field, &name) in &references {
        if code.references.contains_key(&field)
            && !(field..field + 4).all(|p| code.gaps.contains(&p))
        {
            return Err(format!(
                "reference to {} at +{field:#x} with a field width other than 4 is not supported",
                plain(name)
            ));
        }
        let t = targets.get(name).copied().flatten().unwrap_or_default();
        let is_relative = relative.contains(&field);
        let mut target_object = object_at(&image.objects, t);
        if target_object.is_none() && !is_relative {
            // end markers are valid absolute targets (no memory, no call target); an object starting there wins
            let mut ends = image
                .objects
                .iter()
                .filter(|x| x.size > 0 && t == u64::from(x.base) + u64::from(x.size));
            if let (Some(only), None) = (ends.next(), ends.next()) {
                target_object = Some(only);
            }
        }
        let Some(zo) = target_object else {
            return Err(format!("{} ({t:#x}) lies in no object", plain(name)));
        };
        let slot = bytes
            .get_mut(field as usize..field as usize + 4)
            .ok_or_else(|| {
                format!(
                    "field of {} at +{field:#x} lies behind the function",
                    plain(name)
                )
            })?;
        if is_relative {
            if zo.number != o.number {
                return Err(format!(
                    "relative reference to {} into another object",
                    plain(name)
                ));
            }
            let distance = t as i64 - (va as i64 + i64::from(field) + 4);
            slot.copy_from_slice(&(distance as i32).to_le_bytes());
        } else {
            let content = i64::from(i32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]));
            let addend = code.addends.get(&field).copied().unwrap_or(0);
            let value = (t as i64 + content + addend - i64::from(zo.base)) as u32;
            slot.copy_from_slice(&value.to_le_bytes());
            fixups.push(((start + u64::from(field)) as u32, zo.number));
        }
        covered.extend(field..field + 4);
    }
    let open: Vec<u32> = code.gaps.difference(&covered).copied().collect();
    let source = image
        .raw_data
        .get(o.number as usize - 1)
        .map_or(&[][..], Vec::as_slice);
    if let Some(&last) = open.last()
        && start + u64::from(last) >= source.len() as u64
    {
        return Err("linker fields without a name lie behind the file data".into());
    }
    for &i in &open {
        bytes[i as usize] = source[(start + u64::from(i)) as usize];
    }
    Ok(Insert {
        name: f.name.to_string(),
        object: o.number,
        offset: start as u32,
        bytes,
        fixups,
        keep: open.iter().map(|&i| start as u32 + i).collect(),
    })
}

fn fixup_width(source_type: u8) -> u32 {
    match source_type {
        0x02 | 0x05 => 2,
        _ => 4,
    }
}

/// Per object the bytes taken from the file: WLINK cuts zeros at the end of the last page, so a fixup field may
/// reach over the file data; the data reaches to the end of the last fixup field (zero-filled), at most the object
/// size.
fn data_lengths(image: &LeImage) -> Vec<LeObject> {
    let mut end: HashMap<u32, i64> = HashMap::new();
    for f in &image.raw_fixups {
        let e = i64::from(f.offset) + i64::from(fixup_width(f.source_type));
        let x = end.entry(f.object).or_insert(0);
        *x = (*x).max(e);
    }
    image
        .objects
        .iter()
        .map(|o| {
            let mut extended = o.clone();
            let fixup_end =
                u32::try_from(end.get(&o.number).copied().unwrap_or(0).max(0)).unwrap_or(u32::MAX);
            extended.file_length = o.size.min(o.file_length.max(fixup_end));
            extended
        })
        .collect()
}

/// The inserts that go into the module, as indices into `inserts`, and a hint for each one that does not: it reaches
/// over the data of its object, or it overlaps an insert taken before it.
pub fn usable_inserts(image: &LeImage, inserts: &[Insert]) -> (Vec<usize>, Vec<String>) {
    let lengths: HashMap<u32, u32> = data_lengths(image)
        .iter()
        .map(|o| (o.number, o.file_length))
        .collect();
    usable(&lengths, inserts)
}

fn usable(lengths: &HashMap<u32, u32>, inserts: &[Insert]) -> (Vec<usize>, Vec<String>) {
    let mut taken: BTreeMap<(u32, u64), u64> = BTreeMap::new();
    let (mut used, mut hints) = (Vec::new(), Vec::new());
    for (i, e) in inserts.iter().enumerate() {
        let start = u64::from(e.offset);
        let end = start + e.bytes.len() as u64;
        if end > u64::from(lengths.get(&e.object).copied().unwrap_or(0)) {
            hints.push(format!(
                "{}: extends beyond the file data of object {}, not inserted",
                e.name, e.object
            ));
            continue;
        }
        // the taken inserts do not overlap: only the last one starting before `end` can reach into this one
        let overlaps = taken
            .range((e.object, 0)..(e.object, end))
            .next_back()
            .is_some_and(|(_, &taken_end)| taken_end > start);
        if overlaps {
            hints.push(format!("{}: overlaps another insert, not inserted", e.name));
            continue;
        }
        taken.insert((e.object, start), end);
        used.push(i);
    }
    (used, hints)
}

/// One fixup of the module in processing order.
#[derive(Debug, Clone, Copy)]
struct Entry {
    object: u32,
    offset: i32,
    source_type: u8,
    target_object: u32,
    target_offset: u32,
}

impl Entry {
    fn of(f: &RawFixup) -> Self {
        Entry {
            object: f.object,
            offset: f.offset,
            source_type: f.source_type,
            target_object: f.target_object,
            target_offset: f.target_offset,
        }
    }

    fn page(&self, page_size: u32) -> (u32, i64) {
        (
            self.object,
            i64::from(self.offset).div_euclid(i64::from(page_size.max(1))),
        )
    }
}

/// The fixup sequence as a linked list, so that inserting after the last fixup of a page and dropping fixups cost no
/// pass over the whole sequence.
struct Sequence {
    entries: Vec<Entry>,
    next: Vec<Option<usize>>,
    prev: Vec<Option<usize>>,
    head: Option<usize>,
    tail: Option<usize>,
    /// (object, page) → entries in sequence order.
    pages: HashMap<(u32, i64), Vec<usize>>,
    page_size: u32,
}

impl Sequence {
    fn new(entries: Vec<Entry>, page_size: u32) -> Self {
        let n = entries.len();
        let mut pages: HashMap<(u32, i64), Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            pages.entry(e.page(page_size)).or_default().push(i);
        }
        Sequence {
            next: (0..n).map(|i| (i + 1 < n).then_some(i + 1)).collect(),
            prev: (0..n).map(|i| i.checked_sub(1)).collect(),
            head: (n > 0).then_some(0),
            tail: n.checked_sub(1),
            entries,
            pages,
            page_size,
        }
    }

    fn remove(&mut self, i: usize) {
        match self.prev[i] {
            Some(p) => self.next[p] = self.next[i],
            None => self.head = self.next[i],
        }
        match self.next[i] {
            Some(n) => self.prev[n] = self.prev[i],
            None => self.tail = self.prev[i],
        }
        let key = self.entries[i].page(self.page_size);
        if let Some(list) = self.pages.get_mut(&key) {
            list.retain(|&x| x != i);
        }
    }

    /// Adds `e` behind the last entry of its page, or at the end when the page has none.
    fn add(&mut self, e: Entry) {
        let i = self.entries.len();
        let key = e.page(self.page_size);
        self.entries.push(e);
        let after = self
            .pages
            .get(&key)
            .and_then(|list| list.last().copied())
            .or(self.tail);
        self.prev.push(after);
        let next = match after {
            Some(a) => self.next[a],
            None => self.head,
        };
        self.next.push(next);
        match after {
            Some(a) => self.next[a] = Some(i),
            None => self.head = Some(i),
        }
        match next {
            Some(n) => self.prev[n] = Some(i),
            None => self.tail = Some(i),
        }
        self.pages.entry(key).or_default().push(i);
    }

    fn into_vec(self) -> Vec<Entry> {
        let mut out = Vec::with_capacity(self.entries.len());
        let mut at = self.head;
        while let Some(i) = at {
            out.push(self.entries[i]);
            at = self.next[i];
        }
        out
    }
}

/// Port of `_einsetzen` for all inserts in order: the original's fixups inside an insert are replaced by its own
/// (the same place keeps its position, additional ones go behind the last fixup of their page, else to the end,
/// dropped ones go); places in [`Insert::keep`] stay.
fn apply_inserts(order: Vec<Entry>, inserts: &[&Insert], page_size: u32) -> Vec<Entry> {
    let mut by_place: BTreeMap<(u32, i32), Vec<usize>> = BTreeMap::new();
    for (i, e) in order.iter().enumerate() {
        by_place.entry((e.object, e.offset)).or_default().push(i);
    }
    let mut seq = Sequence::new(order, page_size);
    for e in inserts {
        let end = e.offset as usize + e.bytes.len();
        let mut new: BTreeMap<u32, u32> = e.fixups.iter().copied().collect();
        let start = i32::try_from(e.offset).unwrap_or(i32::MAX);
        let end = i32::try_from(end).unwrap_or(i32::MAX);
        let mut inside: Vec<usize> = by_place
            .range((e.object, start)..(e.object, end))
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        inside.sort_unstable();
        for i in inside {
            let offset = seq.entries[i].offset as u32;
            if e.keep.contains(&offset) {
                continue;
            }
            match new.remove(&offset) {
                Some(target) => {
                    let x = &mut seq.entries[i];
                    x.source_type = OFF32;
                    x.target_object = target;
                    x.target_offset = 0;
                }
                None => seq.remove(i),
            }
        }
        for (offset, target) in new {
            seq.add(Entry {
                object: e.object,
                offset: offset as i32,
                source_type: OFF32,
                target_object: target,
                target_offset: 0,
            });
        }
    }
    seq.into_vec()
}

/// Port of `omf_modul`: the whole program `original` (loaded as `image`) as one OMF module with the `inserts` in
/// place: per object its file bytes (extended to the end of the last fixup field), the fixups in the original's
/// processing order (off32, off16, sel16, rel32; the inserts' replacing the original's), the public
/// [`LE_START_SYMBOL`] at the entry point, which also goes into the module end with `start_in_module` (for linkers
/// without `option start`). Hints: inserts not taken ([`usable_inserts`]) and pages whose fixup order is not
/// recoverable. Errors: an object not contiguous in the file, a fixup type the module cannot express, a fixup or
/// the entry outside the file data, an invalid `stack` ([`segment_plan`]).
pub fn le_module(
    original: &[u8],
    image: &LeImage,
    inserts: &[Insert],
    stack: u32,
    start_in_module: bool,
) -> Result<(Vec<u8>, Vec<String>), ToolchainError> {
    if let Some(e) = &image.raw_fixup_error {
        return Err(ToolchainError::Invalid(format!(
            "LE: the fixup table cannot be linked: {e}"
        )));
    }
    let objects = data_lengths(image);
    let plan = segment_plan(&objects, image.header.auto_data_object, stack)?;
    let mut raw: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for (o, extended) in image.objects.iter().zip(&objects) {
        let bytes = match o.file_offset {
            Some(at) => {
                let start = usize::try_from(at).unwrap_or(usize::MAX);
                let end = start.saturating_add(o.file_length as usize);
                original.get(start..end).ok_or_else(|| {
                    ToolchainError::Invalid(format!(
                        "LE: the data of object {} ({:#x} bytes at file offset {at:#x}) lies behind the end of the file",
                        o.number, o.file_length
                    ))
                })?
            }
            None if extended.file_length > 0 => {
                return Err(ToolchainError::Invalid(format!(
                    "LE: object {} does not lie contiguously in the file; cannot link",
                    o.number
                )));
            }
            None => &[][..],
        };
        let mut data = bytes.to_vec();
        data.resize(extended.file_length as usize, 0);
        raw.insert(o.number, data);
    }
    let lengths: HashMap<u32, u32> = objects.iter().map(|o| (o.number, o.file_length)).collect();
    let (used, mut hints) = usable(&lengths, inserts);
    let used: Vec<&Insert> = used.iter().map(|&i| &inserts[i]).collect();
    for e in &used {
        if let Some(data) = raw.get_mut(&e.object) {
            let start = e.offset as usize;
            data[start..start + e.bytes.len()].copy_from_slice(&e.bytes);
        }
    }
    let (order, unclear) = fixup_processing_order(&image.raw_fixups);
    hints.extend(
        unclear
            .iter()
            .map(|p| format!("page {p}: fixup order not recoverable, table order kept")),
    );
    let order: Vec<Entry> = order
        .iter()
        .map(|&i| Entry::of(&image.raw_fixups[i]))
        .collect();
    let order = apply_inserts(order, &used, image.header.page_size);

    let segment_of = |object: u32| -> Result<u32, ToolchainError> {
        plan.object_segment.get(&object).copied().ok_or_else(|| {
            ToolchainError::Invalid(format!("LE: fixup target object {object} does not exist"))
        })
    };
    let place = |object: u32, offset: i64| -> Result<(u32, u32), ToolchainError> {
        let length = lengths.get(&object).copied().unwrap_or(0);
        if !(0..i64::from(length)).contains(&offset) {
            return Err(ToolchainError::Invalid(format!(
                "LE: fixup or entry in object {object} +{offset:#x} lies outside the file data"
            )));
        }
        Ok((segment_of(object)?, offset as u32))
    };
    let mut fixups = Vec::with_capacity(order.len());
    for f in &order {
        let (segment, offset) = place(f.object, i64::from(f.offset))?;
        let target = segment_of(f.target_object)?;
        let fixup = match f.source_type {
            // off16: the target as displacement; the writer clears the field (WLINK truncates it)
            0x05 => WriteFixup::new(
                segment,
                offset,
                WriteFixupKind::Off16,
                target,
                Some(f.target_offset),
            ),
            0x07 => WriteFixup::new(segment, offset, WriteFixupKind::Off32, target, None),
            0x02 => WriteFixup::new(segment, offset, WriteFixupKind::Sel16, target, None),
            0x08 => WriteFixup::new(segment, offset, WriteFixupKind::Rel32, target, None),
            other => {
                return Err(ToolchainError::Invalid(format!(
                    "LE: fixup type {other:#x} (object {} +{:#x}) is not supported when linking",
                    f.object, f.offset
                )));
            }
        };
        fixups.push(fixup);
    }
    let entry = place(
        image.header.entry_object,
        i64::from(image.header.entry_offset),
    )?;
    let data: Vec<(u32, Vec<u8>)> = raw
        .into_iter()
        .filter_map(|(n, d)| Some((*plan.object_segment.get(&n)?, d)))
        .collect();
    let module = write_omf_module(
        OMF_MODULE,
        &plan.segments,
        &plan.groups,
        &[(LE_START_SYMBOL.to_string(), entry.0, entry.1)],
        &data,
        &fixups,
        start_in_module.then_some(entry),
    )
    .map_err(|e| ToolchainError::Invalid(format!("LE: {e}")))?;
    Ok((module, hints))
}

/// The name for `name …` in the response file (WLINK takes it as the resident name): the original's resident name
/// when it is a DOS name (`[A-Za-z0-9_]{1,8}`), else [`LE_DEFAULT_MODULE`].
pub fn module_name(resident: &str) -> String {
    let dos = (1..=8).contains(&resident.len())
        && resident
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if dos {
        resident.to_string()
    } else {
        LE_DEFAULT_MODULE.to_string()
    }
}

/// The WLINK response file (CRLF lines) linking [`LE_OBJECT_FILE`] into `<name>.exe` with the original's stub. The
/// 9.5 tree has no `WLSYSTEM.LNK`, so the DOS/4G system is spelled out. `start_option` false: the linker refuses
/// `option start` (WLINK 9.5 for DOS/4G); the entry point then comes from the module end.
pub fn response_file(name: &str, start_option: bool) -> String {
    let mut lines = vec![
        "format os2 le".to_string(),
        "option osname='DOS/4G'".to_string(),
        format!("option stub={LE_STUB_FILE}"),
        "option nodefaultlibs".to_string(),
    ];
    if start_option {
        lines.push(format!("option start={LE_START_SYMBOL}"));
    }
    lines.push("option map".to_string());
    lines.push(format!("name {name}.exe"));
    lines.push(format!("file {LE_RESPONSE_STEM}"));
    lines.iter().map(|l| format!("{l}\r\n")).collect()
}

/// Writes `module` ([`LE_OBJECT_FILE`]), `stub` ([`LE_STUB_FILE`]) and the response file for `name` into
/// `build_dir` and links them with the linker of `profile` in one runner job (`WLINK @NB`). The profile's linker
/// must take a response file; `option start` is used when the profile allows it.
#[allow(clippy::too_many_arguments)]
pub fn link_le(
    ws: &Workspace,
    profile: &Profile,
    module: &[u8],
    stub: &[u8],
    name: &str,
    build_dir: &Path,
    runners: &[Box<dyn Runner>],
    cancel: Option<CancelToken>,
    progress: &dyn Fn(Progress),
) -> Result<(Linked, Vec<String>), ToolchainError> {
    let linker = le_linker(profile)?;
    std::fs::create_dir_all(build_dir).map_err(|source| ToolchainError::Io {
        path: build_dir.to_path_buf(),
        source,
    })?;
    let response = response_file(name, linker.start_option);
    let files: [(String, &[u8]); 3] = [
        (LE_OBJECT_FILE.to_string(), module),
        (LE_STUB_FILE.to_string(), stub),
        (format!("{LE_RESPONSE_STEM}.LNK"), response.as_bytes()),
    ];
    for (file, bytes) in &files {
        let path = build_dir.join(file);
        std::fs::write(&path, bytes).map_err(|source| ToolchainError::Io { path, source })?;
    }
    let line = profile.link_line("", "", &[], LE_RESPONSE_STEM, &[])?;
    let file = linker.output.replace("{name}", name);
    run_linker(
        ws, profile, line, file, None, build_dir, runners, cancel, progress,
    )
}

/// The linker of `profile` when it can link LE programs (it takes a response file).
pub fn le_linker(profile: &Profile) -> Result<&crate::LinkerSpec, ToolchainError> {
    let linker = profile
        .linker
        .as_ref()
        .ok_or_else(|| ToolchainError::Invalid(format!("profile {} has no linker", profile.id)))?;
    if !linker.command.contains("{response}") {
        return Err(ToolchainError::Invalid(format!(
            "profile {} cannot link LE programs: its linker takes no response file",
            profile.id
        )));
    }
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(object: u32, offset: i32, target_object: u32) -> Entry {
        Entry {
            object,
            offset,
            source_type: 0x07,
            target_object,
            target_offset: 0,
        }
    }

    fn insert(offset: u32, len: usize, fixups: Vec<(u32, u32)>, keep: &[u32]) -> Insert {
        Insert {
            name: "f".into(),
            object: 1,
            offset,
            bytes: vec![0; len],
            fixups,
            keep: keep.iter().copied().collect(),
        }
    }

    fn places(v: &[Entry]) -> Vec<(u32, i32, u32)> {
        v.iter()
            .map(|e| (e.object, e.offset, e.target_object))
            .collect()
    }

    #[test]
    fn inserted_fixups_replace_keep_and_follow_their_page() {
        // pages of 0x100 bytes: 0x10 and 0x20 on page 0 of object 1, 0x120 on page 1, then object 2
        let order = vec![
            entry(1, 0x10, 2),
            entry(1, 0x120, 2),
            entry(1, 0x20, 2),
            entry(2, 0x08, 1),
        ];
        // 0x20 is replaced in place, 0x28 is new and goes behind the last fixup of page 0
        let e = insert(0x18, 0x20, vec![(0x20, 1), (0x28, 1)], &[]);
        let out = apply_inserts(order.clone(), &[&e], 0x100);
        assert_eq!(
            places(&out),
            [
                (1, 0x10, 2),
                (1, 0x120, 2),
                (1, 0x20, 1),
                (1, 0x28, 1),
                (2, 0x08, 1)
            ]
        );
        // an original fixup inside the insert without a counterpart goes, one in `keep` stays
        let e = insert(0x08, 0x10, Vec::new(), &[0x10]);
        let f = insert(0x118, 0x10, Vec::new(), &[]);
        let out = apply_inserts(order.clone(), &[&e, &f], 0x100);
        assert_eq!(places(&out), [(1, 0x10, 2), (1, 0x20, 2), (2, 0x08, 1)]);
        // a new fixup on a page without fixups goes to the end
        let e = insert(0x300, 0x10, vec![(0x304, 2)], &[]);
        let out = apply_inserts(order, &[&e], 0x100);
        assert_eq!(places(&out).last(), Some(&(1, 0x304, 2)));
    }
}
