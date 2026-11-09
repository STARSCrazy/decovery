//! Writing a 32-bit OMF object module: segments, groups, external names, publics, data and fixups (port of
//! Decomp's `nachbau/omf_schreiben.py`).
//!
//! Used to hand a whole LE program to WLINK as one module: the raw bytes of every object plus one fixup per field.
//! All data comes first, then the fixups in the given order (WLINK processes them in that order); every run of
//! fixups repeats the data it covers in an `LEDATA` right before its `FIXUPP`, since a `FIXUPP` refers to the data
//! record before it.

use std::collections::BTreeMap;

use crate::ObjectError;

/// Bytes per `LEDATA` record.
const CHUNK: usize = 1000;
/// Fixups per `FIXUPP` record.
const MAX_RUN: usize = 200;

/// A segment of the written module (`SEGDEF`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteSegment {
    pub name: String,
    pub class: String,
    pub length: u32,
    pub use32: bool,
    /// OMF combination: 2 public, 5 stack.
    pub combine: u8,
    /// OMF alignment: 1 byte, 3 paragraph.
    pub align: u8,
}

impl WriteSegment {
    /// A public, paragraph-aligned segment.
    pub fn new(
        name: impl Into<String>,
        class: impl Into<String>,
        length: u32,
        use32: bool,
    ) -> Self {
        WriteSegment {
            name: name.into(),
            class: class.into(),
            length,
            use32,
            combine: 2,
            align: 3,
        }
    }

    pub fn with_combine(mut self, combine: u8) -> Self {
        self.combine = combine;
        self
    }

    pub fn with_align(mut self, align: u8) -> Self {
        self.align = align;
        self
    }
}

/// What a fixup writes into its field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WriteFixupKind {
    /// 16-bit offset (OMF location 1).
    Off16,
    /// 16-bit selector (location 2).
    Sel16,
    /// 32-bit offset (location 9).
    Off32,
    /// 32-bit self-relative offset (location 9, self-relative).
    Rel32,
    /// 16-bit self-relative offset (location 1, self-relative).
    Rel16,
}

impl WriteFixupKind {
    /// (OMF location, segment-relative, field width).
    fn shape(self) -> (u16, bool, u32) {
        match self {
            WriteFixupKind::Off16 => (1, true, 2),
            WriteFixupKind::Sel16 => (2, true, 2),
            WriteFixupKind::Off32 => (9, true, 4),
            WriteFixupKind::Rel32 => (9, false, 4),
            WriteFixupKind::Rel16 => (1, false, 2),
        }
    }

    pub fn width(self) -> u32 {
        self.shape().2
    }
}

/// A fixup of the written module: the field at `offset` of `segment` (1-based) refers to `target_segment` (1-based)
/// with frame F5 (the target's). Without `target_offset` the value in the field is the distance from the target
/// segment's start; with it, the target is segment plus `target_offset` and the field is written empty (it then
/// holds an addition the linker adds). With `target_external` (1-based index into [`WriteModule::externals`]) the
/// target is that external name instead of a segment and `target_offset` is its displacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteFixup {
    pub segment: u32,
    pub offset: u32,
    pub kind: WriteFixupKind,
    pub target_segment: u32,
    pub target_offset: Option<u32>,
    pub target_external: Option<u32>,
}

impl WriteFixup {
    pub fn new(
        segment: u32,
        offset: u32,
        kind: WriteFixupKind,
        target_segment: u32,
        target_offset: Option<u32>,
    ) -> Self {
        WriteFixup {
            segment,
            offset,
            kind,
            target_segment,
            target_offset,
            target_external: None,
        }
    }

    /// A fixup whose target is the external name `external` (1-based, in the order of
    /// [`WriteModule::externals`]): with `displacement` the field is written empty and the linker adds the
    /// displacement (target method T2), without it the field keeps its content (T6).
    pub fn external(
        segment: u32,
        offset: u32,
        kind: WriteFixupKind,
        external: u32,
        displacement: Option<u32>,
    ) -> Self {
        WriteFixup {
            segment,
            offset,
            kind,
            target_segment: 0,
            target_offset: displacement,
            target_external: Some(external),
        }
    }

    fn end(&self) -> u64 {
        u64::from(self.offset) + u64::from(self.kind.width())
    }
}

fn unwritable(what: String) -> ObjectError {
    ObjectError::Unwritable(what)
}

fn record(out: &mut Vec<u8>, kind: u8, content: &[u8]) -> Result<(), ObjectError> {
    let len = u16::try_from(content.len() + 1).map_err(|_| {
        unwritable(format!(
            "record {kind:#04x} of {} bytes is too long",
            content.len()
        ))
    })?;
    let start = out.len();
    out.push(kind);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(content);
    let sum = out[start..].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    out.push(sum.wrapping_neg());
    Ok(())
}

fn name(out: &mut Vec<u8>, text: &str) -> Result<(), ObjectError> {
    // Latin-1: every char below U+0100 is one byte
    let bytes: Vec<u8> = text
        .chars()
        .map(|c| {
            u8::try_from(u32::from(c))
                .map_err(|_| unwritable(format!("name {text:?} is not Latin-1")))
        })
        .collect::<Result<_, _>>()?;
    let len = u8::try_from(bytes.len())
        .map_err(|_| unwritable(format!("name {text:?} is longer than 255 bytes")))?;
    out.push(len);
    out.extend_from_slice(&bytes);
    Ok(())
}

fn index(out: &mut Vec<u8>, i: u32) -> Result<(), ObjectError> {
    if i < 0x80 {
        out.push(i as u8);
    } else if i < 0x8000 {
        out.extend_from_slice(&[0x80 | (i >> 8) as u8, i as u8]);
    } else {
        return Err(unwritable(format!(
            "index {i} does not fit into an OMF index"
        )));
    }
    Ok(())
}

/// Everything one written OMF module holds (see [`write_omf`]).
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct WriteModule<'a> {
    /// Module name (`THEADR`).
    pub name: &'a str,
    pub segments: &'a [WriteSegment],
    /// Groups: name and member segments (1-based).
    pub groups: &'a [(String, Vec<u32>)],
    /// External names (`EXTDEF`), in order: fixups refer to them by 1-based index.
    pub externals: &'a [String],
    /// Publics: name, 1-based segment, offset.
    pub publics: &'a [(String, u32, u32)],
    /// Data: 1-based segment and its bytes from offset 0.
    pub data: &'a [(u32, Vec<u8>)],
    pub fixups: &'a [WriteFixup],
    /// Start address: 1-based segment, offset.
    pub start: Option<(u32, u32)>,
}

impl<'a> WriteModule<'a> {
    /// A module named `name` with nothing in it yet.
    pub fn new(name: &'a str) -> Self {
        WriteModule {
            name,
            ..WriteModule::default()
        }
    }

    pub fn with_segments(mut self, segments: &'a [WriteSegment]) -> Self {
        self.segments = segments;
        self
    }

    pub fn with_groups(mut self, groups: &'a [(String, Vec<u32>)]) -> Self {
        self.groups = groups;
        self
    }

    pub fn with_externals(mut self, externals: &'a [String]) -> Self {
        self.externals = externals;
        self
    }

    pub fn with_publics(mut self, publics: &'a [(String, u32, u32)]) -> Self {
        self.publics = publics;
        self
    }

    pub fn with_data(mut self, data: &'a [(u32, Vec<u8>)]) -> Self {
        self.data = data;
        self
    }

    pub fn with_fixups(mut self, fixups: &'a [WriteFixup]) -> Self {
        self.fixups = fixups;
        self
    }

    pub fn with_start(mut self, start: Option<(u32, u32)>) -> Self {
        self.start = start;
        self
    }
}

/// One OMF module without external names: [`write_omf`] of these parts.
pub fn write_omf_module(
    module: &str,
    segments: &[WriteSegment],
    groups: &[(String, Vec<u32>)],
    publics: &[(String, u32, u32)],
    data: &[(u32, Vec<u8>)],
    fixups: &[WriteFixup],
    start: Option<(u32, u32)>,
) -> Result<Vec<u8>, ObjectError> {
    write_omf(
        &WriteModule::new(module)
            .with_segments(segments)
            .with_groups(groups)
            .with_publics(publics)
            .with_data(data)
            .with_fixups(fixups)
            .with_start(start),
    )
}

/// One OMF module: `THEADR`, `LNAMES`, `SEGDEF`s, `GRPDEF`s (members are 1-based segment indices), one `EXTDEF`
/// with the external names, `PUBDEF`s (name, 1-based segment, offset), all `data` (1-based segment, bytes) in
/// chunks, then the fixups in the given order in runs (one segment, ascending offsets, at most [`MAX_RUN`] fixups
/// over at most [`CHUNK`] bytes), and `MODEND`, with the start address (1-based segment, offset; frame F5, target T0)
/// for linkers without `option start`.
///
/// Errors: a fixup outside its segment's data or naming an external the module does not have, or something OMF
/// cannot express (an index over 0x7FFF, a name over 255 bytes, a record over 64 KiB).
pub fn write_omf(module: &WriteModule<'_>) -> Result<Vec<u8>, ObjectError> {
    let WriteModule {
        name: module,
        segments,
        groups,
        externals,
        publics,
        data,
        fixups,
        start,
    } = *module;
    let by_segment: BTreeMap<u32, &[u8]> = data.iter().map(|(s, d)| (*s, d.as_slice())).collect();
    let data_of = |segment: u32| by_segment.get(&segment).copied().unwrap_or(&[]);
    for f in fixups {
        if f.end() > data_of(f.segment).len() as u64 {
            return Err(unwritable(format!(
                "fixup outside the data: segment {} +{:#x}",
                f.segment, f.offset
            )));
        }
    }
    for f in fixups {
        if let Some(external) = f.target_external
            && (external == 0 || external as usize > externals.len())
        {
            return Err(unwritable(format!(
                "fixup at segment {} +{:#x} names external {external}, the module has {}",
                f.segment,
                f.offset,
                externals.len()
            )));
        }
    }
    // overlapping fields cannot both be written (and the data under one would be cleared for the other)
    let mut spans: Vec<(u32, u32, u64)> = fixups
        .iter()
        .map(|f| (f.segment, f.offset, f.end()))
        .collect();
    spans.sort_unstable();
    for pair in spans.windows(2) {
        if let [(segment, before, end), (next_segment, offset, _)] = *pair
            && segment == next_segment
            && u64::from(offset) < end
        {
            return Err(unwritable(format!(
                "fixups overlap: segment {segment} +{offset:#x} lies inside the field at +{before:#x}"
            )));
        }
    }
    let mut names: Vec<&str> = vec![""];
    for s in segments {
        for n in [s.name.as_str(), s.class.as_str()] {
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    for (g, _) in groups {
        if !names.contains(&g.as_str()) {
            names.push(g);
        }
    }
    let number = |n: &str| {
        names
            .iter()
            .position(|x| *x == n)
            .map_or(0, |i| i as u32 + 1)
    };

    let mut out = Vec::new();
    let mut body = Vec::new();
    name(&mut body, module)?;
    record(&mut out, 0x80, &body)?;
    body.clear();
    for n in &names {
        name(&mut body, n)?;
    }
    record(&mut out, 0x96, &body)?;
    for s in segments {
        body.clear();
        // a 16-bit segment of up to 64 KiB in the 16-bit record (readers take a 32-bit SEGDEF for a 32-bit
        // segment); 64 KiB exactly is the big bit with length 0
        let short = !s.use32 && s.length <= 0x1_0000;
        let big = if short && s.length == 0x1_0000 { 2 } else { 0 };
        body.push((s.align << 5) | (s.combine << 2) | big | u8::from(s.use32));
        if short {
            body.extend_from_slice(&(s.length as u16).to_le_bytes());
        } else {
            body.extend_from_slice(&s.length.to_le_bytes());
        }
        index(&mut body, number(&s.name))?;
        index(&mut body, number(&s.class))?;
        index(&mut body, 1)?;
        record(&mut out, if short { 0x98 } else { 0x99 }, &body)?;
    }
    for (g, members) in groups {
        body.clear();
        index(&mut body, number(g))?;
        for &m in members {
            body.push(0xFF);
            index(&mut body, m)?;
        }
        record(&mut out, 0x9A, &body)?;
    }
    if !externals.is_empty() {
        body.clear();
        for e in externals {
            name(&mut body, e)?;
            index(&mut body, 0)?;
        }
        record(&mut out, 0x8C, &body)?;
    }
    for (p, segment, offset) in publics {
        body.clear();
        body.push(0);
        index(&mut body, *segment)?;
        name(&mut body, p)?;
        body.extend_from_slice(&offset.to_le_bytes());
        body.push(0);
        record(&mut out, 0x91, &body)?;
    }
    for (&segment, bytes) in &by_segment {
        for (k, chunk) in bytes.chunks(CHUNK).enumerate() {
            ledata(&mut out, segment, (k * CHUNK) as u32, chunk)?;
        }
    }
    let mut run_start = 0;
    for i in 0..fixups.len() {
        let (first, f) = (&fixups[run_start], &fixups[i]);
        let split = i > run_start
            && (f.segment != first.segment
                || f.offset <= fixups[i - 1].offset
                || f.end() - u64::from(first.offset) > CHUNK as u64
                || i - run_start >= MAX_RUN);
        if split {
            run(&mut out, &fixups[run_start..i], data_of(first.segment))?;
            run_start = i;
        }
    }
    if run_start < fixups.len() {
        run(
            &mut out,
            &fixups[run_start..],
            data_of(fixups[run_start].segment),
        )?;
    }
    body.clear();
    match start {
        None => body.push(0),
        Some((segment, offset)) => {
            // main module with start address: frame F5 (the target's), target T0 (segment) with displacement
            body.extend_from_slice(&[0xC1, 0x50]);
            index(&mut body, segment)?;
            body.extend_from_slice(&offset.to_le_bytes());
        }
    }
    record(&mut out, 0x8B, &body)?;
    Ok(out)
}

fn ledata(out: &mut Vec<u8>, segment: u32, offset: u32, bytes: &[u8]) -> Result<(), ObjectError> {
    let mut body = Vec::with_capacity(bytes.len() + 6);
    index(&mut body, segment)?;
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(bytes);
    record(out, 0xA1, &body)
}

/// The data over the span of the run once more, then its fixups. Fields of fixups with a target offset carry the
/// target in the `FIXUPP`: only in the `LEDATA` of their own run is the field empty; a later run covering the place
/// writes the final value (the raw data), so it does not clear the field again.
fn run(out: &mut Vec<u8>, run: &[WriteFixup], data: &[u8]) -> Result<(), ObjectError> {
    let (Some(first), Some(last)) = (run.first(), run.last()) else {
        return Ok(());
    };
    let start = first.offset as usize;
    // the field ending last, not necessarily the last one (the caller rejects overlapping fields)
    let end = run.iter().map(WriteFixup::end).max().unwrap_or(last.end()) as usize;
    let Some(span) = data.get(start..end) else {
        return Err(unwritable(format!(
            "fixup outside the data: segment {} +{:#x}",
            first.segment, first.offset
        )));
    };
    let mut chunk = span.to_vec();
    for f in run.iter().filter(|f| f.target_offset.is_some()) {
        let at = f.offset as usize - start;
        chunk[at..at + f.kind.width() as usize].fill(0);
    }
    ledata(out, first.segment, first.offset, &chunk)?;
    let mut body = Vec::with_capacity(run.len() * 8);
    for f in run {
        let (location, segment_relative, _) = f.kind.shape();
        let locat = 0x8000
            | if segment_relative { 0x4000 } else { 0 }
            | (location << 10)
            | (f.offset - first.offset) as u16;
        body.extend_from_slice(&locat.to_be_bytes());
        match (f.target_external, f.target_offset) {
            // F5, T6: external without displacement
            (Some(external), None) => {
                body.push(0x56);
                index(&mut body, external)?;
            }
            // F5, T2: external with displacement
            (Some(external), Some(offset)) => {
                body.push(0x52);
                index(&mut body, external)?;
                body.extend_from_slice(&offset.to_le_bytes());
            }
            // F5 (frame of the target), T4: segment without displacement
            (None, None) => {
                body.push(0x54);
                index(&mut body, f.target_segment)?;
            }
            // F5, T0: segment with displacement
            (None, Some(offset)) => {
                body.push(0x50);
                index(&mut body, f.target_segment)?;
                body.extend_from_slice(&offset.to_le_bytes());
            }
        }
    }
    record(out, 0x9D, &body)
}
