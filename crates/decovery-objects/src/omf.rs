//! OMF (Object Module Format) reader: `.OBJ` and `.LIB` from Turbo C and Watcom, 16 and 32 bit.
//!
//! Port of Decomp's `signaturen/omf.py` into the section/symbol/relocation model. Differences from
//! Decomp: `LIDATA` is expanded (Decomp skipped it and the fixups after it), record checksums are
//! verified, segment-less (absolute) publics are not kept, and malformed input is an `Err`.

use std::collections::BTreeMap;

use decovery_core::RelocKind;

use crate::model::{
    ObjReloc, ObjSymbol, ObjectError, ObjectFile, ObjectModule, RefTarget, Section, SectionKind,
};

/// Upper bound for the bytes of one section, so a corrupt offset cannot make the reader allocate gigabytes.
const MAX_SECTION: usize = 1 << 26;
const MAX_LIDATA_DEPTH: usize = 32;

/// Reads an OMF object file or library. `file_name` names the module when it has no `THEADR`.
pub fn read_omf(bytes: &[u8], file_name: &str) -> Result<ObjectFile, ObjectError> {
    let mut file = ObjectFile::default();
    for (start, end) in split_modules(bytes)? {
        let module = read_module(
            &bytes[start..end],
            start as u64,
            file_name,
            &mut file.unknown_records,
        )?;
        file.modules.push(module);
    }
    Ok(file)
}

fn malformed(offset: u64, what: impl Into<String>) -> ObjectError {
    ObjectError::Malformed {
        offset,
        what: what.into(),
    }
}

fn u16_at(d: &[u8], i: usize) -> Result<u16, ObjectError> {
    match d.get(i..i + 2) {
        Some(b) => Ok(u16::from_le_bytes([b[0], b[1]])),
        None => Err(ObjectError::Truncated {
            offset: d.len() as u64,
        }),
    }
}

/// End offset of the module starting at `i` (just after its MODEND record).
fn module_end(d: &[u8], mut i: usize) -> Result<usize, ObjectError> {
    loop {
        let t = *d.get(i).ok_or(ObjectError::Truncated {
            offset: d.len() as u64,
        })?;
        let n = usize::from(u16_at(d, i + 1)?);
        i += 3 + n;
        if i > d.len() {
            return Err(ObjectError::Truncated {
                offset: d.len() as u64,
            });
        }
        if t == 0x8A || t == 0x8B {
            return Ok(i);
        }
    }
}

/// Byte ranges of the modules of an object file or library (Decomp's `module()`).
fn split_modules(d: &[u8]) -> Result<Vec<(usize, usize)>, ObjectError> {
    let first = *d.first().ok_or_else(|| malformed(0, "empty file"))?;
    if !matches!(first, 0xF0 | 0x80 | 0x82) {
        return Err(malformed(
            0,
            format!("not an OMF file (first byte {first:#04x})"),
        ));
    }
    let mut modules = Vec::new();
    if first == 0xF0 {
        let page = usize::from(u16_at(d, 1)?) + 3;
        if page > d.len() {
            return Err(ObjectError::Truncated {
                offset: d.len() as u64,
            });
        }
        let mut i = page;
        while i < d.len() && d[i] != 0xF1 {
            let end = module_end(d, i)?;
            modules.push((i, end));
            i = end.div_ceil(page) * page;
        }
    } else {
        let mut i = 0;
        while i < d.len() && matches!(d[i], 0x80 | 0x82) {
            let end = module_end(d, i)?;
            modules.push((i, end));
            i = end;
        }
    }
    Ok(modules)
}

/// Reader over one record body; errors carry the absolute file offset.
struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
    base: u64,
}

impl<'a> Rd<'a> {
    fn err(&self, what: &str) -> ObjectError {
        malformed(self.base + self.pos as u64, what)
    }
    fn at_end(&self) -> bool {
        self.pos >= self.b.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ObjectError> {
        match self.b.get(self.pos..self.pos.saturating_add(n)) {
            Some(s) => {
                self.pos += n;
                Ok(s)
            }
            None => Err(self.err("field extends past the end of the record")),
        }
    }
    fn skip(&mut self, n: usize) -> Result<(), ObjectError> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Result<u8, ObjectError> {
        Ok(self.take(1)?[0])
    }
    /// Little-endian unsigned integer of `w` (at most 4) bytes.
    fn uint(&mut self, w: usize) -> Result<u32, ObjectError> {
        let s = self.take(w)?;
        Ok(s.iter().rev().fold(0u32, |a, &x| (a << 8) | u32::from(x)))
    }
    fn index(&mut self) -> Result<u32, ObjectError> {
        let a = self.u8()?;
        if a & 0x80 != 0 {
            let b = self.u8()?;
            Ok((u32::from(a & 0x7F) << 8) | u32::from(b))
        } else {
            Ok(u32::from(a))
        }
    }
    fn name(&mut self) -> Result<String, ObjectError> {
        let n = usize::from(self.u8()?);
        Ok(self.take(n)?.iter().map(|&c| char::from(c)).collect())
    }
}

enum Current {
    None,
    /// COMDAT: fixups that follow are not evaluated.
    Skip,
    At {
        section: usize,
        base: u32,
    },
}

struct Pending {
    section: usize,
    pos: u32,
    width: u8,
    kind: RelocKind,
    method: Option<u8>,
    index: u32,
    disp: u32,
}

fn fixup_width(loc: u8, easy: bool) -> Option<(u8, RelocKind)> {
    Some(match loc {
        0 | 4 => (1, RelocKind::Absolute),
        1 => (2, RelocKind::Absolute),
        2 => (2, RelocKind::Selector),
        3 => (4, RelocKind::FarPointer),
        // Easy OMF-386 (Watcom 9.x): location 5 is a 32-bit offset
        5 => (if easy { 4 } else { 2 }, RelocKind::Absolute),
        9 | 13 => (4, RelocKind::Absolute),
        11 => (6, RelocKind::FarPointer),
        _ => return None,
    })
}

const KNOWN: [u8; 20] = [
    0x80, 0x82, 0x88, 0x8A, 0x8B, 0x8C, 0x90, 0x91, 0x96, 0x98, 0x99, 0x9A, 0x9C, 0x9D, 0xA0, 0xA1,
    0xB4, 0xB5, 0xB6, 0xB7,
];

struct State {
    lnames: Vec<String>,
    sections: Vec<Section>,
    exts: Vec<String>,
    symbols: Vec<ObjSymbol>,
    threads: [Option<(u8, u32)>; 4],
    current: Current,
    pending: Vec<Pending>,
    easy: bool,
}

fn read_module(
    m: &[u8],
    base: u64,
    file_name: &str,
    unknown: &mut BTreeMap<u8, u32>,
) -> Result<ObjectModule, ObjectError> {
    let mut st = State {
        lnames: vec![String::new()],
        sections: Vec::new(),
        exts: vec![String::new()],
        symbols: Vec::new(),
        threads: [None; 4],
        current: Current::None,
        pending: Vec::new(),
        easy: false,
    };
    let mut name = file_name.to_string();
    let mut i = 0;
    while i < m.len() {
        let rec_off = base + i as u64;
        let t = m[i];
        let n = usize::from(u16_at(m, i + 1)?);
        if n == 0 {
            return Err(malformed(rec_off, "record without checksum byte"));
        }
        let rec = m.get(i..i + 3 + n).ok_or(ObjectError::Truncated {
            offset: base + m.len() as u64,
        })?;
        let (sum_part, check) = rec.split_at(rec.len() - 1);
        let sum = sum_part.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        if check[0] != 0 && sum.wrapping_add(check[0]) != 0 {
            return Err(ObjectError::BadChecksum { offset: rec_off });
        }
        let mut rd = Rd {
            b: &rec[3..rec.len() - 1],
            pos: 0,
            base: rec_off + 3,
        };
        i += 3 + n;
        if t == 0x88
            && rd.b.get(1) == Some(&0xAA)
            && rd.b.get(2..).is_some_and(|s| s.starts_with(b"80386"))
        {
            st.easy = true;
        }
        let gross = matches!(t, 0x8B | 0x91 | 0x99 | 0x9D | 0xA1 | 0xB7 | 0xA3) || st.easy;
        let w = if gross { 4 } else { 2 };
        match t {
            0x80 | 0x82 => {
                let full = rd.name()?.replace('\\', "/");
                name = full.rsplit('/').next().unwrap_or_default().to_string();
            }
            0x96 => {
                while !rd.at_end() {
                    st.lnames.push(rd.name()?);
                }
            }
            0x98 | 0x99 => segdef(&mut st, &mut rd, gross)?,
            0x8C | 0xB4 => {
                while !rd.at_end() {
                    st.exts.push(rd.name()?);
                    rd.index()?;
                }
            }
            0x90 | 0x91 | 0xB6 | 0xB7 => pubdef(&mut st, &mut rd, w, matches!(t, 0x90 | 0x91))?,
            0xA0 | 0xA1 => {
                let seg = rd.index()?;
                let off = rd.uint(w)?;
                let section = section_index(&st, &rd, seg)?;
                let data = rd.take(rd.b.len() - rd.pos)?;
                write_data(&mut st.sections[section], &rd, off, data)?;
                st.current = Current::At { section, base: off };
            }
            0xA2 | 0xA3 => {
                let seg = rd.index()?;
                let off = rd.uint(w)?;
                let section = section_index(&st, &rd, seg)?;
                let mut data = Vec::new();
                while !rd.at_end() {
                    expand_lidata(&mut rd, w, &mut data, 0)?;
                }
                write_data(&mut st.sections[section], &rd, off, &data)?;
                st.current = Current::At { section, base: off };
            }
            0xC2 | 0xC3 => {
                // COMDAT (C++ inline functions) is not evaluated
                *unknown.entry(t).or_insert(0) += 1;
                st.current = Current::Skip;
            }
            0x9C | 0x9D => fixupp(&mut st, &mut rd, gross)?,
            _ if !KNOWN.contains(&t) => *unknown.entry(t).or_insert(0) += 1,
            _ => {}
        }
    }
    Ok(finish(name, st))
}

fn segdef(st: &mut State, rd: &mut Rd, gross: bool) -> Result<(), ObjectError> {
    let attr = rd.u8()?;
    if attr >> 5 == 0 {
        rd.skip(3)?; // absolute segment: frame number and offset
    }
    rd.skip(if gross { 4 } else { 2 })?; // length
    let name = rd.index()?;
    let class = rd.index()?;
    let lookup = |idx: u32| -> Result<String, ObjectError> {
        st.lnames
            .get(idx as usize)
            .cloned()
            .ok_or_else(|| rd.err("segment name index out of range"))
    };
    let name = lookup(name)?;
    let class = lookup(class)?;
    let bits = if gross || attr & 1 != 0 { 32 } else { 16 };
    let kind = if class.eq_ignore_ascii_case("CODE") || name.to_ascii_uppercase().ends_with("TEXT")
    {
        SectionKind::Code
    } else {
        SectionKind::Data
    };
    st.sections.push(Section {
        name,
        class,
        kind,
        bits,
        data: Vec::new(),
        relocs: Vec::new(),
    });
    Ok(())
}

fn section_index(st: &State, rd: &Rd, seg: u32) -> Result<usize, ObjectError> {
    match (seg as usize).checked_sub(1) {
        Some(i) if i < st.sections.len() => Ok(i),
        _ => Err(rd.err("segment index out of range")),
    }
}

fn pubdef(st: &mut State, rd: &mut Rd, w: usize, public: bool) -> Result<(), ObjectError> {
    rd.index()?; // base group
    let seg = rd.index()?;
    if seg == 0 {
        rd.skip(2)?; // base frame of an absolute symbol
    }
    while !rd.at_end() {
        let name = rd.name()?;
        let offset = rd.uint(w)?;
        rd.index()?; // type
        if seg != 0 {
            let section = section_index(st, rd, seg)?;
            st.symbols.push(ObjSymbol {
                name,
                section: section as u32,
                offset,
                public,
            });
        }
    }
    Ok(())
}

fn write_data(section: &mut Section, rd: &Rd, off: u32, data: &[u8]) -> Result<(), ObjectError> {
    let off = off as usize;
    let end = off
        .checked_add(data.len())
        .filter(|&e| e <= MAX_SECTION)
        .ok_or_else(|| rd.err("section data exceeds the supported size"))?;
    if section.data.len() < end {
        section.data.resize(end, 0);
    }
    section.data[off..end].copy_from_slice(data);
    Ok(())
}

/// Expands one iterated data block (repeat count, block count, nested blocks or literal content).
fn expand_lidata(
    rd: &mut Rd,
    w: usize,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), ObjectError> {
    if depth > MAX_LIDATA_DEPTH {
        return Err(rd.err("LIDATA nesting too deep"));
    }
    let repeat = rd.uint(w)? as usize;
    let blocks = rd.uint(2)?;
    let mut content = Vec::new();
    if blocks == 0 {
        let len = usize::from(rd.u8()?);
        content.extend_from_slice(rd.take(len)?);
    } else {
        for _ in 0..blocks {
            expand_lidata(rd, w, &mut content, depth + 1)?;
        }
    }
    if content.is_empty() {
        return Ok(());
    }
    let total = content
        .len()
        .saturating_mul(repeat)
        .saturating_add(out.len());
    if total > MAX_SECTION {
        return Err(rd.err("LIDATA expands beyond the supported size"));
    }
    for _ in 0..repeat {
        out.extend_from_slice(&content);
    }
    Ok(())
}

fn fixupp(st: &mut State, rd: &mut Rd, gross: bool) -> Result<(), ObjectError> {
    while !rd.at_end() {
        let x = rd.u8()?;
        if x & 0x80 == 0 {
            // THREAD subrecord
            let method = (x >> 2) & 7;
            let nr = usize::from(x & 3);
            if x & 0x40 != 0 {
                if method < 3 {
                    rd.index()?;
                }
            } else {
                let idx = rd.index()?;
                st.threads[nr] = Some((method & 3, idx));
            }
            continue;
        }
        let lo = (u16::from(x) << 8) | u16::from(rd.u8()?);
        let selfrel = x & 0x40 == 0;
        let loc = ((lo >> 10) & 0xF) as u8;
        let dro = u32::from(lo & 0x3FF);
        let fd = rd.u8()?;
        if fd & 0x80 == 0 && (fd >> 4) & 7 < 3 {
            rd.index()?; // frame datum
        }
        let (method, index) = if fd & 0x08 != 0 {
            match st.threads[usize::from(fd & 3)] {
                Some((m, i)) => (Some(m), i),
                None => (None, 0),
            }
        } else {
            (Some(fd & 3), rd.index()?)
        };
        let disp = if fd & 0x04 == 0 {
            rd.uint(if gross { 4 } else { 2 })?
        } else {
            0
        };
        let (section, base) = match st.current {
            // fixup of a COMDAT: only the THREADs above count
            Current::Skip => continue,
            Current::None => return Err(rd.err("FIXUPP without a preceding data record")),
            Current::At { section, base } => (section, base),
        };
        let Some((width, kind)) = fixup_width(loc, st.easy) else {
            return Err(rd.err(&format!("unknown fixup location {loc}")));
        };
        let kind = if selfrel && kind == RelocKind::Absolute {
            RelocKind::Relative
        } else {
            kind
        };
        st.pending.push(Pending {
            section,
            pos: base.saturating_add(dro),
            width,
            kind,
            method,
            index,
            disp,
        });
    }
    Ok(())
}

fn finish(name: String, mut st: State) -> ObjectModule {
    let pending = std::mem::take(&mut st.pending);
    for p in pending {
        let target = match p.method {
            Some(0) if (1..=st.sections.len() as u32).contains(&p.index) => RefTarget::Section {
                index: p.index - 1,
                offset: p.disp,
            },
            Some(2) if p.index > 0 && (p.index as usize) < st.exts.len() => {
                RefTarget::Symbol(st.exts[p.index as usize].clone())
            }
            _ => RefTarget::Unknown,
        };
        let addend = match target {
            RefTarget::Section { .. } => 0,
            _ => i64::from(p.disp),
        };
        st.sections[p.section].relocs.push(ObjReloc {
            offset: p.pos,
            width: p.width,
            kind: p.kind,
            target,
            addend,
        });
    }
    for s in &mut st.sections {
        if s.kind != SectionKind::Code && s.data.is_empty() {
            s.kind = SectionKind::Bss;
        }
    }
    ObjectModule {
        name,
        sections: st.sections,
        symbols: st.symbols,
    }
}
