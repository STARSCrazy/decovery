//! Manx Aztec C86 object (`.O`) and library (`.LIB`) reader (ADR 0012).
//!
//! Written from the compiler's object format description. A module is a 30-byte header, a stream of load items up
//! to an end item, a table of named symbols and a table of unnamed ones (labels, literals). Every module maps to three
//! sections: 0 code, 1 data, 2 BSS. References in the stream become relocations; the integer part of a reference
//! expression is written into the field, as an OMF object stores it. Self-relative references to unnamed labels
//! (the assembler leaves even short jumps to the linker) target the own section's position.

use std::collections::{BTreeMap, BTreeSet};

use decovery_core::RelocKind;

use crate::model::{
    Frame, ObjReloc, ObjSymbol, ObjectError, ObjectFile, ObjectModule, RefTarget, Section,
    SectionKind,
};

/// Object module, small code model.
pub(crate) const MAGIC_SMALL: u16 = 0x5466;
/// Object module, large code model.
pub(crate) const MAGIC_LARGE: u16 = 0x020C;
pub(crate) const MAGIC_LIBRARY: u16 = 0xEC62;
pub(crate) const HEADER_LEN: usize = 30;
pub(crate) const DICT_BLOCK: usize = 2048;
/// Library positions (module starts, dictionary blocks) are stored in units of this many bytes.
pub(crate) const LIB_UNIT: usize = 128;

/// Symbol types (low nibble of the type byte).
pub(crate) const T_ABS: u8 = 1;
pub(crate) const T_CODE: u8 = 2;
pub(crate) const T_DATA: u8 = 3;
pub(crate) const T_UNDEF: u8 = 7;
pub(crate) const T_BSS: u8 = 9;
/// Symbol flags.
pub(crate) const F_GLOBAL: u8 = 0x08;
pub(crate) const F_HAS_SEGMENT: u8 = 0x10;

const CODE: u32 = 0;
const DATA: u32 = 1;
const BSS: u32 = 2;

const MAX_EXPR_DEPTH: usize = 64;

/// Reads an Aztec C86 object file or library. `file_name` names a module whose header name is empty.
pub fn read_aztec(bytes: &[u8], file_name: &str) -> Result<ObjectFile, ObjectError> {
    let magic = u16_at(bytes, 0)?;
    let mut file = ObjectFile::default();
    match magic {
        MAGIC_SMALL | MAGIC_LARGE => {
            let (module, _) = read_module(bytes, 0, file_name)?;
            file.modules.push(module);
        }
        MAGIC_LIBRARY => file.modules = read_library(bytes, file_name)?,
        _ => {
            return Err(malformed(
                0,
                format!("not an Aztec object or library (magic {magic:#06x})"),
            ));
        }
    }
    Ok(file)
}

fn malformed(offset: usize, what: impl Into<String>) -> ObjectError {
    ObjectError::Malformed {
        offset: offset as u64,
        what: what.into(),
    }
}

fn truncated(offset: usize) -> ObjectError {
    ObjectError::Truncated {
        offset: offset as u64,
    }
}

fn u8_at(d: &[u8], i: usize) -> Result<u8, ObjectError> {
    d.get(i).copied().ok_or_else(|| truncated(i.min(d.len())))
}

fn u16_at(d: &[u8], i: usize) -> Result<u16, ObjectError> {
    match d.get(i..i.saturating_add(2)) {
        Some(b) => Ok(u16::from_le_bytes([b[0], b[1]])),
        None => Err(truncated(i.min(d.len()))),
    }
}

/// Index of the NUL ending a name that starts at `i`, searched below `end`.
fn name_end(d: &[u8], i: usize, end: usize) -> Option<usize> {
    let end = end.min(d.len());
    d.get(i..end)?.iter().position(|&c| c == 0).map(|k| i + k)
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| char::from(c)).collect()
}

#[derive(Debug, Clone)]
struct Sym {
    kind: u8,
    flags: u8,
    value: u16,
    /// `None` for the unnamed table.
    name: Option<String>,
}

/// Header fields after the magic, at their positions.
struct Header {
    name: String,
    code: u16,
    data: u16,
    bss: u16,
    globals_at: u16,
    globals: i16,
    locals_at: u16,
    locals: i16,
    end: u16,
    next: u16,
}

fn header(d: &[u8], s: usize) -> Result<Header, ObjectError> {
    if d.len() < s.saturating_add(HEADER_LEN) {
        return Err(truncated(d.len()));
    }
    let w = |k: usize| u16::from_le_bytes([d[s + k], d[s + k + 1]]);
    let raw_name = &d[s + 2..s + 10];
    let name_len = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
    Ok(Header {
        name: latin1(&raw_name[..name_len]),
        code: w(10),
        data: w(12),
        bss: w(14),
        globals_at: w(16),
        globals: w(18) as i16,
        locals_at: w(20),
        locals: w(22) as i16,
        end: w(24),
        next: w(26),
    })
}

fn symbol_table(
    d: &[u8],
    mut i: usize,
    count: i16,
    count_at: usize,
    named: bool,
    limit: usize,
) -> Result<Vec<Sym>, ObjectError> {
    let count = usize::try_from(count).map_err(|_| malformed(count_at, "negative symbol count"))?;
    let mut out = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        if i.saturating_add(4) > limit {
            return Err(malformed(i, "symbol table runs past its end"));
        }
        let kind = d[i] & 0x0F;
        let flags = d[i + 1];
        let value = u16::from_le_bytes([d[i + 2], d[i + 3]]);
        i += 4;
        if flags & F_HAS_SEGMENT != 0 {
            i += 1; // segment or group number, not used for DOS programs
        }
        let name = if named {
            let end = name_end(d, i, limit)
                .ok_or_else(|| malformed(i, "symbol name without terminating NUL"))?;
            let n = latin1(&d[i..end]);
            i = end + 1;
            Some(n)
        } else {
            None
        };
        out.push(Sym {
            kind,
            flags,
            value,
            name,
        });
    }
    if i > limit {
        return Err(malformed(i.min(limit), "symbol table runs past its end"));
    }
    Ok(out)
}

/// Reads the module at `s`; returns it with the header's distance to the next module.
fn read_module(d: &[u8], s: usize, file_name: &str) -> Result<(ObjectModule, u16), ObjectError> {
    let h = header(d, s)?;
    let abs = |o: u16| s + usize::from(o);
    let end = abs(h.end);
    if end > d.len() {
        return Err(truncated(d.len()));
    }
    for (at, field) in [(h.globals_at, 16), (h.locals_at, 20)] {
        if abs(at) > end || (usize::from(at) < HEADER_LEN && at != 0) {
            return Err(malformed(
                s + field,
                "symbol table offset outside the module",
            ));
        }
    }
    let globals = symbol_table(d, abs(h.globals_at), h.globals, s + 18, true, end)?;
    let locals = symbol_table(d, abs(h.locals_at), h.locals, s + 22, false, end)?;

    // An assembler object has its load items right after the header and the symbol tables behind them; a library
    // module (written by the librarian) has the tables in front and the items from the end of the tables on.
    let (items, items_end) = if usize::from(h.globals_at) > HEADER_LEN {
        (s + HEADER_LEN, abs(h.globals_at))
    } else {
        let stop = if h.next == 0 { d.len() } else { abs(h.next) };
        if stop > d.len() {
            return Err(truncated(d.len()));
        }
        (end, stop)
    };

    let mut st = Stream {
        d,
        end: items_end,
        globals: &globals,
        locals: &locals,
        bufs: [vec![0; usize::from(h.code)], vec![0; usize::from(h.data)]],
        relocs: [Vec::new(), Vec::new()],
        pos: [0, 0],
        cur: 0,
        start: None,
    };
    st.run(items)?;

    let mut symbols = Vec::new();
    for g in &globals {
        let section = match g.kind {
            T_CODE => CODE,
            T_DATA => DATA,
            T_BSS => BSS,
            _ => continue,
        };
        symbols.push(ObjSymbol {
            name: g.name.clone().unwrap_or_default(),
            section,
            offset: u32::from(g.value),
            public: g.flags & F_GLOBAL != 0,
        });
    }
    let start = st
        .start
        .and_then(|(sec, off)| u32::try_from(off).ok().map(|o| (sec, o)));
    let [code, data] = st.bufs;
    let [code_relocs, data_relocs] = st.relocs;
    let sections = vec![
        Section::new("CODE", "CODE", SectionKind::Code, 16, code, code_relocs),
        Section::new("DATA", "DATA", SectionKind::Data, 16, data, data_relocs),
        Section::new("BSS", "BSS", SectionKind::Bss, 16, Vec::new(), Vec::new())
            .with_size(u32::from(h.bss)),
    ];
    let name = if h.name.is_empty() {
        file_name.to_string()
    } else {
        h.name
    };
    let mut module = ObjectModule::new(name, sections, symbols);
    module.start = start;
    // an undefined name with a value is a common symbol of that size (an uninitialised global)
    module.commons = globals
        .iter()
        .filter(|g| g.kind == T_UNDEF && g.value > 0)
        .filter_map(|g| Some((g.name.clone()?, u32::from(g.value))))
        .collect();
    Ok((module, h.next))
}

/// The base of an operand value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Base {
    None,
    /// A position in a section (unnamed symbol or section reference).
    At(u32, u32),
    Symbol(String),
    /// The paragraph (segment) of a section.
    Segment(u32),
    /// The segment of a named symbol (`seg` operator).
    SegmentOf(String),
}

struct Stream<'a> {
    d: &'a [u8],
    /// End of the item region (exclusive).
    end: usize,
    globals: &'a [Sym],
    locals: &'a [Sym],
    /// Code and data bytes, at header size.
    bufs: [Vec<u8>; 2],
    relocs: [Vec<ObjReloc>; 2],
    pos: [u32; 2],
    cur: usize,
    start: Option<(u32, i64)>,
}

impl Stream<'_> {
    fn byte(&self, i: usize) -> Result<u8, ObjectError> {
        if i >= self.end {
            return Err(malformed(
                i.min(self.d.len()),
                "load item runs past the end of the item stream",
            ));
        }
        u8_at(self.d, i)
    }

    fn word(&self, i: usize) -> Result<u16, ObjectError> {
        Ok(u16::from(self.byte(i)?) | (u16::from(self.byte(i + 1)?) << 8))
    }

    fn long(&self, i: usize) -> Result<i32, ObjectError> {
        Ok(i32::from(self.word(i)?) | (i32::from(self.word(i + 2)?) << 16))
    }

    /// Writes `n` bytes (from `src`, or zeros) at the current position.
    fn write(&mut self, at: usize, src: Option<&[u8]>, n: usize) -> Result<(), ObjectError> {
        let c = self.cur;
        let p = self.pos[c] as usize;
        let buf = &mut self.bufs[c];
        if p + n > buf.len() {
            let what = if c == 0 { "code" } else { "data" };
            return Err(malformed(
                at,
                format!(
                    "load items write {what} up to {:#x}, the header gives {:#x} bytes",
                    p + n,
                    buf.len()
                ),
            ));
        }
        match src {
            Some(b) => buf[p..p + n].copy_from_slice(b),
            None => buf[p..p + n].fill(0),
        }
        self.pos[c] = (p + n) as u32;
        Ok(())
    }

    fn run(&mut self, mut i: usize) -> Result<(), ObjectError> {
        // (width, self-relative) for the next reference
        let mut modifier: Option<(u8, bool)> = None;
        loop {
            let b = self.byte(i)?;
            let nyb = b & 0x0F;
            match b {
                0x00 => return Ok(()),
                0x01..=0x0D => i = self.debug_item(i)?,
                0x0F => match self.byte(i + 1)? {
                    0x01 => {
                        let o = self.word(i + 2)?;
                        self.pos[self.cur] = u32::from(o);
                        i += 4;
                    }
                    x => return Err(malformed(i, format!("unknown extended load item {x:#04x}"))),
                },
                0x10..=0x1F => {
                    let n = usize::from(nyb) + 1;
                    if i + 1 + n > self.end {
                        return Err(malformed(i, "raw data item runs past the item stream"));
                    }
                    let d = self.d;
                    self.write(i, Some(&d[i + 1..i + 1 + n]), n)?;
                    i += 1 + n;
                }
                0x80..=0x8F => {
                    let n = usize::from(nyb) | (usize::from(self.byte(i + 1)?) << 4);
                    self.write(i, None, n)?;
                    i += 2;
                }
                0xF1 => (modifier, i) = (Some((1, false)), i + 1),
                0xF2 => (modifier, i) = (Some((1, true)), i + 1),
                0xFA => (modifier, i) = (Some((2, true)), i + 1),
                0xFD => (modifier, i) = (Some((4, false)), i + 1),
                0xF4 => (self.cur, i) = (0, i + 1),
                0xF5 => (self.cur, i) = (1, i + 1),
                0xFF => i += 1,
                0xF6 => {
                    let (base, num, next) = self.operand(i + 1, 0)?;
                    self.start = match base {
                        Base::At(sec, off) => Some((sec, i64::from(off) + num)),
                        Base::Symbol(name) => self
                            .globals
                            .iter()
                            .find(|g| g.name.as_deref() == Some(name.as_str()))
                            .and_then(|g| {
                                section_of(g.kind).map(|s| (s, i64::from(g.value) + num))
                            }),
                        _ => None,
                    };
                    i = next;
                }
                0x20..=0x7F | 0xA0..=0xCF | 0xF0 | 0xF3 | 0xF7 | 0xF8 | 0xFB | 0xFC | 0xFE => {
                    let (width, relative) = modifier.take().unwrap_or((2, false));
                    let (base, num, next) = self.operand(i, 0)?;
                    self.reference(i, width, relative, base, num)?;
                    i = next;
                }
                0x90..=0x9F => return Err(malformed(i, "common segment switch is not supported")),
                0xD0..=0xDF => {
                    return Err(malformed(i, "segment-relative reference is not supported"));
                }
                _ => return Err(malformed(i, format!("unknown load item {b:#04x}"))),
            }
        }
    }

    fn reference(
        &mut self,
        at: usize,
        width: u8,
        relative: bool,
        base: Base,
        num: i64,
    ) -> Result<(), ObjectError> {
        let offset = self.pos[self.cur];
        let mut field = num;
        let reloc = match base {
            Base::None => None,
            Base::At(index, off) => {
                if relative {
                    let target = i64::from(off) + num;
                    let target = u32::try_from(target).map_err(|_| {
                        malformed(at, "self-relative reference before its section start")
                    })?;
                    Some((
                        RefTarget::Section {
                            index,
                            offset: target,
                        },
                        false,
                    ))
                } else {
                    Some((RefTarget::Section { index, offset: off }, false))
                }
            }
            Base::Symbol(name) => Some((RefTarget::Symbol(name), false)),
            Base::Segment(index) => {
                field = 0;
                Some((RefTarget::Section { index, offset: 0 }, true))
            }
            Base::SegmentOf(name) => {
                field = 0;
                Some((RefTarget::Symbol(name), true))
            }
        };
        if let Some((target, selector)) = reloc {
            let kind = match (selector, relative, width) {
                (true, false, 2) => RelocKind::Selector,
                (true, _, _) => {
                    return Err(malformed(at, "segment reference must be a word"));
                }
                (false, true, 1 | 2) => RelocKind::Relative,
                (false, false, 1 | 2) => RelocKind::Absolute,
                (false, false, 4) => RelocKind::FarPointer,
                _ => return Err(malformed(at, "unsupported reference width")),
            };
            self.relocs[self.cur].push(ObjReloc {
                offset,
                width,
                kind,
                target,
                addend: 0,
                frame: Frame::Target,
            });
        }
        let bytes = field.to_le_bytes();
        self.write(at, Some(&bytes[..usize::from(width)]), usize::from(width))
    }

    fn symbol(&self, at: usize, named: bool, index: usize) -> Result<(Base, i64), ObjectError> {
        let table = if named { self.globals } else { self.locals };
        let sym = table.get(index).ok_or_else(|| {
            malformed(
                at,
                format!(
                    "{} symbol {index} out of range ({} symbols)",
                    if named { "named" } else { "unnamed" },
                    table.len()
                ),
            )
        })?;
        match (sym.kind, &sym.name) {
            (T_ABS, _) => Ok((Base::None, i64::from(sym.value))),
            (T_CODE | T_DATA | T_BSS | T_UNDEF, Some(name)) => Ok((Base::Symbol(name.clone()), 0)),
            (k, None) => match section_of(k) {
                Some(sec) => Ok((Base::At(sec, u32::from(sym.value)), 0)),
                None => Err(malformed(
                    at,
                    format!("unnamed symbol of type {k} cannot be referenced"),
                )),
            },
            (k, Some(_)) => Err(malformed(
                at,
                format!("named symbol of type {k} cannot be referenced"),
            )),
        }
    }

    /// One operand at `i`: its base, its integer part and the index after it.
    fn operand(&self, i: usize, depth: usize) -> Result<(Base, i64, usize), ObjectError> {
        if depth > MAX_EXPR_DEPTH {
            return Err(malformed(i, "expression nested too deeply"));
        }
        let b = self.byte(i)?;
        let nyb = i64::from(b & 0x0F);
        let twelve = |s: &Self| -> Result<usize, ObjectError> {
            Ok(usize::from(b & 0x0F) | (usize::from(s.byte(i + 1)?) << 4))
        };
        Ok(match b {
            0x20..=0x2F => return self.expression(i, b & 0x0F, depth),
            0x30..=0x3F => (Base::None, nyb, i + 1),
            0x40..=0x4F => (Base::None, -nyb, i + 1),
            0x50..=0x5F => {
                let hi = i64::from(self.byte(i + 1)?) - 0x80;
                (Base::None, (hi << 4) | nyb, i + 2)
            }
            0x60..=0x7F => {
                let (base, num) = self.symbol(i, b >= 0x70, twelve(self)?)?;
                (base, num, i + 2)
            }
            0xA0..=0xCF => {
                let sec = match b >> 4 {
                    0xA => CODE,
                    0xB => DATA,
                    _ => BSS,
                };
                (Base::At(sec, 0), twelve(self)? as i64, i + 2)
            }
            0xF7 | 0xF8 | 0xFB => {
                let sec = match b {
                    0xF7 => CODE,
                    0xF8 => DATA,
                    _ => BSS,
                };
                (Base::At(sec, 0), i64::from(self.word(i + 1)?), i + 3)
            }
            0xF3 => (Base::None, i64::from(self.word(i + 1)? as i16), i + 3),
            0xFC => (Base::None, i64::from(self.long(i + 1)?), i + 5),
            0xF0 => (Base::Segment(DATA), 0, i + 1),
            0xFE => (Base::Segment(CODE), 0, i + 1),
            _ => return Err(malformed(i, format!("unknown operand {b:#04x}"))),
        })
    }

    fn expression(
        &self,
        i: usize,
        op: u8,
        depth: usize,
    ) -> Result<(Base, i64, usize), ObjectError> {
        let unsupported = || malformed(i, format!("unsupported expression (operator {op})"));
        let (b1, n1, j) = self.operand(i + 1, depth + 1)?;
        if op >= 11 {
            return match (op, b1) {
                (11, Base::None) => Ok((Base::None, !n1, j)),
                (12, Base::None) => Ok((Base::None, n1.wrapping_neg(), j)),
                (13, Base::None) => Ok((Base::None, (n1 >> 8) & 0xFF, j)),
                (14, Base::None) => Ok((Base::None, n1 & 0xFF, j)),
                (15, Base::At(sec, _)) => Ok((Base::Segment(sec), 0, j)),
                (15, Base::Symbol(name)) => Ok((Base::SegmentOf(name), 0, j)),
                _ => Err(unsupported()),
            };
        }
        let (b2, n2, j) = self.operand(j, depth + 1)?;
        let out = match (op, b1, b2) {
            (1, Base::None, b) | (1, b, Base::None) => (b, n1.wrapping_add(n2)),
            (2, b, Base::None) => (b, n1.wrapping_sub(n2)),
            (2, Base::At(s1, o1), Base::At(s2, o2)) if s1 == s2 => {
                (Base::None, (i64::from(o1) + n1) - (i64::from(o2) + n2))
            }
            (3..=10, Base::None, Base::None) => {
                let v = match op {
                    3 => n1.wrapping_mul(n2),
                    4 | 5 if n2 == 0 => return Err(malformed(i, "division by zero")),
                    4 => n1.wrapping_div(n2),
                    5 => n1.wrapping_rem(n2),
                    6 => n1 & n2,
                    7 => n1 | n2,
                    8 => n1 ^ n2,
                    9 => n1.wrapping_shr(n2 as u32),
                    _ => n1.wrapping_shl(n2 as u32),
                };
                (Base::None, v)
            }
            _ => return Err(unsupported()),
        };
        Ok((out.0, out.1, j))
    }

    /// Skips a debug item (block, variable, type, structure, file and line information).
    fn debug_item(&self, mut i: usize) -> Result<usize, ObjectError> {
        let b = self.byte(i)?;
        i += 1;
        Ok(match b {
            0x01 | 0x0D => i + 2,
            0x02 | 0x03 | 0x06 | 0x07 => self.type_string(self.name(i)? + 2)?,
            0x04 | 0x05 => self.type_string(self.name(i)? + 1)?,
            0x08 => self.type_string(i + 2)?,
            0x09 => self.type_string(self.name(i)?)?,
            0x0A | 0x0C => self.name(i)?,
            0x0B => {
                let members = self.word(i + 2)?;
                i += 6;
                for _ in 0..members {
                    let kind = self.byte(i)?;
                    i = self.name(i + 1)? + 2;
                    match kind {
                        0x01 => {}
                        0x02 => i += 2, // bit field: position and width
                        _ => {
                            return Err(malformed(
                                i,
                                format!("unknown structure member {kind:#04x}"),
                            ));
                        }
                    }
                    i = self.type_string(i)?;
                }
                i
            }
            _ => return Err(malformed(i - 1, format!("unknown debug item {b:#04x}"))),
        })
    }

    /// Index after a NUL-terminated name at `i`.
    fn name(&self, i: usize) -> Result<usize, ObjectError> {
        name_end(self.d, i, self.end)
            .map(|k| k + 1)
            .ok_or_else(|| malformed(i.min(self.d.len()), "name without terminating NUL"))
    }

    /// Index after a debug type string at `i`: modifiers, then a base type letter or `:` with a structure number.
    fn type_string(&self, mut i: usize) -> Result<usize, ObjectError> {
        loop {
            let c = self.byte(i)?;
            match c {
                b'*' | b'#' | b'(' | b'{' => i += 1,
                b'[' => {
                    i += 1;
                    while self.byte(i)?.is_ascii_digit() {
                        i += 1;
                    }
                }
                b':' => return Ok(i + 3),
                b'c' | b'C' | b'i' | b'I' | b'l' | b'L' | b'f' | b'd' | b'v' => return Ok(i + 1),
                _ => return Err(malformed(i, format!("unknown type letter {c:#04x}"))),
            }
        }
    }
}

fn section_of(kind: u8) -> Option<u32> {
    match kind {
        T_CODE => Some(CODE),
        T_DATA => Some(DATA),
        T_BSS => Some(BSS),
        _ => None,
    }
}

/// Module positions from the dictionary blocks, then the modules in file order.
/// One member of an Aztec library: its module (an Aztec object), where it starts in the library, how many bytes
/// it occupies (up to the next member or the end of the file) and its public symbol names.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AztecLibraryMember {
    /// The module name from the member's header (the source file's name without extension, e.g. `strcmp`).
    pub name: String,
    /// Offset of the member's header in the library file.
    pub offset: u64,
    /// Bytes of the member in the library (header, symbol tables, load items, padding).
    pub len: u64,
    /// Public symbols the member defines (code, data or BSS), in table order.
    pub publics: Vec<String>,
    pub module: ObjectModule,
}

impl AztecLibraryMember {
    /// The member as a stand-alone object file (one module).
    pub fn object(&self) -> ObjectFile {
        ObjectFile {
            modules: vec![self.module.clone()],
            ..ObjectFile::default()
        }
    }

    /// The member's bytes within the library it was read from (`library` = the same file).
    pub fn bytes<'a>(&self, library: &'a [u8]) -> Option<&'a [u8]> {
        let s = usize::try_from(self.offset).ok()?;
        let e = s.checked_add(usize::try_from(self.len).ok()?)?;
        library.get(s..e)
    }
}

/// Reads an Aztec library (`.LIB`) member by member. A single object (`.O`) reads as a library of one member, so
/// objects outside libraries (`OVLD.O`) are handled alike. Malformed input is an error naming the offset.
pub fn read_aztec_library(
    bytes: &[u8],
    file_name: &str,
) -> Result<Vec<AztecLibraryMember>, ObjectError> {
    let magic = u16_at(bytes, 0)?;
    let located = match magic {
        MAGIC_SMALL | MAGIC_LARGE => {
            let (module, _) = read_module(bytes, 0, file_name)?;
            vec![(0, bytes.len(), module)]
        }
        MAGIC_LIBRARY => library_modules(bytes, file_name)?,
        _ => {
            return Err(malformed(
                0,
                format!("not an Aztec object or library (magic {magic:#06x})"),
            ));
        }
    };
    Ok(located
        .into_iter()
        .map(|(offset, len, module)| AztecLibraryMember {
            name: module.name.clone(),
            offset: offset as u64,
            len: len as u64,
            publics: module
                .symbols
                .iter()
                .filter(|s| s.public)
                .map(|s| s.name.clone())
                .collect(),
            module,
        })
        .collect())
}

fn read_library(d: &[u8], file_name: &str) -> Result<Vec<ObjectModule>, ObjectError> {
    Ok(library_modules(d, file_name)?
        .into_iter()
        .map(|(_, _, m)| m)
        .collect())
}

/// The modules of a library with their offset and length in the file.
fn library_modules(
    d: &[u8],
    file_name: &str,
) -> Result<Vec<(usize, usize, ObjectModule)>, ObjectError> {
    let mut positions = BTreeMap::new(); // module position -> dictionary entry offset
    let mut blocks = BTreeSet::new();
    let mut blk = 0usize;
    loop {
        if blk.saturating_add(4) > d.len() {
            return Err(malformed(
                blk.min(d.len()),
                "dictionary block past the end of the file",
            ));
        }
        blocks.insert(blk);
        let next = usize::from(u16_at(d, blk + 2)?);
        let end = (blk + DICT_BLOCK).min(d.len());
        let mut j = blk + 4;
        while j + 3 <= end {
            let Some(k) = name_end(d, j + 2, end) else {
                break;
            };
            if k == j + 2 {
                break;
            }
            let pos = usize::from(u16_at(d, j)?) * LIB_UNIT;
            positions.entry(pos).or_insert(j);
            j = k + 1;
        }
        if next == 0 {
            break;
        }
        let nb = next * LIB_UNIT;
        if blocks.contains(&nb) || nb <= blk {
            return Err(malformed(blk + 2, "dictionary blocks form a loop"));
        }
        blk = nb;
    }
    for (&pos, &entry) in &positions {
        if pos.saturating_add(HEADER_LEN) > d.len() {
            return Err(malformed(
                entry,
                format!("module position {pos:#x} past the end of the file"),
            ));
        }
    }
    let mut modules = Vec::new();
    let Some(&first) = positions.keys().next() else {
        return Ok(modules);
    };
    let mut i = first;
    while i.saturating_add(HEADER_LEN) <= d.len() {
        let magic = u16_at(d, i)?;
        if !matches!(magic, MAGIC_SMALL | MAGIC_LARGE) {
            // a dictionary block or padding between modules: go on at the next known module
            match positions.range(i + 1..).next() {
                Some((&p, _)) => {
                    i = p;
                    continue;
                }
                None => break,
            }
        }
        let (module, next) = read_module(d, i, file_name)?;
        let len = if next == 0 {
            d.len() - i
        } else {
            usize::from(next).min(d.len() - i)
        };
        modules.push((i, len, module));
        if next == 0 {
            break;
        }
        i += usize::from(next);
    }
    Ok(modules)
}
