//! Test-only Aztec C86 object writer (feature `test-writer`): builds objects and libraries from a small description
//! so public tests need no compiler output.

use crate::aztec::{
    DICT_BLOCK, F_GLOBAL, HEADER_LEN, LIB_UNIT, MAGIC_LIBRARY, MAGIC_SMALL, T_ABS, T_BSS, T_CODE,
    T_DATA, T_UNDEF,
};

/// Where a symbol lives (or that it is external / absolute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AztecSection {
    Code,
    Data,
    Bss,
    Extern,
    Absolute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AztecSymbolSpec {
    pub name: String,
    pub section: AztecSection,
    pub value: u16,
    pub public: bool,
}

/// The target of a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AztecTarget {
    /// Index into [`AztecModuleSpec::named`].
    Named(usize),
    /// Index into [`AztecModuleSpec::unnamed`].
    Unnamed(usize),
    /// A section position without a symbol (code, data or BSS reference item).
    Section(AztecSection, u16),
    /// The paragraph of the code or data segment.
    Paragraph(AztecSection),
    /// A plain number (the addend).
    Number,
}

/// A reference of `width` bytes at `offset` in `section` (code or data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AztecRefSpec {
    pub section: AztecSection,
    pub offset: u16,
    pub width: u8,
    pub relative: bool,
    pub target: AztecTarget,
    pub addend: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AztecModuleSpec {
    pub name: String,
    pub code: Vec<u8>,
    pub data: Vec<u8>,
    pub bss: u16,
    pub named: Vec<AztecSymbolSpec>,
    /// Unnamed symbols: section and offset.
    pub unnamed: Vec<(AztecSection, u16)>,
    pub refs: Vec<AztecRefSpec>,
    /// Emit debug and line items (the reader skips them).
    pub debug: bool,
    pub start: Option<(AztecSection, u16)>,
}

fn kind(s: AztecSection) -> u8 {
    match s {
        AztecSection::Code => T_CODE,
        AztecSection::Data => T_DATA,
        AztecSection::Bss => T_BSS,
        AztecSection::Extern => T_UNDEF,
        AztecSection::Absolute => T_ABS,
    }
}

fn int(out: &mut Vec<u8>, n: i32) {
    match n {
        0..=15 => out.push(0x30 | n as u8),
        -15..=-1 => out.push(0x40 | (-n) as u8),
        -2048..=2047 => out.extend([0x50 | (n & 0xF) as u8, ((n >> 4) + 0x80) as u8]),
        -32768..=32767 => {
            out.push(0xF3);
            out.extend((n as i16).to_le_bytes());
        }
        _ => {
            out.push(0xFC);
            out.extend(n.to_le_bytes());
        }
    }
}

fn twelve(out: &mut Vec<u8>, high: u8, v: usize) {
    out.extend([high | (v & 0xF) as u8, (v >> 4) as u8]);
}

fn operand(out: &mut Vec<u8>, target: AztecTarget, addend: i32) {
    let base = |out: &mut Vec<u8>| match target {
        AztecTarget::Named(i) => twelve(out, 0x70, i),
        AztecTarget::Unnamed(i) => twelve(out, 0x60, i),
        AztecTarget::Section(s, off) => {
            let (small, large) = match s {
                AztecSection::Code => (0xA0, 0xF7),
                AztecSection::Data => (0xB0, 0xF8),
                _ => (0xC0, 0xFB),
            };
            if off < 0x1000 {
                twelve(out, small, usize::from(off));
            } else {
                out.push(large);
                out.extend(off.to_le_bytes());
            }
        }
        AztecTarget::Paragraph(s) => out.push(if s == AztecSection::Code { 0xFE } else { 0xF0 }),
        AztecTarget::Number => {}
    };
    if target == AztecTarget::Number {
        int(out, addend);
    } else if addend == 0 {
        base(out);
    } else {
        out.push(0x21);
        base(out);
        int(out, addend);
    }
}

fn debug_items(out: &mut Vec<u8>) {
    out.push(0x0C);
    out.extend(b"T.C\0");
    out.extend([0x0D, 1, 0, 0xFF, 0x01, 0, 0]);
    out.push(0x02);
    out.extend(b"x\0");
    out.extend([0xFE, 0xFF]);
    out.extend(b"*i");
    out.push(0x04);
    out.extend(b"r\0");
    out.push(6);
    out.push(b'C');
    out.extend([0x08, 3, 0]);
    out.extend(b"[3[4l");
    out.push(0x09);
    out.extend(b"T\0:");
    out.extend([1, 0]);
    out.push(0x0A);
    out.extend(b"s\0");
    out.extend([0x0B, 1, 0, 2, 0, 4, 0]);
    out.push(0x01);
    out.extend(b"a\0");
    out.extend([0, 0]);
    out.extend(b"#c");
    out.push(0x02);
    out.extend(b"b\0");
    out.extend([2, 0, 0, 3]);
    out.push(b'I');
}

fn segment(out: &mut Vec<u8>, spec: &AztecModuleSpec, section: AztecSection) {
    let bytes = if section == AztecSection::Code {
        &spec.code
    } else {
        &spec.data
    };
    out.push(if section == AztecSection::Code {
        0xF4
    } else {
        0xF5
    });
    let mut refs: Vec<&AztecRefSpec> = spec.refs.iter().filter(|r| r.section == section).collect();
    refs.sort_by_key(|r| r.offset);
    let mut p = 0usize;
    let raw = |out: &mut Vec<u8>, from: usize, to: usize| {
        let mut k = from;
        while k < to {
            let zeros = bytes[k..to].iter().take_while(|&&b| b == 0).count();
            if zeros >= 6 {
                let n = zeros.min(0xFFF);
                twelve(out, 0x80, n);
                k += n;
                continue;
            }
            let n = (to - k).min(16);
            out.push(0x10 | (n - 1) as u8);
            out.extend(&bytes[k..k + n]);
            k += n;
        }
    };
    for r in refs {
        let at = usize::from(r.offset);
        raw(out, p, at);
        match (r.width, r.relative) {
            (1, false) => out.push(0xF1),
            (1, true) => out.push(0xF2),
            (2, true) => out.push(0xFA),
            (4, _) => out.push(0xFD),
            _ => {}
        }
        operand(out, r.target, r.addend);
        p = at + usize::from(r.width);
    }
    raw(out, p, bytes.len());
}

fn items(spec: &AztecModuleSpec) -> Vec<u8> {
    let mut out = Vec::new();
    if spec.debug {
        debug_items(&mut out);
    }
    segment(&mut out, spec, AztecSection::Code);
    segment(&mut out, spec, AztecSection::Data);
    if let Some((s, off)) = spec.start {
        out.push(0xF6);
        operand(&mut out, AztecTarget::Section(s, off), 0);
    }
    out.push(0x00);
    out
}

fn tables(spec: &AztecModuleSpec) -> (Vec<u8>, Vec<u8>) {
    let mut globals = Vec::new();
    for s in &spec.named {
        let flags = 0x40 | if s.public { F_GLOBAL } else { 0 };
        globals.extend([kind(s.section), flags]);
        globals.extend(s.value.to_le_bytes());
        globals.extend(s.name.as_bytes());
        globals.push(0);
    }
    let mut locals = Vec::new();
    for &(s, v) in &spec.unnamed {
        locals.extend([kind(s), 0x80]);
        locals.extend(v.to_le_bytes());
    }
    (globals, locals)
}

fn head(
    spec: &AztecModuleSpec,
    globals_at: usize,
    locals_at: usize,
    end: usize,
    next: usize,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend(MAGIC_SMALL.to_le_bytes());
    let mut name = [0u8; 8];
    for (d, s) in name.iter_mut().zip(spec.name.bytes()) {
        *d = s;
    }
    h.extend(name);
    for w in [
        spec.code.len(),
        spec.data.len(),
        usize::from(spec.bss),
        globals_at,
        spec.named.len(),
        locals_at,
        spec.unnamed.len(),
        end,
        next,
        0,
    ] {
        h.extend((w as u16).to_le_bytes());
    }
    h
}

/// An object file as the assembler writes it: header, load items, named symbols, unnamed symbols.
pub fn write_aztec(spec: &AztecModuleSpec) -> Vec<u8> {
    let items = items(spec);
    let (globals, locals) = tables(spec);
    let globals_at = HEADER_LEN + items.len();
    let locals_at = globals_at + globals.len();
    let end = locals_at + locals.len();
    let mut out = head(spec, globals_at, locals_at, end, 0);
    out.extend(items);
    out.extend(globals);
    out.extend(locals);
    out
}

/// A library as the librarian writes it: one dictionary block (each module's public symbols), then the modules
/// aligned to 128 bytes with their symbol tables in front of the load items.
pub fn write_aztec_library(modules: &[AztecModuleSpec]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut dict = Vec::new();
    for spec in modules {
        let pos = DICT_BLOCK + body.len();
        let items = items(spec);
        let (globals, locals) = tables(spec);
        let locals_at = HEADER_LEN + globals.len();
        let end = locals_at + locals.len();
        let next = (end + items.len()).div_ceil(LIB_UNIT) * LIB_UNIT;
        let mut m = head(spec, HEADER_LEN, locals_at, end, next);
        m.extend(globals);
        m.extend(locals);
        m.extend(items);
        m.resize(next, 0);
        body.extend(m);
        let mut names: Vec<&str> = spec
            .named
            .iter()
            .filter(|s| s.public && s.section != AztecSection::Extern)
            .map(|s| s.name.as_str())
            .collect();
        if names.is_empty() {
            names.push(&spec.name);
        }
        for n in names {
            dict.extend(((pos / LIB_UNIT) as u16).to_le_bytes());
            dict.extend(n.as_bytes());
            dict.push(0);
        }
    }
    let mut out = Vec::with_capacity(DICT_BLOCK + body.len());
    out.extend(MAGIC_LIBRARY.to_le_bytes());
    out.extend([0, 0]);
    out.extend(dict);
    out.resize(DICT_BLOCK, 0);
    out.extend(body);
    out
}
