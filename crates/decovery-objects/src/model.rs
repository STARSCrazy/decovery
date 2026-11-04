//! Format-neutral object model.

use std::collections::BTreeMap;

use decovery_core::RelocKind;

/// A parsed object file or library.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ObjectFile {
    pub modules: Vec<ObjectModule>,
    /// Record types the reader does not evaluate, with their counts.
    pub unknown_records: BTreeMap<u8, u32>,
}

/// One object module (a `.OBJ` has one, a `.LIB` many).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ObjectModule {
    pub name: String,
    pub sections: Vec<Section>,
    pub symbols: Vec<ObjSymbol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SectionKind {
    Code,
    Data,
    /// No initialised bytes in the file.
    Bss,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Section {
    pub name: String,
    pub class: String,
    pub kind: SectionKind,
    /// 16 or 32.
    pub bits: u8,
    /// Initialised bytes up to the highest written offset, raw (fixup fields keep their stored content).
    pub data: Vec<u8>,
    pub relocs: Vec<ObjReloc>,
}

/// A symbol defined in a section. `public` is false for local publics (static functions).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObjSymbol {
    pub name: String,
    /// Index into [`ObjectModule::sections`].
    pub section: u32,
    pub offset: u32,
    pub public: bool,
}

/// A fixup: the `width` bytes at `offset` in the section refer to `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObjReloc {
    pub offset: u32,
    pub width: u8,
    pub kind: RelocKind,
    pub target: RefTarget,
    /// Displacement of the fixup record for symbol and unknown targets (the field content is separate).
    pub addend: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefTarget {
    Symbol(String),
    /// Section start plus the fixup's displacement; the stored field content adds to it.
    Section {
        index: u32,
        offset: u32,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ObjectError {
    #[error("object file truncated at offset {offset:#x}")]
    Truncated { offset: u64 },
    #[error("bad record checksum at offset {offset:#x}")]
    BadChecksum { offset: u64 },
    #[error("malformed object file at offset {offset:#x}: {what}")]
    Malformed { offset: u64, what: String },
}

impl ObjectModule {
    pub fn new(name: impl Into<String>, sections: Vec<Section>, symbols: Vec<ObjSymbol>) -> Self {
        ObjectModule {
            name: name.into(),
            sections,
            symbols,
        }
    }
}

impl Section {
    pub fn new(
        name: impl Into<String>,
        class: impl Into<String>,
        kind: SectionKind,
        bits: u8,
        data: Vec<u8>,
        relocs: Vec<ObjReloc>,
    ) -> Self {
        Section {
            name: name.into(),
            class: class.into(),
            kind,
            bits,
            data,
            relocs,
        }
    }
}

impl ObjSymbol {
    pub fn new(name: impl Into<String>, section: u32, offset: u32, public: bool) -> Self {
        ObjSymbol {
            name: name.into(),
            section,
            offset,
            public,
        }
    }
}

impl ObjReloc {
    pub fn new(offset: u32, width: u8, kind: RelocKind, target: RefTarget, addend: i64) -> Self {
        ObjReloc {
            offset,
            width,
            kind,
            target,
            addend,
        }
    }
}
