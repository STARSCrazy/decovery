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
    /// Segment groups (OMF `GRPDEF`), e.g. `DGROUP`.
    pub groups: Vec<Group>,
    /// Program start address of a main module (OMF `MODEND`): section index and offset.
    pub start: Option<(u32, u32)>,
}

/// A segment group: the member sections share one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Group {
    pub name: String,
    /// Indices into [`ObjectModule::sections`].
    pub sections: Vec<u32>,
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
    /// The frame the fixup is relative to.
    pub frame: Frame,
}

/// The frame of a fixup (what a 16-bit offset is relative to).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame {
    /// Relative to a segment group (OMF frame method F1).
    Group(String),
    /// Relative to a section (F0); 0-based index like [`RefTarget::Section`].
    Section(u32),
    /// The frame of the target (F4, F5).
    Target,
    Unknown,
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
    /// A segment group (OMF target method T1), e.g. the selector of `mov dx, DGROUP`.
    Group(String),
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
    /// The writer cannot express the module.
    #[error("cannot write the object: {0}")]
    Unwritable(String),
}

impl ObjectModule {
    pub fn new(name: impl Into<String>, sections: Vec<Section>, symbols: Vec<ObjSymbol>) -> Self {
        ObjectModule {
            name: name.into(),
            sections,
            symbols,
            groups: Vec::new(),
            start: None,
        }
    }

    /// The first group that contains `section`.
    pub fn group_of(&self, section: u32) -> Option<&Group> {
        self.groups.iter().find(|g| g.sections.contains(&section))
    }
}

impl Group {
    pub fn new(name: impl Into<String>, sections: Vec<u32>) -> Self {
        Group {
            name: name.into(),
            sections,
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
    pub fn new(
        offset: u32,
        width: u8,
        kind: RelocKind,
        target: RefTarget,
        addend: i64,
        frame: Frame,
    ) -> Self {
        ObjReloc {
            offset,
            width,
            kind,
            target,
            addend,
            frame,
        }
    }
}
