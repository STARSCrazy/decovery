//! Object file readers: OMF (Turbo C, Watcom; 16 and 32 bit; `.OBJ` and `.LIB`) and Manx Aztec C86 (`.O`, `.LIB`;
//! ADR 0012), behind the format-neutral [`read_object`]. A 32-bit OMF writer ([`write_omf_module`]) hands whole
//! programs to a linker.
//!
//! The model ([`ObjectModule`]: sections, symbols, relocations) is format-neutral. The
//! "function = public symbol in a code section" split is a derived view in [`functions`].

mod aztec;
#[cfg(feature = "test-writer")]
mod aztec_write;
mod functions;
mod model;
mod omf;
mod omf_write;

pub use aztec::read_aztec;
#[cfg(feature = "test-writer")]
pub use aztec_write::{
    AztecModuleSpec, AztecRefSpec, AztecSection, AztecSymbolSpec, AztecTarget, write_aztec,
    write_aztec_library,
};
pub use functions::{FunctionView, functions, public_functions};
pub use model::{
    Frame, Group, ObjReloc, ObjSymbol, ObjectError, ObjectFile, ObjectModule, RefTarget, Section,
    SectionKind,
};
pub use omf::read_omf;
pub use omf_write::{
    WriteFixup, WriteFixupKind, WriteModule, WriteSegment, write_omf, write_omf_module,
};

/// Format of the objects a compiler writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ObjectFormat {
    Omf,
    /// Manx Aztec C86 objects (`.O`) and libraries.
    Aztec,
}

/// Reads an object file or library of the given format. `file_name` names a module that carries no name.
pub fn read_object(
    format: ObjectFormat,
    bytes: &[u8],
    file_name: &str,
) -> Result<ObjectFile, ObjectError> {
    match format {
        ObjectFormat::Omf => read_omf(bytes, file_name),
        ObjectFormat::Aztec => read_aztec(bytes, file_name),
    }
}
