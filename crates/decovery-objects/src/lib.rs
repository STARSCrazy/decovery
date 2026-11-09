//! Object file readers. Phase 0 reads OMF (Turbo C, Watcom; 16 and 32 bit; `.OBJ` and `.LIB`); a 32-bit OMF
//! writer ([`write_omf_module`]) hands whole programs to a linker.
//!
//! The model ([`ObjectModule`]: sections, symbols, relocations) is format-neutral. The
//! "function = public symbol in a code section" split is a derived view in [`functions`].

mod functions;
mod model;
mod omf;
mod omf_write;

pub use functions::{FunctionView, functions};
pub use model::{
    Frame, Group, ObjReloc, ObjSymbol, ObjectError, ObjectFile, ObjectModule, RefTarget, Section,
    SectionKind,
};
pub use omf::read_omf;
pub use omf_write::{
    WriteFixup, WriteFixupKind, WriteModule, WriteSegment, write_omf, write_omf_module,
};
