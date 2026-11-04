//! Object file readers. Phase 0 reads OMF (Turbo C, Watcom; 16 and 32 bit; `.OBJ` and `.LIB`).
//!
//! The model ([`ObjectModule`]: sections, symbols, relocations) is format-neutral. The
//! "function = public symbol in a code section" split is a derived view in [`functions`].

mod functions;
mod model;
mod omf;

pub use functions::{FunctionView, functions};
pub use model::{
    ObjReloc, ObjSymbol, ObjectError, ObjectFile, ObjectModule, RefTarget, Section, SectionKind,
};
pub use omf::read_omf;
