//! x86 decoding for decovery, built on iced-x86. All opcode knowledge of decovery lives in this crate.
//!
//! - [`decode`] / [`decode_detailed`]: one function's bytes as instructions, with Watcom alignment padding,
//!   jump tables and the operand fields that can carry an address (port of Decomp's `nachbau/befehle.py`
//!   `zerlege`).
//! - [`padding_positions`]: bytes of no-op padding behind an unconditional instruction (Decomp's `nop_fuellung`).
//! - [`internal_calls`]: every `E8`/`E9` near call/jump position with its target, for calls the compiler
//!   resolved inside the object without a fixup.
//!
//! Instructions are compared through a *shape* (see [`Decoded::shape`]): a syntax-independent normal form
//! built from the decoded operands (mnemonic with prefixes, register names, memory operand size, segment
//! override, base, index and scale, immediates and displacement-only addresses as `N`). It replaces Decomp's
//! capstone text with numbers masked, so the comparison does not depend on how a disassembler prints.

mod calls;
mod decode;

use std::collections::BTreeSet;

pub use calls::internal_calls;
pub use decode::{DecodeOptions, Decoded, DecodedKind, FieldRole, decode_detailed};

/// One decoded instruction (or padding run, jump table, undecodable byte) of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Instruction {
    /// Offset from the start of the decoded bytes.
    pub offset: u32,
    pub len: u8,
    /// Intel syntax text (padding, tables and undecodable bytes get a descriptive text).
    pub text: String,
    /// Alignment padding (no-op instructions behind an unconditional one, or a following function's table).
    pub padding: bool,
    /// Absolute target of a relative near branch (`jmp`, `jcc`, `call`, `loop`, …).
    pub near_branch: Option<u64>,
}

/// Decodes `code` (placed at `base`) in `bits`-bit mode (16 or 32; anything else yields no instructions).
pub fn decode(code: &[u8], bits: u32, base: u64) -> Vec<Instruction> {
    decode_detailed(code, bits, base, &DecodeOptions::default())
        .into_iter()
        .map(|d| Instruction {
            offset: d.offset,
            len: u8::try_from(d.len).unwrap_or(u8::MAX),
            padding: d.is_padding(),
            text: d.text,
            near_branch: d.near_branch,
        })
        .collect()
}

/// Positions belonging to no-op padding behind an unconditional instruction (Decomp's `nop_fuellung`).
pub fn padding_positions(code: &[u8], bits: u32) -> BTreeSet<u32> {
    decode_detailed(code, bits, 0, &DecodeOptions::default())
        .into_iter()
        .filter(Decoded::is_padding)
        .flat_map(|d| d.offset..d.offset + d.len)
        .collect()
}
