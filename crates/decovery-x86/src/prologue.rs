//! Prologue search with placeholder bytes and an optional resolved call target (port of Decomp's `prologe.py`).
//!
//! A pattern is hex text, spaces allowed, `??` for any byte. With a call target the last placeholders are the
//! displacement of a relative call (2 bytes in segmented code, 4 in flat code); a match counts only when that call
//! lands on an address the resolver names as the target. Aztec C86 (`+b`): `B8 ?? ?? E8 ?? ??` calling `$csav`
//! (`mov ax,-frame; call $csav`). For segmented addresses only segment and offset count: a call from an overlay into
//! the main program hits the same processor address, so the resolver gets the target as an address of the
//! overlay's kind and maps it itself.

use std::fmt;

use decovery_core::address::Address;

/// One byte of a [`ProloguePattern`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    Exact(u8),
    Any,
}

/// Prologue pattern: bytes with placeholders, optionally ending in a relative call to a named target.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProloguePattern {
    pub bytes: Vec<PatternByte>,
    /// Name the call at the end of the pattern must resolve to (e.g. `$csav`).
    pub call_target: Option<String>,
}

/// A pattern text that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError(pub String);

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PatternError {}

impl ProloguePattern {
    /// Parses hex text with `??` placeholders. With `call_target`, the last two bytes must be placeholders (the
    /// call displacement; flat code needs four, checked at match time).
    pub fn parse(text: &str, call_target: Option<&str>) -> Result<Self, PatternError> {
        let hex: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
        if hex.is_empty() || !hex.len().is_multiple_of(2) {
            return Err(PatternError(format!(
                "prologue pattern {text:?}: hex text of even length expected"
            )));
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.chunks(2) {
            let s: String = pair.iter().collect();
            if s == "??" {
                bytes.push(PatternByte::Any);
            } else {
                let b = u8::from_str_radix(&s, 16).map_err(|_| {
                    PatternError(format!(
                        "prologue pattern {text:?}: {s:?} is neither a hex byte nor ??"
                    ))
                })?;
                bytes.push(PatternByte::Exact(b));
            }
        }
        if call_target.is_some()
            && (bytes.len() < 3 || bytes[bytes.len() - 2..] != [PatternByte::Any; 2])
        {
            return Err(PatternError(format!(
                "prologue pattern {text:?}: with a call target the last bytes must be ??"
            )));
        }
        Ok(ProloguePattern {
            bytes,
            call_target: call_target.map(str::to_string),
        })
    }

    fn matches_at(&self, code: &[u8], at: usize) -> bool {
        code.get(at..at + self.bytes.len()).is_some_and(|window| {
            window.iter().zip(&self.bytes).all(|(b, p)| match p {
                PatternByte::Exact(e) => b == e,
                PatternByte::Any => true,
            })
        })
    }
}

/// Every position in `code` (placed at `base`) where `pattern` matches; overlapping matches count each. With a
/// call target, the call displacement at the end must lead to an address `resolve` names as that target.
pub fn find_prologues(
    code: &[u8],
    base: Address,
    pattern: &ProloguePattern,
    resolve: &dyn Fn(Address) -> Option<String>,
) -> Vec<Address> {
    let len = pattern.bytes.len();
    if len == 0 || code.len() < len {
        return Vec::new();
    }
    let mut out = Vec::new();
    for at in 0..=code.len() - len {
        if !pattern.matches_at(code, at) {
            continue;
        }
        let Ok(address) = base.offset_by(at as i64) else {
            continue; // past the end of the segment: not addressable
        };
        if let Some(target) = &pattern.call_target {
            let end = at + len;
            match call_destination(code, end, len, address) {
                Some(dest) if resolve(dest).as_deref() == Some(target.as_str()) => {}
                _ => continue,
            }
        }
        out.push(address);
    }
    out
}

/// Destination of the relative call whose displacement ends at `end` (the pattern's end, `len` bytes after
/// `address`): 16-bit wrap-around for segmented addresses, 32-bit for flat ones.
fn call_destination(code: &[u8], end: usize, len: usize, address: Address) -> Option<Address> {
    match address {
        Address::Flat(a) => {
            let disp = i32::from_le_bytes(code.get(end.checked_sub(4)?..end)?.try_into().ok()?);
            Some(Address::Flat(
                a.wrapping_add(len as u32).wrapping_add(disp as u32),
            ))
        }
        Address::Seg { seg, off } => Some(Address::Seg {
            seg,
            off: wrap16(code, end, len, off)?,
        }),
        Address::Ovl { overlay, seg, off } => Some(Address::Ovl {
            overlay,
            seg,
            off: wrap16(code, end, len, off)?,
        }),
        Address::Sel { segment, off } => {
            let disp = i16::from_le_bytes(code.get(end.checked_sub(2)?..end)?.try_into().ok()?);
            Some(Address::Sel {
                segment,
                off: off
                    .wrapping_add(len as u32)
                    .wrapping_add(i32::from(disp) as u32)
                    & 0xFFFF,
            })
        }
        _ => None,
    }
}

fn wrap16(code: &[u8], end: usize, len: usize, off: u16) -> Option<u16> {
    let disp = u16::from_le_bytes(code.get(end.checked_sub(2)?..end)?.try_into().ok()?);
    Some(off.wrapping_add(len as u16).wrapping_add(disp))
}

/// Targets of direct near calls (`call rel16`, `E8`) in 16-bit segmented code that are function starts.
///
/// Rule: `code` is decoded once linearly with [`crate::decode_detailed`], which already separates jump tables and
/// padding from instructions. A target counts only when the call itself decoded as code and the target is the
/// offset of an instruction decoded as code inside `code` — a target into the middle of an instruction, into a
/// jump table, into padding or outside the code range is dropped. Far calls are not followed (their segment is a
/// relocation, not known from the bytes). Flat and selector addresses give an empty list.
pub fn find_call_targets(code: &[u8], base: Address) -> Vec<Address> {
    let off = match base {
        Address::Seg { off, .. } | Address::Ovl { off, .. } => off,
        _ => return Vec::new(),
    };
    let decoded = crate::decode_detailed(code, 16, u64::from(off), &Default::default());
    let starts: std::collections::BTreeSet<u64> = decoded
        .iter()
        .filter(|d| d.kind == crate::DecodedKind::Code)
        .map(|d| u64::from(d.offset))
        .collect();
    let mut out: std::collections::BTreeSet<Address> = std::collections::BTreeSet::new();
    for d in &decoded {
        if d.kind != crate::DecodedKind::Code || d.mnemonic != "call" {
            continue;
        }
        let Some(target) = d.near_branch else {
            continue;
        };
        let Some(rel) = target.checked_sub(u64::from(off)) else {
            continue;
        };
        if rel >= code.len() as u64 || !starts.contains(&rel) {
            continue;
        }
        if let Ok(a) = base.offset_by(rel as i64) {
            out.insert(a);
        }
    }
    out.into_iter().collect()
}

/// Function starts: prologue matches ([`find_prologues`]) united with direct call targets
/// ([`find_call_targets`]) and the known `entries` (e.g. an overlay header's entry point) that lie inside `code`,
/// sorted and without duplicates.
pub fn find_function_starts(
    code: &[u8],
    base: Address,
    pattern: &ProloguePattern,
    resolve: &dyn Fn(Address) -> Option<String>,
    entries: &[Address],
) -> Vec<Address> {
    let mut all: std::collections::BTreeSet<Address> = find_prologues(code, base, pattern, resolve)
        .into_iter()
        .collect();
    all.extend(find_call_targets(code, base));
    all.extend(
        entries
            .iter()
            .filter(|e| e.bytes_from(base).is_some_and(|d| d < code.len() as u64)),
    );
    all.into_iter().collect()
}
