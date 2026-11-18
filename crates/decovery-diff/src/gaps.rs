//! Object against image with link gaps (phase 4, Aztec C86): there is no linker step, so a rebuilt function is
//! compared with the original image bytes directly, as Decomp's `vergleiche` does for Aztec objects.
//!
//! Every field the object relocates is a *link gap*: its bytes count as equal (`Metrics::gaps`). Bytes outside
//! the gaps must be equal. A self-relative field (near `call`/`jmp`) whose target lies in the function's own
//! section (an unnamed label, or a symbol of that section) is checked on top: the original's field must lead to
//! the same distance from the function start as the object's target. Self-relative fields to other targets
//! (externals) and absolute fields cannot be resolved without a linked program; they count as
//! `refs_unchecked` and do not block (there is no symbol view in this comparison).

use decovery_core::{Address, RelocKind};
use decovery_objects::{FunctionView, RefTarget};

use crate::{Blocker, Comparison, Metrics, Verdict};

fn signed(bytes: &[u8]) -> i64 {
    let raw = bytes
        .iter()
        .rev()
        .fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let bits = 8 * bytes.len() as u32;
    if bits > 0 && bits < 64 && raw >> (bits - 1) != 0 {
        raw as i64 - (1i64 << bits)
    } else {
        raw as i64
    }
}

/// Offset part of `at` and the width of its space in bits.
fn space(at: Address) -> Option<(i64, u32)> {
    match at {
        Address::Flat(a) => Some((i64::from(a), 32)),
        Address::Seg { off, .. } | Address::Ovl { off, .. } => Some((i64::from(off), 16)),
        Address::Sel { off, .. } => Some((i64::from(off), 32)),
        _ => None,
    }
}

fn wrap(value: i64, bits: u32) -> i64 {
    if bits >= 64 {
        value
    } else {
        value & ((1i64 << bits) - 1)
    }
}

/// Compare an object function against image bytes, masking fields the object relocates (link gaps).
///
/// `image` holds the original bytes starting at the function's original address `image_base`. Masked fields
/// count as equal and are counted in `Metrics::gaps`. An image shorter than the function is
/// [`Blocker::OriginalUnavailable`].
pub fn compare_with_gaps(object: &FunctionView, image: &[u8], image_base: Address) -> Comparison {
    let code = object.code();
    let len = u32::try_from(code.len()).unwrap_or(u32::MAX);
    let mut metrics = Metrics {
        bytes: len,
        ..Metrics::default()
    };
    let Some((base, bits)) = space(image_base).filter(|_| image.len() >= code.len()) else {
        return Comparison {
            verdict: Verdict::Unchecked,
            blockers: vec![Blocker::OriginalUnavailable],
            metrics,
            diagnoses: Vec::new(),
        };
    };
    let gaps = object.gaps();
    let mut blockers = Vec::new();
    for (k, (&a, &b)) in code.iter().zip(image).enumerate() {
        let k = k as u32;
        if gaps.contains(&k) {
            metrics.gaps += 1;
        } else if a == b {
            metrics.equal += 1;
        } else {
            metrics.differing += 1;
            metrics.first_difference.get_or_insert(k);
        }
    }
    if metrics.differing > 0 {
        blockers.push(Blocker::BytesDiffer {
            count: metrics.differing,
        });
    }
    for r in object.relocs() {
        let at = r.offset - object.start;
        let width = u32::from(r.width);
        let own_target = match &r.target {
            RefTarget::Section { index, offset } if *index == object.section => Some(*offset),
            RefTarget::Symbol(name) => object
                .module
                .symbols
                .iter()
                .find(|s| s.section == object.section && s.name == *name)
                .map(|s| s.offset),
            _ => None,
        };
        let field = image.get(at as usize..at.saturating_add(width) as usize);
        match (r.kind, own_target, field) {
            (RelocKind::Relative, Some(target), Some(field)) => {
                let original = wrap(
                    base + i64::from(at) + i64::from(width) + signed(field),
                    bits,
                );
                let expected = wrap(base + i64::from(target) - i64::from(object.start), bits);
                if original == expected {
                    metrics.refs_ok += 1;
                } else {
                    metrics.refs_wrong += 1;
                    blockers.push(Blocker::WrongRelativeRef { at });
                }
            }
            _ => metrics.refs_unchecked += 1,
        }
    }
    let verdict = if blockers.is_empty() {
        Verdict::Identical
    } else {
        Verdict::Differs
    };
    Comparison {
        verdict,
        blockers,
        metrics,
        diagnoses: Vec::new(),
    }
}
