//! Near calls and jumps the compiler resolved inside an object (no fixup).

/// Every position `k` with an `E8` (call near) or `E9` (jmp near) byte whose `bits / 8`-byte field fits in
/// `code`, as `(field offset, absolute target)`. The scan looks at every byte, not only at instruction starts,
/// exactly like Decomp's `_interne_aufrufe`; callers drop positions overlapping a fixup and targets that are
/// not a function of the same object. The target wraps at the field width.
pub fn internal_calls(code: &[u8], bits: u32, base: u64) -> Vec<(u32, u64)> {
    let width = match bits {
        16 => 2usize,
        32 => 4,
        _ => return Vec::new(),
    };
    let mask: u64 = (1u64 << (8 * width)) - 1;
    let mut out = Vec::new();
    for k in 0..code.len().saturating_sub(width) {
        if code[k] != 0xE8 && code[k] != 0xE9 {
            continue;
        }
        let field = k + 1;
        let raw = code[field..field + width]
            .iter()
            .rev()
            .fold(0u64, |a, &b| (a << 8) | u64::from(b));
        let value = if raw >> (8 * width - 1) != 0 {
            raw as i64 - (1i64 << (8 * width))
        } else {
            raw as i64
        };
        let target = (base as i64)
            .wrapping_add((field + width) as i64)
            .wrapping_add(value) as u64
            & mask;
        out.push((field as u32, target));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_call_and_jmp_targets() {
        // call +0 (to 5), nop, jmp -11 (to 0xFFFFFFFF... wraps)
        let code = [0xE8, 0, 0, 0, 0, 0x90, 0xE9, 0xF5, 0xFF, 0xFF, 0xFF, 0xC3];
        let calls = internal_calls(&code, 32, 0x100);
        assert_eq!(calls, vec![(1, 0x105), (7, 0x100)]);
    }

    #[test]
    fn field_must_fit() {
        assert!(internal_calls(&[0x90, 0xE8, 0, 0, 0], 32, 0).is_empty());
        assert!(internal_calls(&[0xE8, 0, 0, 0, 0], 64, 0).is_empty());
    }
}
