//! Structured decoding of one function (port of Decomp's `zerlege` / `_zerlege` in `nachbau/befehle.py`).

use std::collections::BTreeSet;

use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction as IcedInstruction, IntelFormatter, Mnemonic,
    OpKind, Register,
};

/// Inputs of [`decode_detailed`] besides the bytes.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DecodeOptions {
    /// Bytes (relative to the start) a linker fills in later (relocated fields).
    pub gaps: BTreeSet<u32>,
    /// Runs of 1–3 `00` or `90` bytes behind an unconditional instruction (up to 7 at the very end) count as
    /// padding (Decomp's `fuellung`, for assemblers that align with zeros).
    pub byte_padding: bool,
}

impl DecodeOptions {
    pub fn new(gaps: BTreeSet<u32>, byte_padding: bool) -> Self {
        DecodeOptions { gaps, byte_padding }
    }
}

/// What a decoded item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodedKind {
    Code,
    /// Alignment padding (no-op instructions, `00`/`90` runs).
    Padding,
    /// Jump table of this function (`entries` pointers of the address width).
    JumpTable {
        entries: u32,
    },
    /// Jump table of the *following* function hanging at the end of this one (only fixups, then padding);
    /// counts as padding.
    ForeignJumpTable {
        entries: u32,
    },
    /// A byte that does not decode.
    Invalid,
}

/// Operand field that can carry an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FieldRole {
    /// Displacement of the memory operand.
    Displacement,
    /// Immediate.
    Immediate,
}

/// One decoded item.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decoded {
    pub offset: u32,
    pub len: u32,
    pub kind: DecodedKind,
    /// Lowercase mnemonic with `rep`/`repne`/`lock` prefixes (`dd`/`dw` for jump tables, `db` for bytes,
    /// empty for padding).
    pub mnemonic: String,
    /// Syntax-independent comparison form: mnemonic and operands with immediates, branch targets and memory
    /// displacements masked (a displacement-only address becomes `[N]`). Empty for padding.
    pub shape: String,
    /// Intel syntax text for display.
    pub text: String,
    /// Absolute target of a relative near branch with an immediate target.
    pub near_branch: Option<u64>,
    /// Memory-indirect `jmp` (`jmp [table + reg*4]`).
    pub indirect_jmp: bool,
    /// Fields of the address width: role, offset inside the instruction, size.
    pub fields: Vec<(FieldRole, u32, u32)>,
}

impl Decoded {
    pub fn is_padding(&self) -> bool {
        matches!(
            self.kind,
            DecodedKind::Padding | DecodedKind::ForeignJumpTable { .. }
        )
    }

    fn unconditional(&self) -> bool {
        matches!(
            self.mnemonic.as_str(),
            "jmp" | "ret" | "retf" | "iret" | "iretd" | "iretq"
        )
    }
}

/// Decodes `code` placed at `base`. Port of Decomp's `zerlege` (structure only; naming of targets and data
/// is the caller's job): passes repeat while new jump tables are found before their `jmp` or a branch target
/// falls into what was taken for padding.
pub fn decode_detailed(code: &[u8], bits: u32, base: u64, options: &DecodeOptions) -> Vec<Decoded> {
    if bits != 16 && bits != 32 {
        return Vec::new();
    }
    let mut tables = BTreeSet::new();
    let mut branch_targets = BTreeSet::new();
    // Each pass can only add offsets inside `code`, so the loop ends after at most 2 * len + 1 passes.
    loop {
        let (out, found) = pass(code, bits, base, options, &tables, &branch_targets);
        let targets: BTreeSet<u32> = out
            .iter()
            .filter_map(|d| internal_target(d, code.len(), base, &options.gaps))
            .collect();
        let in_padding: BTreeSet<u32> = targets
            .into_iter()
            .filter(|&t| {
                out.iter()
                    .any(|d| d.is_padding() && d.offset <= t && t < d.offset + d.len)
            })
            .collect();
        if found.is_subset(&tables) && in_padding.is_subset(&branch_targets) {
            return out;
        }
        tables.extend(found);
        branch_targets.extend(in_padding);
    }
}

/// Target offset of a branch that stays inside the function and carries no fixup.
pub(crate) fn internal_target(
    d: &Decoded,
    len: usize,
    base: u64,
    gaps: &BTreeSet<u32>,
) -> Option<u32> {
    let t = d.near_branch?;
    if gaps.range(d.offset..d.offset + d.len).next().is_some() {
        return None;
    }
    (t >= base && t - base < len as u64).then(|| (t - base) as u32)
}

fn read_uint(code: &[u8], at: usize, width: usize) -> u64 {
    code[at..at + width]
        .iter()
        .rev()
        .fold(0u64, |a, &b| (a << 8) | u64::from(b))
}

fn decode_one(
    code: &[u8],
    k: usize,
    bits: u32,
    base: u64,
) -> Option<(IcedInstruction, Decoder<'_>)> {
    let end = (k + 16).min(code.len());
    let mut decoder = Decoder::try_with_ip(
        bits,
        &code[k..end],
        base.wrapping_add(k as u64),
        DecoderOptions::NONE,
    )
    .ok()?;
    let instruction = decoder.decode();
    (!instruction.is_invalid()).then_some((instruction, decoder))
}

/// No-op as Watcom writes it for alignment: `nop`, `mov r,r`, `lea r,[r]` (no index, displacement 0, no segment).
fn nop_like(i: &IcedInstruction) -> bool {
    match i.mnemonic() {
        Mnemonic::Nop => true,
        Mnemonic::Mov => {
            i.op_count() == 2
                && i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Register
                && i.op0_register() == i.op1_register()
        }
        Mnemonic::Lea => {
            i.op_count() == 2
                && i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Memory
                && i.memory_base() == i.op0_register()
                && i.memory_index() == Register::None
                && i.memory_displacement64() == 0
                && i.segment_prefix() == Register::None
        }
        _ => false,
    }
}

/// `rest` is empty or only alignment (`00`/`90` bytes or no-op instructions).
fn only_padding(rest: &[u8], bits: u32) -> bool {
    if rest.iter().all(|&b| b == 0x00 || b == 0x90) {
        return true;
    }
    let mut k = 0;
    while k < rest.len() {
        match decode_one(rest, k, bits, 0) {
            Some((i, _)) if nop_like(&i) => k += i.len(),
            _ => return false,
        }
    }
    true
}

fn lower<T: std::fmt::Debug>(value: T) -> String {
    format!("{value:?}").to_lowercase()
}

fn mnemonic_of(i: &IcedInstruction) -> String {
    let mut m = String::new();
    if i.has_lock_prefix() {
        m.push_str("lock ");
    }
    if i.has_rep_prefix() {
        m.push_str("rep ");
    } else if i.has_repne_prefix() {
        m.push_str("repne ");
    }
    m.push_str(&lower(i.mnemonic()));
    m
}

fn is_relative_branch(i: &IcedInstruction) -> bool {
    i.op_count() >= 1
        && matches!(
            i.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
}

fn shape_of(i: &IcedInstruction, mnemonic: &str) -> String {
    if is_relative_branch(i) {
        return format!("{mnemonic} N");
    }
    let operands: Vec<String> = (0..i.op_count())
        .map(|n| match i.op_kind(n) {
            OpKind::Register => lower(i.op_register(n)),
            OpKind::Memory => {
                let mut s = format!("m{} ", i.memory_size().size());
                if i.segment_prefix() != Register::None {
                    s.push_str(&lower(i.segment_prefix()));
                    s.push(':');
                }
                let base = i.memory_base();
                let index = i.memory_index();
                if base == Register::None && index == Register::None {
                    s.push_str("[N]");
                } else {
                    s.push('[');
                    if base != Register::None {
                        s.push_str(&lower(base));
                    }
                    if index != Register::None {
                        if base != Register::None {
                            s.push('+');
                        }
                        s.push_str(&format!("{}*{}", lower(index), i.memory_index_scale()));
                    }
                    s.push(']');
                }
                s
            }
            OpKind::FarBranch16 | OpKind::FarBranch32 => "N:N".to_string(),
            OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI => format!("m{} {}", i.memory_size().size(), lower(i.op_kind(n))),
            _ => "N".to_string(),
        })
        .collect();
    if operands.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {}", operands.join(", "))
    }
}

fn text_of(i: &IcedInstruction) -> String {
    let mut formatter = IntelFormatter::new();
    let mut out = String::new();
    formatter.format(i, &mut out);
    out
}

fn item(
    offset: usize,
    len: usize,
    kind: DecodedKind,
    mnemonic: &str,
    shape: String,
    text: String,
) -> Decoded {
    Decoded {
        offset: offset as u32,
        len: len as u32,
        kind,
        mnemonic: mnemonic.to_string(),
        shape,
        text,
        near_branch: None,
        indirect_jmp: false,
        fields: Vec::new(),
    }
}

/// One pass; returns the items and the starts of jump tables found (`jmp [reg + table]` into the function).
fn pass(
    code: &[u8],
    bits: u32,
    base: u64,
    options: &DecodeOptions,
    tables: &BTreeSet<u32>,
    branch_targets: &BTreeSet<u32>,
) -> (Vec<Decoded>, BTreeSet<u32>) {
    let width = (bits / 8) as usize;
    let gaps = &options.gaps;
    let gap = |p: usize| gaps.contains(&(p as u32));
    let table_mnemonic = if width == 2 { "dw" } else { "dd" };
    let n = code.len();
    let mut out: Vec<Decoded> = Vec::new();
    let mut found = BTreeSet::new();
    let mut k = 0usize;
    while k < n {
        if tables.contains(&(k as u32)) {
            // Entries while they point into the function or the linker fills them. The table ends at the first
            // target behind it (code starts there); a target inside the table itself is no entry any more.
            let (mut end, mut limit) = (k, n);
            while end + width <= limit
                && end - k < 256 * width
                && (end == k || !tables.contains(&(end as u32)))
            {
                let value = read_uint(code, end, width);
                if !gap(end) {
                    let inside = value >= base && value - base < n as u64;
                    if !inside {
                        break;
                    }
                    let rel = value - base;
                    if (k as u64) <= rel && rel < (end + width) as u64 {
                        break;
                    }
                    if rel > k as u64 {
                        limit = limit.min(rel as usize);
                    }
                }
                end += width;
            }
            if end > k {
                let entries = ((end - k) / width) as u32;
                out.push(item(
                    k,
                    end - k,
                    DecodedKind::JumpTable { entries },
                    table_mnemonic,
                    format!("{table_mnemonic} table {entries}"),
                    format!("{table_mnemonic} jump table, {entries} entries"),
                ));
                k = end;
                continue;
            }
        }
        let after_unconditional = out.last().is_some_and(|d| d.unconditional());
        let after_stop = out
            .last()
            .is_some_and(|d| d.unconditional() || d.is_padding());
        if gap(k) && !found.contains(&(k as u32)) && after_stop {
            // Watcom puts a function's jump table before its start; in the rebuild it hangs at the previous
            // function (only fixups up to the end, at most padding behind). The original does not see it there.
            let mut end = k;
            while end + width <= n && gap(end) {
                end += width;
            }
            if end > k && only_padding(&code[end..], bits) {
                let entries = ((end - k) / width) as u32;
                out.push(item(
                    k,
                    end - k,
                    DecodedKind::ForeignJumpTable { entries },
                    table_mnemonic,
                    String::new(),
                    format!(
                        "{table_mnemonic} jump table of the following function, {entries} entries"
                    ),
                ));
                k = end;
                continue;
            }
        }
        if options.byte_padding && after_unconditional {
            let mut end = k;
            while end < n && (code[end] == 0x00 || code[end] == 0x90) && code[end] == code[k] {
                end += 1;
            }
            if end > k && (end - k <= 3 || (end == n && end - k <= 7)) {
                out.push(item(
                    k,
                    end - k,
                    DecodedKind::Padding,
                    "",
                    String::new(),
                    format!("(padding {} bytes)", end - k),
                ));
                k = end;
                continue;
            }
        }
        let Some((i, decoder)) = decode_one(code, k, bits, base) else {
            out.push(item(
                k,
                1,
                DecodedKind::Invalid,
                "db",
                format!("db {:#04x}", code[k]),
                format!("db {:#04x}", code[k]),
            ));
            k += 1;
            continue;
        };
        let size = i.len();
        let has_gap = (k..k + size).any(gap);
        if bits == 32
            && !branch_targets.contains(&(k as u32))
            && after_stop
            && nop_like(&i)
            && !has_gap
        {
            out.push(item(
                k,
                size,
                DecodedKind::Padding,
                "",
                String::new(),
                format!("({})", text_of(&i)),
            ));
            k += size;
            continue;
        }
        let mnemonic = mnemonic_of(&i);
        let mut d = item(
            k,
            size,
            DecodedKind::Code,
            &mnemonic,
            shape_of(&i, &mnemonic),
            text_of(&i),
        );
        if is_relative_branch(&i) {
            d.near_branch = Some(i.near_branch_target());
        } else {
            if i.mnemonic() == Mnemonic::Jmp && i.op0_kind() == OpKind::Memory {
                d.indirect_jmp = true;
                let indexed =
                    i.memory_base() != Register::None || i.memory_index() != Register::None;
                if indexed && has_gap {
                    // The linker fills in the table address: the table follows directly (after alignment).
                    let behind = k + size;
                    let start = (behind..behind + 4).find(|&j| gap(j)).unwrap_or(behind);
                    found.insert(start as u32);
                } else if indexed {
                    let disp = if bits == 16 {
                        i.memory_displacement64() & 0xFFFF
                    } else {
                        i.memory_displacement64() & 0xFFFF_FFFF
                    };
                    if disp >= base && disp - base < n as u64 {
                        found.insert((disp - base) as u32);
                    }
                }
            }
            let offsets = decoder.get_constant_offsets(&i);
            if offsets.has_displacement() && offsets.displacement_size() == width {
                d.fields.push((
                    FieldRole::Displacement,
                    offsets.displacement_offset() as u32,
                    width as u32,
                ));
            }
            if offsets.has_immediate() && offsets.immediate_size() == width {
                d.fields.push((
                    FieldRole::Immediate,
                    offsets.immediate_offset() as u32,
                    width as u32,
                ));
            }
        }
        out.push(d);
        k += size;
    }
    (out, found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(code: &[u8]) -> Vec<Decoded> {
        decode_detailed(code, 32, 0x1000, &DecodeOptions::default())
    }

    #[test]
    fn padding_after_ret() {
        let d = decode(&[0xC3, 0x90, 0x8B, 0xC0, 0x8D, 0x40, 0x00]);
        let kinds: Vec<_> = d.iter().map(|x| x.kind).collect();
        assert_eq!(
            kinds,
            vec![
                DecodedKind::Code,
                DecodedKind::Padding,
                DecodedKind::Padding,
                DecodedKind::Padding
            ]
        );
    }

    #[test]
    fn branch_target_in_padding_is_code() {
        // jmp +1 (to the nop at 3), ret, nop
        let d = decode(&[0xEB, 0x01, 0xC3, 0x90]);
        assert_eq!(d.last().unwrap().kind, DecodedKind::Code);
        assert_eq!(d[0].near_branch, Some(0x1003));
    }

    #[test]
    fn shape_masks_numbers() {
        let a = decode(&[0x8B, 0x45, 0xFC]); // mov eax,[ebp-4]
        let b = decode(&[0x8B, 0x45, 0xF8]); // mov eax,[ebp-8]
        assert_eq!(a[0].shape, b[0].shape);
        let c = decode(&[0xA1, 0x10, 0x20, 0x30, 0x00]); // mov eax,[302010]
        assert_eq!(c[0].shape, "mov eax, m4 [N]");
        assert_eq!(c[0].fields, vec![(FieldRole::Displacement, 1, 4)]);
    }

    #[test]
    fn jump_table_after_indirect_jmp() {
        // jmp [eax*4 + 0x1008]; nop; table of two entries pointing at 0x1010 (ret)
        let mut code = vec![0xFF, 0x24, 0x85, 0x08, 0x10, 0x00, 0x00, 0x90];
        code.extend_from_slice(&0x1010u32.to_le_bytes());
        code.extend_from_slice(&0x1010u32.to_le_bytes());
        code.push(0xC3);
        let d = decode(&code);
        assert!(
            d.iter()
                .any(|x| x.kind == DecodedKind::JumpTable { entries: 2 } && x.offset == 8)
        );
    }

    #[test]
    fn invalid_byte_and_bad_bits() {
        let d = decode(&[0x0F]);
        assert_eq!(d[0].kind, DecodedKind::Invalid);
        assert!(decode_detailed(&[0x90], 64, 0, &DecodeOptions::default()).is_empty());
        assert!(decode(&[]).is_empty());
    }
}
