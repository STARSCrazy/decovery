//! Instruction comparison (port of Decomp's `vergleiche_befehle` with the naming parts of `zerlege`).
//!
//! Both sides are decoded by `decovery_x86`; sequences are aligned on the syntax-independent shape with
//! minimum cost (same shape 0, same mnemonic 1, otherwise 5 like a missing or extra instruction; conditional
//! jumps count as one mnemonic), or with a difflib-style matcher for very large functions. Each aligned pair is
//! judged exactly: branches by target (paired offset inside the function, name outside), data references by
//! name and addend against the original's address, everything else by bytes outside relocated fields.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use decovery_x86::{DecodeOptions, Decoded, DecodedKind, FieldRole, decode_detailed};

use crate::pairs::{Pair, PairKind};
use crate::sequence::{Op, opcodes};

/// Cells of the cost table above which the difflib-style alignment is used (Decomp's `_AUSRICHTEN_MAX`).
const ALIGN_MAX: usize = 2_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Internal(u32),
    External(Option<String>),
}

#[derive(Debug, Clone)]
struct Insn {
    /// The decoded instruction; handed on in the [`Pair`]s.
    d: Decoded,
    raw: Vec<u8>,
    table: bool,
    target: Option<Target>,
    /// Relocated byte positions inside the instruction.
    gaps: BTreeSet<u32>,
    /// Rebuild: named data references per field role (name, addend).
    refs: Vec<(FieldRole, String, i64)>,
    /// Original: address in a field per role, with its known names `(name, distance)`.
    addresses: Vec<(FieldRole, u64, Names)>,
}

/// Known names of an address: `(name, distance)`.
type Names = Vec<(String, i64)>;

/// How to name things while decoding one side.
pub(crate) struct Naming<'a> {
    /// Fixup start (relative to the function) → name (rebuild only).
    pub names: &'a BTreeMap<u32, String>,
    /// Displacement of the fixup record per fixup start (rebuild only).
    pub addends: &'a BTreeMap<u32, i64>,
    /// Name of an absolute branch target outside the function.
    pub target_name: &'a dyn Fn(u64) -> Option<String>,
    /// Known names of a data address (original only); `None` disables data naming.
    pub data_names: Option<&'a dyn Fn(u64) -> Vec<(String, i64)>>,
}

fn read_uint(code: &[u8], at: usize, n: usize) -> Option<u64> {
    code.get(at..at.checked_add(n)?)
        .map(|s| s.iter().rev().fold(0u64, |a, &b| (a << 8) | u64::from(b)))
}

/// Field content plus the record displacement, signed in the field width (Decomp's `_zusatz`).
fn addend(code: &[u8], at: usize, n: usize, shift: i64) -> i64 {
    let bits = 8 * n as u32;
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let value = read_uint(code, at, n)
        .unwrap_or(0)
        .wrapping_add(shift as u64)
        & mask;
    if bits > 0 && bits < 64 && value >> (bits - 1) != 0 {
        value as i64 - (1i64 << bits)
    } else {
        value as i64
    }
}

fn build(
    code: &[u8],
    bits: u32,
    base: u64,
    gaps: &BTreeSet<u32>,
    byte_padding: bool,
    naming: &Naming<'_>,
) -> Vec<Insn> {
    let decoded = decode_detailed(
        code,
        bits,
        base,
        &DecodeOptions::new(gaps.clone(), byte_padding),
    );
    decoded
        .into_iter()
        .filter(|d| !d.is_padding())
        .map(|d| insn(code, base, gaps, naming, d))
        .collect()
}

fn insn(code: &[u8], base: u64, gaps: &BTreeSet<u32>, naming: &Naming<'_>, d: Decoded) -> Insn {
    let k = d.offset;
    let end = k + d.len;
    let inner: BTreeSet<u32> = gaps.range(k..end).map(|&p| p - k).collect();
    let target = d.near_branch.map(|t| {
        if !inner.is_empty() {
            Target::External(naming.names.range(k..end).next().map(|(_, n)| n.clone()))
        } else if t >= base && t - base < code.len() as u64 {
            Target::Internal((t - base) as u32)
        } else {
            Target::External((naming.target_name)(t))
        }
    });
    let mut refs = Vec::new();
    let mut addresses = Vec::new();
    if target.is_none() {
        if !inner.is_empty() {
            for &(role, st, n) in &d.fields {
                let at = k + st;
                if let Some(name) = naming.names.get(&at) {
                    let shift = naming.addends.get(&at).copied().unwrap_or(0);
                    refs.push((
                        role,
                        name.clone(),
                        addend(code, at as usize, n as usize, shift),
                    ));
                }
            }
        } else if let Some(data_names) = naming.data_names {
            for &(role, st, n) in &d.fields {
                let t = read_uint(code, (k + st) as usize, n as usize).unwrap_or(0);
                if t != 0 {
                    addresses.push((role, t, data_names(t)));
                }
            }
        }
    }
    Insn {
        raw: code.get(k as usize..end as usize).unwrap_or(&[]).to_vec(),
        table: matches!(d.kind, DecodedKind::JumpTable { .. }),
        d,
        target,
        gaps: inner,
        refs,
        addresses,
    }
}

fn bytes_equal(nb: &Insn, og: &Insn) -> bool {
    nb.raw.len() == og.raw.len()
        && nb
            .raw
            .iter()
            .zip(&og.raw)
            .enumerate()
            .all(|(k, (a, b))| a == b || nb.gaps.contains(&(k as u32)))
}

/// Decomp's `_verweise_passen` without the display hints.
fn refs_match(nb: &Insn, og: &Insn, data_address: &dyn Fn(&str) -> Option<u64>) -> bool {
    for (role, name, add) in &nb.refs {
        let Some((t, names)) = og
            .addresses
            .iter()
            .find(|(r, _, _)| r == role)
            .map(|(_, t, n)| (*t, n))
        else {
            continue;
        };
        if names.iter().any(|(n, d)| n == name && d == add) {
            continue;
        }
        match data_address(name) {
            None => {
                if !names.is_empty() && *add == 0 {
                    return false;
                }
            }
            Some(a) => {
                if (a as i64).wrapping_add(*add) as u64 & 0xFFFF_FFFF != t {
                    return false;
                }
            }
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Judgement {
    Equal,
    Form,
    Different,
}

fn judge(
    nb: &Insn,
    og: &Insn,
    pairing: &HashMap<u32, u32>,
    data_address: &dyn Fn(&str) -> Option<u64>,
) -> Judgement {
    if nb.d.shape != og.d.shape {
        return Judgement::Different;
    }
    if nb.table {
        return Judgement::Equal;
    }
    if nb.target.is_some() || og.target.is_some() {
        let ok = match (&nb.target, &og.target) {
            (Some(Target::Internal(a)), Some(Target::Internal(b))) => pairing.get(a) == Some(b),
            (Some(Target::External(a)), Some(Target::External(b))) => {
                a.is_none() || b.is_none() || a == b
            }
            _ => false,
        };
        if !ok {
            return Judgement::Different;
        }
        return if nb.raw.len() == og.raw.len() {
            Judgement::Equal
        } else {
            Judgement::Form
        };
    }
    if !refs_match(nb, og, data_address) {
        return Judgement::Different;
    }
    if bytes_equal(nb, og) {
        Judgement::Equal
    } else {
        Judgement::Different
    }
}

fn mnemonic_class(m: &str) -> &str {
    if m.starts_with('j') && m != "jmp" {
        "jcc"
    } else {
        m
    }
}

type Pairs = Vec<(Option<usize>, Option<usize>)>;

/// Minimum-cost alignment (Decomp's `_ausrichten`); `None` when the table would be too large.
fn align(a: &[Insn], b: &[Insn]) -> Option<Pairs> {
    let common = a.len().min(b.len());
    let mut front = 0;
    while front < common && a[front].d.shape == b[front].d.shape {
        front += 1;
    }
    let mut back = 0;
    while back < common - front && a[a.len() - 1 - back].d.shape == b[b.len() - 1 - back].d.shape {
        back += 1;
    }
    let xa = &a[front..a.len() - back];
    let xb = &b[front..b.len() - back];
    let (n, m) = (xa.len(), xb.len());
    if (n + 1).saturating_mul(m + 1) > ALIGN_MAX {
        return None;
    }
    let ma: Vec<&str> = xa.iter().map(|x| mnemonic_class(&x.d.mnemonic)).collect();
    let mb: Vec<&str> = xb.iter().map(|x| mnemonic_class(&x.d.mnemonic)).collect();
    // way: 0 diagonal, 1 rebuild only (up), 2 original only (left)
    let mut way = vec![vec![0u8; m + 1]; n + 1];
    let mut prev: Vec<u64> = (0..=m as u64).map(|j| 5 * j).collect();
    for cell in way[0].iter_mut().skip(1) {
        *cell = 2;
    }
    for i in 1..=n {
        let mut cur = vec![0u64; m + 1];
        cur[0] = 5 * i as u64;
        way[i][0] = 1;
        for j in 1..=m {
            let step = if xa[i - 1].d.shape == xb[j - 1].d.shape {
                0
            } else if ma[i - 1] == mb[j - 1] {
                1
            } else {
                5
            };
            let d = prev[j - 1] + step;
            let o = prev[j] + 5;
            let l = cur[j - 1] + 5;
            if d <= o && d <= l {
                cur[j] = d;
            } else if o <= l {
                cur[j] = o;
                way[i][j] = 1;
            } else {
                cur[j] = l;
                way[i][j] = 2;
            }
        }
        prev = cur;
    }
    let mut middle = Vec::new();
    let (mut i, mut j) = (n, m);
    while i > 0 || j > 0 {
        match way[i][j] {
            0 => {
                i -= 1;
                j -= 1;
                middle.push((Some(front + i), Some(front + j)));
            }
            1 => {
                i -= 1;
                middle.push((Some(front + i), None));
            }
            _ => {
                j -= 1;
                middle.push((None, Some(front + j)));
            }
        }
    }
    middle.reverse();
    let mut out: Pairs = (0..front).map(|k| (Some(k), Some(k))).collect();
    out.extend(middle);
    out.extend((0..back).map(|k| (Some(a.len() - back + k), Some(b.len() - back + k))));
    Some(out)
}

fn align_difflib(a: &[Insn], b: &[Insn]) -> Pairs {
    let mut ids: HashMap<&str, u32> = HashMap::new();
    for x in a.iter().chain(b) {
        let next = ids.len() as u32;
        ids.entry(x.d.shape.as_str()).or_insert(next);
    }
    let sa: Vec<u32> = a.iter().map(|x| ids[x.d.shape.as_str()]).collect();
    let sb: Vec<u32> = b.iter().map(|x| ids[x.d.shape.as_str()]).collect();
    let mut out = Pairs::new();
    for (op, i1, i2, j1, j2) in opcodes(&sa, &sb) {
        match op {
            Op::Equal => out.extend((i1..i2).zip(j1..j2).map(|(i, j)| (Some(i), Some(j)))),
            Op::Replace => {
                let n = (i2 - i1).min(j2 - j1);
                out.extend((0..n).map(|k| (Some(i1 + k), Some(j1 + k))));
                out.extend((i1 + n..i2).map(|i| (Some(i), None)));
                out.extend((j1 + n..j2).map(|j| (None, Some(j))));
            }
            Op::Delete => out.extend((i1..i2).map(|i| (Some(i), None))),
            Op::Insert => out.extend((j1..j2).map(|j| (None, Some(j)))),
        }
    }
    out
}

/// One side of the instruction comparison.
pub(crate) struct Side<'a> {
    pub code: &'a [u8],
    pub base: u64,
    pub gaps: &'a BTreeSet<u32>,
    pub naming: Naming<'a>,
}

/// Which pairs [`pairs`] hands back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keep {
    Always,
    /// Only when some pair is not [`PairKind::Equal`] (what a diagnosis needs).
    IfNotEqual,
    Never,
}

/// The instruction comparison of both sides (Decomp's `vergleiche_befehle`): the number of differing pairs
/// (Decomp's `Befehlsvergleich.abweichend`: not [`PairKind::Equal`] or [`PairKind::Form`]) and, as `keep` asks, the
/// aligned, judged pairs (else empty).
pub(crate) fn pairs(
    rebuild: &Side<'_>,
    original: &Side<'_>,
    bits: u32,
    byte_padding: bool,
    data_address: &dyn Fn(&str) -> Option<u64>,
    keep: Keep,
) -> (u32, Vec<Pair>) {
    let a = build(
        rebuild.code,
        bits,
        rebuild.base,
        rebuild.gaps,
        byte_padding,
        &rebuild.naming,
    );
    let b = build(
        original.code,
        bits,
        original.base,
        original.gaps,
        byte_padding,
        &original.naming,
    );
    let aligned = align(&a, &b).unwrap_or_else(|| align_difflib(&a, &b));
    let pairing: HashMap<u32, u32> = aligned
        .iter()
        .filter_map(|&(x, y)| Some((a[x?].d.offset, b[y?].d.offset)))
        .collect();
    let kinds: Vec<PairKind> = aligned
        .iter()
        .map(|&(x, y)| match (x, y) {
            (Some(x), Some(y)) => match judge(&a[x], &b[y], &pairing, data_address) {
                Judgement::Equal => PairKind::Equal,
                Judgement::Form => PairKind::Form,
                Judgement::Different => PairKind::Different,
            },
            (Some(_), None) => PairKind::RebuildOnly,
            _ => PairKind::OriginalOnly,
        })
        .collect();
    let differing = kinds.iter().filter(|k| k.differs()).count() as u32;
    let wanted = match keep {
        Keep::Always => true,
        Keep::IfNotEqual => kinds.iter().any(|&k| k != PairKind::Equal),
        Keep::Never => false,
    };
    if !wanted {
        return (differing, Vec::new());
    }
    // every instruction is in exactly one pair: move the decoded instructions out
    let mut a: Vec<Option<Decoded>> = a.into_iter().map(|x| Some(x.d)).collect();
    let mut b: Vec<Option<Decoded>> = b.into_iter().map(|x| Some(x.d)).collect();
    let pairs = aligned
        .into_iter()
        .zip(kinds)
        .map(|((x, y), kind)| {
            Pair::new(
                kind,
                x.and_then(|x| a.get_mut(x)?.take()),
                y.and_then(|y| b.get_mut(y)?.take()),
            )
        })
        .collect();
    (differing, pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addend_is_signed_in_field_width() {
        assert_eq!(addend(&[0xFC, 0xFF, 0xFF, 0xFF], 0, 4, 0), -4);
        assert_eq!(addend(&[0x00, 0x00, 0x00, 0x00], 0, 4, 8), 8);
        assert_eq!(addend(&[0x10], 0, 4, 0), 0);
    }
}
