//! Diagnosis of known deviation patterns from the instruction pairs (port of the generic rules of Decomp's
//! `nachbau/diagnose.py`).
//!
//! Every rule is narrow: rather no finding than a wrong one. A finding names the cause and a suggestion. Decomp's
//! rules read capstone's Intel text; here they read iced-x86's Intel text, normalized once per function (numbers
//! as `0x…`, no `… ptr` size keywords, operands split at commas), so the patterns match the same things.
//! Deviation from Decomp: absolute memory operands (`[0x1234]`) count as equal in every differing pair, not only
//! when the rebuild's instruction carries a fixup (the pairs do not keep the fixup positions); in a rebuilt object
//! such an operand is almost always filled by the linker. The Watcom-specific rules (`folgefunktion`,
//! `vergleich-gespiegelt`, `gleiche-enden`) and the data-driven `cw:*` rules are not ported here.

use decovery_x86::Decoded;

use crate::pairs::{Pair, PairKind};

/// One diagnosis: the rule's id, what it found and what to try.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Finding {
    pub rule: String,
    pub text: String,
    pub suggestion: String,
}

impl Finding {
    pub fn new(
        rule: impl Into<String>,
        text: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Finding {
            rule: rule.into(),
            text: text.into(),
            suggestion: suggestion.into(),
        }
    }
}

/// One instruction with normalized operands.
struct Ins<'a> {
    offset: u32,
    mnemonic: &'a str,
    ops: Vec<String>,
    text: &'a str,
    shape: &'a str,
    branch: bool,
}

struct View<'a> {
    kind: PairKind,
    rebuild: Option<Ins<'a>>,
    original: Option<Ins<'a>>,
}

impl<'a> View<'a> {
    fn side(&self, rebuild: bool) -> Option<&Ins<'a>> {
        if rebuild {
            self.rebuild.as_ref()
        } else {
            self.original.as_ref()
        }
    }
}

/// Number tokens of an operand as `0x…` (iced writes `0Ah`, `7FFFh` and small numbers in decimal).
fn normalize_numbers(op: &str) -> String {
    let chars: Vec<char> = op.chars().collect();
    let mut out = String::with_capacity(op.len() + 4);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let starts_word = i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_');
        if c.is_ascii_digit() && starts_word {
            let mut j = i;
            while j < chars.len() && chars[j].is_ascii_hexdigit() {
                j += 1;
            }
            let digits: String = chars[i..j].iter().collect();
            let hex = j < chars.len() && (chars[j] == 'h' || chars[j] == 'H');
            let value = if hex {
                u64::from_str_radix(&digits, 16).ok()
            } else if digits.bytes().all(|b| b.is_ascii_digit()) {
                digits.parse::<u64>().ok()
            } else {
                None
            };
            let end_ok = {
                let k = if hex { j + 1 } else { j };
                k >= chars.len() || !(chars[k].is_ascii_alphanumeric() || chars[k] == '_')
            };
            if let (Some(v), true) = (value, end_ok) {
                out.push_str(&format!("{v:#x}"));
                i = if hex { j + 1 } else { j };
                continue;
            }
        }
        out.push(c.to_ascii_lowercase());
        i += 1;
    }
    out
}

/// The operand without `byte ptr` and the like.
fn without_size(op: &str) -> String {
    let words: Vec<&str> = op.split(' ').collect();
    let mut out: Vec<&str> = Vec::with_capacity(words.len());
    let mut k = 0;
    while k < words.len() {
        if words.get(k + 1) == Some(&"ptr") {
            k += 2;
            continue;
        }
        out.push(words[k]);
        k += 1;
    }
    out.join(" ")
}

/// The operands of `d`, normalized (numbers as `0x…`, no size keywords).
pub(crate) fn operands(d: &Decoded) -> Vec<String> {
    let words = d.mnemonic.split(' ').filter(|w| !w.is_empty()).count();
    let rest = d
        .text
        .splitn(words + 1, ' ')
        .nth(words)
        .unwrap_or("")
        .trim();
    if rest.is_empty() {
        return Vec::new();
    }
    rest.split(',')
        .map(|o| without_size(&normalize_numbers(o.trim())))
        .collect()
}

fn ins(d: &Decoded) -> Ins<'_> {
    Ins {
        offset: d.offset,
        mnemonic: &d.mnemonic,
        ops: operands(d),
        text: &d.text,
        shape: &d.shape,
        branch: d.near_branch.is_some(),
    }
}

fn is_register(s: &str) -> bool {
    matches!(
        s,
        "ax" | "bx"
            | "cx"
            | "dx"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "al"
            | "ah"
            | "bl"
            | "bh"
            | "cl"
            | "ch"
            | "dl"
            | "dh"
            | "si"
            | "di"
            | "esi"
            | "edi"
            | "bp"
            | "ebp"
    )
}

fn number(s: &str) -> Option<i64> {
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) if !hex.is_empty() => u64::from_str_radix(hex, 16).ok()?,
        Some(_) => return None,
        None if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
            digits.parse().ok()?
        }
        None => return None,
    };
    let value = value as i64;
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

pub(crate) fn is_number(s: &str) -> bool {
    number(s).is_some()
}

/// Replaces every `[content]` of `op` for which `f` returns a replacement (brackets included).
fn map_brackets(op: &str, f: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(op.len());
    let mut rest = op;
    while let Some(open) = rest.find('[') {
        let Some(close) = rest[open..].find(']').map(|c| open + c) else {
            break;
        };
        out.push_str(&rest[..open]);
        match f(&rest[open + 1..close]) {
            Some(new) => out.push_str(&new),
            None => out.push_str(&rest[open..=close]),
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

fn bracket_contents(op: &str) -> impl Iterator<Item = &str> {
    op.split('[')
        .skip(1)
        .filter_map(|part| part.split_once(']').map(|(inside, _)| inside))
}

/// `bp-N` / `ebp-N` (`sign` `-`) or `bp+N` / `ebp+N` (`+`): the frame register and N.
fn frame_slot(content: &str, sign: char) -> Option<(&str, u64)> {
    let (register, value) = content.split_once(sign)?;
    if register != "bp" && register != "ebp" {
        return None;
    }
    let n = number(value)?;
    u64::try_from(n).ok().map(|n| (register, n))
}

fn locals(op: &str) -> Vec<u64> {
    bracket_contents(op)
        .filter_map(|c| frame_slot(c, '-').map(|(_, n)| n))
        .collect()
}

fn without_locals(op: &str) -> String {
    map_brackets(op, &|c| frame_slot(c, '-').map(|_| "[L]".to_string()))
}

fn mask_absolute(op: &str) -> String {
    map_brackets(op, &|c| is_number(c).then(|| "[M]".to_string()))
}

fn joined(i: &Ins<'_>) -> String {
    i.ops.join(", ")
}

/// Operands of both sides of a pair with absolute memory addresses counted as equal (Decomp's
/// `_vergleichbare_operanden`).
fn comparable(a: &Ins<'_>, b: &Ins<'_>) -> (Vec<String>, Vec<String>) {
    (
        a.ops.iter().map(|o| mask_absolute(o)).collect(),
        b.ops.iter().map(|o| mask_absolute(o)).collect(),
    )
}

type LocalMap = Vec<(u64, u64)>;

/// Stack slot rebuild → original from all pairs of the same shape; `None` when contradictory (Decomp's
/// `_lokale_zuordnung`). Sorted by the rebuild's slot.
fn local_mapping(views: &[View<'_>]) -> Option<LocalMap> {
    let mut map: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    for v in views
        .iter()
        .filter(|v| matches!(v.kind, PairKind::Equal | PairKind::Different))
    {
        let (Some(a), Some(b)) = (&v.rebuild, &v.original) else {
            continue;
        };
        let (ja, jb) = (joined(a), joined(b));
        if a.shape != b.shape || without_locals(&ja) != without_locals(&jb) {
            continue;
        }
        for (x, y) in locals(&ja).into_iter().zip(locals(&jb)) {
            if *map.entry(x).or_insert(y) != y {
                return None;
            }
        }
    }
    let mut targets: Vec<u64> = map.values().copied().collect();
    targets.sort_unstable();
    targets.dedup();
    if targets.len() != map.len() {
        return None;
    }
    Some(map.into_iter().collect())
}

fn frame_register(bits: u8) -> &'static str {
    if bits == 32 { "ebp" } else { "bp" }
}

fn local_order(_: &[View<'_>], bits: u8, mapping: Option<&LocalMap>) -> Option<Finding> {
    let mapping = mapping?;
    if mapping.iter().all(|(a, b)| a == b) {
        return None;
    }
    let r = frame_register(bits);
    let swaps: Vec<String> = mapping
        .iter()
        .filter(|(a, b)| a != b)
        .map(|(a, b)| format!("[{r}-{a}]→[{r}-{b}]"))
        .collect();
    Some(Finding::new(
        "local-order",
        format!(
            "local variables are at other stack slots ({})",
            swaps.join(", ")
        ),
        "change the declaration order of the local variables",
    ))
}

/// Does `register` hold the value of `memory` after `seen` (newest last)? Looks back up to 6 instructions for
/// `mov memory,register` or `mov register,memory`; an instruction writing `register` first, a call or a jump stops.
fn knows(seen: &[&Ins<'_>], memory: &str, register: &str) -> bool {
    for b in seen.iter().rev().take(6) {
        let ops: Vec<&str> = b.ops.iter().map(String::as_str).collect();
        if b.mnemonic == "mov" && (ops == [memory, register] || ops == [register, memory]) {
            return true;
        }
        if ops.first() == Some(&register) || b.mnemonic == "call" || b.mnemonic.starts_with('j') {
            return false;
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Rebuild,
    Original,
}

impl Who {
    fn name(self) -> &'static str {
        match self {
            Who::Rebuild => "rebuild",
            Who::Original => "original",
        }
    }
}

/// Turbo C `-Z` (register contents remembered): an immediate against a register with a known value, memory against
/// a register that already holds it (`cmp [m],0` against `or r,r`; `push [m]` against `push r`), and reloading a
/// value that is already in the register.
fn turbo_c_z(views: &[View<'_>], bits: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let mut direction: Vec<Who> = Vec::new();
    fn add(w: Who, direction: &mut Vec<Who>) {
        if !direction.contains(&w) {
            direction.push(w);
        }
    }
    let mut seen_rebuild: Vec<&Ins<'_>> = Vec::new();
    let mut seen_original: Vec<&Ins<'_>> = Vec::new();
    for v in views {
        match (v.kind, &v.rebuild, &v.original) {
            (PairKind::Different, Some(nb), Some(og)) => {
                let (a, b) = comparable(nb, og);
                if nb.mnemonic == og.mnemonic && a.len() == b.len() {
                    let diff: Vec<(usize, &String, &String)> = a
                        .iter()
                        .zip(&b)
                        .enumerate()
                        .filter(|(_, (x, y))| x != y)
                        .map(|(k, (x, y))| (k, x, y))
                        .collect();
                    if let [(k, x, y)] = diff[..] {
                        if is_register(y) && (is_number(x) || knows(&seen_original, &nb.ops[k], y))
                        {
                            add(Who::Original, &mut direction);
                        } else if is_register(x)
                            && (is_number(y) || knows(&seen_rebuild, &og.ops[k], x))
                        {
                            add(Who::Rebuild, &mut direction);
                        }
                    }
                }
                for (with_zero, with_register, seen, who) in [
                    (nb, og, &seen_original, Who::Original),
                    (og, nb, &seen_rebuild, Who::Rebuild),
                ] {
                    let (ops, r) = (&with_zero.ops, &with_register.ops);
                    if with_zero.mnemonic == "cmp"
                        && ops.len() == 2
                        && number(&ops[1]) == Some(0)
                        && matches!(with_register.mnemonic, "or" | "test")
                        && r.len() == 2
                        && r[0] == r[1]
                        && is_register(&r[0])
                        && knows(seen, &ops[0], &r[0])
                    {
                        add(who, &mut direction);
                    }
                }
            }
            (PairKind::RebuildOnly, Some(nb), _) if nb.mnemonic == "mov" => {
                let ops = &nb.ops;
                if ops.len() == 2
                    && is_register(&ops[0])
                    && ops[1].contains('[')
                    && knows(&seen_rebuild, &ops[1], &ops[0])
                {
                    add(Who::Original, &mut direction);
                }
            }
            (PairKind::OriginalOnly, _, Some(og)) if og.mnemonic == "mov" => {
                let ops = &og.ops;
                if ops.len() == 2
                    && is_register(&ops[0])
                    && ops[1].contains('[')
                    && knows(&seen_original, &ops[1], &ops[0])
                {
                    add(Who::Rebuild, &mut direction);
                }
            }
            _ => {}
        }
        seen_rebuild.extend(v.rebuild.as_ref());
        seen_original.extend(v.original.as_ref());
    }
    let [who] = direction[..] else {
        return None;
    };
    Some(if bits == 16 {
        match who {
            Who::Original => Finding::new(
                "turbo-c-z",
                "the original uses a register whose value is already known where the rebuild uses memory or an immediate",
                "switch on the Turbo C option -Z (remember register contents)",
            ),
            Who::Rebuild => Finding::new(
                "turbo-c-z",
                "the rebuild uses a register whose value is already known where the original uses memory or an immediate",
                "switch off the Turbo C option -Z",
            ),
        }
    } else {
        Finding::new(
            "turbo-c-z",
            format!(
                "the {} uses a register whose value is already known",
                who.name()
            ),
            "try another optimization option",
        )
    })
}

fn only<'v, 'a>(views: &'v [View<'a>], kind: PairKind) -> Vec<&'v Ins<'a>> {
    views
        .iter()
        .filter(|v| v.kind == kind)
        .filter_map(|v| match kind {
            PairKind::RebuildOnly => v.rebuild.as_ref(),
            _ => v.original.as_ref(),
        })
        .collect()
}

fn extra_jump(views: &[View<'_>], _: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let nb = only(views, PairKind::RebuildOnly);
    let og = only(views, PairKind::OriginalOnly);
    match (&nb[..], &og[..]) {
        ([j], []) if j.mnemonic == "jmp" => Some(Finding::new(
            "extra-jump",
            format!("the rebuild has an extra jump ({:04X} jmp)", j.offset),
            "drop the else and return early",
        )),
        ([], [j]) if j.mnemonic == "jmp" => Some(Finding::new(
            "extra-jump",
            format!("the original has an extra jump ({:04X} jmp)", j.offset),
            "write if/else instead of an early return",
        )),
        _ => None,
    }
}

/// `xor ax,ax` / `mov ax,…` (32-bit: `eax`): setting the return value.
fn sets_return_value(b: &Ins<'_>) -> bool {
    let accumulator = |r: &str| r == "ax" || r == "eax";
    match (b.mnemonic, &b.ops[..]) {
        ("xor", [x, y]) => x == y && accumulator(x),
        ("mov", [x, _]) => accumulator(x),
        _ => false,
    }
}

/// One side sets the return value right before a jump (a `return x` in the middle of the function), the other
/// jumps without it.
fn early_return(views: &[View<'_>], _: u8, _: Option<&LocalMap>) -> Option<Finding> {
    for w in views.windows(2) {
        let (p, next) = (&w[0], &w[1]);
        let both_jump = matches!((&next.rebuild, &next.original), (Some(a), Some(b)) if a.mnemonic == "jmp" && b.mnemonic == "jmp");
        if !both_jump {
            continue;
        }
        let (b, original) = match (p.kind, &p.rebuild, &p.original) {
            (PairKind::OriginalOnly, _, Some(b)) => (b, true),
            (PairKind::RebuildOnly, Some(b), _) => (b, false),
            _ => continue,
        };
        if !sets_return_value(b) {
            continue;
        }
        return Some(if original {
            Finding::new(
                "early-return",
                format!(
                    "the original sets the return value before a jump to the end ({:04X} {})",
                    b.offset, b.text
                ),
                "write return directly in the branch instead of else and a shared return at the end",
            )
        } else {
            Finding::new(
                "early-return",
                format!(
                    "the rebuild sets the return value before a jump to the end ({:04X} {})",
                    b.offset, b.text
                ),
                "use an else branch with a shared return at the end instead of the early return",
            )
        });
    }
    None
}

fn constant(views: &[View<'_>], _: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let mut values: Vec<(u32, i64, i64)> = Vec::new();
    for v in views.iter().filter(|v| v.kind == PairKind::Different) {
        let (Some(nb), Some(og)) = (&v.rebuild, &v.original) else {
            continue;
        };
        let (a, b) = comparable(nb, og);
        if nb.mnemonic != og.mnemonic || a.len() != b.len() || nb.branch || og.branch {
            continue;
        }
        let diff: Vec<(Option<i64>, Option<i64>)> = a
            .iter()
            .zip(&b)
            .filter(|(x, y)| x != y)
            .map(|(x, y)| (number(x), number(y)))
            .collect();
        if !diff.is_empty() && diff.iter().all(|(x, y)| x.is_some() && y.is_some()) {
            values.extend(
                diff.into_iter()
                    .filter_map(|(x, y)| Some((nb.offset, x?, y?))),
            );
        }
    }
    if values.is_empty() {
        return None;
    }
    let parts: Vec<String> = values
        .iter()
        .take(5)
        .map(|(o, x, y)| format!("{o:04X}: rebuild {x:#x} ({x}), original {y:#x} ({y})"))
        .collect();
    Some(Finding::new(
        "constant",
        format!("immediate differs: {}", parts.join("; ")),
        "check the constant in the source",
    ))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Extension {
    Signed,
    Zero,
}

fn extension(b: &Ins<'_>, before: Option<&Ins<'_>>, bits: u8) -> Option<Extension> {
    let ops: Vec<&str> = b.ops.iter().map(String::as_str).collect();
    if matches!(b.mnemonic, "cbw" | "cwde" | "movsx") {
        return Some(Extension::Signed);
    }
    if b.mnemonic == "movzx"
        || (b.mnemonic == "mov" && ops == ["ah", "0x0"])
        || (b.mnemonic == "xor" && ops == ["ah", "ah"])
    {
        return Some(Extension::Zero);
    }
    // Watcom (32-bit): xor ebx,ebx; mov bl,byte ptr [x] = an unsigned byte into a cleared register
    if bits == 32
        && b.mnemonic == "mov"
        && let [low @ ("al" | "bl" | "cl" | "dl"), memory] = ops[..]
        && memory.contains('[')
        && let Some(before) = before
    {
        let wide = format!("e{}x", &low[..1]);
        if before.mnemonic == "xor" && before.ops == [wide.clone(), wide] {
            return Some(Extension::Zero);
        }
    }
    None
}

fn sign_extension(views: &[View<'_>], bits: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let kinds = |rebuild: bool| {
        let mut out: Vec<Extension> = Vec::new();
        let mut before: Option<&Ins<'_>> = None;
        for v in views {
            let Some(b) = v.side(rebuild) else {
                continue;
            };
            if v.kind != PairKind::Equal
                && let Some(e) = extension(b, before, bits)
                && !out.contains(&e)
            {
                out.push(e);
            }
            before = Some(b);
        }
        out
    };
    match (&kinds(true)[..], &kinds(false)[..]) {
        ([Extension::Signed], [Extension::Zero]) => Some(Finding::new(
            "sign-extension",
            "the rebuild extends with sign, the original without",
            "use unsigned char (or unsigned) instead of char",
        )),
        ([Extension::Zero], [Extension::Signed]) => Some(Finding::new(
            "sign-extension",
            "the rebuild extends without sign, the original with",
            "use char (signed) instead of unsigned char; Watcom's char is unsigned: option -j (for all functions) or signed char",
        )),
        _ => None,
    }
}

fn side_instructions<'v, 'a>(views: &'v [View<'a>], rebuild: bool) -> Vec<&'v Ins<'a>> {
    views.iter().filter_map(|v| v.side(rebuild)).collect()
}

/// Registers saved with `push` among the first six instructions.
fn saved(instructions: &[&Ins<'_>]) -> Vec<String> {
    let mut out: Vec<String> = instructions
        .iter()
        .take(6)
        .filter(|b| b.mnemonic == "push")
        .filter_map(|b| match &b.ops[..] {
            [r] if matches!(r.as_str(), "si" | "di" | "bx" | "ebx" | "esi" | "edi") => {
                Some(r.clone())
            }
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn extra_register(views: &[View<'_>], _: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let nb = saved(&side_instructions(views, true));
    let og = saved(&side_instructions(views, false));
    let more = |a: &[String], b: &[String]| -> Vec<String> {
        a.iter().filter(|r| !b.contains(r)).cloned().collect()
    };
    let (nb_more, og_more) = (more(&nb, &og), more(&og, &nb));
    match (nb_more.is_empty(), og_more.is_empty()) {
        (false, true) => Some(Finding::new(
            "extra-register",
            format!("the rebuild additionally saves {}", nb_more.join(", ")),
            "fewer intermediate values: rearrange the expression, make the parameter or variable an int",
        )),
        (true, false) => Some(Finding::new(
            "extra-register",
            format!(
                "the original additionally saves {} (register variable)",
                og_more.join(", ")
            ),
            "introduce a local copy or a register variable, typed int",
        )),
        _ => None,
    }
}

/// Parameter slots (`[bp+N]`) loaded into a general register among the first twelve instructions.
fn loads(instructions: &[&Ins<'_>]) -> Vec<u64> {
    instructions
        .iter()
        .take(12)
        .filter(|b| {
            b.mnemonic == "mov"
                && b.ops.first().is_some_and(|r| {
                    matches!(
                        r.as_str(),
                        "ax" | "bx"
                            | "cx"
                            | "dx"
                            | "si"
                            | "di"
                            | "eax"
                            | "ebx"
                            | "ecx"
                            | "edx"
                            | "esi"
                            | "edi"
                    )
                })
        })
        .filter_map(|b| {
            b.ops
                .iter()
                .flat_map(|o| bracket_contents(o))
                .find_map(|c| frame_slot(c, '+').map(|(_, n)| n))
        })
        .collect()
}

fn sorted<T: Ord + Clone>(v: &[T]) -> Vec<T> {
    let mut s = v.to_vec();
    s.sort();
    s
}

fn load_order(views: &[View<'_>], bits: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let nb = loads(&side_instructions(views, true));
    let og = loads(&side_instructions(views, false));
    if nb.len() < 2 || sorted(&nb) != sorted(&og) || nb == og {
        return None;
    }
    let r = frame_register(bits);
    let list = |v: &[u64]| {
        v.iter()
            .map(|x| format!("[{r}+{x}]"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Some(Finding::new(
        "load-order",
        format!(
            "parameters loaded in another order (rebuild {}; original {})",
            list(&nb),
            list(&og)
        ),
        "create local copies of the parameters in the original order",
    ))
}

fn sorted_mnemonics<'a>(v: &[&Ins<'a>]) -> Vec<&'a str> {
    sorted(&v.iter().map(|b| b.mnemonic).collect::<Vec<_>>())
}

fn sorted_operands<'s>(v: &[&'s Ins<'_>]) -> Vec<&'s str> {
    sorted(
        &v.iter()
            .flat_map(|b| b.ops.iter().map(String::as_str))
            .collect::<Vec<_>>(),
    )
}

/// Runs of consecutive differing pairs (equal and form pairs end a run): the instructions of each side.
fn runs<'v, 'a>(views: &'v [View<'a>]) -> Vec<(Vec<&'v Ins<'a>>, Vec<&'v Ins<'a>>)> {
    let mut out = Vec::new();
    let (mut nb, mut og): (Vec<&Ins<'_>>, Vec<&Ins<'_>>) = (Vec::new(), Vec::new());
    for v in views {
        if v.kind.differs() {
            nb.extend(v.rebuild.as_ref());
            og.extend(v.original.as_ref());
        } else if !nb.is_empty() || !og.is_empty() {
            out.push((std::mem::take(&mut nb), std::mem::take(&mut og)));
        }
    }
    if !nb.is_empty() || !og.is_empty() {
        out.push((nb, og));
    }
    out
}

/// The shape with general registers as `R` (Decomp's `_gestalt`).
fn generic_shape(shape: &str) -> String {
    let mut out = String::with_capacity(shape.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        let register = matches!(
            word.as_str(),
            "ax" | "bx"
                | "cx"
                | "dx"
                | "eax"
                | "ebx"
                | "ecx"
                | "edx"
                | "si"
                | "di"
                | "esi"
                | "edi"
                | "al"
                | "ah"
                | "bl"
                | "bh"
                | "cl"
                | "ch"
                | "dl"
                | "dh"
        );
        out.push_str(if register { "R" } else { word.as_str() });
        word.clear();
    };
    for c in shape.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

fn operand_swap(views: &[View<'_>], _: u8, mapping: Option<&LocalMap>) -> Option<Finding> {
    let translated = |b: &Ins<'_>| -> String {
        let j = joined(b);
        match mapping {
            None => j,
            Some(map) => map_brackets(&j, &|c| {
                let (register, n) = frame_slot(c, '-')?;
                let to = map.iter().find(|(a, _)| *a == n).map_or(n, |(_, b)| *b);
                Some(format!("[{register}-{to:#x}]"))
            }),
        }
    };
    for (nb, og) in runs(views) {
        if nb.len() < 2 || nb.len() != og.len() {
            continue;
        }
        let same_mnemonics = nb.iter().zip(&og).all(|(a, b)| a.mnemonic == b.mnemonic);
        if same_mnemonics && nb.iter().zip(&og).all(|(a, b)| translated(a) == joined(b)) {
            continue; // explained by the slots of the local variables
        }
        if sorted_mnemonics(&nb) != sorted_mnemonics(&og) {
            continue;
        }
        if sorted_operands(&nb) == sorted_operands(&og) {
            return Some(Finding::new(
                "operand-swap",
                format!(
                    "same instructions and operands in another order (from rebuild {:04X}, original {:04X})",
                    nb[0].offset, og[0].offset
                ),
                "swap operands/factors or write x = x op y instead of x op= y",
            ));
        }
    }
    // computation steps at another place (also with another register): all differing instructions of both sides
    // are the same, only moved
    let nb: Vec<&Ins<'_>> = views
        .iter()
        .filter(|v| matches!(v.kind, PairKind::Different | PairKind::RebuildOnly))
        .filter_map(|v| v.rebuild.as_ref())
        .collect();
    let og: Vec<&Ins<'_>> = views
        .iter()
        .filter(|v| matches!(v.kind, PairKind::Different | PairKind::OriginalOnly))
        .filter_map(|v| v.original.as_ref())
        .collect();
    let shapes =
        |v: &[&Ins<'_>]| sorted(&v.iter().map(|b| generic_shape(b.shape)).collect::<Vec<_>>());
    let moved = views
        .iter()
        .any(|v| matches!(v.kind, PairKind::RebuildOnly | PairKind::OriginalOnly));
    if nb.len() >= 2 && moved && shapes(&nb) == shapes(&og) {
        return Some(Finding::new(
            "operand-swap",
            format!(
                "the same computation steps at another place (rebuild {:04X} {}, original {:04X} {})",
                nb[0].offset, nb[0].text, og[0].offset, og[0].text
            ),
            "reorder factors/summands or bracket differently, e.g. (a) * (b) instead of b * a",
        ));
    }
    None
}

/// One side computes the element address beforehand (`lea`/`shl`/`add`: a pointer), the other indexes in the memory
/// access (`[base + index*n + field]`).
fn address_arithmetic(views: &[View<'_>], _: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let nb: Vec<&Ins<'_>> = views
        .iter()
        .filter(|v| matches!(v.kind, PairKind::Different | PairKind::RebuildOnly))
        .filter_map(|v| v.rebuild.as_ref())
        .collect();
    let og: Vec<&Ins<'_>> = views
        .iter()
        .filter(|v| matches!(v.kind, PairKind::Different | PairKind::OriginalOnly))
        .filter_map(|v| v.original.as_ref())
        .collect();
    let scaled = |bs: &[&Ins<'_>]| {
        bs.iter().any(|b| {
            b.mnemonic != "lea"
                && b.ops.iter().any(|o| {
                    bracket_contents(o).any(|c| {
                        c.split('*')
                            .skip(1)
                            .any(|after| after.starts_with(|ch: char| ch.is_ascii_digit()))
                    })
                })
        })
    };
    let beforehand = |bs: &[&Ins<'_>]| {
        bs.iter().any(|b| {
            b.mnemonic == "shl" || (b.mnemonic == "lea" && b.ops.iter().any(|o| o.contains('*')))
        })
    };
    if scaled(&nb) && !scaled(&og) && beforehand(&og) {
        return Some(Finding::new(
            "address-arithmetic",
            "the original computes the element address beforehand, the rebuild indexes in the memory access",
            "create a local pointer (p = array + n; then p->x) instead of array[n].x",
        ));
    }
    if scaled(&og) && !scaled(&nb) && beforehand(&nb) {
        return Some(Finding::new(
            "address-arithmetic",
            "the original indexes in the memory access, the rebuild computes the element address beforehand",
            "write array[n].x directly instead of a local pointer",
        ));
    }
    None
}

fn form_only(views: &[View<'_>]) -> bool {
    !views.iter().any(|v| v.kind.differs()) && views.iter().any(|v| v.kind == PairKind::Form)
}

fn jump_width(views: &[View<'_>], _: u8, _: Option<&LocalMap>) -> Option<Finding> {
    form_only(views).then(|| {
        Finding::new(
            "jump-width",
            "instructions equal, only jump widths (short/near) differ",
            "the code between jump and target has another length; usually a consequence of another difference",
        )
    })
}

fn length_end(views: &[View<'_>], _: u8, _: Option<&LocalMap>) -> Option<Finding> {
    let mut k = views.len();
    while k > 0
        && matches!(
            views[k - 1].kind,
            PairKind::RebuildOnly | PairKind::OriginalOnly
        )
    {
        k -= 1;
    }
    if k == views.len()
        || views[..k]
            .iter()
            .any(|v| !matches!(v.kind, PairKind::Equal | PairKind::Form))
    {
        return None;
    }
    let who = if views.last()?.kind == PairKind::RebuildOnly {
        "rebuild"
    } else {
        "original"
    };
    Some(Finding::new(
        "length-end",
        format!(
            "the {who} has {} more instruction(s) at the end",
            views.len() - k
        ),
        "check the return value or the final return",
    ))
}

type Rule = fn(&[View<'_>], u8, Option<&LocalMap>) -> Option<Finding>;

/// The rules in Decomp's order; the second field is whether the rule applies only to Turbo C.
const RULES: &[(Rule, bool)] = &[
    (local_order, false),
    (turbo_c_z, true),
    (extra_jump, false),
    (early_return, false),
    (constant, false),
    (sign_extension, false),
    (extra_register, false),
    (load_order, false),
    (operand_swap, false),
    (address_arithmetic, false),
    (jump_width, false),
    (length_end, false),
];

/// The findings of the generic rules for the instruction pairs of one function (`bits` 16 or 32; `family` the
/// compiler family, `turbo-c-z` applies only to `turbo-c`). Empty when no instruction differs. The pairs are
/// normalized once; every rule reads the same normalized instructions.
pub fn diagnose(pairs: &[Pair], bits: u8, family: &str) -> Vec<Finding> {
    if !pairs
        .iter()
        .any(|p| p.kind.differs() || p.kind == PairKind::Form)
    {
        return Vec::new();
    }
    let views: Vec<View<'_>> = pairs
        .iter()
        .map(|p| View {
            kind: p.kind,
            rebuild: p.rebuild.as_ref().map(ins),
            original: p.original.as_ref().map(ins),
        })
        .collect();
    let mapping = local_mapping(&views);
    let turbo_c = family.starts_with("turbo-c");
    RULES
        .iter()
        .filter(|(_, only_turbo_c)| turbo_c || !only_turbo_c)
        .filter_map(|(rule, _)| rule(&views, bits, mapping.as_ref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_normalized() {
        assert_eq!(normalize_numbers("[bp-2]"), "[bp-0x2]");
        assert_eq!(normalize_numbers("0FFFFh"), "0xffff");
        assert_eq!(normalize_numbers("[eax*4+10h]"), "[eax*0x4+0x10]");
        assert_eq!(normalize_numbers("ah"), "ah");
        assert_eq!(normalize_numbers("es:[1234h]"), "es:[0x1234]");
        assert_eq!(without_size("word ptr [bp+0x4]"), "[bp+0x4]");
    }

    #[test]
    fn brackets_are_mapped() {
        assert_eq!(mask_absolute("es:[0x1234]"), "es:[M]");
        assert_eq!(without_locals("[bp-0x2]"), "[L]");
        assert_eq!(locals("[ebp-0x8]"), [8]);
        assert_eq!(
            map_brackets("[unclosed", &|_| Some("x".into())),
            "[unclosed"
        );
    }
}
