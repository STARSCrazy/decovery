//! Kinds of deviation (port of Decomp's `nachbau/abweichungsart.py`, `klassifiziere`) and the stage of an original
//! function before it is rebuilt (port of `nachbau/einstufung.py`).

use decovery_x86::{DecodeOptions, decode_detailed};

use crate::diagnose::{is_byte_register, is_number, is_word_register, operands, same_sizes};
use crate::pairs::{Pair, PairKind};

/// What all differing pairs of a comparison change, when it is only the compiler's slot or register choice: the
/// source already forms the values right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeviationKind {
    /// Same instructions, only other stack slots (`[esp+N]`, `[ebp-N]`, `[bp-N]`).
    StackOnly,
    /// Same instructions, only other registers (register-to-register copies inserted or dropped by the other
    /// choice included).
    RegistersOnly,
    StackAndRegisters,
}

impl DeviationKind {
    /// The serialized id (`stack`, `registers`, `stack-registers`).
    pub fn id(self) -> &'static str {
        match self {
            DeviationKind::StackOnly => "stack",
            DeviationKind::RegistersOnly => "registers",
            DeviationKind::StackAndRegisters => "stack-registers",
        }
    }
}

/// Every local slot as `[reg+N]`: `[esp]`, `[esp+N]`, `[esp-N]`, and `[ebp-N]` / `[bp-N]` (a frame register with a
/// positive offset is a parameter, not a slot).
fn stack_masked(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(open) = rest.find('[') {
        let Some(close) = rest[open..].find(']').map(|c| open + c) else {
            break;
        };
        out.push_str(&rest[..open]);
        let content = &rest[open + 1..close];
        let register = content.split(['+', '-']).next().unwrap_or("");
        let offset = &content[register.len()..];
        let plain_offset = offset.is_empty() || offset.get(1..).is_some_and(is_number);
        let slot = match register {
            "esp" => plain_offset,
            "ebp" | "bp" => offset.starts_with('-') && plain_offset,
            _ => false,
        };
        if slot {
            out.push_str(&format!("[{register}+N]"));
        } else {
            out.push_str(&rest[open..=close]);
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

fn is_general_register(w: &str) -> bool {
    is_word_register(w) || is_byte_register(w) || w == "ebp"
}

/// Every general register as `R`.
fn registers_masked(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut word = String::new();
    for c in t.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        out.push_str(if is_general_register(&word) {
            "R"
        } else {
            &word
        });
        word.clear();
        if c != '\0' {
            out.push(c);
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PairChange {
    Stack,
    Registers,
    Both,
}

fn pair_change(p: &Pair) -> Option<PairChange> {
    let (Some(a), Some(b)) = (&p.rebuild, &p.original) else {
        return None;
    };
    // a changed operand size (char against int) is a type difference, not a slot or register choice
    if a.mnemonic != b.mnemonic || !same_sizes(a, b) {
        return None;
    }
    let (a, b) = (operands(a).join(", "), operands(b).join(", "));
    if a == b {
        return None;
    }
    if stack_masked(&a) == stack_masked(&b) {
        return Some(PairChange::Stack);
    }
    if registers_masked(&a) == registers_masked(&b) {
        return Some(PairChange::Registers);
    }
    if registers_masked(&stack_masked(&a)) == registers_masked(&stack_masked(&b)) {
        return Some(PairChange::Both);
    }
    None
}

/// A register-to-register `mov` (a copy another register choice inserts or drops).
fn is_register_copy(p: &Pair) -> bool {
    let d = match p.kind {
        PairKind::RebuildOnly => p.rebuild.as_ref(),
        _ => p.original.as_ref(),
    };
    let Some(d) = d else {
        return false;
    };
    let copyable = |r: &str| is_word_register(r) || r == "ebp";
    d.mnemonic == "mov" && matches!(&operands(d)[..], [x, y] if copyable(x) && copyable(y))
}

/// The kind of deviation and the number of differing instructions, when every differing pair only changes stack
/// slots and/or register names (plus inserted or dropped register copies, only together with a register change);
/// otherwise `None`.
pub fn classify_deviation(pairs: &[Pair]) -> Option<(DeviationKind, u32)> {
    let differing: Vec<&Pair> = pairs.iter().filter(|p| p.kind.differs()).collect();
    if differing.is_empty() {
        return None;
    }
    let mut changes: Vec<PairChange> = Vec::new();
    let mut copies = 0u32;
    for p in &differing {
        if p.kind != PairKind::Different {
            if is_register_copy(p) {
                copies += 1;
                continue;
            }
            return None;
        }
        changes.push(pair_change(p)?);
    }
    let first = *changes.first()?;
    let kind = if changes.contains(&PairChange::Both) || changes.iter().any(|&c| c != first) {
        DeviationKind::StackAndRegisters
    } else {
        match first {
            PairChange::Stack => DeviationKind::StackOnly,
            PairChange::Registers => DeviationKind::RegistersOnly,
            PairChange::Both => DeviationKind::StackAndRegisters,
        }
    };
    if copies > 0 && kind != DeviationKind::RegistersOnly {
        return None;
    }
    Some((kind, differing.len() as u32))
}

/// What an original function looks like before it is rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// Looks like compiled C.
    Rebuildable,
    /// Looks like hand-written assembler.
    Assembly,
    /// Library code.
    Library,
}

impl Stage {
    /// The serialized id (`rebuildable`, `assembly`, `library`).
    pub fn id(self) -> &'static str {
        match self {
            Stage::Rebuildable => "rebuildable",
            Stage::Assembly => "assembly",
            Stage::Library => "library",
        }
    }
}

/// Instructions that alone make a function assembler.
const STRONG: &[&str] = &[
    "insb", "insw", "insd", "outsb", "outsw", "outsd", "pusha", "popa", "pushal", "popal",
    "pushad", "popad", "lgdt", "lidt", "lldt", "ltr", "lmsw", "hlt", "clts", "invlpg",
];
/// Instructions the old C compilers rarely emit (or only through special functions such as Turbo C's
/// `inportb`/`outportb` → `in`/`out`, `disable`/`enable` → `cli`/`sti`).
const WEAK: &[&str] = &[
    "in", "out", "cli", "sti", "lodsb", "lodsw", "lodsd", "xlatb", "loop", "loope", "loopne",
    "jcxz", "jecxz", "bswap", "cld", "std", "das", "daa", "aaa", "aas", "aam", "aad", "sahf",
    "lahf", "rcl", "rcr",
];
/// So many different weak reasons are enough even with a frame.
const WEAK_ENOUGH: usize = 3;
const SEGMENT_REGISTERS: &[&str] = &["ds", "es", "ss", "fs", "gs"];
/// `push ebp; mov ebp,esp` in the encoding of the assemblers (8B /r); Watcom and GCC write 89 E5.
const ASSEMBLER_FRAME_32: &[u8] = &[0x55, 0x8B, 0xEC];

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

fn hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The stage of an original function and the reasons (port of Decomp's `einstufen`): `signature_named` when the
/// knowledge names it by a library signature, `library` the library its code matches by pattern; `prologue` is the
/// profile's standard frame. Strong reasons (port block instructions, `pusha`, system registers) alone make it
/// assembler; weak ones (instructions the C compilers rarely emit) together with a missing frame or from three
/// different ones.
pub fn classify_code(
    code: &[u8],
    bits: u8,
    prologue: &[u8],
    signature_named: bool,
    library: Option<&str>,
) -> (Stage, Vec<String>) {
    if signature_named {
        return (
            Stage::Library,
            vec!["named as a library function by signature".to_string()],
        );
    }
    if let Some(library) = library.filter(|l| !l.is_empty()) {
        return (
            Stage::Library,
            vec![format!("library code by pattern: {library}")],
        );
    }
    if code.is_empty() {
        return (Stage::Rebuildable, Vec::new());
    }
    let decoded = decode_detailed(code, u32::from(bits), 0, &DecodeOptions::default());
    let (mut strong, mut weak, mut hints) = (Vec::new(), Vec::new(), Vec::new());
    for d in decoded.iter().filter(|d| !d.is_padding()) {
        let m = d.mnemonic.rsplit(' ').next().unwrap_or("");
        if STRONG.contains(&m) {
            push_unique(&mut strong, d.mnemonic.clone());
        } else if WEAK.contains(&m) {
            push_unique(&mut weak, d.mnemonic.clone());
        } else if bits == 32
            && m == "mov"
            && let Some(target) = operands(d).first()
            && SEGMENT_REGISTERS.contains(&target.as_str())
        {
            push_unique(&mut strong, format!("mov {target}"));
        } else if m == "iret" || m == "iretd" {
            push_unique(
                &mut hints,
                "iret: interrupt function (Turbo C 'interrupt') or assembler".to_string(),
            );
        }
    }
    if bits == 32 && code.starts_with(ASSEMBLER_FRAME_32) && prologue != ASSEMBLER_FRAME_32 {
        strong.insert(0, "frame in assembler notation (55 8b ec)".to_string());
    }
    let no_frame = !prologue.is_empty() && !code.starts_with(prologue);
    let mut reasons = Vec::new();
    if no_frame {
        reasons.push(format!("no standard frame ({})", hex_spaced(prologue)));
    }
    if !strong.is_empty() {
        reasons.push(format!(
            "instructions as in assembler: {}",
            strong.join(", ")
        ));
    }
    if !weak.is_empty() {
        reasons.push(format!("rarely from the compiler: {}", weak.join(", ")));
    }
    if !strong.is_empty() || (no_frame && !weak.is_empty()) || weak.len() >= WEAK_ENOUGH {
        return (Stage::Assembly, reasons);
    }
    reasons.extend(hints);
    (Stage::Rebuildable, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(stack_masked("eax, [ebp-0x8]"), "eax, [ebp+N]");
        assert_eq!(stack_masked("eax, [esp]"), "eax, [esp+N]");
        assert_eq!(stack_masked("eax, [ebx+0x4]"), "eax, [ebx+0x4]");
        assert_eq!(stack_masked("ax, [bp+si]"), "ax, [bp+si]");
        assert_eq!(stack_masked("ax, [bp+0x4]"), "ax, [bp+0x4]");
        assert_eq!(stack_masked("ax, [bp-0x4]"), "ax, [bp+N]");
        assert_eq!(registers_masked("dx, [bp-0x2]"), "R, [bp-0x2]");
    }
}
