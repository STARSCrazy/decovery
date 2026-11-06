//! The aligned instruction pairs of a comparison (Decomp's `Befehlsvergleich.paare`) and their side-by-side text.

use decovery_core::{Address, Program};
use decovery_objects::FunctionView;
use decovery_x86::Decoded;

use crate::{CompareOptions, Decoration, SymbolView};

/// How the two instructions of a pair compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PairKind {
    Equal,
    /// Same instruction, only the encoding differs (a short against a near jump to the same target).
    Form,
    Different,
    RebuildOnly,
    OriginalOnly,
}

impl PairKind {
    /// The serialized id (`equal`, `form`, `different`, `rebuild-only`, `original-only`).
    pub fn id(self) -> &'static str {
        match self {
            PairKind::Equal => "equal",
            PairKind::Form => "form",
            PairKind::Different => "different",
            PairKind::RebuildOnly => "rebuild-only",
            PairKind::OriginalOnly => "original-only",
        }
    }

    /// The mark in [`pairs_text`]: `=`, `~`, `≠`, `+`, `-`.
    pub fn mark(self) -> &'static str {
        match self {
            PairKind::Equal => "=",
            PairKind::Form => "~",
            PairKind::Different => "≠",
            PairKind::RebuildOnly => "+",
            PairKind::OriginalOnly => "-",
        }
    }

    /// Counts as a differing instruction (`Metrics::instructions_differing`).
    pub fn differs(self) -> bool {
        matches!(
            self,
            PairKind::Different | PairKind::RebuildOnly | PairKind::OriginalOnly
        )
    }
}

/// One aligned pair; offsets of the instructions are relative to the function start. `rebuild` is `None` for
/// [`PairKind::OriginalOnly`], `original` for [`PairKind::RebuildOnly`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pair {
    pub kind: PairKind,
    pub rebuild: Option<Decoded>,
    pub original: Option<Decoded>,
}

impl Pair {
    pub fn new(kind: PairKind, rebuild: Option<Decoded>, original: Option<Decoded>) -> Self {
        Pair {
            kind,
            rebuild,
            original,
        }
    }
}

/// The aligned instruction pairs of the rebuilt function `f` against the original at `at`: the same alignment and
/// judgement that yield `Metrics::instructions_differing` of [`crate::compare`]. Empty when the function cannot be
/// compared (no 16/32-bit section, original bytes not in the program).
pub fn instruction_pairs(
    f: &FunctionView,
    at: Address,
    program: &Program,
    symbols: &dyn SymbolView,
    decoration: &Decoration,
    options: &CompareOptions,
) -> Vec<Pair> {
    crate::compare::instruction_pairs(f, at, program, symbols, decoration, options)
}

/// Equal pairs farther than this from a non-equal pair are collapsed in [`pairs_text`].
const CONTEXT: usize = 3;
/// Width of the rebuild column in [`pairs_text`].
const COLUMN: usize = 40;

/// Instructions side by side (rebuild left, original right), one pair per line with its mark; runs of equal pairs
/// farther than three pairs from a difference are collapsed into one line. Ends with the counts.
pub fn pairs_text(pairs: &[Pair]) -> String {
    let collapse = pairs.len() > 2 * CONTEXT + 4;
    let mut shown = vec![!collapse; pairs.len()];
    if collapse {
        for (i, p) in pairs.iter().enumerate() {
            if p.kind != PairKind::Equal {
                let end = (i + CONTEXT + 1).min(pairs.len());
                for s in &mut shown[i.saturating_sub(CONTEXT)..end] {
                    *s = true;
                }
            }
        }
    }
    let mut lines = vec![format!("  {:<COLUMN$} | original", "rebuild")];
    let mut hidden = 0usize;
    let flush = |hidden: &mut usize, lines: &mut Vec<String>| {
        if *hidden > 0 {
            lines.push(format!("  … {hidden} equal instructions"));
            *hidden = 0;
        }
    };
    for (p, &show) in pairs.iter().zip(&shown) {
        if !show {
            hidden += 1;
            continue;
        }
        flush(&mut hidden, &mut lines);
        let side = |d: &Option<Decoded>| {
            d.as_ref()
                .map_or_else(String::new, |d| format!("{:04X} {}", d.offset, d.text))
        };
        let line = format!(
            "{} {:<COLUMN$} | {}",
            p.kind.mark(),
            side(&p.rebuild),
            side(&p.original)
        );
        lines.push(line.trim_end().to_string());
    }
    flush(&mut hidden, &mut lines);
    let count = |k: PairKind| pairs.iter().filter(|p| p.kind == k).count();
    let rebuild = pairs.iter().filter(|p| p.rebuild.is_some()).count();
    let original = pairs.iter().filter(|p| p.original.is_some()).count();
    let differing = pairs.iter().filter(|p| p.kind.differs()).count();
    let form = count(PairKind::Form);
    lines.push(String::new());
    lines.push(format!(
        "instructions: rebuild {rebuild}, original {original}; {} equal{}, {differing} differing",
        count(PairKind::Equal),
        if form > 0 {
            format!(", {form} only in the encoding")
        } else {
            String::new()
        }
    ));
    let mut text = lines.join("\n");
    text.push('\n');
    text
}
