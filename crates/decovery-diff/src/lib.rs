//! Function comparison: a rebuilt function (from an object file) against the original program.
//!
//! [`compare`] yields decovery's [`Verdict`] with its [`Blocker`]s and Decomp's numbers as [`Metrics`].
//!
//! **Metrics** port Decomp's `nachbau/vergleich.py` (`vergleiche`) and the instruction comparison of
//! `dienst.py` (`_befehlsvergleich` with `nachbau/befehle.py`) and reproduce its fields exactly:
//! `bytes`, `gleich` → `equal`, `luecken` → `gaps`, `fuellbytes` → `padding`, `abweichend` → `differing`,
//! `verweise_passend/falsch/ungeprueft` → `refs_ok/refs_wrong/refs_unchecked`,
//! `befehle_abweichend` → `instructions_differing`, `erste_abweichung` → `first_difference`.
//!
//! **Instruction text.** Decomp aligns instruction sequences on capstone's Intel text with numbers masked.
//! decovery decodes with iced-x86 and aligns on a syntax-independent *shape* built from the decoded operands
//! (see `decovery_x86::Decoded::shape`): mnemonic with prefixes, registers, memory operand size, segment
//! override, base/index/scale, and `N` for immediates, branch targets and displacements. Every aligned pair is
//! then judged exactly as Decomp does, on raw bytes outside relocated fields plus equality of branch targets
//! (paired offset inside the function, name outside) and data references (name + addend against the
//! original's address). So only the alignment step uses the shape, and it masks the same things capstone's
//! text did; the one systematic difference is that capstone printed some negative immediates as `-N`, which
//! here are `N` like all immediates (the pair still differs on its bytes).
//!
//! **Verdict** follows decovery's rule (design 5.11 item 1), stricter than Decomp's: every relocation of the
//! rebuilt function (and every call the compiler resolved inside the object without a fixup) must refer to the
//! same target as the original. Absolute fields need a [`Program`] relocation at the same place with the same
//! kind and width whose target equals the symbol's address (via [`SymbolView::address_of`] of the undecorated
//! name) plus the addend (field content plus fixup displacement). Own-section targets resolve through the
//! function's own address; a 32-bit reference to the function's own jump table, which Watcom places before the
//! function start at a distance that depends on the code before it, matches when the original's relocation
//! points at a table whose entries lead to the same offsets of the function as the rebuild's entries;
//! a target exactly at another symbol of the section resolves through that symbol's address, and a target
//! behind the function through the function containing it. Self-relative fields have no relocation in a
//! linked LE image when caller and callee share an object, so their original target is read from the original
//! bytes (`at + width + field`) unless the program does carry a relocation there, which then has to match.
//! Fields inside padding behind the original's end (the following function's jump table) are left to that
//! function, as in Decomp's byte comparison. On top of that, zero differing bytes and zero differing
//! instructions. A target that cannot be resolved (an unknown symbol, a group target) is an
//! [`Blocker::UncheckedRef`].
//!
//! **Anchors** (ADR 0006, [`compare_module`]): fields of 16-bit functions whose original has no relocation at the
//! same place (MZ offsets) are checked against frame and section anchors established by consensus over all
//! placements of one comparison; 16-bit selector fields against the frame anchor's segment. A 32-bit field whose
//! target is an unnamed position in another section (a string in `CONST`) is checked against a section anchor.
//! A dissenting field whose item equals the original at the position the field proposes (the item is unchanged,
//! only the section's layout moved it) is a [`Blocker::DataLayout`] instead of a wrong reference. A frame base can
//! also come from the program's startup code ([`startup_frames`]): the toolchain's startup object, placed at the
//! program entry and equal to the original there, names the frame of each segment relocation of the original.
//! [`compare`] is [`compare_module`] with one placement.
//!
//! **Diagnosis** ([`diagnose`], port of the generic rules of Decomp's `nachbau/diagnose.py`) reads the aligned
//! instruction pairs ([`instruction_pairs`], the alignment behind `instructions_differing`) and names known causes
//! of a difference; with [`ModuleOptions::with_diagnosis`] a module comparison records the rule ids from the pairs
//! it already has. [`classify_deviation`] tells slot- or register-only differences apart, [`classify_code`] the
//! stage of an original function (port of `einstufung.py`).
//!
//! Deviations from Decomp, all outside the metrics: the table of functions of the same object used to name
//! fixup-less calls (`intern`) holds only the function's own section (Decomp merged all code segments by
//! offset); data names come only from [`SymbolView::name_at`] (Decomp also named addresses inside variables
//! of known size, which only adds display hints when the name is known by address).

mod anchors;
mod classify;
mod compare;
mod diagnose;
mod instructions;
mod pairs;
mod program_le;
mod program_mz;
mod sequence;

use std::collections::BTreeMap;

use decovery_core::Address;
use decovery_objects::FunctionView;

pub use anchors::{StartupFrames, startup_frames};
pub use classify::{DeviationKind, Stage, classify_code, classify_deviation};
pub use compare::{
    InsertCode, SharedFunctions, compare, compare_module, compare_module_with, insert_code,
    same_code,
};
pub use diagnose::{Finding, diagnose};
pub use pairs::{Pair, PairKind, instruction_pairs, pairs_text};
pub use program_le::compare_le;
pub use program_mz::{Place, PlaceKind, diagnose_mz_link, load_image};

/// The name of an address in the original, and whether it is only a default name (`fun_0001A2B0`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NameAt {
    pub name: String,
    pub is_default: bool,
}

impl NameAt {
    pub fn new(name: impl Into<String>, is_default: bool) -> Self {
        NameAt {
            name: name.into(),
            is_default,
        }
    }
}

/// What the knowledge base says about names in the original program (undecorated C names). `Sync`, because
/// [`compare_module`] compares the functions in parallel.
pub trait SymbolView: Sync {
    /// The name at `at`; `None` is treated like a default name that matches nothing.
    fn name_at(&self, at: Address) -> Option<NameAt>;
    /// Where `name` lives in the original.
    fn address_of(&self, name: &str) -> Option<Address>;
}

/// How the compiler decorates public names: patterns with `{name}`, e.g. `"{name}_"` and `"_{name}"` (Watcom).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decoration {
    pub function: String,
    pub data: String,
}

impl Decoration {
    pub fn new(function: impl Into<String>, data: impl Into<String>) -> Self {
        Decoration {
            function: function.into(),
            data: data.into(),
        }
    }

    /// Watcom register convention: functions `name_`, data `_name`.
    pub fn watcom() -> Self {
        Decoration::new("{name}_", "_{name}")
    }

    /// The C name of a public: the function pattern is tried first, then the data pattern (Decomp's `c_name`).
    /// A pattern matches only if something is left for the name.
    pub fn undecorate<'a>(&self, public: &'a str) -> &'a str {
        for pattern in [&self.function, &self.data] {
            let Some((prefix, suffix)) = pattern.split_once("{name}") else {
                continue;
            };
            if prefix.is_empty() && suffix.is_empty() {
                continue;
            }
            if let Some(name) = public
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
                .filter(|name| !name.is_empty())
            {
                return name;
            }
        }
        public
    }
}

/// Options of a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct CompareOptions {
    /// Tolerate alignment written as `00` by the rebuild's assembler where the original has `90` (Decomp's
    /// `fuellung`).
    pub padding: bool,
    /// Length of the original function, when known (Decomp took it from the analysis engine). Padding of the
    /// rebuild behind it always counts as padding, and instructions are compared over this length.
    pub original_len: Option<u32>,
}

impl CompareOptions {
    pub fn new(padding: bool, original_len: Option<u32>) -> Self {
        CompareOptions {
            padding,
            original_len,
        }
    }
}

/// decovery's verdict on a rebuilt function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    Identical,
    Equivalent {
        level: EquivalenceLevel,
    },
    Differs,
    /// Not compared (never built, or the original bytes are not available).
    Unchecked,
}

/// Evidence for [`Verdict::Equivalent`]. No producer in phase 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EquivalenceLevel {
    Static,
    Tested,
}

/// Why a function is not identical. Offsets are relative to the function start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Blocker {
    BytesDiffer {
        count: u32,
    },
    /// A relocated field whose target cannot be resolved (no name, unknown symbol).
    UncheckedRef {
        at: u32,
    },
    WrongAbsoluteRef {
        at: u32,
    },
    WrongRelativeRef {
        at: u32,
    },
    InstructionsDiffer {
        count: u32,
    },
    /// The original bytes of the function's range are not in the program.
    OriginalUnavailable,
    /// A reference to an unnamed data item (a string in `CONST`) that is unchanged but lies at another offset of
    /// its section than in the original: the function's bytes may match, the module's data layout does not.
    DataLayout {
        at: u32,
    },
    /// The source of the function contains inline assembly, `_emit` or machine code in `#pragma aux`; byte
    /// equality does not count as a rebuild.
    InlineAssembly,
}

impl Blocker {
    /// The serialized kind (`bytes-differ`, `wrong-absolute-ref`, ...).
    pub fn kind(&self) -> &'static str {
        match self {
            Blocker::BytesDiffer { .. } => "bytes-differ",
            Blocker::UncheckedRef { .. } => "unchecked-ref",
            Blocker::WrongAbsoluteRef { .. } => "wrong-absolute-ref",
            Blocker::WrongRelativeRef { .. } => "wrong-relative-ref",
            Blocker::InstructionsDiffer { .. } => "instructions-differ",
            Blocker::OriginalUnavailable => "original-unavailable",
            Blocker::DataLayout { .. } => "data-layout",
            Blocker::InlineAssembly => "inline-assembly",
        }
    }

    /// The offset in the function, for kinds that have one.
    pub fn at(&self) -> Option<u32> {
        match *self {
            Blocker::UncheckedRef { at }
            | Blocker::WrongAbsoluteRef { at }
            | Blocker::WrongRelativeRef { at }
            | Blocker::DataLayout { at } => Some(at),
            _ => None,
        }
    }

    /// The count, for kinds that have one.
    pub fn count(&self) -> Option<u32> {
        match *self {
            Blocker::BytesDiffer { count } | Blocker::InstructionsDiffer { count } => Some(count),
            _ => None,
        }
    }
}

/// Decomp's numbers for a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Metrics {
    pub bytes: u32,
    pub equal: u32,
    pub gaps: u32,
    pub padding: u32,
    pub differing: u32,
    pub refs_ok: u32,
    pub refs_wrong: u32,
    pub refs_unchecked: u32,
    pub instructions_differing: u32,
    pub first_difference: Option<u32>,
}

/// Result of [`compare`]. `verdict` is [`Verdict::Identical`] iff `blockers` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Comparison {
    pub verdict: Verdict,
    pub blockers: Vec<Blocker>,
    pub metrics: Metrics,
    /// Ids of the diagnosis rules ([`diagnose`]) that apply to a differing function, when the comparison was asked
    /// for them ([`ModuleOptions::diagnosis`]); empty otherwise and for identical functions.
    pub diagnoses: Vec<String>,
}

/// A rebuilt function and where its original lives.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Placement<'a> {
    pub function: FunctionView<'a>,
    pub at: Address,
    /// Length of the original function, when known (see [`CompareOptions::original_len`]).
    pub original_len: Option<u32>,
}

impl<'a> Placement<'a> {
    pub fn new(function: FunctionView<'a>, at: Address, original_len: Option<u32>) -> Self {
        Placement {
            function,
            at,
            original_len,
        }
    }
}

/// Options of a module comparison.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ModuleOptions {
    /// See [`CompareOptions::padding`].
    pub padding: bool,
    /// Frame bases fixed by configuration (`[rebuild.frames]`), by frame name (group or section); they override
    /// the consensus.
    pub frames: BTreeMap<String, Address>,
    /// Frame bases proven by the program's startup code ([`startup_frames`], ADR 0006 item 10); they override the
    /// consensus, a configured frame overrides them.
    pub startup_frames: BTreeMap<String, Address>,
    /// Compiler family (`turbo-c`, `watcom`) to diagnose differing functions for, from the instruction pairs the
    /// comparison already has ([`Comparison::diagnoses`]); `None` skips the diagnosis.
    pub diagnosis: Option<String>,
}

impl ModuleOptions {
    pub fn new(padding: bool, frames: BTreeMap<String, Address>) -> Self {
        ModuleOptions {
            padding,
            frames,
            startup_frames: BTreeMap::new(),
            diagnosis: None,
        }
    }

    /// The same options with the frame bases proven by the startup code ([`startup_frames`]).
    pub fn with_startup_frames(mut self, frames: BTreeMap<String, Address>) -> Self {
        self.startup_frames = frames;
        self
    }

    /// The same options with the diagnosis for compiler `family`.
    pub fn with_diagnosis(mut self, family: impl Into<String>) -> Self {
        self.diagnosis = Some(family.into());
        self
    }
}

/// Where an anchor's base comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorSource {
    Config,
    /// The selector fields of the program's startup code ([`startup_frames`]).
    Startup,
    Consensus,
    /// A section without agreed votes whose bytes occur exactly once in its frame, at the position one of its
    /// votes names (ADR 0006 item 4, amendment 2026-11-09).
    Content,
}

/// A frame anchor (`section` is `None`: linear base of the frame) or a section anchor (offset of the OBJ section
/// inside its frame; for 32-bit sections the linear address, frame `FLAT`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Anchor {
    pub frame: String,
    pub section: Option<String>,
    pub base: u64,
    /// Distinct (target, proposed base) pairs agreeing with `base`.
    pub votes: u32,
    /// Distinct pairs proposing another base.
    pub dissent: u32,
    pub source: AnchorSource,
}

/// Result of [`compare_module`]: one [`Comparison`] per placement, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ModuleComparison {
    pub functions: Vec<Comparison>,
    pub anchors: Vec<Anchor>,
    pub warnings: Vec<String>,
}
