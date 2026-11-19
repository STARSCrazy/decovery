//! A workspace opened together with its analysis.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use decovery_core::{
    Address, Analysis, Confidence, Provider, RebuildRecord, SegmentConfig, Symbol, TargetFormat,
    Workspace, read_rebuild,
};
use decovery_diff::{NameAt, SymbolView};

use crate::FacadeError;

/// Workspace, analysis and rebuild records, loaded once.
pub struct Session {
    pub workspace: Workspace,
    pub analysis: Analysis,
    pub rebuild: Vec<RebuildRecord>,
}

/// Name of the memory-map segment that [`add_uninitialized_data`] derives.
pub const UNINITIALIZED_SEGMENT: &str = "uninitialized";

/// The memory DOS allocates behind an MZ program's load image (`minalloc` paragraphs of the header: the
/// uninitialised data in DS, BSS, and the stack and heap after it) as a segment of the memory map, so globals there
/// can be named. It starts at the paragraph-aligned end of the load image (`seg:SSSS:000O` with the image length as
/// paragraph and offset) and has no file bytes. Nothing is added when the target is not MZ, its header cannot be
/// read, `minalloc` is 0, or a configured segment already holds the image end. Only the session sees it;
/// `decovery.toml` is not changed.
pub fn add_uninitialized_data(ws: &mut Workspace) {
    if ws.config.target.format != TargetFormat::Mz {
        return;
    }
    let path = crate::program::target_path(ws);
    let Some((header, file_len)) = read_mz_header(&path) else {
        return;
    };
    if header.min_alloc == 0 {
        return;
    }
    let (_, image_len) = decovery_loaders::mz_image_range(&header, file_len);
    let (Ok(seg), Ok(off)) = (u16::try_from(image_len >> 4), u16::try_from(image_len & 15)) else {
        return;
    };
    let start = Address::Seg { seg, off };
    let segments = &mut ws.config.target.segments;
    if segments
        .iter()
        .any(|s| crate::resolve::in_segment(s, start))
    {
        return;
    }
    segments.push(SegmentConfig::new(
        UNINITIALIZED_SEGMENT,
        start,
        u64::from(header.min_alloc) * 16,
        None,
        None,
        "rw",
    ));
}

fn read_mz_header(path: &Path) -> Option<(decovery_loaders::MzHeader, u64)> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let mut head = [0u8; 28];
    file.read_exact(&mut head).ok()?;
    Some((decovery_loaders::parse_mz_header(&head).ok()?, len))
}

/// The name shown for an address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisplayName {
    pub name: String,
    /// `true` for the generated `fun_XXXXXXXX` name.
    pub is_default: bool,
}

impl Session {
    /// Opens the workspace; fails if there is no analysis of this target.
    pub fn open(root: &Path) -> Result<Session, FacadeError> {
        let mut workspace = Workspace::open(root)?;
        add_uninitialized_data(&mut workspace);
        let analysis = Analysis::load(root)?.ok_or(FacadeError::NoAnalysis)?;
        check_target(&workspace, &analysis)?;
        let rebuild = read_rebuild(root)?;
        Ok(Session {
            workspace,
            analysis,
            rebuild,
        })
    }

    /// Opens the workspace for `analyze` and `annotate`: without a stored analysis the analysis is empty.
    pub fn open_without_analysis(root: &Path) -> Result<Session, FacadeError> {
        let mut workspace = Workspace::open(root)?;
        add_uninitialized_data(&mut workspace);
        let analysis = match Analysis::load(root)? {
            Some(analysis) => {
                check_target(&workspace, &analysis)?;
                analysis
            }
            None => Analysis::new(
                Provider::new("none", ""),
                workspace.config.target.sha256.clone(),
                "",
                "",
            ),
        };
        let rebuild = read_rebuild(root)?;
        Ok(Session {
            workspace,
            analysis,
            rebuild,
        })
    }

    /// Active symbol name at `at`, else the default name.
    pub fn name_of(&self, at: Address) -> DisplayName {
        match self.symbol_at(at) {
            Some(symbol) => DisplayName {
                name: symbol.name.clone(),
                is_default: false,
            },
            None => DisplayName {
                name: default_name(at),
                is_default: true,
            },
        }
    }

    /// The active (not refuted) symbol with a name at exactly `at`.
    pub fn symbol_at(&self, at: Address) -> Option<&Symbol> {
        self.workspace
            .symbols
            .iter()
            .find(|s| s.address == at && s.confidence != Confidence::Refuted && !s.name.is_empty())
    }

    /// The knowledge as names for comparisons: active symbols, default names for flat and real-mode addresses.
    pub fn symbol_view(&self) -> impl SymbolView + '_ {
        KnowledgeView::new(&self.workspace, Some(&self.analysis))
    }
}

/// Active (not refuted) names of a workspace's knowledge for comparisons ([`SymbolView`]). An address without a
/// name has its default name (`fun_0001A2B0`, `fun_1234_0010`); static segment addresses have none. A default name
/// resolves to its address; with an analysis that has functions, only when a function starts there. On a flat
/// target (LE, flat32) the default names of disassemblers for flat addresses resolve too, as the link resolves them:
/// `DAT_00041230` and `data_00041230` (data, any address) and `FUN_0001A2B0` (a function, under the same rule as
/// `fun_`).
pub struct KnowledgeView<'a> {
    by_address: BTreeMap<Address, &'a str>,
    by_name: BTreeMap<&'a str, Address>,
    function_starts: Option<BTreeSet<Address>>,
    /// Addresses with more than one distinct active name.
    shared: BTreeSet<Address>,
    flat: bool,
}

/// `DAT_`, `data_` or `FUN_` and eight hex digits: the flat address and whether the name is a function's.
/// `data_` is the name Decomp's assembler listings give unnamed data (`dd data_0005bcfa`).
pub(crate) fn parse_flat_default_name(name: &str) -> Option<(Address, bool)> {
    let (hex, function) = match name
        .strip_prefix("DAT_")
        .or_else(|| name.strip_prefix("data_"))
    {
        Some(hex) => (hex, false),
        None => (name.strip_prefix("FUN_")?, true),
    };
    (hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
        .map(|at| (Address::Flat(at), function))
}

impl<'a> KnowledgeView<'a> {
    /// The one name longer than `length` whose first `length` characters are `cut` (a name the compiler cut to
    /// `length` characters), with its address. `None` when `cut` is not that long or no or several names fit.
    pub fn address_of_cut(&self, cut: &str, length: usize) -> Option<(&'a str, Address)> {
        if cut.len() != length {
            return None;
        }
        let mut fits = self
            .by_name
            .range::<str, _>((std::ops::Bound::Included(cut), std::ops::Bound::Unbounded))
            .take_while(|(n, _)| n.starts_with(cut))
            .filter(|(n, _)| n.len() > length);
        let (&name, &at) = fits.next()?;
        fits.next().is_none().then_some((name, at))
    }

    /// Whether the target is flat (LE, flat32): only then do `DAT_` and `FUN_` default names resolve.
    pub fn is_flat(&self) -> bool {
        self.flat
    }

    pub fn new(workspace: &'a Workspace, analysis: Option<&Analysis>) -> Self {
        let mut by_address = BTreeMap::new();
        let mut shared = BTreeSet::new();
        for s in &workspace.symbols {
            if s.confidence != Confidence::Refuted && !s.name.is_empty() {
                let first = *by_address.entry(s.address).or_insert(s.name.as_str());
                if first != s.name {
                    shared.insert(s.address);
                }
            }
        }
        let mut by_name = BTreeMap::new();
        for (&address, &name) in &by_address {
            by_name.entry(name).or_insert(address);
        }
        let function_starts = analysis
            .filter(|a| !a.functions.is_empty())
            .map(|a| a.functions.iter().map(|f| f.start).collect());
        let flat = matches!(
            workspace.config.target.format,
            TargetFormat::Le | TargetFormat::Flat32
        );
        KnowledgeView {
            by_address,
            by_name,
            function_starts,
            shared,
            flat,
        }
    }

    /// The knowledge's one name of a function starting at `at`: its active name, else the default name where the
    /// analysis has a function start. `None` when several names share the address or nothing names a function
    /// there.
    pub fn function_name_at(&self, at: Address) -> Option<String> {
        if self.shared.contains(&at) {
            return None;
        }
        match self.by_address.get(&at) {
            Some(&name) => Some(name.to_string()),
            None => self
                .function_starts
                .as_ref()
                .is_some_and(|s| s.contains(&at))
                .then(|| default_name(at)),
        }
    }
}

impl SymbolView for KnowledgeView<'_> {
    fn name_at(&self, at: Address) -> Option<NameAt> {
        match self.by_address.get(&at) {
            Some(&name) => Some(NameAt::new(name, false)),
            None => match at {
                Address::Flat(_) | Address::Seg { .. } | Address::Ovl { .. } => {
                    Some(NameAt::new(default_name(at), true))
                }
                _ => None,
            },
        }
    }

    fn address_of(&self, name: &str) -> Option<Address> {
        if let Some(&at) = self.by_name.get(name) {
            return Some(at);
        }
        let (at, function) = match parse_default_name(name) {
            Some(at) => (at, true),
            None if self.flat => parse_flat_default_name(name)?,
            None => return None,
        };
        let starts_function = !function
            || self
                .function_starts
                .as_ref()
                .is_none_or(|starts| starts.contains(&at));
        starts_function.then_some(at)
    }
}

fn check_target(workspace: &Workspace, analysis: &Analysis) -> Result<(), FacadeError> {
    if analysis.target_sha256 == workspace.config.target.sha256 {
        Ok(())
    } else {
        Err(FacadeError::AnalysisOfOtherTarget {
            expected: workspace.config.target.sha256.clone(),
            found: analysis.target_sha256.clone(),
        })
    }
}

/// Decomp's `standardname`: `fun_` plus the address text without its prefix, `:` as `_`
/// (`fun_0001A2B0`, `fun_1234_0010`, `fun_0007_00001234`, `fun_VINIT_0000_505E`).
pub(crate) fn default_name(at: Address) -> String {
    let text = at.to_string();
    let short = text.split_once(':').map_or(text.as_str(), |(_, rest)| rest);
    format!("fun_{}", short.replace(':', "_"))
}

/// The address a default name stands for (inverse of [`default_name`]).
pub fn parse_default_name(name: &str) -> Option<Address> {
    let rest = name.strip_prefix("fun_")?;
    let hex = |t: &str, n: usize| {
        (t.len() == n && t.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| u32::from_str_radix(t, 16).ok())
            .flatten()
    };
    let parts: Vec<&str> = rest.split('_').collect();
    match parts.as_slice() {
        [a] => Some(Address::Flat(hex(a, 8)?)),
        [s, o] if o.len() == 4 => Some(Address::Seg {
            seg: u16::try_from(hex(s, 4)?).ok()?,
            off: u16::try_from(hex(o, 4)?).ok()?,
        }),
        [s, o] => Some(Address::Sel {
            segment: u16::try_from(hex(s, 4)?).ok()?,
            off: hex(o, 8)?,
        }),
        [n, s, o] => Some(Address::Ovl {
            overlay: decovery_core::OverlayName::new(n).ok()?,
            seg: u16::try_from(hex(s, 4)?).ok()?,
            off: u16::try_from(hex(o, 4)?).ok()?,
        }),
        _ => None,
    }
}
