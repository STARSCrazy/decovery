//! Symbol addresses proven by an identical `link`: when the linked program equals the original byte for byte,
//! every public of the linker's map lies at the same address in the original. Publics the knowledge base lacks
//! are recorded with source `link`; known names and occupied addresses are never changed.

use std::collections::{BTreeMap, HashMap, HashSet};

use decovery_core::{Address, Analysis, ClaimSource, Confidence, Symbol, SymbolKind};
use decovery_diff::Decoration;
use decovery_toolchain::{LinkMap, MapFormat, parse_tlink_map};

/// A public of the map that may be recorded.
pub(super) struct Candidate {
    name: String,
    address: Address,
    linear: u64,
    kind: SymbolKind,
    evidence: String,
}

/// The publics of `map` (in `format`) as candidates: undecorated names at `seg:` addresses, absolute symbols left
/// out. Kind: a data-class segment gives a global, a code-class segment a function where the analysis has a
/// function start, else a label; `other` when the map has no segment there. Names the map gives two addresses
/// and addresses it gives two names are left out with a hint. A map that does not read gives a hint and no
/// candidates.
pub(super) fn candidates(
    map: &[u8],
    format: MapFormat,
    file: &str,
    decoration: &Decoration,
    analysis: Option<&Analysis>,
    hints: &mut Vec<String>,
) -> Vec<Candidate> {
    let parsed: LinkMap = match format {
        MapFormat::Tlink => match parse_tlink_map(map) {
            Ok(parsed) => parsed,
            Err(e) => {
                hints.push(format!(
                    "{file}: {e}; no symbol addresses recorded from the map"
                ));
                return Vec::new();
            }
        },
        _ => return Vec::new(),
    };
    let starts: HashSet<u64> = analysis
        .map(|a| {
            a.functions
                .iter()
                .filter_map(|f| f.start.linear())
                .collect()
        })
        .unwrap_or_default();
    // one entry per name and per address; BTreeMap keeps the hints in a stable order
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut by_linear: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let publics: Vec<_> = parsed.publics.iter().filter(|p| !p.absolute).collect();
    for (i, p) in publics.iter().enumerate() {
        let linear = u64::from(p.seg) * 16 + u64::from(p.off);
        by_name
            .entry(decoration.undecorate(&p.name))
            .or_default()
            .push(i);
        by_linear.entry(linear).or_default().push(i);
    }
    let mut skip: HashSet<usize> = HashSet::new();
    for (name, list) in &by_name {
        if list.len() > 1 {
            hints.push(format!(
                "{file}: {name} is listed {} times; not recorded",
                list.len()
            ));
            skip.extend(list);
        }
    }
    for list in by_linear.values() {
        if list.len() > 1 {
            let names: Vec<&str> = list.iter().map(|&i| publics[i].name.as_str()).collect();
            let p = publics[list[0]];
            hints.push(format!(
                "{file}: {} share seg:{:04X}:{:04X}; not recorded",
                names.join(", "),
                p.seg,
                p.off
            ));
            skip.extend(list);
        }
    }
    publics
        .iter()
        .enumerate()
        .filter(|(i, p)| !skip.contains(i) && !p.name.is_empty())
        .map(|(_, p)| {
            let linear = u64::from(p.seg) * 16 + u64::from(p.off);
            let class = u32::try_from(linear)
                .ok()
                .and_then(|at| parsed.segment_at(at))
                .map(|s| s.class.to_ascii_uppercase());
            let kind = match class.as_deref() {
                Some(c) if c.ends_with("CODE") => {
                    if starts.contains(&linear) {
                        SymbolKind::Function
                    } else {
                        SymbolKind::Label
                    }
                }
                Some(c)
                    if ["DATA", "BSS", "CONST", "STACK"]
                        .iter()
                        .any(|d| c.ends_with(d)) =>
                {
                    SymbolKind::Global
                }
                _ => SymbolKind::Other,
            };
            Candidate {
                name: decoration.undecorate(&p.name).to_string(),
                address: Address::Seg {
                    seg: p.seg,
                    off: p.off,
                },
                linear,
                kind,
                evidence: format!(
                    "public {} in {file} line {} of a link identical to the original",
                    p.name, p.line
                ),
            }
        })
        .collect()
}

/// The candidates to add to `current`: not when the name is known (at this address: already recorded; elsewhere:
/// a hint) or the address holds another symbol (a hint). Addresses compare by linear address.
pub(super) fn additions(
    current: &[Symbol],
    candidates: &[Candidate],
    hints: &mut Vec<String>,
) -> Vec<Symbol> {
    let mut names: HashMap<&str, Vec<&Symbol>> = HashMap::new();
    let mut places: HashMap<u64, Vec<&Symbol>> = HashMap::new();
    for s in current {
        if s.confidence != Confidence::Refuted && !s.name.is_empty() {
            names.entry(s.name.as_str()).or_default().push(s);
        }
        if let Some(linear) = s.address.linear() {
            places.entry(linear).or_default().push(s);
        }
    }
    let mut added = Vec::new();
    for c in candidates {
        let known = names.get(c.name.as_str()).map_or(&[][..], Vec::as_slice);
        if known.iter().any(|s| s.address.linear() == Some(c.linear)) {
            continue;
        }
        if let Some(s) = known.first() {
            hints.push(format!(
                "{}: the link map places it at {}, the knowledge base at {}; not recorded",
                c.name, c.address, s.address
            ));
            continue;
        }
        if let Some(s) = places.get(&c.linear).and_then(|l| l.first()) {
            let held = if s.name.is_empty() {
                "an unnamed symbol".to_string()
            } else if s.name == c.name {
                format!("{} (refuted)", s.name)
            } else {
                s.name.clone()
            };
            hints.push(format!(
                "{}: the link map names it {}, the knowledge base holds {held} there; not recorded",
                c.address, c.name
            ));
            continue;
        }
        let mut symbol = Symbol::new(c.address, c.kind, c.name.clone());
        symbol.source = ClaimSource::Link;
        symbol.confidence = Confidence::Confirmed;
        symbol.evidence = Some(c.evidence.clone());
        added.push(symbol);
    }
    added
}
