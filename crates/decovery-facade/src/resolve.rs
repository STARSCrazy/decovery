//! Turning user input (name, address, file offset) into an analyzed function.

use decovery_core::{
    Address, AddressInput, Analysis, Confidence, RebuildRecord, SegmentConfig, Symbol, Workspace,
};

use crate::{FacadeError, Session};

/// A resolved target: the function's start and the address that was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolved {
    pub function: Address,
    pub requested: Address,
}

/// Resolves `input` (`file:0x…`, canonical address, or a name) to the analyzed function containing it.
pub fn resolve(session: &Session, input: &str) -> Result<Resolved, FacadeError> {
    let requested = locate(session, input)?;
    let index = session.analysis.index();
    match index.function_containing(requested) {
        Some(f) => Ok(Resolved {
            function: f.start,
            requested,
        }),
        None => Err(FacadeError::NotInFunction {
            address: requested,
            nearest: nearest(session, requested),
        }),
    }
}

/// The address `input` stands for (`file:0x…`, canonical address, or a name), checked against the memory map.
pub(crate) fn locate(session: &Session, input: &str) -> Result<Address, FacadeError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(FacadeError::Invalid("empty target".into()));
    }
    let requested = if input.contains(':') {
        match input
            .parse::<AddressInput>()
            .map_err(|e| FacadeError::Invalid(e.to_string()))?
        {
            AddressInput::Address(a) => a,
            AddressInput::FileOffset(off) => from_file_offset(session, off)?,
        }
    } else {
        match address_of_name(session, input) {
            Err(FacadeError::NotFound(_)) if bare_hex(input).is_some() => {
                address_of_bare_offset(session, input)?
            }
            other => other?,
        }
    };
    check_overlay(session, requested)?;
    if segment_of(session, requested).is_none() {
        return Err(FacadeError::OutsideMap(requested));
    }
    Ok(requested)
}

/// The configured segment containing `at`.
pub(crate) fn segment_of(session: &Session, at: Address) -> Option<&SegmentConfig> {
    session
        .workspace
        .config
        .target
        .segments
        .iter()
        .find(|s| in_segment(s, at))
}

fn address_of_name(session: &Session, name: &str) -> Result<Address, FacadeError> {
    if let Some(s) = session
        .workspace
        .symbols
        .iter()
        .find(|s| s.confidence != Confidence::Refuted && !s.name.is_empty() && s.name == name)
    {
        return Ok(s.address);
    }
    if let Some(f) = session
        .analysis
        .functions
        .iter()
        .find(|f| f.provider_name.as_deref() == Some(name))
    {
        return Ok(f.start);
    }
    if let Some(a) = crate::session::parse_default_name(name) {
        return Ok(a);
    }
    Err(FacadeError::NotFound(name.to_string()))
}

/// The value of a bare hexadecimal target (`9D6B`, `0x9D6B`): 1 to 8 hex digits.
fn bare_hex(input: &str) -> Option<u32> {
    let digits = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    (digits.len() <= 8 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(digits, 16).ok())
        .flatten()
}

/// The offset part of a function start: a segment offset (also of an overlay) or the flat address itself.
fn offset_part(a: Address) -> u32 {
    match a {
        Address::Flat(v) => v,
        Address::Seg { off, .. } | Address::Ovl { off, .. } => u32::from(off),
        Address::Sel { off, .. } => off,
        _ => 0,
    }
}

/// The function whose start has the offset `input` (bare hex) in the main program or any overlay. Several are
/// an error listing their full addresses with names.
fn address_of_bare_offset(session: &Session, input: &str) -> Result<Address, FacadeError> {
    let value = bare_hex(input).ok_or_else(|| FacadeError::NotFound(input.to_string()))?;
    let mut found: Vec<Address> = session
        .analysis
        .functions
        .iter()
        .map(|f| f.start)
        .filter(|a| offset_part(*a) == value)
        .collect();
    found.sort();
    found.dedup();
    match found.as_slice() {
        [] => Err(FacadeError::NotFound(input.to_string())),
        [one] => Ok(*one),
        many => {
            let listed: Vec<String> = many
                .iter()
                .map(|a| format!("{} ({a})", session.name_of(*a).name))
                .collect();
            Err(FacadeError::Invalid(format!(
                "{input} is ambiguous: {}; give the full address",
                listed.join(", ")
            )))
        }
    }
}

fn from_file_offset(session: &Session, off: u64) -> Result<Address, FacadeError> {
    // `file:` offsets are offsets in the main program's file; overlay segments hold offsets in their own files.
    for seg in &session.workspace.config.target.segments {
        let Some(start) = seg.file_offset.filter(|_| seg.start.overlay().is_none()) else {
            continue;
        };
        let len = seg.file_length.unwrap_or(seg.length);
        if off >= start
            && off - start < len
            && off - start < seg.length
            && let Ok(delta) = i64::try_from(off - start)
            && let Ok(a) = seg.start.offset_by(delta)
        {
            return Ok(a);
        }
    }
    Err(FacadeError::Invalid(format!(
        "file offset {off:#x} is not in any segment"
    )))
}

/// The address a function name stands for, before the analysis is asked: an exact name of the knowledge (active
/// symbol) or of the analysis wins; else the rebuild records of that name and the overlay-qualified knowledge names
/// `<OVERLAY>_<name>` of a function in that overlay (how Decomp names each overlay's copy of `ovmain`). Several
/// such candidates are an error that lists them. `None` when nothing matches.
pub fn function_by_name(
    ws: &Workspace,
    analysis: Option<&Analysis>,
    rebuild: &[RebuildRecord],
    name: &str,
) -> Result<Option<Address>, FacadeError> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(None);
    }
    let active = |s: &&Symbol| s.confidence != Confidence::Refuted && !s.name.is_empty();
    if let Some(s) = ws.symbols.iter().filter(active).find(|s| s.name == name) {
        return Ok(Some(s.address));
    }
    if let Some(f) = analysis
        .into_iter()
        .flat_map(|a| &a.functions)
        .find(|f| f.provider_name.as_deref() == Some(name))
    {
        return Ok(Some(f.start));
    }
    let mut candidates: Vec<Address> = Vec::new();
    let records = rebuild.iter().filter(|r| r.name == name).map(|r| r.address);
    let qualified = ws.symbols.iter().filter(active).filter_map(|s| {
        let overlay = s.address.overlay()?;
        (s.name.strip_prefix(overlay.as_str())?.strip_prefix('_')? == name).then_some(s.address)
    });
    for a in records.chain(qualified) {
        if !candidates.contains(&a) {
            candidates.push(a);
        }
    }
    match candidates.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        many => {
            let listed: Vec<String> = many
                .iter()
                .map(|a| {
                    let shown = ws
                        .symbols
                        .iter()
                        .filter(active)
                        .find(|s| s.address == *a)
                        .map_or_else(|| crate::session::default_name(*a), |s| s.name.clone());
                    format!("{shown} ({a})")
                })
                .collect();
            Err(FacadeError::Invalid(format!(
                "{name} is ambiguous: {}; give the full name or the address",
                listed.join(", ")
            )))
        }
    }
}

pub(crate) fn in_segment(seg: &SegmentConfig, at: Address) -> bool {
    at.bytes_from(seg.start).is_some_and(|d| d < seg.length)
}

/// An `ovl:` address must name a configured overlay.
fn check_overlay(session: &Session, at: Address) -> Result<(), FacadeError> {
    let Some(name) = at.overlay() else {
        return Ok(());
    };
    let known = &session.workspace.config.overlays;
    if known.iter().any(|o| o.name == name) {
        return Ok(());
    }
    let names: Vec<&str> = known.iter().map(|o| o.name.as_str()).collect();
    Err(FacadeError::Invalid(format!(
        "unknown overlay {name} in {at} (known overlays: {})",
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(", ")
        }
    )))
}

/// The analyzed function with the smallest distance to `at`, with its display name.
fn nearest(session: &Session, at: Address) -> Option<(Address, String)> {
    session
        .analysis
        .functions
        .iter()
        .filter_map(|f| {
            let distance = match f.start.bytes_from(at) {
                Some(d) => d,
                None => at
                    .bytes_from(f.end)
                    .or_else(|| f.end.bytes_from(at).map(|_| 0))?,
            };
            Some((distance, f.start))
        })
        .min()
        .map(|(_, start)| (start, session.name_of(start).name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unnamed_symbol_is_not_found_by_empty_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("knowledge")).unwrap();
        std::fs::write(
            dir.path().join("decovery.toml"),
            "schema = 1

[target]
file = \"t.exe\"
sha256 = \"aa\"
format = \"flat32\"
processor = \"x86\"
",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("knowledge/symbols.toml"),
            "schema = 1

[[symbol]]
address = \"flat:00010010\"
kind = \"label\"
name = \"\"
source = \"human\"
confidence = \"assumed\"
comment = \"only a comment\"
",
        )
        .unwrap();
        let session = Session::open_without_analysis(dir.path()).unwrap();
        assert_eq!(session.workspace.symbols.len(), 1);
        assert!(matches!(
            address_of_name(&session, ""),
            Err(FacadeError::NotFound(_))
        ));
    }

    #[test]
    fn unknown_overlay_name_is_named() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("decovery.toml"),
            "schema = 1

[target]
file = \"t.exe\"
sha256 = \"aa\"
format = \"mz\"
processor = \"x86\"

[[target.segment]]
name = \"VINIT.code\"
start = \"ovl:VINIT:0000:5000\"
length = 256
file_offset = 14
permissions = \"rx\"

[[overlay]]
name = \"VINIT\"
file = \"VINIT.OVR\"
sha256 = \"bb\"
format = \"aztec-c86\"
size = 270

[[overlay]]
name = \"VBASE\"
file = \"VBASE.OVR\"
sha256 = \"cc\"
format = \"aztec-c86\"
size = 270
",
        )
        .unwrap();
        let session = Session::open_without_analysis(dir.path()).unwrap();
        let Err(FacadeError::Invalid(message)) = locate(&session, "ovl:NOPE:0000:5000") else {
            panic!("unknown overlay accepted");
        };
        assert!(
            message.contains("NOPE") && message.contains("VINIT, VBASE"),
            "{message}"
        );
        assert!(locate(&session, "ovl:vinit:0000:5010").is_ok());
        assert!(matches!(
            locate(&session, "ovl:VINIT:0000:5100"),
            Err(FacadeError::OutsideMap(_))
        ));
        // the overlay's window is not part of the main program and vice versa
        assert!(matches!(
            locate(&session, "ovl:VBASE:0000:5010"),
            Err(FacadeError::OutsideMap(_))
        ));
        assert!(matches!(
            locate(&session, "seg:0000:5010"),
            Err(FacadeError::OutsideMap(_))
        ));
        // `file:` offsets belong to the main program's file, not to an overlay file
        assert!(matches!(
            locate(&session, "file:0x10"),
            Err(FacadeError::Invalid(_))
        ));
    }
}
