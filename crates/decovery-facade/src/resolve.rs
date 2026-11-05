//! Turning user input (name, address, file offset) into an analyzed function.

use decovery_core::{Address, AddressInput, Confidence, SegmentConfig};

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
        address_of_name(session, input)?
    };
    if !session
        .workspace
        .config
        .target
        .segments
        .iter()
        .any(|s| in_segment(s, requested))
    {
        return Err(FacadeError::OutsideMap(requested));
    }
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

fn from_file_offset(session: &Session, off: u64) -> Result<Address, FacadeError> {
    for seg in &session.workspace.config.target.segments {
        let Some(start) = seg.file_offset else {
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

pub(crate) fn in_segment(seg: &SegmentConfig, at: Address) -> bool {
    match (seg.start, at) {
        (
            Address::Sel {
                segment: s,
                off: base,
            },
            Address::Sel { segment, off },
        ) => s == segment && off >= base && u64::from(off - base) < seg.length,
        (Address::Sel { .. }, _) | (_, Address::Sel { .. }) => false,
        (start, at) => match (start.linear(), at.linear()) {
            (Some(s), Some(a)) => a >= s && a - s < seg.length,
            _ => false,
        },
    }
}

/// The analyzed function with the smallest distance to `at`, with its display name.
fn nearest(session: &Session, at: Address) -> Option<(Address, String)> {
    let target = at.linear()?;
    session
        .analysis
        .functions
        .iter()
        .filter_map(|f| {
            let (start, end) = (f.start.linear()?, f.end.linear()?);
            let distance = if target < start {
                start - target
            } else {
                target.saturating_sub(end)
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
}
