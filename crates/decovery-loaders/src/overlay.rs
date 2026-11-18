//! Aztec C86 overlays (`*.OVR`): files the main program's `ovloader` reads into a fixed window of its own code and
//! data segments at run time (ADR 0011).
//!
//! Layout (the compiler's `OVLOADER.C`): a 14-byte header of seven little-endian words — magic `0xF2`, `corg`,
//! `csize`, `dorg`, `dsize`, `bss`, `entry` — then `csize` bytes of code (loaded at `CS:corg`) and `dsize` bytes of
//! data (at `DS:dorg`); `bss` zero bytes follow the data. No relocations: small model, the main program's CS and DS.

use crate::LoadError;

/// Magic word of an Aztec C86 overlay.
pub const OVERLAY_MAGIC: u16 = 0xF2;
/// Size of the overlay header.
pub const OVERLAY_HEADER: usize = 14;

/// The overlay header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OverlayHeader {
    pub corg: u16,
    pub csize: u16,
    pub dorg: u16,
    pub dsize: u16,
    pub bss: u16,
    pub entry: u16,
}

/// A read overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Overlay {
    pub name: String,
    pub header: OverlayHeader,
    pub code: Vec<u8>,
    pub data: Vec<u8>,
}

impl OverlayHeader {
    /// File offset of the code.
    pub fn code_offset(&self) -> u64 {
        OVERLAY_HEADER as u64
    }

    /// File offset of the data.
    pub fn data_offset(&self) -> u64 {
        OVERLAY_HEADER as u64 + u64::from(self.csize)
    }
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Reads an overlay. Errors name the byte offset of the offending header field or of the missing bytes.
pub fn read_overlay(bytes: &[u8], name: &str) -> Result<Overlay, LoadError> {
    if bytes.len() < OVERLAY_HEADER {
        return Err(LoadError::Truncated {
            offset: 0,
            needed: OVERLAY_HEADER,
        });
    }
    if word(bytes, 0) != OVERLAY_MAGIC {
        return Err(LoadError::BadMagic { offset: 0 });
    }
    let header = OverlayHeader {
        corg: word(bytes, 2),
        csize: word(bytes, 4),
        dorg: word(bytes, 6),
        dsize: word(bytes, 8),
        bss: word(bytes, 10),
        entry: word(bytes, 12),
    };
    let code_end = OVERLAY_HEADER + usize::from(header.csize);
    let data_end = code_end + usize::from(header.dsize);
    if bytes.len() < code_end {
        return Err(LoadError::Truncated {
            offset: OVERLAY_HEADER as u64,
            needed: usize::from(header.csize),
        });
    }
    if bytes.len() < data_end {
        return Err(LoadError::Truncated {
            offset: code_end as u64,
            needed: usize::from(header.dsize),
        });
    }
    if u32::from(header.corg) + u32::from(header.csize) > 0x1_0000 {
        return Err(LoadError::Malformed {
            offset: 2,
            detail: format!(
                "code {:#06x}+{:#x} runs past the 64 KiB segment",
                header.corg, header.csize
            ),
        });
    }
    if u32::from(header.dorg) + u32::from(header.dsize) + u32::from(header.bss) > 0x1_0000 {
        return Err(LoadError::Malformed {
            offset: 6,
            detail: format!(
                "data {:#06x}+{:#x} and BSS {:#x} run past the 64 KiB segment",
                header.dorg, header.dsize, header.bss
            ),
        });
    }
    if !(u32::from(header.corg)..u32::from(header.corg) + u32::from(header.csize))
        .contains(&u32::from(header.entry))
    {
        return Err(LoadError::Malformed {
            offset: 12,
            detail: format!(
                "entry {:#06x} is outside the code {:#06x}+{:#x}",
                header.entry, header.corg, header.csize
            ),
        });
    }
    Ok(Overlay {
        name: name.to_string(),
        header,
        code: bytes[OVERLAY_HEADER..code_end].to_vec(),
        data: bytes[code_end..data_end].to_vec(),
    })
}

/// Reads several overlays; a bad one gives its error and does not stop the others.
pub fn read_overlays<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Vec<(String, Result<Overlay, LoadError>)> {
    files
        .into_iter()
        .map(|(name, bytes)| (name.to_string(), read_overlay(bytes, name)))
        .collect()
}

/// `ovloader_` of the Aztec runtime (`OVLOADER.C`): `mov bx,sp; mov ax,[bx+2]; mov [ovname],ax; call _ovld;
/// jmp ax`. `None` = any byte.
const OVLOADER: [Option<u8>; 13] = [
    Some(0x8B),
    Some(0xDC),
    Some(0x8B),
    Some(0x47),
    Some(0x02),
    Some(0xA3),
    None,
    None,
    Some(0xE8),
    Some(0x02),
    Some(0x00),
    Some(0xFF),
    Some(0xE0),
];

/// Offset of the overlay loader `ovloader_` in `code` (the main program's code segment) when it occurs exactly
/// once.
pub fn find_overlay_loader(code: &[u8]) -> Option<u32> {
    let mut hits = code.windows(OVLOADER.len()).enumerate().filter(|(_, w)| {
        w.iter()
            .zip(OVLOADER.iter())
            .all(|(b, p)| p.is_none_or(|p| p == *b))
    });
    let (first, _) = hits.next()?;
    if hits.next().is_some() {
        return None;
    }
    u32::try_from(first).ok()
}

/// The data segment the Aztec startup code loads (`mov bp, <segment>` at the entry point `CS:IP` of the load
/// image `image`), relative to the load segment.
pub fn aztec_data_segment(image: &[u8], cs: u16, ip: u16) -> Option<u16> {
    let at = usize::from(cs) * 16 + usize::from(ip);
    match image.get(at..at + 3)? {
        [0xBD, lo, hi] => Some(u16::from_le_bytes([*lo, *hi])),
        _ => None,
    }
}
