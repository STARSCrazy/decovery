//! MZ (DOS EXE) and COM loaders.

use decovery_core::{
    Address, ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};

use crate::LoadError;

const HEADER_LEN: usize = 28;
const COM_MAX: usize = 65_280;

/// The fixed 28-byte MZ header, fields in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MzHeader {
    pub last_page_bytes: u16,
    pub pages: u16,
    pub relocation_count: u16,
    pub header_paragraphs: u16,
    pub min_alloc: u16,
    pub max_alloc: u16,
    pub ss: u16,
    pub sp: u16,
    pub checksum: u16,
    pub ip: u16,
    pub cs: u16,
    pub relocation_table: u16,
    pub overlay: u16,
}

/// A loaded MZ file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MzImage {
    pub program: Program,
    pub header: MzHeader,
    /// File offset of the load image.
    pub image_offset: u64,
    pub image_len: u64,
    /// Bytes behind the load image (overlay data).
    pub trailing_len: u64,
    pub warnings: Vec<String>,
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Parses the header; accepts the magics `MZ` and `ZM`.
pub fn parse_mz_header(bytes: &[u8]) -> Result<MzHeader, LoadError> {
    if bytes.len() < 2 {
        return Err(LoadError::Truncated {
            offset: 0,
            needed: 2,
        });
    }
    if &bytes[..2] != b"MZ" && &bytes[..2] != b"ZM" {
        return Err(LoadError::BadMagic { offset: 0 });
    }
    if bytes.len() < HEADER_LEN {
        return Err(LoadError::Truncated {
            offset: 0,
            needed: HEADER_LEN,
        });
    }
    Ok(MzHeader {
        last_page_bytes: word(bytes, 2),
        pages: word(bytes, 4),
        relocation_count: word(bytes, 6),
        header_paragraphs: word(bytes, 8),
        min_alloc: word(bytes, 10),
        max_alloc: word(bytes, 12),
        ss: word(bytes, 14),
        sp: word(bytes, 16),
        checksum: word(bytes, 18),
        ip: word(bytes, 20),
        cs: word(bytes, 22),
        relocation_table: word(bytes, 24),
        overlay: word(bytes, 26),
    })
}

/// `(offset, len)` of the load image inside a file of `file_len` bytes.
pub fn mz_image_range(h: &MzHeader, file_len: u64) -> (u64, u64) {
    let offset = (u64::from(h.header_paragraphs) * 16).min(file_len);
    let short = if h.last_page_bytes == 0 {
        0
    } else {
        512 - u64::from(h.last_page_bytes).min(512)
    };
    let end = (u64::from(h.pages) * 512)
        .saturating_sub(short)
        .clamp(offset, file_len);
    (offset, end - offset)
}

fn rwx() -> Permissions {
    Permissions {
        read: true,
        write: true,
        execute: true,
    }
}

/// Loads an MZ executable. The region holds the image as stored; relocations are recorded, not applied.
pub fn load_mz(bytes: &[u8]) -> Result<MzImage, LoadError> {
    let header = parse_mz_header(bytes)?;
    let file_len = bytes.len() as u64;
    let (offset, len) = mz_image_range(&header, file_len);
    if u64::from(header.header_paragraphs) * 16 > file_len {
        return Err(LoadError::Truncated {
            offset: file_len,
            needed: usize::from(header.header_paragraphs) * 16 - bytes.len(),
        });
    }
    let image = &bytes[offset as usize..(offset + len) as usize];

    let mut relocations = Vec::with_capacity(usize::from(header.relocation_count));
    for i in 0..usize::from(header.relocation_count) {
        let entry = usize::from(header.relocation_table) + i * 4;
        if entry + 4 > bytes.len() {
            return Err(LoadError::Truncated {
                offset: entry as u64,
                needed: 4,
            });
        }
        let (off, seg) = (word(bytes, entry), word(bytes, entry + 2));
        let place = usize::from(seg) * 16 + usize::from(off);
        if place + 2 > image.len() {
            return Err(LoadError::Unsupported(format!(
                "relocation entry at file offset {entry:#x} points to {seg:04x}:{off:04x}, outside the {}-byte image",
                image.len()
            )));
        }
        relocations.push(Relocation::new(
            Address::Seg { seg, off },
            RelocKind::Selector,
            2,
            Address::Seg {
                seg: word(image, place),
                off: 0,
            },
            0,
        ));
    }

    let mut region = Region::new(
        "image",
        Address::Seg { seg: 0, off: 0 },
        len,
        image.to_vec(),
        rwx(),
        ArchMode::X86Real16,
    );
    region.file_offset = Some(offset);

    let trailing_len = file_len - offset - len;
    let mut warnings = Vec::new();
    if trailing_len > 0 {
        warnings.push(format!(
            "{trailing_len} bytes behind the load image (from file offset {:#x}) are not loaded",
            offset + len
        ));
    }
    let program = Program::new(
        ExecutableFormat::Mz,
        vec![region],
        vec![Address::Seg {
            seg: header.cs,
            off: header.ip,
        }],
        relocations,
    );
    Ok(MzImage {
        program,
        header,
        image_offset: offset,
        image_len: len,
        trailing_len,
        warnings,
    })
}

/// Loads a COM file at `seg:0000:0100`.
pub fn load_com(bytes: &[u8]) -> Result<Program, LoadError> {
    if bytes.len() > COM_MAX {
        return Err(LoadError::Unsupported(format!(
            "COM file of {} bytes exceeds the maximum of {COM_MAX}",
            bytes.len()
        )));
    }
    let start = Address::Seg { seg: 0, off: 0x100 };
    let mut region = Region::new(
        "image",
        start,
        bytes.len() as u64,
        bytes.to_vec(),
        rwx(),
        ArchMode::X86Real16,
    );
    region.file_offset = Some(0);
    Ok(Program::new(
        ExecutableFormat::Com,
        vec![region],
        vec![start],
        Vec::new(),
    ))
}
