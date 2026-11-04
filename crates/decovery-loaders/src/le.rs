//! LE/LX reader (DOS/4GW and relatives): objects with fixups applied.
//!
//! Port of Decomp's `formate/le.py` (`lese_le`, `_setzen`, `kopfdaten`, `rohfixups`). Differences are limited
//! to malformed input, which returns an error with the offset instead of raising or reading silently short.

use std::collections::HashSet;

use decovery_core::{
    Address, ArchMode, ExecutableFormat, Permissions, Program, Region, RelocKind, Relocation,
};

use crate::LoadError;

/// Largest single object accepted; guards against allocating gigabytes for a corrupt header.
const MAX_OBJECT_BYTES: u64 = 256 << 20;
/// Largest sum of all object sizes accepted.
const MAX_TOTAL_BYTES: u64 = 512 << 20;

/// A loaded LE image with Decomp-compatible diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LeImage {
    pub program: Program,
    pub header: LeHeader,
    /// Every fixup table entry in table order (page by page). Diagnostics and tests only; empty when the
    /// table uses features the raw reader does not handle (a warning says why).
    pub raw_fixups: Vec<RawFixup>,
    pub warnings: Vec<String>,
}

/// Selected LE header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LeHeader {
    /// File offset of the LE/LX header (`e_lfanew`).
    pub le_offset: u64,
    pub page_size: u32,
    pub last_page_size: u32,
    pub object_count: u32,
    pub entry: Address,
    pub stack: Address,
}

/// One entry of the fixup record table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RawFixup {
    /// 1-based page the record is stored for.
    pub page: u32,
    /// 1-based source object.
    pub object: u32,
    /// Source offset inside the object; negative when the field starts on the previous page.
    pub offset: i32,
    /// LE source type (low nibble of the source byte).
    pub source_type: u8,
    pub target_object: u32,
    pub target_offset: u32,
    /// Target offset stored in 16 bits.
    pub short_target: bool,
    /// Size of the entry in the table in bytes.
    pub length: u32,
}

/// Bounds-checked little-endian reads over the input.
struct Input<'a> {
    bytes: &'a [u8],
}

impl<'a> Input<'a> {
    fn get(&self, offset: u64, len: usize) -> Result<&'a [u8], LoadError> {
        let truncated = LoadError::Truncated {
            offset,
            needed: len,
        };
        let start = usize::try_from(offset).map_err(|_| truncated.clone())?;
        let end = start.checked_add(len).ok_or_else(|| truncated.clone())?;
        self.bytes.get(start..end).ok_or(truncated)
    }

    fn u8(&self, offset: u64) -> Result<u8, LoadError> {
        Ok(self.get(offset, 1)?[0])
    }

    fn u16(&self, offset: u64) -> Result<u16, LoadError> {
        let b = self.get(offset, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn i16(&self, offset: u64) -> Result<i16, LoadError> {
        self.u16(offset).map(|v| v as i16)
    }

    fn u32(&self, offset: u64) -> Result<u32, LoadError> {
        let b = self.get(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Header access and the table locations shared by the object and fixup readers.
struct Header<'a> {
    input: Input<'a>,
    /// File offset of the LE/LX header.
    base: u64,
    is_lx: bool,
}

impl<'a> Header<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, LoadError> {
        if bytes.len() >= 2 && !matches!(&bytes[..2], b"MZ" | b"ZM") {
            return Err(LoadError::BadMagic { offset: 0 });
        }
        if bytes.len() < 0x40 {
            return Err(LoadError::Truncated {
                offset: 0,
                needed: 0x40,
            });
        }
        let input = Input { bytes };
        let base = u64::from(input.u32(0x3C)?);
        let magic = input.get(base, 2)?;
        if magic != b"LE" && magic != b"LX" {
            return Err(LoadError::BadMagic { offset: base });
        }
        input.get(base, 0xAC)?;
        Ok(Header {
            input,
            base,
            is_lx: magic == b"LX",
        })
    }

    /// Field at `offset` inside the LE header.
    fn field(&self, offset: u64) -> Result<u32, LoadError> {
        self.input.u32(self.base + offset)
    }

    /// File offset of a table given by its header-relative offset; the table must lie inside the file.
    fn table(&self, name: &str, relative: u32, len: u64) -> Result<u64, LoadError> {
        let start = self.base + u64::from(relative);
        if relative == 0 {
            return Err(LoadError::Unsupported(format!(
                "LE: {name} offset is zero (header offset {:#x})",
                self.base
            )));
        }
        let end = start.saturating_add(len);
        if end > self.input.bytes.len() as u64 {
            return Err(LoadError::Truncated {
                offset: start,
                needed: usize::try_from(len).unwrap_or(usize::MAX),
            });
        }
        Ok(start)
    }
}

struct ObjectEntry {
    number: u32,
    base: u32,
    size: u32,
    flags: u32,
    first_page: u32,
    page_count: u32,
}

/// (type, width) of the supported fixup source types.
fn fixup_shape(source_type: u8) -> Option<(RelocKind, u8)> {
    Some(match source_type {
        0x02 => (RelocKind::Selector, 2),
        0x03 => (RelocKind::FarPointer, 4),
        0x05 => (RelocKind::Absolute, 2),
        0x06 => (RelocKind::FarPointer, 6),
        0x07 => (RelocKind::Absolute, 4),
        0x08 => (RelocKind::Relative, 4),
        _ => return None,
    })
}

/// Loads an LE/LX executable: objects with all fixups applied, one region per object.
pub fn load_le(bytes: &[u8]) -> Result<LeImage, LoadError> {
    let h = Header::new(bytes)?;
    let input = &h.input;
    let page_count = u64::from(h.field(0x14)?);
    let page_size = h.field(0x28)?;
    if !(0x10..=0x10000).contains(&page_size) {
        return Err(LoadError::Unsupported(format!(
            "LE: implausible page size {page_size:#x}"
        )));
    }
    let page = u64::from(page_size);
    let last_page_size = if h.is_lx { page_size } else { h.field(0x2C)? };
    let object_count = h.field(0x44)?;
    let object_table = h.table("object table", h.field(0x40)?, 24 * u64::from(object_count))?;
    let page_map_len = if h.is_lx { 8 } else { 4 } * page_count;
    let page_map = h.table("object page table", h.field(0x48)?, page_map_len)?;
    let fixup_page_table = h.table("fixup page table", h.field(0x68)?, 4 * (page_count + 1))?;
    let fixup_records = h.base + u64::from(h.field(0x6C)?);
    let data_pages = u64::from(h.field(0x80)?);
    let shift = if h.is_lx { h.field(0x2C)? } else { 0 };

    // File offset and length of 1-based page `i`.
    let page_location = |i: u64| -> Result<(u64, u64), LoadError> {
        if h.is_lx {
            let at = page_map + 8 * (i - 1);
            let (off, len, flags) = (
                u64::from(input.u32(at)?),
                u64::from(input.u16(at + 4)?),
                input.u16(at + 6)?,
            );
            if flags != 0 {
                return Err(LoadError::Unsupported(format!(
                    "LX: page {i} is packed or special (flags {flags:#x}); not supported (offset {at:#x})"
                )));
            }
            let shifted = off
                .checked_shl(shift)
                .filter(|_| shift <= 32)
                .ok_or_else(|| {
                    LoadError::Unsupported(format!("LX: page shift {shift} out of range"))
                })?;
            Ok((data_pages.saturating_add(shifted), len))
        } else {
            let at = page_map + 4 * (i - 1);
            let b = input.get(at, 3)?;
            let number = u64::from(b[0]) << 16 | u64::from(b[1]) << 8 | u64::from(b[2]);
            if number == 0 || number > page_count {
                return Err(LoadError::Unsupported(format!(
                    "LE: page {i} maps to data page {number} of {page_count} (offset {at:#x})"
                )));
            }
            let len = if number == page_count {
                u64::from(last_page_size)
            } else {
                page
            };
            Ok((data_pages + (number - 1) * page, len))
        }
    };

    let mut entries = Vec::new();
    let mut contents: Vec<Vec<u8>> = Vec::new();
    let mut regions = Vec::new();
    // 1-based page -> (0-based object, offset of the page inside the object).
    let mut page_owner: Vec<Option<(usize, u64)>> =
        vec![None; usize::try_from(page_count).unwrap_or(0) + 1];
    let mut total = 0u64;
    for o in 0..u64::from(object_count) {
        let at = object_table + 24 * o;
        let entry = ObjectEntry {
            number: o as u32 + 1,
            size: input.u32(at)?,
            base: input.u32(at + 4)?,
            flags: input.u32(at + 8)?,
            first_page: input.u32(at + 12)?,
            page_count: input.u32(at + 16)?,
        };
        let (first, count) = (i64::from(entry.first_page), i64::from(entry.page_count));
        if first + count - 1 > page_count as i64 || (count != 0 && first == 0) {
            return Err(LoadError::Unsupported(format!(
                "LE: object {} refers to pages {first}..{} of {page_count} (offset {at:#x})",
                entry.number,
                first + count - 1
            )));
        }
        let size = u64::from(entry.size);
        total += size;
        if size > MAX_OBJECT_BYTES || total > MAX_TOTAL_BYTES {
            return Err(LoadError::Unsupported(format!(
                "LE: object {} of {size:#x} bytes exceeds the size limit (offset {at:#x})",
                entry.number
            )));
        }
        let mut buffer = vec![0u8; entry.size as usize];
        let mut locations = Vec::new();
        for j in 0..u64::from(entry.page_count) {
            let (off, len) = page_location(u64::from(entry.first_page) + j)?;
            let take = len.min(size.saturating_sub(j * page));
            let chunk = input.get(off, take as usize)?;
            if !chunk.is_empty() {
                let start = (j * page) as usize;
                buffer[start..start + chunk.len()].copy_from_slice(chunk);
            }
            page_owner[(u64::from(entry.first_page) + j) as usize] = Some((o as usize, j * page));
            locations.push(off);
        }
        let contiguous = locations
            .iter()
            .enumerate()
            .all(|(j, &off)| off == locations[0] + j as u64 * page);
        let mut region = Region::new(
            format!("obj{}", entry.number),
            Address::Flat(entry.base),
            size,
            Vec::new(),
            Permissions {
                read: entry.flags & 1 != 0,
                write: entry.flags & 2 != 0,
                execute: entry.flags & 4 != 0,
            },
            ArchMode::X86Flat32,
        );
        region.file_offset = locations.first().filter(|_| contiguous).copied();
        regions.push(region);
        contents.push(buffer);
        entries.push(entry);
    }

    let mut relocations = Vec::new();
    let mut applied: HashSet<u64> = HashSet::new();
    let mut warnings = Vec::new();
    for s in 1..=page_count {
        let von = u64::from(input.u32(fixup_page_table + 4 * (s - 1))?);
        let bis = u64::from(input.u32(fixup_page_table + 4 * (s - 1) + 4)?);
        let Some((o, page_start)) = page_owner[s as usize] else {
            continue;
        };
        if von == bis {
            continue;
        }
        let mut pos = fixup_records + von;
        let end = fixup_records + bis;
        if end > bytes.len() as u64 {
            return Err(LoadError::Truncated {
                offset: pos,
                needed: usize::try_from(bis.saturating_sub(von)).unwrap_or(usize::MAX),
            });
        }
        while pos < end {
            let source = input.u8(pos)?;
            let flags = input.u8(pos + 1)?;
            pos += 2;
            let source_type = source & 0x0F;
            if flags & 3 != 0 {
                warnings.push(format!(
                    "page {s}: import fixups not supported, rest of page skipped"
                ));
                break;
            }
            let Some((kind, width)) = fixup_shape(source_type) else {
                warnings.push(format!(
                    "page {s}: unknown fixup type {source_type:#x}, rest of page skipped"
                ));
                break;
            };
            let mut count = 0u64;
            let mut offsets = Vec::new();
            if source & 0x20 != 0 {
                count = u64::from(input.u8(pos)?);
                pos += 1;
            } else {
                offsets.push(input.i16(pos)?);
                pos += 2;
            }
            let target_object = if flags & 0x40 != 0 {
                pos += 2;
                u32::from(input.u16(pos - 2)?)
            } else {
                pos += 1;
                u32::from(input.u8(pos - 1)?)
            };
            let mut target_offset = 0u32;
            if source_type != 0x02 {
                if flags & 0x10 != 0 {
                    target_offset = input.u32(pos)?;
                    pos += 4;
                } else {
                    target_offset = u32::from(input.u16(pos)?);
                    pos += 2;
                }
            }
            if source & 0x20 != 0 {
                for i in 0..count {
                    offsets.push(input.i16(pos + 2 * i)?);
                }
                pos += 2 * count;
            }
            let Some(target_base) = usize::try_from(target_object)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|n| entries.get(n))
                .map(|e| e.base)
            else {
                warnings.push(format!(
                    "page {s}: fixup to unknown object {target_object} skipped"
                ));
                continue;
            };
            let target = u64::from(target_base) + u64::from(target_offset);
            for q in offsets {
                let in_object = page_start as i64 + i64::from(q);
                let object_base = u64::from(entries[o].base);
                let address = object_base as i64 + in_object;
                let fits = in_object >= 0
                    && in_object <= contents[o].len() as i64 - i64::from(width)
                    && address <= i64::from(u32::MAX);
                if !fits || applied.contains(&(address as u64)) {
                    continue;
                }
                applied.insert(address as u64);
                apply(
                    &mut contents[o],
                    in_object as usize,
                    source_type,
                    target,
                    target_offset,
                    target_object,
                    address as u32,
                );
                relocations.push(Relocation::new(
                    Address::Flat(address as u32),
                    kind,
                    width,
                    Address::Flat(target as u32),
                    0,
                ));
            }
        }
    }

    let virtual_address = |object: u32, offset: u32, what: &str| -> Result<Address, LoadError> {
        usize::try_from(object)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| entries.get(n))
            .and_then(|e| e.base.checked_add(offset))
            .map(Address::Flat)
            .ok_or_else(|| {
                LoadError::Unsupported(format!(
                    "LE: {what} refers to object {object} offset {offset:#x}, image has {} objects",
                    entries.len()
                ))
            })
    };
    let entry = virtual_address(h.field(0x18)?, h.field(0x1C)?, "entry point")?;
    let stack = virtual_address(h.field(0x20)?, h.field(0x24)?, "stack")?;

    let raw_fixups = match read_raw_fixups(
        &h,
        &entries,
        page_count,
        fixup_page_table,
        fixup_records,
        page,
    ) {
        Ok(raw) => raw,
        Err(error) => {
            warnings.push(format!("raw fixup table not read: {error}"));
            Vec::new()
        }
    };

    for (region, data) in regions.iter_mut().zip(contents) {
        region.data = data;
    }
    Ok(LeImage {
        program: Program::new(ExecutableFormat::Le, regions, vec![entry], relocations),
        header: LeHeader {
            le_offset: h.base,
            page_size,
            last_page_size,
            object_count,
            entry,
            stack,
        },
        raw_fixups,
        warnings,
    })
}

/// Writes the fixed-up field exactly as Decomp's `_setzen` does (values truncated to the field width).
fn apply(
    buffer: &mut [u8],
    at: usize,
    source_type: u8,
    target: u64,
    target_offset: u32,
    target_object: u32,
    address: u32,
) {
    let mut put = |bytes: &[u8]| buffer[at..at + bytes.len()].copy_from_slice(bytes);
    match source_type {
        0x07 => put(&(target as u32).to_le_bytes()),
        0x08 => put(&(target as u32)
            .wrapping_sub(address.wrapping_add(4))
            .to_le_bytes()),
        0x02 => put(&(target_object as u16).to_le_bytes()),
        0x05 => put(&(target_offset as u16).to_le_bytes()),
        0x03 => {
            put(&(target_offset as u16).to_le_bytes()[..]);
            buffer[at + 2..at + 4].copy_from_slice(&(target_object as u16).to_le_bytes());
        }
        _ => {
            // 0x06 ptr16:32
            buffer[at..at + 4].copy_from_slice(&(target as u32).to_le_bytes());
            buffer[at + 4..at + 6].copy_from_slice(&(target_object as u16).to_le_bytes());
        }
    }
}

/// Port of `rohfixups`: all table entries in table order, without applying them.
fn read_raw_fixups(
    h: &Header<'_>,
    entries: &[ObjectEntry],
    page_count: u64,
    fixup_page_table: u64,
    fixup_records: u64,
    page: u64,
) -> Result<Vec<RawFixup>, LoadError> {
    let input = &h.input;
    let mut page_owner = vec![None; usize::try_from(page_count).unwrap_or(0) + 1];
    for e in entries {
        for j in 0..u64::from(e.page_count) {
            page_owner[(u64::from(e.first_page) + j) as usize] = Some((e.number, j * page));
        }
    }
    let unsupported = |s: u64, what: String, at: u64| {
        LoadError::Unsupported(format!("LE: page {s}: {what} (offset {at:#x})"))
    };
    let mut result = Vec::new();
    for s in 1..=page_count {
        let von = u64::from(input.u32(fixup_page_table + 4 * (s - 1))?);
        let bis = u64::from(input.u32(fixup_page_table + 4 * (s - 1) + 4)?);
        if von == bis {
            continue;
        }
        let Some((object, start)) = page_owner[s as usize] else {
            return Err(unsupported(
                s,
                "fixups on a page that belongs to no object".into(),
                fixup_records + von,
            ));
        };
        let mut pos = fixup_records + von;
        let end = fixup_records + bis;
        if end > input.bytes.len() as u64 {
            return Err(LoadError::Truncated {
                offset: pos,
                needed: usize::try_from(bis.saturating_sub(von)).unwrap_or(usize::MAX),
            });
        }
        while pos < end {
            let begin = pos;
            let source = input.u8(pos)?;
            let flags = input.u8(pos + 1)?;
            pos += 2;
            if flags & 0x03 != 0 {
                return Err(unsupported(
                    s,
                    "import fixups are not supported".into(),
                    begin,
                ));
            }
            if source & 0x20 != 0 {
                return Err(unsupported(
                    s,
                    "fixup source lists are not supported".into(),
                    begin,
                ));
            }
            if flags & !0x50 != 0 {
                return Err(unsupported(
                    s,
                    format!("fixup target flags {flags:#x} are not supported"),
                    begin,
                ));
            }
            let source_type = source & 0x0F;
            let q = i64::from(input.i16(pos)?);
            pos += 2;
            let target_object = if flags & 0x40 != 0 {
                pos += 2;
                u32::from(input.u16(pos - 2)?)
            } else {
                pos += 1;
                u32::from(input.u8(pos - 1)?)
            };
            let (mut target_offset, mut short_target) = (0u32, false);
            if source_type != 0x02 {
                if flags & 0x10 != 0 {
                    target_offset = input.u32(pos)?;
                    pos += 4;
                } else {
                    target_offset = u32::from(input.u16(pos)?);
                    short_target = true;
                    pos += 2;
                }
            }
            let offset = i32::try_from(start as i64 + q)
                .map_err(|_| unsupported(s, "source offset out of range".into(), begin))?;
            result.push(RawFixup {
                page: s as u32,
                object,
                offset,
                source_type,
                target_object,
                target_offset,
                short_target,
                length: (pos - begin) as u32,
            });
        }
    }
    Ok(result)
}
