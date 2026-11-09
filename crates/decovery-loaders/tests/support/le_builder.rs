//! Synthetic LE images for tests (no proprietary data). Shared by the loader, toolchain and diff tests through
//! `#[path]`.

#![allow(dead_code)]

/// Page size of [`build_le`].
pub const PAGE: usize = 0x100;
/// Size of the LE header written by the builder.
pub const HEADER: usize = 0xAC;
/// File offset of the LE header (the stub is the 0x40 bytes before it).
pub const LE_OFFSET: usize = 0x40;

pub struct Obj {
    pub base: u32,
    pub flags: u32,
    pub data: Vec<u8>,
    /// Object size in memory; at least `data.len()` (0 = `data.len()`).
    pub size: u32,
}

impl Obj {
    pub fn new(base: u32, flags: u32, data: Vec<u8>) -> Self {
        Obj {
            base,
            flags,
            data,
            size: 0,
        }
    }

    fn virtual_size(&self) -> u32 {
        self.size.max(self.data.len() as u32)
    }
}

#[derive(Clone, Copy)]
pub struct Fix {
    /// 0-based source object.
    pub object: usize,
    /// Offset of the field inside the source object.
    pub offset: usize,
    /// LE source type (0x07 off32, 0x05 off16, 0x02 sel16, 0x08 rel32, ...).
    pub kind: u8,
    /// 1-based target object.
    pub target_object: u8,
    pub target_offset: u32,
}

impl Fix {
    pub fn new(
        object: usize,
        offset: usize,
        kind: u8,
        target_object: u8,
        target_offset: u32,
    ) -> Self {
        Fix {
            object,
            offset,
            kind,
            target_object,
            target_offset,
        }
    }
}

/// What the builder writes besides objects and fixups.
pub struct Le {
    pub page: usize,
    pub objects: Vec<Obj>,
    /// Fixup records in table order, page by page as given.
    pub fixups: Vec<Fix>,
    /// Auto data object (header 0x94; 0 = none).
    pub auto_data: u32,
    /// First entry of the resident name table.
    pub resident_name: Option<String>,
    /// Entry point: 1-based object and offset.
    pub entry: (u32, u32),
    /// Stack: 1-based object (0 = last object) and ESP.
    pub stack: (u32, u32),
    /// Byte 2 of the stub (anything to make two stubs differ).
    pub stub_mark: u8,
}

impl Le {
    pub fn new(objects: Vec<Obj>, fixups: Vec<Fix>) -> Self {
        Le {
            page: PAGE,
            objects,
            fixups,
            auto_data: 0,
            resident_name: None,
            entry: (1, 0x10),
            stack: (0, 0x40),
            stub_mark: 0,
        }
    }

    /// MZ stub + LE header + object table + page map + fixup page table + fixup records (+ resident names) +
    /// page data. The page data comes last, so every proper prefix of the image lacks needed bytes.
    pub fn build(&self) -> Vec<u8> {
        let page_size = self.page;
        let objects = &self.objects;
        let pages_of = |o: &Obj| o.data.len().div_ceil(page_size);
        let total_pages: usize = objects.iter().map(pages_of).sum();
        let last_page = {
            let rem = objects.last().map_or(0, |o| o.data.len() % page_size);
            if rem == 0 { page_size } else { rem }
        };

        let mut per_page: Vec<Vec<u8>> = vec![Vec::new(); total_pages];
        let mut first_page = Vec::new();
        let mut next = 0usize;
        for o in objects {
            first_page.push(next);
            next += pages_of(o);
        }
        for f in &self.fixups {
            let size = objects[f.object].data.len();
            let pages = pages_of(&objects[f.object]);
            let page = f.offset / page_size;
            let mut emit = |page: usize, q: i16| {
                let rec = &mut per_page[first_page[f.object] + page];
                rec.push(f.kind);
                rec.push(if f.kind == 0x02 { 0 } else { 0x10 });
                rec.extend_from_slice(&q.to_le_bytes());
                rec.push(f.target_object);
                if f.kind != 0x02 {
                    rec.extend_from_slice(&f.target_offset.to_le_bytes());
                }
            };
            let q = (f.offset % page_size) as i16;
            emit(page, q);
            if f.offset % page_size + width(f.kind) > page_size
                && page + 1 < pages
                && f.offset < size
            {
                emit(page + 1, q - page_size as i16);
            }
        }

        let k = LE_OFFSET;
        let obj_tab = HEADER;
        let page_map = obj_tab + 24 * objects.len();
        let fpt = page_map + 4 * total_pages;
        let frt = fpt + 4 * (total_pages + 1);
        let records: Vec<u8> = per_page.iter().flatten().copied().collect();
        let names = frt + records.len();
        let name_bytes: Vec<u8> = match &self.resident_name {
            Some(n) => {
                let mut v = vec![n.len() as u8];
                v.extend_from_slice(n.as_bytes());
                v.extend_from_slice(&[0, 0, 0]);
                v
            }
            None => Vec::new(),
        };
        let data_pages = k + names + name_bytes.len();

        let mut out = vec![0u8; k + HEADER];
        out[..2].copy_from_slice(b"MZ");
        out[2] = self.stub_mark;
        put32(&mut out, 0x3C, k as u32);
        let h = k;
        out[h..h + 2].copy_from_slice(b"LE");
        let stack_object = if self.stack.0 == 0 {
            objects.len() as u32
        } else {
            self.stack.0
        };
        put32(&mut out, h + 0x14, total_pages as u32);
        put32(&mut out, h + 0x18, self.entry.0);
        put32(&mut out, h + 0x1C, self.entry.1);
        put32(&mut out, h + 0x20, stack_object);
        put32(&mut out, h + 0x24, self.stack.1);
        put32(&mut out, h + 0x28, page_size as u32);
        put32(&mut out, h + 0x2C, last_page as u32);
        put32(
            &mut out,
            h + 0x30,
            records.len() as u32 + 4 * (total_pages as u32 + 1),
        );
        put32(&mut out, h + 0x40, obj_tab as u32);
        put32(&mut out, h + 0x44, objects.len() as u32);
        put32(&mut out, h + 0x48, page_map as u32);
        if !name_bytes.is_empty() {
            put32(&mut out, h + 0x58, names as u32);
        }
        put32(&mut out, h + 0x68, fpt as u32);
        put32(&mut out, h + 0x6C, frt as u32);
        put32(&mut out, h + 0x80, data_pages as u32);
        put32(&mut out, h + 0x94, self.auto_data);

        for (i, o) in objects.iter().enumerate() {
            for x in [
                o.virtual_size(),
                o.base,
                o.flags,
                first_page[i] as u32 + 1,
                pages_of(o) as u32,
                0,
            ] {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        for p in 1..=total_pages as u32 {
            out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8, 0]);
        }
        let mut cumulative = 0u32;
        out.extend_from_slice(&cumulative.to_le_bytes());
        for rec in &per_page {
            cumulative += rec.len() as u32;
            out.extend_from_slice(&cumulative.to_le_bytes());
        }
        out.extend_from_slice(&records);
        out.extend_from_slice(&name_bytes);
        assert_eq!(out.len(), data_pages);
        for o in objects {
            out.extend_from_slice(&o.data);
            out.resize(
                out.len() + o.data.len().next_multiple_of(page_size) - o.data.len(),
                0,
            );
        }
        // Trim the padding of the very last page down to the declared last page size.
        out.truncate(data_pages + (total_pages - 1) * page_size + last_page);
        out
    }
}

pub fn width(kind: u8) -> usize {
    match kind {
        0x02 | 0x05 => 2,
        0x03 | 0x07 | 0x08 => 4,
        0x06 => 6,
        _ => unreachable!(),
    }
}

pub fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

/// [`Le::build`] with the defaults.
pub fn build_le(objects: Vec<Obj>, fixups: &[Fix]) -> Vec<u8> {
    Le::new(objects, fixups.to_vec()).build()
}

pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}
