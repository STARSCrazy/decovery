//! Why a linked LE program differs from the original (port of Decomp's `nachbau/le_vergleich.py`): stub, header
//! fields, object table, pages (with the first difference and whether the bytes there only lie shifted) and the
//! fixups per page (missing, extra, other target, only another order); else the first differing file offset.

use std::collections::BTreeMap;

use decovery_loaders::{LeImage, RawFixup, load_le};

/// Header fields compared, by offset inside the LE header.
const HEADER_FIELDS: [(u64, &str); 12] = [
    (0x10, "module flags"),
    (0x14, "page count"),
    (0x18, "entry object"),
    (0x1C, "entry"),
    (0x20, "stack object"),
    (0x24, "ESP"),
    (0x28, "page size"),
    (0x2C, "last page"),
    (0x30, "fixup section size"),
    (0x38, "loader section size"),
    (0x44, "object count"),
    (0x94, "auto data object"),
];
/// Bytes behind the first difference looked for shifted in the other file.
const WINDOW: usize = 32;
/// Largest shift looked for.
const MAX_SHIFT: usize = 64;

/// What makes two fixup records the same (the target offset width counts).
type FixupKey = (u32, i32, u8, u32, u32, bool);

fn fixup_key(f: &RawFixup) -> FixupKey {
    (
        f.object,
        f.offset,
        f.source_type,
        f.target_object,
        f.target_offset,
        f.short_target,
    )
}

/// The `u32` at `offset` of the LE header; 0 when the file is too short (both files loaded, so it is not).
fn header_field(file: &[u8], image: &LeImage, offset: u64) -> u32 {
    usize::try_from(image.header.le_offset + offset)
        .ok()
        .and_then(|at| file.get(at..at.checked_add(4)?))
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn part(v: &[u8], start: usize, end: usize) -> &[u8] {
    &v[start.min(v.len())..end.min(v.len())]
}

/// Lines naming why `rebuilt` differs from `original` (empty = equal): stub, header fields, per object its table
/// fields and its pages, the fixups per page, else the first differing file offset. `place(virtual address)` names
/// what lies at an address of the original; at most `max_lines` fixup lines (and pages listed) are given.
pub fn compare_le(
    original: &[u8],
    rebuilt: &[u8],
    place: &dyn Fn(u32) -> String,
    max_lines: usize,
) -> Vec<String> {
    let (a, b) = match (load_le(original), load_le(rebuilt)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return vec![format!("original is not an LE program: {e}")],
        (_, Err(e)) => return vec![format!("rebuilt is not an LE program: {e}")],
    };
    let mut lines = Vec::new();
    let (sa, sb) = (a.header.le_offset as usize, b.header.le_offset as usize);
    if part(original, 0, sa) != part(rebuilt, 0, sb) {
        lines.push(format!(
            "stub differs (original {sa} bytes, rebuilt {sb} bytes)"
        ));
    }
    let header: Vec<String> = HEADER_FIELDS
        .iter()
        .filter_map(|&(offset, name)| {
            let (x, y) = (
                header_field(original, &a, offset),
                header_field(rebuilt, &b, offset),
            );
            (x != y).then(|| format!("{name} {y:#x} instead of {x:#x}"))
        })
        .collect();
    if !header.is_empty() {
        lines.push(format!("header: {}", header.join(", ")));
    }
    let page = header_field(original, &a, 0x28) as usize;
    for ((oa, ob), (ra, rb)) in a
        .objects
        .iter()
        .zip(&b.objects)
        .zip(a.program.regions.iter().zip(&b.program.regions))
    {
        let fields: Vec<String> = [
            ("size", oa.size, ob.size),
            ("base", oa.base, ob.base),
            ("flags", oa.flags, ob.flags),
            ("file data", oa.file_length, ob.file_length),
        ]
        .iter()
        .filter(|(_, x, y)| x != y)
        .map(|(name, x, y)| format!("{name} {y:#x} instead of {x:#x}"))
        .collect();
        if !fields.is_empty() {
            lines.push(format!("object {}: {}", oa.number, fields.join(", ")));
        }
        lines.extend(pages(oa.number, oa.base, &ra.data, &rb.data, page, place));
    }
    lines.extend(fixups(&a, &b, place, max_lines));
    if lines.is_empty() && original != rebuilt {
        let first = original
            .iter()
            .zip(rebuilt)
            .position(|(x, y)| x != y)
            .unwrap_or(original.len().min(rebuilt.len()));
        let mut line = format!("file: first difference at file offset {first:#x}");
        if original.len() != rebuilt.len() {
            line.push_str(&format!(
                ", length {} instead of {}",
                rebuilt.len(),
                original.len()
            ));
        }
        lines.push(line);
    }
    lines
}

/// One line for an object whose pages differ: how many, the first difference and a shift of up to [`MAX_SHIFT`]
/// bytes found over a [`WINDOW`]-byte window.
fn pages(
    number: u32,
    base: u32,
    x: &[u8],
    y: &[u8],
    page: usize,
    place: &dyn Fn(u32) -> String,
) -> Option<String> {
    if page == 0 {
        return None;
    }
    let n = x.len().max(y.len());
    let differing: Vec<usize> = (0..n)
        .step_by(page)
        .filter(|&s| part(x, s, s + page) != part(y, s, s + page))
        .collect();
    let &first_page = differing.first()?;
    let d = first_page
        + part(x, first_page, n)
            .iter()
            .zip(part(y, first_page, n))
            .position(|(p, q)| p != q)
            .unwrap_or(x.len().min(y.len()).saturating_sub(first_page));
    let mut text = format!(
        "object {number}: {} of {} pages differ, first difference at {}",
        differing.len(),
        n.div_ceil(page),
        place(base.wrapping_add(d as u32))
    );
    for k in 1..=MAX_SHIFT {
        if x.len() > d + WINDOW && y.get(d + k..d + k + WINDOW) == Some(&x[d..d + WINDOW]) {
            text.push_str(&format!(", {k} bytes inserted from there (shift)"));
            break;
        }
        if y.len() > d + WINDOW && x.get(d + k..d + k + WINDOW) == Some(&y[d..d + WINDOW]) {
            text.push_str(&format!(", {k} bytes missing from there (shift)"));
            break;
        }
    }
    Some(text)
}

/// The fixup lines: a summary (pages with other content, pages only in another order), the order-only pages, then
/// per differing page every place that is missing, extra or targets something else (at most `max_lines`).
fn fixups(
    a: &LeImage,
    b: &LeImage,
    place: &dyn Fn(u32) -> String,
    max_lines: usize,
) -> Vec<String> {
    fn by_page(raw: &[RawFixup]) -> BTreeMap<u32, Vec<&RawFixup>> {
        let mut pages: BTreeMap<u32, Vec<&RawFixup>> = BTreeMap::new();
        for f in raw {
            pages.entry(f.page).or_default().push(f);
        }
        pages
    }
    let base: BTreeMap<u32, u32> = a.objects.iter().map(|o| (o.number, o.base)).collect();
    let (pa, pb) = (by_page(&a.raw_fixups), by_page(&b.raw_fixups));
    let mut all: Vec<u32> = pa.keys().chain(pb.keys()).copied().collect();
    all.sort_unstable();
    all.dedup();
    let (mut details, mut order_only, mut content) = (Vec::new(), Vec::new(), 0usize);
    for page in all {
        let (la, lb) = (
            pa.get(&page).map_or(&[][..], Vec::as_slice),
            pb.get(&page).map_or(&[][..], Vec::as_slice),
        );
        let mut ka: Vec<FixupKey> = la.iter().map(|f| fixup_key(f)).collect();
        let mut kb: Vec<FixupKey> = lb.iter().map(|f| fixup_key(f)).collect();
        if ka == kb {
            continue;
        }
        ka.sort_unstable();
        kb.sort_unstable();
        if ka == kb {
            order_only.push(page);
            continue;
        }
        content += 1;
        // a later record at the same place wins, as in a dictionary
        let ma: BTreeMap<(u32, i32), &RawFixup> =
            la.iter().map(|f| ((f.object, f.offset), *f)).collect();
        let mb: BTreeMap<(u32, i32), &RawFixup> =
            lb.iter().map(|f| ((f.object, f.offset), *f)).collect();
        let mut places: Vec<(u32, i32)> = ma.keys().chain(mb.keys()).copied().collect();
        places.sort_unstable();
        places.dedup();
        for at in places {
            let va = base
                .get(&at.0)
                .copied()
                .unwrap_or(0)
                .wrapping_add(at.1 as u32);
            let wo = place(va);
            match (ma.get(&at), mb.get(&at)) {
                (Some(x), None) => details.push(format!(
                    "fixup page {page}: missing at {wo} (original → object {} +{:#x})",
                    x.target_object, x.target_offset
                )),
                (None, Some(y)) => details.push(format!(
                    "fixup page {page}: extra at {wo} (→ object {} +{:#x})",
                    y.target_object, y.target_offset
                )),
                (Some(x), Some(y)) if fixup_key(x) != fixup_key(y) => details.push(format!(
                    "fixup page {page}: {wo} targets object {} +{:#x} instead of object {} +{:#x}",
                    y.target_object, y.target_offset, x.target_object, x.target_offset
                )),
                _ => {}
            }
        }
    }
    if order_only.is_empty() && content == 0 {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "fixups: {content} pages with other content, {} pages only in another order",
        order_only.len()
    )];
    if !order_only.is_empty() {
        let listed: Vec<String> = order_only
            .iter()
            .take(max_lines)
            .map(u32::to_string)
            .collect();
        let more = if order_only.len() > max_lines {
            " …"
        } else {
            ""
        };
        lines.push(format!(
            "fixups only in order: page {}{more}",
            listed.join(", ")
        ));
    }
    details.truncate(max_lines);
    lines.extend(details);
    lines
}
