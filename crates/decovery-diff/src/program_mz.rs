//! Why a linked MZ program differs from the original (port of Decomp's `nachbau/linkdiagnose.py`): the header
//! fields, the first difference in the load image (the file without its header) with what lies there, and whether
//! the bytes there only lie shifted in the rebuild.

/// The header fields in file order (word 1 to 13), with the names the diagnosis uses.
const FIELDS: [&str; 13] = [
    "bytes on the last page",
    "pages",
    "relocations",
    "header size (paragraphs)",
    "minalloc",
    "maxalloc",
    "SS",
    "SP",
    "checksum",
    "IP",
    "CS",
    "relocation table offset",
    "overlay",
];
const LAST_PAGE: usize = 0;
const PAGES: usize = 1;
const HEADER_PARAGRAPHS: usize = 3;
const MIN_ALLOC: usize = 4;
const CHECKSUM: usize = 8;
/// Bytes from the start of a function searched for in the rebuild.
const PATTERN: usize = 32;
/// A shorter pattern says nothing.
const MIN_PATTERN: usize = 8;
/// Most hits of the pattern looked at.
const MAX_HITS: usize = 50;

/// What lies at a place of the original load image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PlaceKind {
    /// A library function (named by signature or with a library).
    Library,
    /// A function rebuilt identically.
    Rebuilt,
    /// Startup code or an assembler routine.
    Assembly,
    /// Any other function.
    Function,
    Data,
}

/// A place of the original load image: `description` such as `seg:0000:1A7C in malloc`, `start` the image offset of
/// the function's start (for the shift search).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Place {
    pub description: String,
    pub kind: Option<PlaceKind>,
    pub start: Option<u64>,
}

impl Place {
    pub fn new(
        description: impl Into<String>,
        kind: Option<PlaceKind>,
        start: Option<u64>,
    ) -> Self {
        Place {
            description: description.into(),
            kind,
            start,
        }
    }
}

/// The 13 header words after the magic; `None` without an MZ header.
fn header(file: &[u8]) -> Option<[u16; 13]> {
    if file.len() < 28 || !(file.starts_with(b"MZ") || file.starts_with(b"ZM")) {
        return None;
    }
    let mut words = [0u16; 13];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u16::from_le_bytes([file[2 + i * 2], file[3 + i * 2]]);
    }
    Some(words)
}

/// File length the header declares (may be negative for a broken header).
fn declared_len(h: &[u16; 13]) -> i64 {
    let (pages, last) = (i64::from(h[PAGES]), i64::from(h[LAST_PAGE]));
    if last != 0 {
        (pages - 1) * 512 + last
    } else {
        pages * 512
    }
}

/// The load image: the file without its header, up to the declared length; the whole file without an MZ header.
pub fn load_image(file: &[u8]) -> &[u8] {
    let Some(h) = header(file) else {
        return file;
    };
    let start = usize::from(h[HEADER_PARAGRAPHS]) * 16;
    let end = usize::try_from(declared_len(&h).max(0))
        .unwrap_or(usize::MAX)
        .min(file.len());
    file.get(start..end).unwrap_or(&[])
}

/// One line per header field that differs (the checksum excepted).
fn header_differences(original: &[u8], rebuilt: &[u8]) -> Vec<String> {
    match (header(original), header(rebuilt)) {
        (None, None) => Vec::new(),
        (Some(o), Some(n)) => (0..FIELDS.len())
            .filter(|&i| i != CHECKSUM && o[i] != n[i])
            .map(|i| format!("{}: original {:#x}, rebuilt {:#x}", FIELDS[i], o[i], n[i]))
            .collect(),
        _ => vec!["only one of the two files has an MZ header".to_string()],
    }
}

/// How far the first [`PATTERN`] bytes of `original` from `start` lie shifted in `rebuilt`: the nearest of the first
/// [`MAX_HITS`] hits; `None` when they are not found or also lie at `start`.
fn shift(original: &[u8], rebuilt: &[u8], start: u64) -> Option<i64> {
    let start = usize::try_from(start).ok()?;
    let end = start.saturating_add(PATTERN).min(original.len());
    let pattern = original.get(start..end)?;
    if pattern.len() < MIN_PATTERN {
        return None;
    }
    let hits: Vec<usize> = rebuilt
        .windows(pattern.len())
        .enumerate()
        .filter(|(_, w)| *w == pattern)
        .map(|(i, _)| i)
        .take(MAX_HITS)
        .collect();
    if hits.is_empty() || hits.contains(&start) {
        return None;
    }
    let nearest = hits.into_iter().min_by_key(|&t| t.abs_diff(start))?;
    Some(nearest as i64 - start as i64)
}

/// Hints why `rebuilt` differs from `original`, in the order header, `/i` switch, bytes behind the image, first
/// difference in the load image with what lies there, length, shift. `place(image offset)` names what lies at an
/// offset of the original load image.
pub fn diagnose_mz_link(
    original: &[u8],
    rebuilt: &[u8],
    place: &dyn Fn(u64) -> Option<Place>,
) -> Vec<String> {
    let mut lines: Vec<String> = header_differences(original, rebuilt)
        .into_iter()
        .map(|d| format!("header: {d}"))
        .collect();
    let (ho, hn) = (header(original), header(rebuilt));
    if let (Some(o), Some(n)) = (&ho, &hn) {
        if o[MIN_ALLOC] == 0 && n[MIN_ALLOC] > 0 && rebuilt.len() < original.len() {
            lines.push(
                "the original holds the uninitialized data in the file (minalloc 0, rebuilt shorter): \
                 TLINK switch /i"
                    .to_string(),
            );
        }
        let behind_o = original.len() as i64 - declared_len(o);
        let behind_n = rebuilt.len() as i64 - declared_len(n);
        if behind_o != behind_n && behind_o.max(behind_n) > 0 {
            lines.push(format!(
                "behind the load image: original {} bytes, rebuilt {} bytes (overlay or debug info, e.g. TLINK /v?)",
                behind_o.max(0),
                behind_n.max(0)
            ));
        }
    }
    let (io, in_) = (load_image(original), load_image(rebuilt));
    let first = io
        .iter()
        .zip(in_)
        .position(|(a, b)| a != b)
        .or_else(|| (io.len() != in_.len()).then(|| io.len().min(in_.len())));
    let Some(first) = first else {
        lines.push(if lines.is_empty() {
            "no difference found".to_string()
        } else {
            "load image equal, only the header or the bytes behind it differ".to_string()
        });
        return lines;
    };
    if io.len() != in_.len() {
        lines.push(format!(
            "load image: rebuilt {:+} bytes against the original",
            in_.len() as i64 - io.len() as i64
        ));
    }
    if first >= io.len() {
        lines.push(format!(
            "load image equal up to the end of the original; the rebuilt one has {} bytes more",
            in_.len() - io.len()
        ));
        return lines;
    }
    let at = place(first as u64);
    let mut location = format!("image offset {first:#x}");
    if let Some(p) = &at {
        location.push_str(&format!(" ({})", p.description));
    }
    let explanation = match at.as_ref().map(|p| p.kind) {
        None => None,
        Some(Some(PlaceKind::Library)) => {
            Some("library differs, another compiler or library version?")
        }
        Some(Some(PlaceKind::Rebuilt)) => {
            Some("rebuilt function, the diagnose tool shows the difference")
        }
        Some(Some(PlaceKind::Assembly)) => Some(
            "startup code or assembler routine differs, another startup code or library version?",
        ),
        Some(Some(PlaceKind::Function)) => {
            Some("function missing in the rebuild or placed elsewhere")
        }
        Some(_) => Some("data differs, check the placement of the globals and strings"),
    };
    lines.push(match explanation {
        Some(e) => format!("first difference at {location}: {e}"),
        None => format!("first difference at {location}"),
    });
    if let Some(d) = at
        .and_then(|p| p.start)
        .and_then(|start| shift(io, in_, start))
    {
        lines.push(format!(
            "the bytes from its start lie {d:+} bytes shifted in the rebuild: the cause is before it"
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An MZ file with a 32-byte header over `image`; `min_alloc` and `sp` as given.
    fn mz(image: &[u8], min_alloc: u16, sp: u16) -> Vec<u8> {
        let total = 32 + image.len();
        let words: [u16; 14] = [
            0x5A4D,
            (total % 512) as u16,
            total.div_ceil(512) as u16,
            0,
            2,
            min_alloc,
            0xFFFF,
            0,
            sp,
            0,
            0x10,
            0,
            0x1C,
            0,
        ];
        let mut v = vec![0u8; 32];
        for (i, w) in words.iter().enumerate() {
            v[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
        }
        v.extend_from_slice(image);
        v
    }

    fn none(_: u64) -> Option<Place> {
        None
    }

    #[test]
    fn equal_files_have_no_difference() {
        let f = mz(&[1, 2, 3], 0, 0x100);
        assert_eq!(diagnose_mz_link(&f, &f, &none), ["no difference found"]);
    }

    #[test]
    fn checksum_is_not_named() {
        let o = mz(&[1, 2, 3], 0, 0x100);
        let mut n = o.clone();
        n[18] = 0x77;
        assert_eq!(diagnose_mz_link(&o, &n, &none), ["no difference found"]);
    }

    #[test]
    fn bytes_behind_the_image() {
        let o = mz(&[1, 2, 3], 0, 0x100);
        let mut n = o.clone();
        n.extend_from_slice(&[0; 5]);
        assert_eq!(
            diagnose_mz_link(&o, &n, &none),
            [
                "behind the load image: original 0 bytes, rebuilt 5 bytes (overlay or debug info, e.g. TLINK /v?)",
                "load image equal, only the header or the bytes behind it differ",
            ]
        );
    }

    #[test]
    fn longer_rebuild() {
        let o = mz(&[1, 2, 3], 0, 0x100);
        let n = mz(&[1, 2, 3, 4], 0, 0x100);
        let lines = diagnose_mz_link(&o, &n, &none);
        assert_eq!(
            &lines[1..],
            [
                "load image: rebuilt +1 bytes against the original",
                "load image equal up to the end of the original; the rebuilt one has 1 bytes more",
            ]
        );
    }

    #[test]
    fn one_header_only() {
        let o = mz(&[1], 0, 0);
        let lines = diagnose_mz_link(&o, b"plain", &none);
        assert_eq!(
            lines[0],
            "header: only one of the two files has an MZ header"
        );
    }

    #[test]
    fn broken_input_does_not_panic() {
        let mut odd = mz(&[1, 2], 0, 0);
        odd[8] = 0xFF; // header beyond the file
        odd[4] = 0; // no pages
        for (a, b) in [
            (&odd[..], &odd[..]),
            (&b"MZ"[..], &odd[..]),
            (&[][..], &[][..]),
        ] {
            let _ = diagnose_mz_link(a, b, &|_| Some(Place::new("x", None, Some(u64::MAX))));
        }
        assert!(load_image(&odd).is_empty());
    }
}
