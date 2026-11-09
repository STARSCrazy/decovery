//! Reading a linker map file: the segments with their classes and the public symbols with their addresses.

use crate::cp437;

/// One segment of the segment list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MapSegment {
    /// Linear start relative to the load image.
    pub start: u32,
    pub length: u32,
    pub name: String,
    /// The class, e.g. `CODE`, `DATA`, `BSS`; empty when the map gives none.
    pub class: String,
}

/// One public symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MapPublic {
    /// Segment relative to the load segment.
    pub seg: u16,
    pub off: u16,
    /// The public name as the linker writes it (decorated).
    pub name: String,
    /// An absolute symbol (`Abs`): a value, not an address in the program.
    pub absolute: bool,
    /// 1-based line in the map file.
    pub line: usize,
}

/// The parts of a map file decovery reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct LinkMap {
    /// Sorted by start.
    pub segments: Vec<MapSegment>,
    /// In the order of the map's publics list (by value when the map has one, else by name).
    pub publics: Vec<MapPublic>,
}

impl LinkMap {
    /// The segment containing the linear address `at`.
    pub fn segment_at(&self, at: u32) -> Option<&MapSegment> {
        let after = self.segments.partition_point(|s| s.start <= at);
        self.segments[..after]
            .iter()
            .rev()
            .find(|s| at - s.start < s.length)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Start,
    Segments,
    ByName,
    ByValue,
    /// A part decovery does not read (detailed segment map, line numbers, entry point).
    Other,
}

/// Parses a Borland TLINK map (`/m`): the segment list (`00000H 03796H 03797H _TEXT CODE`) and the publics
/// (`0000:01F8 name`, `0000:0000 Abs name`, `... Idle name`). Line ends may be CR LF or LF; text is code page 437.
/// One pass. A line of the segment list or of a publics list that does not read is an error naming the line; a
/// map without a publics list is an error as well.
pub fn parse_tlink_map(bytes: &[u8]) -> Result<LinkMap, String> {
    let text = cp437::decode(bytes);
    let mut section = Section::Start;
    let mut segments = Vec::new();
    let mut by_name = Vec::new();
    let mut by_value = Vec::new();
    let mut seen_by_value = false;
    let mut seen_by_name = false;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.starts_with(&["Start", "Stop", "Length"]) {
            section = Section::Segments;
            continue;
        }
        if line.ends_with("Publics by Name") {
            section = Section::ByName;
            seen_by_name = true;
            continue;
        }
        if line.ends_with("Publics by Value") {
            section = Section::ByValue;
            seen_by_value = true;
            continue;
        }
        if line.starts_with("Detailed map")
            || line.starts_with("Program entry point")
            || line.starts_with("Line numbers")
        {
            section = Section::Other;
            continue;
        }
        let bad = |what: &str| format!("line {number}: {what}: {line:?}");
        match section {
            Section::Start | Section::Other => {}
            Section::Segments => {
                let (start, length) = match words.as_slice() {
                    [start, _stop, length, _name, ..] => (hex_h(start), hex_h(length)),
                    _ => (None, None),
                };
                let (Some(start), Some(length)) = (start, length) else {
                    return Err(bad("not a segment line"));
                };
                segments.push(MapSegment {
                    start,
                    length,
                    name: words[3].to_string(),
                    class: words.get(4).map_or(String::new(), |c| (*c).to_string()),
                });
            }
            Section::ByName | Section::ByValue => {
                let (address, marker, name) = match words.as_slice() {
                    [address, name] => (*address, None, *name),
                    [address, marker, name] => (*address, Some(*marker), *name),
                    _ => return Err(bad("not a public line")),
                };
                let Some((seg, off)) = seg_off(address) else {
                    return Err(bad("not a SSSS:OOOO address"));
                };
                let absolute = match marker {
                    None | Some("Idle") => false,
                    Some("Abs") => true,
                    Some(_) => return Err(bad("unknown public marker")),
                };
                let public = MapPublic {
                    seg,
                    off,
                    name: name.to_string(),
                    absolute,
                    line: number,
                };
                if section == Section::ByValue {
                    by_value.push(public);
                } else {
                    by_name.push(public);
                }
            }
        }
    }
    if !seen_by_value && !seen_by_name {
        return Err("the map has no publics list (link without the map option?)".into());
    }
    segments.sort_by_key(|s: &MapSegment| s.start);
    Ok(LinkMap {
        segments,
        publics: if seen_by_value { by_value } else { by_name },
    })
}

/// `03796H` as a number.
fn hex_h(word: &str) -> Option<u32> {
    let digits = word.strip_suffix(['H', 'h'])?;
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// `037A:06B2` as segment and offset.
fn seg_off(word: &str) -> Option<(u16, u16)> {
    let (seg, off) = word.split_once(':')?;
    let part = |p: &str| {
        (p.len() == 4 && p.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| u16::from_str_radix(p, 16).ok())
            .flatten()
    };
    Some((part(seg)?, part(off)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = "\r\n Start  Stop   Length Name               Class\r\n\r\n \
        00000H 0062BH 0062CH _TEXT              CODE\r\n \
        00630H 0074FH 00120H _DATA              DATA\r\n \
        00750H 0084FH 00100H _BSS               BSS\r\n\r\n  \
        Address         Publics by Name\r\n\r\n \
        0000:01F8       DGROUP@\r\n \
        0063:0010       _counter\r\n\r\n  \
        Address         Publics by Value\n\n \
        0000:0000  Abs  __turboCrt\n \
        0000:01F8       DGROUP@\n \
        0063:0010       _counter\n \
        0063:0120  Idle _unused\n\n\
        Program entry point at 0000:0000\n";

    #[test]
    fn reads_segments_and_publics_by_value() {
        let map = parse_tlink_map(MAP.as_bytes()).unwrap();
        assert_eq!(map.segments.len(), 3);
        assert_eq!(map.segments[1].class, "DATA");
        assert_eq!(map.publics.len(), 4);
        assert!(map.publics[0].absolute);
        assert_eq!(
            (map.publics[2].seg, map.publics[2].off, map.publics[2].line),
            (0x0063, 0x0010, 17)
        );
        assert!(!map.publics[3].absolute);
        assert_eq!(map.segment_at(0x640).unwrap().name, "_DATA");
        assert_eq!(map.segment_at(0x62C), None);
        assert_eq!(map.segment_at(0x850), None);
    }

    #[test]
    fn malformed_lines_name_the_line() {
        let bad = MAP.replace("0063:0010       _counter\n", "0063:00G0       _counter\n");
        let err = parse_tlink_map(bad.as_bytes()).unwrap_err();
        assert!(err.starts_with("line 17:"), "{err}");
        let bad = MAP.replace("00630H 0074FH", "00630H");
        let err = parse_tlink_map(bad.as_bytes()).unwrap_err();
        assert!(err.starts_with("line 5:"), "{err}");
        let err = parse_tlink_map(b"\r\n Start  Stop   Length Name Class\r\n").unwrap_err();
        assert!(err.contains("no publics list"), "{err}");
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = parse_tlink_map(&bytes);
        }
        let _ = parse_tlink_map(b"Publics by Value\n 0000:0000 a b c d\n");
        let _ = parse_tlink_map(b" Start Stop Length\n FFFFFFFFH 0H 0H x\n");
    }
}
