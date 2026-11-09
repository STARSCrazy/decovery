//! Built-in assembler for byte-listing MASM sources: sources that give every byte (`db`) and name only what the
//! linker must place (`dd name+n`, `call name`, `jmp near ptr name`), as Decomp exports functions it classifies as
//! assembler. Such a source needs no real assembler; [`assemble_listing`] turns it into an OMF object.
//!
//! The accepted subset (keywords case-insensitive, `;` comments, blank lines): `.386`, `.386p`, `.387`,
//! `.model flat`; `extrn name:near|far|proc|byte|word|dword|fword|qword|abs` (comma lists); `public name` (lists);
//! `<seg> segment [byte|word|dword|para|page] [public|private|stack|common] [use16|use32] ['class']` … `<seg> ends`;
//! labels `name:`; `db`/`dw`/`dd` with numbers (`0ABh`, `0x1a`, decimal, negative) and quoted strings in `db`
//! (code page 437, as the source is staged for a DOS assembler);
//! `dw`/`dd` with `name`, `name+n`, `name-n` (an offset fixup of the field width; `dw` only in `use16`, `dd` only in
//! `use32` segments); `call name` (E8 and a 16- or 32-bit field by the segment's use); `jmp near ptr name` (E9);
//! `end [label]`. A name is a label of the file (target: its segment and offset) or an `extrn` (target: the
//! external, displacement `n`); `call` and `jmp` take only labels and `near`, `proc` or `abs` externals (MASM makes
//! a call to a `far` external a far call, one to a data external an indirect call). Anything else is
//! [`AssembleError::Unsupported`]: nothing is guessed.
//!
//! A value that is neither a number nor a string is read as a name: `ABh` (a hex number without its leading digit)
//! is the name `ABh` to MASM too, and unless it is declared it ends as [`AssembleError::Invalid`] (an unknown name),
//! a file error without fallback to the profile's assembler.
//!
//! What the object holds is what MASM-style assemblers write for these lines: a segment per `segment` (default
//! alignment paragraph, combination private, `use32` after a `.386` directive), the `extrn` names in declaration
//! order, a `PUBDEF` per `public` (labels that are not public are not written), and one fixup per named field. A
//! call or jump to a label of its own segment is resolved here, without fixup. Fixup fields are written empty with
//! the target's offset (labels) or the displacement (externals) in the fixup; a negative displacement of an
//! external stays in the field instead (the fixup carries none), which a linker adds the same way.

use std::collections::HashMap;

use decovery_objects::{WriteFixup, WriteFixupKind, WriteModule, WriteSegment, write_omf};

/// The `compiler` a rebuild record names for a function the built-in assembler built, with the version of its
/// encoding: a change to what the assembler writes raises the version, so objects kept by an older one are stale.
pub const BUILTIN_ASSEMBLER: &str = "builtin-asm/1";

/// Why a source cannot be assembled by [`assemble_listing`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssembleError {
    /// The line (1-based) is outside the accepted subset; a real assembler may still take it.
    #[error("line {line} is outside the built-in assembler subset ({text})")]
    Unsupported { line: usize, text: String },
    /// The source is wrong in a way any assembler would refuse (an unknown name, a value out of range, …).
    #[error("line {line}: {reason}")]
    Invalid { line: usize, reason: String },
}

/// A segment being assembled.
struct Segment {
    name: String,
    align: u8,
    combine: u8,
    use32: bool,
    class: String,
    bytes: Vec<u8>,
    /// The `segment` line, for an error about the whole segment.
    line: usize,
}

/// A named field whose value depends on a name.
struct Reference {
    line: usize,
    /// 0-based segment index.
    segment: usize,
    offset: u32,
    kind: WriteFixupKind,
    name: String,
    addend: i64,
    /// The statement of a call or jump (its target must be a label or a near external).
    branch: Option<String>,
}

/// `extrn` types a near call or jump may target.
const NEAR_TYPES: [&str; 3] = ["near", "proc", "abs"];

#[derive(Default)]
struct Assembler {
    segments: Vec<Segment>,
    /// 0-based index of the open segment.
    open: Option<usize>,
    /// A `.386` directive was seen: new segments default to `use32`.
    use32_default: bool,
    flat: bool,
    externals: Vec<String>,
    /// The declared type of each external (lower case).
    extern_types: HashMap<String, String>,
    labels: HashMap<String, (usize, u32)>,
    /// `public` names with their line.
    publics: Vec<(String, usize)>,
    references: Vec<Reference>,
    start: Option<(String, usize)>,
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || matches!(c, '_' | '@' | '$' | '?')
}

fn is_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(is_name_start) && chars.all(|c| is_name_start(c) || c.is_ascii_digit())
}

/// Sets an attribute slot once; false when it was set already.
fn set<T>(slot: &mut Option<T>, value: T) -> bool {
    if slot.is_some() {
        return false;
    }
    *slot = Some(value);
    true
}

/// The line without its `;` comment (a `;` inside quotes is text).
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == ';' => return &line[..i],
            None => {}
        }
    }
    line
}

/// Splits at commas outside quotes.
fn split_items(text: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut quote: Option<char> = None;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == ',' => {
                items.push(text[start..i].trim());
                start = i + 1;
            }
            None => {}
        }
    }
    items.push(text[start..].trim());
    items
}

/// A number: `0ABh`, `0x1a`, decimal, with an optional sign.
fn number(text: &str) -> Option<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, text.strip_prefix('+').unwrap_or(text).trim_start()),
    };
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (!hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| i64::from_str_radix(hex, 16).ok())
            .flatten()?
    } else if let Some(hex) = digits
        .strip_suffix('h')
        .or_else(|| digits.strip_suffix('H'))
    {
        (hex.starts_with(|c: char| c.is_ascii_digit())
            && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| i64::from_str_radix(hex, 16).ok())
        .flatten()?
    } else {
        (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
            .then(|| digits.parse::<i64>().ok())
            .flatten()?
    };
    Some(if negative { -value } else { value })
}

/// `name`, `name+n` or `name-n` (blanks allowed around the sign).
fn name_expression(text: &str) -> Option<(String, i64)> {
    let (name, addend) = match text.find(['+', '-']) {
        Some(i) => {
            let (name, rest) = text.split_at(i);
            let value = number(rest[1..].trim())?;
            (
                name.trim(),
                if rest.starts_with('-') { -value } else { value },
            )
        }
        None => (text.trim(), 0),
    };
    is_name(name).then(|| (name.to_string(), addend))
}

/// The bytes of a quoted string (`'it''s'`, `"a"`), code page 437.
fn string(text: &str) -> Option<Result<Vec<u8>, String>> {
    let quote = text.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let inner = text.strip_prefix(quote)?.strip_suffix(quote)?;
    let doubled = format!("{quote}{quote}");
    // a lone quote inside is not a string of this form
    if inner.replace(&doubled, "").contains(quote) {
        return None;
    }
    let text = inner.replace(&doubled, &quote.to_string());
    Some(
        text.chars()
            .map(|c| {
                crate::cp437::encode(c)
                    .ok_or_else(|| format!("character {c:?} is not in code page 437"))
            })
            .collect(),
    )
}

impl Assembler {
    fn unsupported(line: usize, text: &str) -> AssembleError {
        AssembleError::Unsupported {
            line,
            text: text.to_string(),
        }
    }

    fn invalid(line: usize, reason: impl Into<String>) -> AssembleError {
        AssembleError::Invalid {
            line,
            reason: reason.into(),
        }
    }

    fn current(&mut self, line: usize, what: &str) -> Result<usize, AssembleError> {
        self.open
            .ok_or_else(|| Self::invalid(line, format!("{what} outside a segment")))
    }

    fn here(&self, segment: usize) -> u32 {
        self.segments[segment].bytes.len() as u32
    }

    /// One statement (comment and label removed). Returns false at `end`.
    fn statement(&mut self, line: usize, text: &str) -> Result<bool, AssembleError> {
        let mut words = text.split_whitespace();
        let first = words.next().unwrap_or_default();
        let keyword = first.to_ascii_lowercase();
        let rest = text[first.len()..].trim();
        match keyword.as_str() {
            ".386" | ".386p" => {
                self.use32_default = true;
                return Ok(true);
            }
            ".387" => return Ok(true),
            ".model" => {
                if !rest.eq_ignore_ascii_case("flat") {
                    return Err(Self::unsupported(line, text));
                }
                self.flat = true;
                self.use32_default = true;
                return Ok(true);
            }
            "extrn" => return self.extrn(line, text, rest).map(|_| true),
            "public" => {
                for name in split_items(rest) {
                    if !is_name(name) {
                        return Err(Self::unsupported(line, text));
                    }
                    self.publics.push((name.to_string(), line));
                }
                return Ok(true);
            }
            "db" | "dw" | "dd" => return self.data(line, text, &keyword, rest).map(|_| true),
            "call" => {
                if !is_name(rest) {
                    return Err(Self::unsupported(line, text));
                }
                self.branch(line, text, 0xE8, rest)?;
                return Ok(true);
            }
            "jmp" => {
                let words: Vec<&str> = rest.split_whitespace().collect();
                match words.as_slice() {
                    [near, ptr, name]
                        if near.eq_ignore_ascii_case("near")
                            && ptr.eq_ignore_ascii_case("ptr")
                            && is_name(name) =>
                    {
                        self.branch(line, text, 0xE9, name)?;
                        return Ok(true);
                    }
                    _ => return Err(Self::unsupported(line, text)),
                }
            }
            "end" => {
                if !rest.is_empty() {
                    if !is_name(rest) {
                        return Err(Self::unsupported(line, text));
                    }
                    self.start = Some((rest.to_string(), line));
                }
                return Ok(false);
            }
            _ => {}
        }
        // `<seg> segment …` and `<seg> ends`
        let second = words.next().map(str::to_ascii_lowercase);
        match second.as_deref() {
            Some("segment") if is_name(first) => {
                let attributes = text[first.len()..].trim()["segment".len()..].trim();
                self.segment(line, text, first, attributes)?;
                Ok(true)
            }
            Some("ends") if is_name(first) && words.next().is_none() => match self.open {
                Some(i) if self.segments[i].name == first => {
                    self.open = None;
                    Ok(true)
                }
                Some(i) => Err(Self::invalid(
                    line,
                    format!(
                        "{first} ends while segment {} is open",
                        self.segments[i].name
                    ),
                )),
                None => Err(Self::invalid(
                    line,
                    format!("{first} ends without an open segment"),
                )),
            },
            _ => Err(Self::unsupported(line, text)),
        }
    }

    fn extrn(&mut self, line: usize, text: &str, rest: &str) -> Result<(), AssembleError> {
        const TYPES: [&str; 9] = [
            "near", "far", "proc", "byte", "word", "dword", "fword", "qword", "abs",
        ];
        for item in split_items(rest) {
            let Some((name, kind)) = item.split_once(':') else {
                return Err(Self::unsupported(line, text));
            };
            let (name, kind) = (name.trim(), kind.trim().to_ascii_lowercase());
            if !is_name(name) || !TYPES.contains(&kind.as_str()) {
                return Err(Self::unsupported(line, text));
            }
            if self.labels.contains_key(name) {
                return Err(Self::invalid(
                    line,
                    format!("{name} is a label of this file and cannot be external"),
                ));
            }
            match self.extern_types.get(name) {
                Some(before) if *before != kind => {
                    return Err(Self::invalid(
                        line,
                        format!("{name} declared external as {before} and as {kind}"),
                    ));
                }
                Some(_) => {}
                None => {
                    self.externals.push(name.to_string());
                    self.extern_types.insert(name.to_string(), kind);
                }
            }
        }
        Ok(())
    }

    fn segment(
        &mut self,
        line: usize,
        text: &str,
        name: &str,
        attributes: &str,
    ) -> Result<(), AssembleError> {
        if self.open.is_some() {
            // nested segments are valid MASM, but not part of the subset
            return Err(Self::unsupported(line, text));
        }
        let (mut align, mut combine, mut use32, mut class) = (None, None, None, None);
        for word in attributes.split_whitespace() {
            let lower = word.to_ascii_lowercase();
            let fresh = match lower.as_str() {
                "byte" => set(&mut align, 1u8),
                "word" => set(&mut align, 2),
                "para" => set(&mut align, 3),
                "page" => set(&mut align, 4),
                "dword" => set(&mut align, 5),
                "private" => set(&mut combine, 0u8),
                "public" => set(&mut combine, 2),
                "stack" => set(&mut combine, 5),
                "common" => set(&mut combine, 6),
                "use16" => set(&mut use32, false),
                "use32" => set(&mut use32, true),
                _ => match word
                    .strip_prefix('\'')
                    .and_then(|w| w.strip_suffix('\''))
                    .filter(|w| !w.contains('\''))
                {
                    Some(c) if class.is_none() => {
                        class = Some(c.to_string());
                        true
                    }
                    _ => return Err(Self::unsupported(line, text)),
                },
            };
            if !fresh {
                return Err(Self::invalid(
                    line,
                    format!("segment {name}: attribute {word} given twice"),
                ));
            }
        }
        if let Some(i) = self.segments.iter().position(|s| s.name == name) {
            // reopened: attributes, when given, must be the same
            let s = &self.segments[i];
            let differs = align.is_some_and(|a| a != s.align)
                || combine.is_some_and(|c| c != s.combine)
                || use32.is_some_and(|u| u != s.use32)
                || class.as_ref().is_some_and(|c| *c != s.class);
            if differs {
                return Err(Self::invalid(
                    line,
                    format!("segment {name} reopened with other attributes"),
                ));
            }
            self.open = Some(i);
            return Ok(());
        }
        self.segments.push(Segment {
            name: name.to_string(),
            align: align.unwrap_or(3),
            combine: combine.unwrap_or(0),
            use32: use32.unwrap_or(self.use32_default),
            class: class.unwrap_or_default(),
            bytes: Vec::new(),
            line,
        });
        self.open = Some(self.segments.len() - 1);
        Ok(())
    }

    fn label(&mut self, line: usize, name: &str) -> Result<(), AssembleError> {
        let segment = self.current(line, &format!("label {name}"))?;
        if self.externals.iter().any(|e| e == name) {
            return Err(Self::invalid(
                line,
                format!("{name} is declared external and cannot be a label"),
            ));
        }
        let offset = self.here(segment);
        if self
            .labels
            .insert(name.to_string(), (segment, offset))
            .is_some()
        {
            return Err(Self::invalid(line, format!("label {name} defined twice")));
        }
        Ok(())
    }

    fn data(
        &mut self,
        line: usize,
        text: &str,
        keyword: &str,
        rest: &str,
    ) -> Result<(), AssembleError> {
        let segment = self.current(line, keyword)?;
        let use32 = self.segments[segment].use32;
        let width: usize = match keyword {
            "db" => 1,
            "dw" => 2,
            _ => 4,
        };
        let (min, max): (i64, i64) = match width {
            1 => (-0x80, 0xFF),
            2 => (-0x8000, 0xFFFF),
            _ => (-0x8000_0000, 0xFFFF_FFFF),
        };
        if rest.is_empty() {
            return Err(Self::unsupported(line, text));
        }
        let mut bytes: Vec<u8> = Vec::new();
        let mut references = Vec::new();
        for item in split_items(rest) {
            if let Some(n) = number(item) {
                if !(min..=max).contains(&n) {
                    return Err(Self::invalid(
                        line,
                        format!("{item} does not fit into {keyword}"),
                    ));
                }
                bytes.extend_from_slice(&n.to_le_bytes()[..width]);
            } else if width == 1
                && let Some(s) = string(item)
            {
                let s = s.map_err(|reason| Self::invalid(line, reason))?;
                if s.is_empty() {
                    return Err(Self::invalid(line, "empty string"));
                }
                bytes.extend_from_slice(&s);
            } else if let Some((name, addend)) = name_expression(item) {
                // an offset of the field width: dw in 16-bit, dd in 32-bit segments only
                let kind = match (width, use32) {
                    (2, false) => WriteFixupKind::Off16,
                    (4, true) => WriteFixupKind::Off32,
                    _ => return Err(Self::unsupported(line, text)),
                };
                references.push((bytes.len() as u32, kind, name, addend));
                bytes.extend(std::iter::repeat_n(0u8, width));
            } else {
                return Err(Self::unsupported(line, text));
            }
        }
        let at = self.here(segment);
        for (offset, kind, name, addend) in references {
            self.references.push(Reference {
                line,
                segment,
                offset: at + offset,
                kind,
                name,
                addend,
                branch: None,
            });
        }
        self.segments[segment].bytes.extend_from_slice(&bytes);
        Ok(())
    }

    fn branch(
        &mut self,
        line: usize,
        text: &str,
        opcode: u8,
        name: &str,
    ) -> Result<(), AssembleError> {
        let what = if opcode == 0xE8 { "call" } else { "jmp" };
        let segment = self.current(line, what)?;
        let use32 = self.segments[segment].use32;
        let (kind, width) = if use32 {
            (WriteFixupKind::Rel32, 4)
        } else {
            (WriteFixupKind::Rel16, 2)
        };
        let at = self.here(segment);
        let bytes = &mut self.segments[segment].bytes;
        bytes.push(opcode);
        bytes.extend(std::iter::repeat_n(0u8, width));
        self.references.push(Reference {
            line,
            segment,
            offset: at + 1,
            kind,
            name: name.to_string(),
            addend: 0,
            branch: Some(text.to_string()),
        });
        Ok(())
    }

    /// The object: references resolved, publics checked.
    fn finish(mut self, module: &str, last_line: usize) -> Result<Vec<u8>, AssembleError> {
        if let Some(i) = self.open {
            let s = &self.segments[i];
            return Err(Self::invalid(
                s.line,
                format!("segment {} is not closed", s.name),
            ));
        }
        for s in &self.segments {
            if !s.use32 && s.bytes.len() > 0x1_0000 {
                return Err(Self::invalid(
                    s.line,
                    format!("16-bit segment {} is longer than 64 KiB", s.name),
                ));
            }
            if u32::try_from(s.bytes.len()).is_err() {
                return Err(Self::invalid(
                    s.line,
                    format!("segment {} is longer than 4 GiB", s.name),
                ));
            }
        }
        let mut fixups: Vec<WriteFixup> = Vec::new();
        let references = std::mem::take(&mut self.references);
        for r in references {
            let segment = r.segment as u32 + 1;
            let width = r.kind.width() as usize;
            let relative = matches!(r.kind, WriteFixupKind::Rel32 | WriteFixupKind::Rel16);
            if let Some(&(target_segment, target_offset)) = self.labels.get(&r.name) {
                let target = i64::from(target_offset) + r.addend;
                if relative && target_segment == r.segment {
                    // resolved here: the distance from the end of the field
                    let value = target - (i64::from(r.offset) + width as i64);
                    let field = &mut self.segments[r.segment].bytes
                        [r.offset as usize..r.offset as usize + width];
                    field.copy_from_slice(&value.to_le_bytes()[..width]);
                    continue;
                }
                let target_segment = target_segment as u32 + 1;
                fixups.push(match u32::try_from(target) {
                    Ok(offset) => {
                        WriteFixup::new(segment, r.offset, r.kind, target_segment, Some(offset))
                    }
                    Err(_) => {
                        // before the segment start: the distance goes into the field
                        let field = &mut self.segments[r.segment].bytes
                            [r.offset as usize..r.offset as usize + width];
                        field.copy_from_slice(&target.to_le_bytes()[..width]);
                        WriteFixup::new(segment, r.offset, r.kind, target_segment, None)
                    }
                });
            } else if let Some(i) = self.externals.iter().position(|e| *e == r.name) {
                if let Some(statement) = &r.branch
                    && !self
                        .extern_types
                        .get(&r.name)
                        .is_some_and(|t| NEAR_TYPES.contains(&t.as_str()))
                {
                    // a far call or an indirect one through a data external: other bytes than E8/E9
                    return Err(Self::unsupported(r.line, statement));
                }
                let external = i as u32 + 1;
                fixups.push(if relative {
                    WriteFixup::external(segment, r.offset, r.kind, external, None)
                } else {
                    match u32::try_from(r.addend) {
                        Ok(displacement) => WriteFixup::external(
                            segment,
                            r.offset,
                            r.kind,
                            external,
                            Some(displacement),
                        ),
                        Err(_) => {
                            let field = &mut self.segments[r.segment].bytes
                                [r.offset as usize..r.offset as usize + width];
                            field.copy_from_slice(&r.addend.to_le_bytes()[..width]);
                            WriteFixup::external(segment, r.offset, r.kind, external, None)
                        }
                    }
                });
            } else {
                return Err(Self::invalid(
                    r.line,
                    format!(
                        "{} is neither a label of this file nor declared extrn",
                        r.name
                    ),
                ));
            }
        }
        fixups.sort_by_key(|f| (f.segment, f.offset));
        let mut publics: Vec<(String, u32, u32)> = Vec::new();
        for (name, line) in &self.publics {
            let Some(&(segment, offset)) = self.labels.get(name) else {
                return Err(Self::invalid(
                    *line,
                    format!("public {name} is not a label of this file"),
                ));
            };
            if !publics.iter().any(|(p, _, _)| p == name) {
                publics.push((name.clone(), segment as u32 + 1, offset));
            }
        }
        let start = match &self.start {
            None => None,
            Some((name, line)) => match self.labels.get(name) {
                Some(&(segment, offset)) => Some((segment as u32 + 1, offset)),
                None if self.externals.contains(name) => {
                    return Err(Self::unsupported(*line, &format!("end {name}")));
                }
                None => {
                    return Err(Self::invalid(
                        *line,
                        format!("start label {name} is not a label of this file"),
                    ));
                }
            },
        };
        let segments: Vec<WriteSegment> = self
            .segments
            .iter()
            .map(|s| {
                WriteSegment::new(&s.name, &s.class, s.bytes.len() as u32, s.use32)
                    .with_align(s.align)
                    .with_combine(s.combine)
            })
            .collect();
        let data: Vec<(u32, Vec<u8>)> = self
            .segments
            .iter_mut()
            .enumerate()
            .filter(|(_, s)| !s.bytes.is_empty())
            .map(|(i, s)| (i as u32 + 1, std::mem::take(&mut s.bytes)))
            .collect();
        let groups: Vec<(String, Vec<u32>)> = if self.flat {
            vec![("FLAT".to_string(), Vec::new())]
        } else {
            Vec::new()
        };
        write_omf(
            &WriteModule::new(module)
                .with_segments(&segments)
                .with_groups(&groups)
                .with_externals(&self.externals)
                .with_publics(&publics)
                .with_data(&data)
                .with_fixups(&fixups)
                .with_start(start),
        )
        .map_err(|e| Self::invalid(last_line, e.to_string()))
    }
}

/// Assembles the byte-listing MASM source `text` into an OMF object module named `name` (see the module
/// documentation for the subset). Lines after `end` are ignored.
pub fn assemble_listing(name: &str, text: &str) -> Result<Vec<u8>, AssembleError> {
    let mut asm = Assembler::default();
    let mut last_line = 0;
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        last_line = line;
        let mut statement = strip_comment(raw).trim();
        if statement.is_empty() {
            continue;
        }
        // a label `name:` before the statement
        if let Some(colon) = statement.find(':') {
            let candidate = &statement[..colon];
            if is_name(candidate) && !statement[colon + 1..].starts_with(':') {
                asm.label(line, candidate)?;
                statement = statement[colon + 1..].trim();
                if statement.is_empty() {
                    continue;
                }
            }
        }
        if !asm.statement(line, statement)? {
            break;
        }
    }
    asm.finish(name, last_line)
}
