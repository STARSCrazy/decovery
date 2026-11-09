//! Derived function view (Decomp's `BibFunktion`). The "function = symbol in a code section" split lives only here.

use std::collections::BTreeSet;

use decovery_core::RelocKind;

use crate::model::{ObjReloc, ObjectModule, RefTarget, SectionKind};

/// A function-sized slice of a code section: from a symbol to the next symbol offset (or the section end).
#[derive(Debug, Clone)]
pub struct FunctionView<'a> {
    pub name: &'a str,
    pub module: &'a ObjectModule,
    /// Index into [`ObjectModule::sections`].
    pub section: u32,
    /// Offset of the function in its section.
    pub start: u32,
    pub len: u32,
}

/// All functions of a module: sections in order, within a section by (offset, name). Sections without
/// initialised bytes yield none. Symbols at the same offset share the same extent.
pub fn functions(module: &ObjectModule) -> Vec<FunctionView<'_>> {
    let mut out = Vec::new();
    for (si, section) in module.sections.iter().enumerate() {
        if section.kind != SectionKind::Code || section.data.is_empty() {
            continue;
        }
        let mut starts: Vec<(u32, &str)> = module
            .symbols
            .iter()
            .filter(|s| s.section as usize == si)
            .map(|s| (s.offset, s.name.as_str()))
            .collect();
        starts.sort_unstable();
        let total = u32::try_from(section.data.len()).unwrap_or(u32::MAX);
        for &(off, name) in &starts {
            let end = starts
                .iter()
                .map(|&(o, _)| o)
                .find(|&o| o > off)
                .unwrap_or(total);
            out.push(FunctionView {
                name,
                module,
                section: si as u32,
                start: off,
                len: end.saturating_sub(off),
            });
        }
    }
    out
}

fn signed_le(bytes: &[u8]) -> i64 {
    let mut v = bytes
        .iter()
        .rev()
        .fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let bits = 8 * bytes.len() as u32;
    if bits > 0 && bits < 64 && v & (1 << (bits - 1)) != 0 {
        v |= !0u64 << bits;
    }
    v as i64
}

impl<'a> FunctionView<'a> {
    fn section_data(&self) -> &'a [u8] {
        self.module
            .sections
            .get(self.section as usize)
            .map_or(&[], |s| s.data.as_slice())
    }

    fn end(&self) -> u32 {
        self.start.saturating_add(self.len)
    }

    /// Raw bytes of the function; fixup fields keep their stored content.
    pub fn code(&self) -> &'a [u8] {
        let d = self.section_data();
        let s = (self.start as usize).min(d.len());
        let e = (self.end() as usize).min(d.len());
        &d[s..e]
    }

    fn section_relocs(&self) -> &'a [ObjReloc] {
        self.module
            .sections
            .get(self.section as usize)
            .map_or(&[], |s| s.relocs.as_slice())
    }

    /// Relocations whose field starts inside the function; offsets are relative to the section.
    pub fn relocs(&self) -> impl Iterator<Item = &'a ObjReloc> + use<'a> {
        let (s, e) = (self.start, self.end());
        self.section_relocs()
            .iter()
            .filter(move |r| r.offset >= s && r.offset < e)
    }

    /// Bytes of the function overwritten by a fixup (relative to the function start), including the
    /// part of a field that starts before the function.
    pub fn gaps(&self) -> BTreeSet<u32> {
        let (s, e) = (self.start, self.end());
        let mut set = BTreeSet::new();
        for r in self.section_relocs() {
            for p in r.offset..r.offset.saturating_add(u32::from(r.width)) {
                if p >= s && p < e {
                    set.insert(p - s);
                }
            }
        }
        set
    }

    /// Start offsets (relative to the function) of self-relative fixups (near call/jmp).
    pub fn relative_offsets(&self) -> BTreeSet<u32> {
        self.relocs()
            .filter(|r| r.kind == RelocKind::Relative)
            .map(|r| r.offset - self.start)
            .collect()
    }

    /// Named references `(offset in function, name)`, sorted. Own-section absolute references are named
    /// when field plus displacement hits a symbol start exactly (Watcom: section start plus distance).
    pub fn references(&self) -> Vec<(u32, &'a str)> {
        let all_gaps: BTreeSet<u32> = self
            .section_relocs()
            .iter()
            .flat_map(|r| r.offset..r.offset.saturating_add(u32::from(r.width)))
            .collect();
        let mut v: Vec<(u32, &'a str)> = self
            .relocs()
            .filter_map(|r| {
                self.target_name(r, &all_gaps)
                    .map(|n| (r.offset - self.start, n))
            })
            .collect();
        v.sort_unstable();
        v
    }

    /// Displacements of named external references `(offset in function, displacement)`, sorted; zero
    /// displacements and self-relative fixups are left out.
    pub fn addends(&self) -> Vec<(u32, i64)> {
        let mut v: Vec<(u32, i64)> = self
            .relocs()
            .filter(|r| {
                matches!(r.target, RefTarget::Symbol(_))
                    && r.addend != 0
                    && r.kind != RelocKind::Relative
            })
            .map(|r| (r.offset - self.start, r.addend))
            .collect();
        v.sort_unstable();
        v
    }

    fn target_name(&self, r: &'a ObjReloc, section_gaps: &BTreeSet<u32>) -> Option<&'a str> {
        match &r.target {
            RefTarget::Symbol(s) => Some(s.as_str()),
            RefTarget::Section { index, offset } => {
                let in_section = |s: &&'a crate::model::ObjSymbol| s.section == *index;
                if r.kind != RelocKind::Relative && *index == self.section {
                    let data = self.section_data();
                    let p = r.offset;
                    let wide = (p..p.saturating_add(4)).all(|q| section_gaps.contains(&q));
                    let w = if wide { 4 } else { 2 };
                    let field = data
                        .get(p as usize..)
                        .map_or(&[][..], |d| &d[..d.len().min(w)]);
                    let target = i64::from(*offset) + signed_le(field);
                    // a later symbol at the same offset wins (Decomp builds a dict over sorted starts)
                    self.module
                        .symbols
                        .iter()
                        .filter(in_section)
                        .filter(|s| i64::from(s.offset) == target)
                        .map(|s| s.name.as_str())
                        .max()
                } else {
                    self.module
                        .symbols
                        .iter()
                        .find(|s| s.section == *index && s.offset == *offset)
                        .map(|s| s.name.as_str())
                }
            }
            RefTarget::Group(_) | RefTarget::Unknown => None,
        }
    }
}
