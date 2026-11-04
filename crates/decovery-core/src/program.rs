//! The loaded program image: regions, entry points and relocations.

use serde::{Deserialize, Serialize};

use crate::address::Address;

/// Executable file format. Further variants arrive together with their loaders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExecutableFormat {
    Com,
    Mz,
    Le,
}

/// Architecture and processor mode of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ArchMode {
    #[serde(rename = "x86-real-16")]
    X86Real16,
    #[serde(rename = "x86-flat-32")]
    X86Flat32,
}

/// Access rights of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// A contiguous part of the image (LE object, MZ load module, section).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Region {
    pub name: String,
    pub start: Address,
    /// Size in memory; may exceed `data.len()` (uninitialized tail).
    pub virtual_size: u64,
    /// Initialized bytes, with relocations already applied as the loader would.
    pub data: Vec<u8>,
    pub file_offset: Option<u64>,
    pub permissions: Permissions,
    pub arch: ArchMode,
}

/// What a relocation stores in its field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RelocKind {
    Absolute,
    Relative,
    Selector,
    FarPointer,
}

/// A relocated field of `width` bytes at `at` referring to `target` (+ `addend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Relocation {
    pub at: Address,
    pub kind: RelocKind,
    pub width: u8,
    pub target: Address,
    pub addend: i64,
}

/// A loaded executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Program {
    pub format: ExecutableFormat,
    pub regions: Vec<Region>,
    pub entry_points: Vec<Address>,
    /// Sorted by the linear address of `at` (see [`Program::new`]).
    pub relocations: Vec<Relocation>,
}

impl Region {
    pub fn new(
        name: impl Into<String>,
        start: Address,
        virtual_size: u64,
        data: Vec<u8>,
        permissions: Permissions,
        arch: ArchMode,
    ) -> Self {
        Region {
            name: name.into(),
            start,
            virtual_size,
            data,
            file_offset: None,
            permissions,
            arch,
        }
    }

    fn contains(&self, linear: u64, len: u64) -> bool {
        let Some(start) = self.start.linear() else {
            return false;
        };
        linear >= start && linear.saturating_add(len) <= start.saturating_add(self.virtual_size)
    }
}

impl Relocation {
    pub fn new(at: Address, kind: RelocKind, width: u8, target: Address, addend: i64) -> Self {
        Relocation {
            at,
            kind,
            width,
            target,
            addend,
        }
    }
}

fn sort_key(relocation: &Relocation) -> u64 {
    relocation.at.linear().unwrap_or(u64::MAX)
}

impl Program {
    /// Builds a program; relocations are sorted by address.
    pub fn new(
        format: ExecutableFormat,
        regions: Vec<Region>,
        entry_points: Vec<Address>,
        mut relocations: Vec<Relocation>,
    ) -> Self {
        relocations.sort_by_key(sort_key);
        Program {
            format,
            regions,
            entry_points,
            relocations,
        }
    }

    /// The region containing `at`.
    pub fn region_at(&self, at: Address) -> Option<&Region> {
        let linear = at.linear()?;
        self.regions.iter().find(|r| r.contains(linear, 1))
    }

    /// `len` initialized bytes at `at`, if the whole range lies inside one region's data.
    pub fn read(&self, at: Address, len: usize) -> Option<&[u8]> {
        let linear = at.linear()?;
        let region = self.region_at(at)?;
        let offset = usize::try_from(linear - region.start.linear()?).ok()?;
        region.data.get(offset..offset.checked_add(len)?)
    }

    /// Relocations whose field starts in `[start, start + len)`.
    pub fn relocations_in(&self, start: Address, len: u64) -> &[Relocation] {
        let Some(begin) = start.linear() else {
            return &[];
        };
        let end = begin.saturating_add(len);
        let lo = self.relocations.partition_point(|r| sort_key(r) < begin);
        let hi = self.relocations.partition_point(|r| sort_key(r) < end);
        &self.relocations[lo..hi]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx() -> Permissions {
        Permissions {
            read: true,
            write: false,
            execute: true,
        }
    }

    fn sample() -> Program {
        let code = Region::new(
            "obj1",
            Address::Flat(0x10000),
            0x20,
            (0u8..0x20).collect(),
            rx(),
            ArchMode::X86Flat32,
        );
        let data = Region::new(
            "obj2",
            Address::Flat(0x10020),
            0x40,
            vec![0xAA; 0x10],
            Permissions::default(),
            ArchMode::X86Flat32,
        );
        let relocations = vec![
            Relocation::new(
                Address::Flat(0x10010),
                RelocKind::Absolute,
                4,
                Address::Flat(0x10020),
                0,
            ),
            Relocation::new(
                Address::Flat(0x10004),
                RelocKind::Relative,
                4,
                Address::Flat(0x10000),
                0,
            ),
        ];
        Program::new(
            ExecutableFormat::Le,
            vec![code, data],
            vec![Address::Flat(0x10000)],
            relocations,
        )
    }

    #[test]
    fn read_inside_region() {
        assert_eq!(
            sample().read(Address::Flat(0x10002), 3),
            Some(&[2u8, 3, 4][..])
        );
    }

    #[test]
    fn read_across_regions_is_none() {
        assert_eq!(sample().read(Address::Flat(0x1001E), 4), None);
    }

    #[test]
    fn read_uninitialized_tail_is_none() {
        let program = sample();
        assert!(program.read(Address::Flat(0x10020), 0x10).is_some());
        assert_eq!(program.read(Address::Flat(0x1002C), 8), None);
        assert_eq!(
            program
                .region_at(Address::Flat(0x1005F))
                .map(|r| r.name.as_str()),
            Some("obj2")
        );
    }

    #[test]
    fn relocations_in_range_sorted() {
        let program = sample();
        let all = program.relocations_in(Address::Flat(0x10000), 0x20);
        assert_eq!(
            all.iter().map(|r| r.at).collect::<Vec<_>>(),
            vec![Address::Flat(0x10004), Address::Flat(0x10010)]
        );
        assert_eq!(
            program.relocations_in(Address::Flat(0x10005), 0x0B).len(),
            0
        );
        assert_eq!(program.relocations_in(Address::Flat(0x10010), 1).len(), 1);
    }

    #[test]
    fn arch_serializes_as_string_id() {
        assert_eq!(
            serde_json::to_string(&ArchMode::X86Flat32).unwrap(),
            "\"x86-flat-32\""
        );
        assert_eq!(
            serde_json::to_string(&RelocKind::FarPointer).unwrap(),
            "\"far-pointer\""
        );
    }
}
