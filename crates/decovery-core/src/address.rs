//! Typed addresses with one canonical text form each.
//!
//! - `flat:0001A2B0` — 32-bit linear/virtual address
//! - `seg:1234:0010` — real-mode segment:offset, relative to the load segment
//! - `sel:0007:00001234` — static segment number from the file (e.g. NE segment table index) and offset
//!
//! `file:0x1A2B` is accepted only as [`AddressInput`] at the CLI/MCP boundary. `flat64:` is reserved.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An address inside a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Address {
    /// 32-bit linear (virtual) address.
    Flat(u32),
    /// Real-mode segment and offset, segment relative to the load segment.
    Seg { seg: u16, off: u16 },
    /// Static segment number from the file and offset; has no linear address.
    Sel { segment: u16, off: u32 },
}

/// An address as typed by a user or agent: either a program address or a file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressInput {
    Address(Address),
    FileOffset(u64),
}

/// Errors when parsing or computing addresses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AddressError {
    #[error("invalid address syntax: {0:?}")]
    Syntax(String),
    #[error("address form `{0}:` is reserved and not supported yet")]
    Reserved(&'static str),
    #[error("address arithmetic overflow")]
    Overflow,
}

impl Address {
    /// Linear address for flat and real-mode addresses; `None` for static segment addresses.
    pub fn linear(&self) -> Option<u64> {
        match *self {
            Address::Flat(a) => Some(u64::from(a)),
            Address::Seg { seg, off } => Some(u64::from(seg) * 16 + u64::from(off)),
            Address::Sel { .. } => None,
        }
    }

    /// The same kind of address moved by `delta` bytes (offset part only for segmented forms).
    pub fn offset_by(&self, delta: i64) -> Result<Address, AddressError> {
        fn add<T: TryFrom<i128>>(value: i128, delta: i64) -> Result<T, AddressError> {
            T::try_from(value + i128::from(delta)).map_err(|_| AddressError::Overflow)
        }
        Ok(match *self {
            Address::Flat(a) => Address::Flat(add(i128::from(a), delta)?),
            Address::Seg { seg, off } => Address::Seg {
                seg,
                off: add(i128::from(off), delta)?,
            },
            Address::Sel { segment, off } => Address::Sel {
                segment,
                off: add(i128::from(off), delta)?,
            },
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Address::Flat(a) => write!(f, "flat:{a:08X}"),
            Address::Seg { seg, off } => write!(f, "seg:{seg:04X}:{off:04X}"),
            Address::Sel { segment, off } => write!(f, "sel:{segment:04X}:{off:08X}"),
        }
    }
}

fn hex<T: TryFrom<u64>>(text: &str, max_digits: usize, whole: &str) -> Result<T, AddressError> {
    let syntax = || AddressError::Syntax(whole.to_string());
    if text.is_empty() || text.len() > max_digits || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(syntax());
    }
    let value = u64::from_str_radix(text, 16).map_err(|_| syntax())?;
    T::try_from(value).map_err(|_| syntax())
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (prefix, rest) = s
            .split_once(':')
            .ok_or_else(|| AddressError::Syntax(s.to_string()))?;
        match prefix {
            "flat" => Ok(Address::Flat(hex(rest, 8, s)?)),
            "seg" => {
                let (seg, off) = rest
                    .split_once(':')
                    .ok_or_else(|| AddressError::Syntax(s.to_string()))?;
                Ok(Address::Seg {
                    seg: hex(seg, 4, s)?,
                    off: hex(off, 4, s)?,
                })
            }
            "sel" => {
                let (segment, off) = rest
                    .split_once(':')
                    .ok_or_else(|| AddressError::Syntax(s.to_string()))?;
                Ok(Address::Sel {
                    segment: hex(segment, 4, s)?,
                    off: hex(off, 8, s)?,
                })
            }
            "flat64" => Err(AddressError::Reserved("flat64")),
            _ => Err(AddressError::Syntax(s.to_string())),
        }
    }
}

impl FromStr for AddressInput {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("file:") {
            let digits = rest
                .strip_prefix("0x")
                .or_else(|| rest.strip_prefix("0X"))
                .ok_or_else(|| AddressError::Syntax(s.to_string()))?;
            return Ok(AddressInput::FileOffset(hex(digits, 16, s)?));
        }
        s.parse().map(AddressInput::Address)
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_forms() {
        for text in ["flat:0001A2B0", "seg:1234:0010", "sel:0007:00001234"] {
            let address: Address = text.parse().unwrap();
            assert_eq!(address.to_string(), text);
        }
    }

    #[test]
    fn parse_accepts_lowercase_hex() {
        let address: Address = "flat:0001a2b0".parse().unwrap();
        assert_eq!(address.to_string(), "flat:0001A2B0");
    }

    #[test]
    fn rejects_garbage() {
        for text in [
            "va:00010000",
            "flat:",
            "seg:12345:0000",
            "flat:1FFFFFFFF",
            "flat",
            "",
            "seg:1234",
            "flat:-1",
        ] {
            assert!(
                text.parse::<Address>().is_err(),
                "{text} should be rejected"
            );
        }
    }

    #[test]
    fn flat64_is_reserved() {
        assert_eq!(
            "flat64:0000000000401000".parse::<Address>(),
            Err(AddressError::Reserved("flat64"))
        );
    }

    #[test]
    fn file_offset_is_input_only() {
        assert!("file:0x1A2B".parse::<Address>().is_err());
        assert_eq!(
            "file:0x1A2B".parse::<AddressInput>(),
            Ok(AddressInput::FileOffset(0x1A2B))
        );
        assert_eq!(
            "flat:00010000".parse::<AddressInput>(),
            Ok(AddressInput::Address(Address::Flat(0x10000)))
        );
    }

    #[test]
    fn seg_linear() {
        let address: Address = "seg:1234:0010".parse().unwrap();
        assert_eq!(address.linear(), Some(0x12350));
        assert_eq!(
            "sel:0001:00000000".parse::<Address>().unwrap().linear(),
            None
        );
    }

    #[test]
    fn offset_overflow() {
        assert_eq!(
            Address::Flat(0xFFFF_FFFF).offset_by(1),
            Err(AddressError::Overflow)
        );
        assert_eq!(Address::Flat(0x10).offset_by(-0x10), Ok(Address::Flat(0)));
        assert_eq!(
            Address::Seg {
                seg: 1,
                off: 0xFFFF
            }
            .offset_by(1),
            Err(AddressError::Overflow)
        );
    }

    #[test]
    fn serializes_as_canonical_string() {
        let json = serde_json::to_string(&Address::Flat(0x10010)).unwrap();
        assert_eq!(json, "\"flat:00010010\"");
        let back: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Address::Flat(0x10010));
    }
}
