//! Code page 437: the upper half (0x80..=0xFF) as a table; 0x00..=0x7F is ASCII.

const UPPER: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', //
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', //
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', //
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', //
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', //
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', //
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', //
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}', //
];

/// The code page 437 byte of `c`, if it has one.
pub(crate) fn encode(c: char) -> Option<u8> {
    if c.is_ascii() {
        return Some(c as u8);
    }
    UPPER.iter().position(|&u| u == c).map(|i| 0x80 + i as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_round_trips() {
        for (i, &c) in UPPER.iter().enumerate() {
            assert_eq!(encode(c), Some(0x80 + i as u8), "{c:?}");
        }
    }

    #[test]
    fn known_bytes() {
        assert_eq!(encode('ä'), Some(0x84));
        assert_eq!(encode('ß'), Some(0xE1));
        assert_eq!(encode('A'), Some(0x41));
        assert_eq!(encode('€'), None);
    }
}
