//! Similarity of instruction sequences: forms, MinHash prefilter and exemplar ranking (port of Decomp's
//! `nachbau/vorbilder.py`).
//!
//! Forms are strings per instruction; callers intern them to `u32` and pass the sequences to [`coverage`],
//! [`indel_similarity`], [`shared_stretches`], [`minhash`] and [`rank`]. Positions in a [`Stretch`] are
//! instruction indices (inclusive) into the padding-free sequences, not byte offsets as in Decomp; the caller
//! maps them when it needs offsets.

use std::collections::HashMap;

use decovery_x86::{DecodeOptions, decode_detailed};

/// Window length (instructions) of coverage, stretches and MinHash grams.
pub const WINDOW: usize = 6;
/// Number of MinHash values in a sketch.
pub const HASHES: usize = 64;
/// Number of LSH bands (4 rows each).
pub const BANDS: usize = 16;
/// Candidates kept by the coverage preselection of [`rank`] (at least `top`).
pub const PRESELECT: usize = 30;

const ROWS: usize = HASHES / BANDS;
const SEED_START: u64 = 0x6465_636f_7665_7279;
const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// A shared run: `(first, last)` instruction index in the target and in the candidate (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stretch {
    pub target: (usize, usize),
    pub candidate: (usize, usize),
}

/// One ranked candidate of [`rank`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Ranked {
    /// Index into the candidate slice.
    pub candidate: usize,
    /// Indel similarity rounded to 3 decimals.
    pub similarity: f64,
    /// Coverage rounded to 3 decimals.
    pub coverage: f64,
    /// `(similarity + coverage) / 2`.
    pub score: f64,
    pub stretches: Vec<Stretch>,
    /// The coarse sequences (registers kept) are equal: only addresses and numbers differ.
    pub twin: bool,
}

/// Normalised form per non-padding instruction: Intel text with numbers as `N` and general registers as
/// `r`/`r16`/`r8` (frame registers kept). Empty for an unsupported `bits`.
pub fn instruction_forms(code: &[u8], bits: u32, base: u64) -> Vec<String> {
    decode_detailed(code, bits, base, &DecodeOptions::default())
        .iter()
        .filter(|d| !d.is_padding())
        .map(|d| normalise(&d.text))
        .collect()
}

/// Comparison form per non-padding instruction: numbers masked, registers kept (the decoder's shape).
pub fn coarse_forms(code: &[u8], bits: u32, base: u64) -> Vec<String> {
    decode_detailed(code, bits, base, &DecodeOptions::default())
        .into_iter()
        .filter(|d| !d.is_padding())
        .map(|d| d.shape)
        .collect()
}

/// Decomp's `form`: numbers (`0x…`, `…h`, decimal, with a leading `-`) become `N`, then registers are grouped;
/// iced-x86's `short`/`near` branch markers are dropped (capstone has none).
fn normalise(text: &str) -> String {
    let chars: Vec<char> = text.trim().chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if !is_word(c) {
            out.push(c);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_word(chars[i]) {
            i += 1;
        }
        let word: String = chars[start..i].iter().collect();
        // Branch distance markers: capstone (Decomp) prints `jmp 0x…` for rel8 and rel32 alike.
        if (word == "short" || word == "near") && chars.get(i) == Some(&' ') {
            i += 1;
            continue;
        }
        if is_number(&word) {
            if out.ends_with('-') {
                out.pop();
            }
            out.push('N');
        } else {
            out.push_str(register_group(&word).unwrap_or(&word));
        }
    }
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_number(word: &str) -> bool {
    let b = word.as_bytes();
    if b.is_empty() || !b[0].is_ascii_digit() {
        return false;
    }
    if b.iter().all(u8::is_ascii_digit) {
        return true;
    }
    if b.len() > 2 && b[0] == b'0' && b[1] == b'x' {
        return b[2..].iter().all(u8::is_ascii_hexdigit);
    }
    // iced's IntelFormatter prints hex as `0Ch` / `0FFFFh` (ruling on preflight row 12).
    b.len() > 1
        && b[b.len() - 1] == b'h'
        && b[1..b.len() - 1]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c))
}

fn register_group(word: &str) -> Option<&'static str> {
    match word {
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" => Some("r"),
        "ax" | "bx" | "cx" | "dx" | "si" | "di" => Some("r16"),
        "al" | "ah" | "bl" | "bh" | "cl" | "ch" | "dl" | "dh" => Some("r8"),
        _ => None,
    }
}

fn window(len: usize) -> usize {
    WINDOW.min(len)
}

/// Decomp's `abdeckung`: share of target positions inside a window (length `min(WINDOW, |target|)`) that also
/// occurs in the candidate; 0 when the candidate is shorter than the window or the target is empty.
pub fn coverage(target: &[u32], candidate: &[u32]) -> f64 {
    let n = window(target.len());
    if n == 0 || candidate.len() < n {
        return 0.0;
    }
    let theirs: std::collections::HashSet<&[u32]> = candidate.windows(n).collect();
    let windows = target.len() - n + 1;
    let (mut covered, mut until) = (0usize, 0usize);
    for (i, w) in target.windows(n).enumerate() {
        if theirs.contains(w) {
            covered += i + n - i.max(until);
            until = i + n;
        }
    }
    covered as f64 / (windows + n - 1) as f64
}

/// `2·LCS / (|a| + |b|)`; 1.0 for two empty sequences.
pub fn indel_similarity(a: &[u32], b: &[u32]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let (long, short) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let mut row = vec![0usize; short.len() + 1];
    for &x in long {
        let mut diag = 0;
        for (j, &y) in short.iter().enumerate() {
            let up = row[j + 1];
            row[j + 1] = if x == y { diag + 1 } else { up.max(row[j]) };
            diag = up;
        }
    }
    2.0 * row[short.len()] as f64 / (a.len() + b.len()) as f64
}

/// Decomp's `_strecken` with `min(WINDOW, |target|)`: greedy from the front, per start the longest continuation
/// among candidate positions starting the same window; the three longest, sorted by position (ruling (c)).
pub fn shared_stretches(target: &[u32], candidate: &[u32]) -> Vec<Stretch> {
    let n = window(target.len());
    if n == 0 || candidate.len() < n {
        return Vec::new();
    }
    let mut starts: HashMap<&[u32], Vec<usize>> = HashMap::new();
    for (j, w) in candidate.windows(n).enumerate() {
        starts.entry(w).or_default().push(j);
    }
    let mut found: Vec<(usize, usize, usize)> = Vec::new();
    let mut i = 0;
    while i + n <= target.len() {
        let mut best: Option<(usize, usize, usize)> = None;
        for &j in starts
            .get(&target[i..i + n])
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let mut m = n;
            while i + m < target.len()
                && j + m < candidate.len()
                && target[i + m] == candidate[j + m]
            {
                m += 1;
            }
            if best.is_none_or(|b| m > b.2) {
                best = Some((i, j, m));
            }
        }
        match best {
            Some(b) => {
                found.push(b);
                i += b.2;
            }
            None => i += 1,
        }
    }
    found.sort_by_key(|s| std::cmp::Reverse(s.2));
    found.truncate(3);
    found.sort();
    found
        .into_iter()
        .map(|(i, j, m)| Stretch {
            target: (i, i + m - 1),
            candidate: (j, j + m - 1),
        })
        .collect()
}

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn splitmix64(x: u64) -> u64 {
    mix(x.wrapping_add(GAMMA))
}

fn seeds() -> [u64; HASHES] {
    let mut state = SEED_START;
    std::array::from_fn(|_| {
        state = state.wrapping_add(GAMMA);
        mix(state)
    })
}

fn hash8(bytes: &[u8]) -> u64 {
    let h = blake3::hash(bytes);
    let mut first = [0u8; 8];
    first.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(first)
}

fn gram_hash(gram: &[u32]) -> u64 {
    let bytes: Vec<u8> = gram.iter().flat_map(|v| v.to_le_bytes()).collect();
    hash8(&bytes)
}

/// MinHash sketch over the `WINDOW`-grams of `forms` (a shorter sequence is one gram). Hash `i` of a gram is
/// `splitmix64(gram_hash ^ seed_i)`, seeds the splitmix64 sequence from `0x6465636f76657279`, `gram_hash` the
/// first 8 bytes (LE) of blake3 over the gram's u32 values (LE).
pub fn minhash(forms: &[u32]) -> [u64; HASHES] {
    let seeds = seeds();
    let grams: Vec<u64> = if forms.len() < WINDOW {
        vec![gram_hash(forms)]
    } else {
        forms.windows(WINDOW).map(gram_hash).collect()
    };
    std::array::from_fn(|i| {
        grams
            .iter()
            .map(|&g| splitmix64(g ^ seeds[i]))
            .min()
            .unwrap_or(u64::MAX)
    })
}

/// One key per band of 4 rows: first 8 bytes of blake3 over the band index (u32 LE) and its rows (u64 LE).
pub fn lsh_keys(sketch: &[u64; HASHES]) -> [u64; BANDS] {
    std::array::from_fn(|band| {
        let mut bytes = Vec::with_capacity(4 + 8 * ROWS);
        bytes.extend((band as u32).to_le_bytes());
        for v in &sketch[band * ROWS..(band + 1) * ROWS] {
            bytes.extend(v.to_le_bytes());
        }
        hash8(&bytes)
    })
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// Decomp's `suchen`: preselect by (coverage, −|length difference|) descending (stable, so index order breaks
/// ties), keep `max(PRESELECT, top)`, then score `(similarity + coverage) / 2` with both rounded to 3 decimals,
/// sorted descending and stable (ties keep the preselection order, ruling (b)); the best `top`.
/// `candidates` are `(forms, coarse)` pairs.
pub fn rank(
    target: &[u32],
    target_coarse: &[u32],
    candidates: &[(&[u32], &[u32])],
    top: usize,
) -> Vec<Ranked> {
    if target.is_empty() || candidates.is_empty() {
        return Vec::new();
    }
    let mut pre: Vec<(usize, f64, usize)> = candidates
        .iter()
        .enumerate()
        .map(|(k, (forms, _))| {
            (
                k,
                coverage(target, forms),
                forms.len().abs_diff(target.len()),
            )
        })
        .collect();
    pre.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.2.cmp(&b.2)));
    pre.truncate(PRESELECT.max(top));
    let mut out: Vec<Ranked> = pre
        .into_iter()
        .map(|(k, cov, _)| {
            let (forms, coarse) = candidates[k];
            let similarity = round3(indel_similarity(target, forms));
            let coverage = round3(cov);
            Ranked {
                candidate: k,
                similarity,
                coverage,
                score: (similarity + coverage) / 2.0,
                stretches: shared_stretches(target, forms),
                twin: coarse == target_coarse,
            }
        })
        .collect();
    out.sort_by(|a, b| b.score.total_cmp(&a.score));
    out.truncate(top);
    out
}
