//! Port of Python's `difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()` for sequences of
//! comparable items. Decomp falls back to it for functions too large for the minimum-cost alignment.

use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Equal,
    Replace,
    Delete,
    Insert,
}

struct Matcher<'a, T> {
    a: &'a [T],
    b: &'a [T],
    b2j: HashMap<&'a T, Vec<usize>>,
}

impl<'a, T: Eq + Hash> Matcher<'a, T> {
    fn new(a: &'a [T], b: &'a [T]) -> Self {
        let mut b2j: HashMap<&T, Vec<usize>> = HashMap::new();
        for (j, x) in b.iter().enumerate() {
            b2j.entry(x).or_default().push(j);
        }
        Matcher { a, b, b2j }
    }

    fn find_longest_match(
        &self,
        alo: usize,
        ahi: usize,
        blo: usize,
        bhi: usize,
    ) -> (usize, usize, usize) {
        let (a, b) = (self.a, self.b);
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, x) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut next: HashMap<usize, usize> = HashMap::new();
            if let Some(js) = self.b2j.get(x) {
                for &j in js {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let k = j
                        .checked_sub(1)
                        .and_then(|p| j2len.get(&p))
                        .copied()
                        .unwrap_or(0)
                        + 1;
                    next.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = next;
        }
        while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && a[besti + bestsize] == b[bestj + bestsize]
        {
            bestsize += 1;
        }
        (besti, bestj, bestsize)
    }

    fn matching_blocks(&self) -> Vec<(usize, usize, usize)> {
        let (la, lb) = (self.a.len(), self.b.len());
        let mut queue = vec![(0, la, 0, lb)];
        let mut blocks = Vec::new();
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let (i, j, k) = self.find_longest_match(alo, ahi, blo, bhi);
            if k > 0 {
                blocks.push((i, j, k));
                if alo < i && blo < j {
                    queue.push((alo, i, blo, j));
                }
                if i + k < ahi && j + k < bhi {
                    queue.push((i + k, ahi, j + k, bhi));
                }
            }
        }
        blocks.sort_unstable();
        let (mut i1, mut j1, mut k1) = (0, 0, 0);
        let mut merged = Vec::new();
        for (i2, j2, k2) in blocks {
            if i1 + k1 == i2 && j1 + k1 == j2 {
                k1 += k2;
            } else {
                if k1 > 0 {
                    merged.push((i1, j1, k1));
                }
                (i1, j1, k1) = (i2, j2, k2);
            }
        }
        if k1 > 0 {
            merged.push((i1, j1, k1));
        }
        merged.push((la, lb, 0));
        merged
    }
}

/// `(op, i1, i2, j1, j2)` like `SequenceMatcher.get_opcodes()` without junk heuristics.
pub(crate) fn opcodes<T: Eq + Hash>(a: &[T], b: &[T]) -> Vec<(Op, usize, usize, usize, usize)> {
    let matcher = Matcher::new(a, b);
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    for (ai, bj, size) in matcher.matching_blocks() {
        let op = if i < ai && j < bj {
            Some(Op::Replace)
        } else if i < ai {
            Some(Op::Delete)
        } else if j < bj {
            Some(Op::Insert)
        } else {
            None
        };
        if let Some(op) = op {
            out.push((op, i, ai, j, bj));
        }
        i = ai + size;
        j = bj + size;
        if size > 0 {
            out.push((Op::Equal, ai, i, bj, j));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_difflib() {
        // difflib.SequenceMatcher(None, "qabxcd", "abycdf", autojunk=False).get_opcodes()
        let a: Vec<char> = "qabxcd".chars().collect();
        let b: Vec<char> = "abycdf".chars().collect();
        assert_eq!(
            opcodes(&a, &b),
            vec![
                (Op::Delete, 0, 1, 0, 0),
                (Op::Equal, 1, 3, 0, 2),
                (Op::Replace, 3, 4, 2, 3),
                (Op::Equal, 4, 6, 3, 5),
                (Op::Insert, 6, 6, 5, 6),
            ]
        );
        assert!(opcodes::<char>(&[], &[]).is_empty());
    }
}
