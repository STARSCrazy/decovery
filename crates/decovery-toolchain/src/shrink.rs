//! Function-level attempts (port of Decomp's `nachbau/einzeln.py`): the definition finder, splicing one function
//! into its source file, and shrinking a file to one function and what its code depends on, so that a compile
//! translates only that.
//!
//! What a shrunk file keeps: all text outside function bodies (includes, types, globals, prototypes, macros); the
//! targets and every function of the file that names a kept function (call or address), transitively (Watcom
//! knows the register use of functions of the same file and drops calls of empty ones); static functions named
//! outside bodies (tables of function pointers); functions with K&R parameters (no prototype can be cut from
//! them). Every other definition becomes its prototype followed by as many line ends as its body had, so every line
//! number stays.

use std::collections::{BTreeMap, BTreeSet};

use crate::ToolchainError;
use crate::cheat::{is_word, mask};

/// Words that can stand before `(` without defining a function.
const NOT_FUNCTIONS: [&str; 13] = [
    "if",
    "while",
    "for",
    "switch",
    "return",
    "sizeof",
    "do",
    "else",
    "case",
    "__pragma",
    "_Pragma",
    "defined",
    "__declspec",
];

/// A function definition at the top level of a source text (byte offsets into the text).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Definition {
    pub name: String,
    /// Start of the line of the head; a return type on lines of its own before it belongs to the head.
    pub start: usize,
    /// The opening brace of the body.
    pub brace: usize,
    /// Behind the closing brace and its line end.
    pub end: usize,
    /// K&R parameter declarations between `)` and `{`.
    pub knr: bool,
    pub is_static: bool,
}

/// A source text shrunk by [`shrink`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Shrunk {
    pub text: String,
    /// The functions whose definitions stay, in text order.
    pub kept: Vec<String>,
    /// The functions whose definitions became prototypes, in text order.
    pub dropped: Vec<String>,
}

fn is_word_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn skip_space(m: &[u8], mut i: usize) -> usize {
    while i < m.len() && m[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// End of the identifier starting at `i`.
fn word_end(m: &[u8], mut i: usize) -> usize {
    while i < m.len() && is_word(m[i]) {
        i += 1;
    }
    i
}

/// Blanks preprocessor lines (and their `\` continuations), keeping line ends, so that `#define F(x) { ... }` is no
/// definition.
fn blank_preprocessor(m: &mut [u8]) {
    let mut continued = false;
    let mut line_start = 0;
    while line_start < m.len() {
        let end = m[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(m.len(), |p| line_start + p);
        let line = &m[line_start..end];
        if continued || line.trim_ascii_start().first() == Some(&b'#') {
            continued = line.trim_ascii_end().last() == Some(&b'\\');
            for b in &mut m[line_start..end] {
                *b = b' ';
            }
        }
        line_start = end + 1;
    }
}

/// End of the K&R declarations behind a parameter list (`<text without ;{}()>;` any number of times, then
/// white space): where the body brace has to be.
fn after_declarations(m: &[u8], mut k: usize) -> usize {
    loop {
        let run = m[k..]
            .iter()
            .position(|b| b";{}()".contains(b))
            .map_or(m.len(), |p| k + p);
        if run > k && m.get(run) == Some(&b';') {
            k = run + 1;
        } else {
            return skip_space(m, k);
        }
    }
}

/// All function definitions at the top level of `text`, in text order. Comments, string literals and preprocessor
/// lines do not count.
pub fn definitions(text: &str) -> Vec<Definition> {
    let mut m = mask(text.as_bytes());
    blank_preprocessor(&mut m);
    let n = m.len();
    let mut found: Vec<Definition> = Vec::new();
    let mut depth = 0i64;
    let mut i = 0;
    while i < n {
        let c = m[i];
        if c == b'{' {
            depth += 1;
            i += 1;
            continue;
        }
        if c == b'}' {
            depth -= 1;
            i += 1;
            continue;
        }
        if depth != 0 || !is_word_start(c) || (i > 0 && is_word(m[i - 1])) {
            i += 1;
            continue;
        }
        let name_end = word_end(&m, i);
        let name = &text[i..name_end];
        let mut k = skip_space(&m, name_end);
        if NOT_FUNCTIONS.contains(&name) || m.get(k) != Some(&b'(') {
            i = name_end;
            continue;
        }
        // the parameter list
        let mut open = 1;
        k += 1;
        while k < n && open > 0 {
            match m[k] {
                b'(' => open += 1,
                b')' => open -= 1,
                _ => {}
            }
            k += 1;
        }
        let brace = after_declarations(&m, k);
        if m.get(brace) != Some(&b'{') {
            i = name_end;
            continue;
        }
        let knr = !m[k..brace].trim_ascii().is_empty();
        let mut inner = 0i64;
        let mut e = brace;
        while e < n {
            match m[e] {
                b'{' => inner += 1,
                b'}' => inner -= 1,
                _ => {}
            }
            e += 1;
            if inner == 0 {
                break;
            }
        }
        let end = if m.get(e) == Some(&b'\n') { e + 1 } else { e };
        // the head starts at its line, or earlier with the return type on lines of its own
        let floor = found.last().map_or(0, |d| d.end);
        let mut start = m[..i]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |p| p + 1);
        while start > floor {
            let before = m[..start - 1]
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |p| p + 1);
            let line = m[before..start - 1].trim_ascii();
            if line.is_empty()
                || line[0] == b'#'
                || matches!(line.last(), Some(b';' | b'}' | b'{' | b')'))
            {
                break;
            }
            start = before;
        }
        let start = start.max(floor);
        let head = &m[start..i];
        let is_static = head.split(|&b| !is_word(b)).any(|word| word == b"static");
        found.push(Definition {
            name: name.to_string(),
            start,
            brace,
            end,
            knr,
            is_static,
        });
        i = end;
    }
    found
}

/// Replaces the definition of `name` in `file_text` by `function_source`, which must define exactly that one
/// function (other text such as comments may come with it).
pub fn splice_function(
    file_text: &str,
    name: &str,
    function_source: &str,
) -> Result<String, ToolchainError> {
    let given = definitions(function_source);
    match given.as_slice() {
        [one] if one.name == name => {}
        [] => {
            return Err(ToolchainError::Invalid(format!(
                "the function source must define exactly one function, {name}; it defines none"
            )));
        }
        _ => {
            let names: Vec<&str> = given.iter().map(|d| d.name.as_str()).collect();
            return Err(ToolchainError::Invalid(format!(
                "the function source must define exactly one function, {name}; it defines {}",
                names.join(", ")
            )));
        }
    }
    let in_file: Vec<Definition> = definitions(file_text)
        .into_iter()
        .filter(|d| d.name == name)
        .collect();
    let d = match in_file.as_slice() {
        [one] => one,
        [] => {
            return Err(ToolchainError::Invalid(format!(
                "the file does not define {name}"
            )));
        }
        more => {
            return Err(ToolchainError::Invalid(format!(
                "the file defines {name} {} times",
                more.len()
            )));
        }
    };
    let mut out = String::with_capacity(file_text.len() + function_source.len());
    out.push_str(&file_text[..d.start]);
    out.push_str(function_source);
    if file_text[..d.end].ends_with('\n') && !function_source.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&file_text[d.end..]);
    Ok(out)
}

/// The identifiers of `m`.
fn identifiers(m: &[u8]) -> BTreeSet<&[u8]> {
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < m.len() {
        if is_word_start(m[i]) && (i == 0 || !is_word(m[i - 1])) {
            let end = word_end(m, i);
            out.insert(&m[i..end]);
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// End of a prototype `name (<params with one level of nested parentheses>) ;` starting at the identifier `i`.
fn prototype_end(m: &[u8], i: usize) -> Option<usize> {
    let mut k = skip_space(m, word_end(m, i));
    if m.get(k) != Some(&b'(') {
        return None;
    }
    k += 1;
    let mut nested = false;
    loop {
        match *m.get(k)? {
            b';' | b'{' | b'}' => return None,
            b'(' if nested => return None,
            b'(' => nested = true,
            b')' if nested => nested = false,
            b')' => break,
            _ => {}
        }
        k += 1;
    }
    let k = skip_space(m, k + 1);
    (m.get(k) == Some(&b';')).then_some(k + 1)
}

/// `m` with every prototype replaced by a space.
fn without_prototypes(m: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(m.len());
    let mut i = 0;
    while i < m.len() {
        if is_word_start(m[i]) && (i == 0 || !is_word(m[i - 1])) {
            if let Some(end) = prototype_end(m, i) {
                out.push(b' ');
                i = end;
            } else {
                let end = word_end(m, i);
                out.extend_from_slice(&m[i..end]);
                i = end;
            }
        } else {
            out.push(m[i]);
            i += 1;
        }
    }
    out
}

/// Shrinks `text` to the `targets` and what their code depends on (see the module documentation). `None` when
/// nothing can be dropped: a target not defined exactly once, a function defined twice (`#if` branches), or every
/// function needed.
pub fn shrink(text: &str, targets: &[&str]) -> Option<Shrunk> {
    let defs = definitions(text);
    if targets
        .iter()
        .any(|t| defs.iter().filter(|d| d.name == *t).count() != 1)
    {
        return None;
    }
    let by_name: BTreeMap<&str, &Definition> = defs.iter().map(|d| (d.name.as_str(), d)).collect();
    if by_name.len() != defs.len() {
        return None;
    }
    let m = mask(text.as_bytes());
    // static functions named outside the bodies stay (a never defined static function would be an error)
    let mut outside = Vec::with_capacity(m.len());
    let mut pos = 0;
    for d in &defs {
        outside.extend_from_slice(&m[pos..d.start]);
        pos = d.end;
    }
    outside.extend_from_slice(&m[pos..]);
    let outside = without_prototypes(&outside);
    let outside_names = identifiers(&outside);
    let mut kept: BTreeSet<&str> = targets.iter().copied().collect();
    kept.extend(
        defs.iter()
            .filter(|d| d.knr || (d.is_static && outside_names.contains(d.name.as_bytes())))
            .map(|d| d.name.as_str()),
    );
    let mut open: Vec<&str> = kept.iter().copied().collect();
    while let Some(name) = open.pop() {
        let d = by_name[name];
        for word in identifiers(&m[d.brace..d.end]) {
            let Ok(word) = std::str::from_utf8(word) else {
                continue;
            };
            if let Some((&callee, _)) = by_name.get_key_value(word)
                && kept.insert(callee)
            {
                open.push(callee);
            }
        }
    }
    if kept.len() == defs.len() {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut dropped = Vec::new();
    let mut pos = 0;
    for d in &defs {
        out.push_str(&text[pos..d.start]);
        if kept.contains(d.name.as_str()) {
            out.push_str(&text[d.start..d.end]);
        } else {
            dropped.push(d.name.clone());
            let raw = &text[d.start..d.brace];
            let mut head = raw.trim_end();
            let masked = std::str::from_utf8(&m[d.start..d.start + head.len()]).unwrap_or("");
            if masked.trim_end() != head {
                // a comment at the end of the head: the `;` goes behind its line end
                head = raw.trim_end_matches([' ', '\t']);
            }
            let line_ends = raw[head.len()..].matches('\n').count()
                + text[d.brace..d.end].matches('\n').count();
            out.push_str(head);
            out.push(';');
            out.extend(std::iter::repeat_n('\n', line_ends));
        }
        pos = d.end;
    }
    out.push_str(&text[pos..]);
    Some(Shrunk {
        text: out,
        kept: defs
            .iter()
            .filter(|d| kept.contains(d.name.as_str()))
            .map(|d| d.name.clone())
            .collect(),
        dropped,
    })
}
