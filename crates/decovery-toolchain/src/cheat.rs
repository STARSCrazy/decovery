//! Inline-assembly check of rebuild sources: inline assembly, machine code in `#pragma aux` and embedded bytes
//! make a function byte-identical without being real C, so such a function does not count as a rebuild.
//!
//! `#pragma aux` without code (calling convention: `parm`, `modify`, `value`, `aborts` ...), comments, string
//! literals and separate assembler files are allowed.

use crate::shrink::definitions;

/// What kind of shortcut a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheatKind {
    /// `_asm`, `__asm`, `__asm__`, `asm (`, `asm volatile`, `asm {`.
    InlineAssembly,
    /// `_emit`, `__emit`, `__emit__`.
    Emit,
    /// `#pragma aux name = <bytes>`.
    PragmaCode,
}

impl CheatKind {
    /// The serialized id: `inline-asm`, `emit` or `pragma-code`.
    pub fn id(self) -> &'static str {
        match self {
            CheatKind::InlineAssembly => "inline-asm",
            CheatKind::Emit => "emit",
            CheatKind::PragmaCode => "pragma-code",
        }
    }
}

/// One finding in a source text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheatFinding {
    /// 1-based line.
    pub line: u32,
    pub kind: CheatKind,
    /// The function containing the finding (the pragma name for `PragmaCode`); `None` at file level.
    pub function: Option<String>,
    /// The matched text (at most 80 characters for a pragma).
    pub text: String,
}

impl CheatFinding {
    /// Whether the finding blocks `function`: a finding inside it, and every finding outside a function body. The
    /// machine code of a `#pragma aux` is inlined into each caller (Watcom), and code at file level can reach any
    /// function of the file, so neither may be attributed to one function.
    pub fn blocks(&self, function: &str) -> bool {
        self.kind == CheatKind::PragmaCode || self.function.as_deref().is_none_or(|f| f == function)
    }

    /// One line for the result of `function`: line, kind and text, and why a finding outside `function` blocks it.
    pub fn describe(&self, function: &str) -> String {
        let line = format!("line {}: {} {}", self.line, self.kind.id(), self.text);
        if self.kind == CheatKind::PragmaCode {
            format!(
                "{line} (machine code inlined into its callers: blocks every function of the file)"
            )
        } else if self.function.is_none() {
            format!("{line} (outside a function: blocks every function of the file)")
        } else if self.function.as_deref() != Some(function) {
            format!("{line} (in another function)")
        } else {
            line
        }
    }
}

pub(crate) fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Replaces comments, string literals and character literals by spaces (newlines stay), keeping the length,
/// so that braces and names inside them do not count.
pub(crate) fn mask(text: &[u8]) -> Vec<u8> {
    let mut out = text.to_vec();
    let n = text.len();
    let mut i = 0;
    while i < n {
        let c = text[i];
        let end = if text[i..].starts_with(b"/*") {
            find(text, b"*/", i + 2).map_or(n, |j| j + 2)
        } else if text[i..].starts_with(b"//") {
            text[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(n, |j| i + j)
        } else if c == b'"' || c == b'\'' {
            let mut j = i + 1;
            while j < n && text[j] != c && text[j] != b'\n' {
                j += if text[j] == b'\\' { 2 } else { 1 };
            }
            (j + 1).min(n)
        } else {
            i += 1;
            continue;
        };
        for b in &mut out[i..end] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
        i = end;
    }
    out
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

fn skip_space(m: &[u8], mut i: usize) -> usize {
    while i < m.len() && m[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// `#pragma aux` spans (start of line, end of text); a trailing `\` continues a pragma on the next line.
fn pragma_spans(m: &[u8]) -> Vec<(usize, usize)> {
    let blank = |b: u8| b == b' ' || b == b'\t';
    let mut out = Vec::new();
    let mut line_start = 0;
    while line_start < m.len() {
        let mut end = m[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(m.len(), |p| line_start + p);
        let line = &m[line_start..end];
        let rest = line.trim_ascii_start();
        let is_aux = rest.strip_prefix(b"#").is_some_and(|r| {
            let r = r.trim_ascii_start();
            r.strip_prefix(b"pragma").is_some_and(|r| {
                let r2 = &r[r.iter().take_while(|&&b| blank(b)).count()..];
                r2.len() < r.len()
                    && r2.starts_with(b"aux")
                    && !r2.get(3).is_some_and(|&b| is_word(b))
            })
        });
        if is_aux {
            let span_start = line_start;
            while end < m.len() && m[end - 1] == b'\\' {
                end = m[end + 1..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(m.len(), |p| end + 1 + p);
            }
            out.push((span_start, end));
        }
        line_start = end + 1;
    }
    out
}

fn line_of(text: &[u8], pos: usize) -> u32 {
    text[..pos].iter().filter(|&&b| b == b'\n').count() as u32 + 1
}

/// Finds inline assembly, `_emit` and machine code in `#pragma aux` in a C source text, sorted by line.
/// Comments and string/character literals do not count.
pub fn find_cheats(source: &str) -> Vec<CheatFinding> {
    let text = source.as_bytes();
    let m = mask(text);
    let ranges = definitions(source);
    let function_at = |pos: usize| {
        ranges
            .iter()
            .find(|d| d.brace <= pos && pos < d.end)
            .map(|d| d.name.clone())
    };
    let mut found = Vec::new();
    let spans = pragma_spans(&m);
    for &(start, end) in &spans {
        if let Some(name) = pragma_code_name(&m[start..end]) {
            let shown: String = source[start..end].trim().chars().take(80).collect();
            found.push(CheatFinding {
                line: line_of(text, start),
                kind: CheatKind::PragmaCode,
                function: Some(name),
                text: shown,
            });
        }
    }
    let in_pragma = |pos: usize| spans.iter().any(|&(a, e)| a <= pos && pos < e);
    let mut i = 0;
    while i < m.len() {
        if !is_word(m[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < m.len() && is_word(m[i]) {
            i += 1;
        }
        let token = &m[start..i];
        let mut end = None;
        let mut kind = CheatKind::InlineAssembly;
        match token {
            b"_asm" | b"__asm" | b"__asm__" => end = Some(i),
            b"_emit" | b"__emit" | b"__emit__" => {
                end = Some(i);
                kind = CheatKind::Emit;
            }
            b"asm" => {
                let j = skip_space(&m, i);
                if matches!(m.get(j), Some(b'(' | b'{')) {
                    end = Some(j + 1);
                } else if m[j..].starts_with(b"volatile")
                    && !m.get(j + 8).is_some_and(|&b| is_word(b))
                {
                    end = Some(j + 8);
                }
            }
            _ => {}
        }
        if let Some(end) = end {
            i = end.max(i);
            if !in_pragma(start) {
                found.push(CheatFinding {
                    line: line_of(text, start),
                    kind,
                    function: function_at(start),
                    text: source[start..end].to_string(),
                });
            }
        }
    }
    found.sort_by_key(|f| (f.line, f.kind.id()));
    found
}

/// For the span of a `#pragma aux` line: the pragma name if it defines code (`name = bytes`, optionally with a
/// `(...)` argument list before the name).
fn pragma_code_name(span: &[u8]) -> Option<String> {
    let hash = span.iter().position(|&b| b == b'#')?;
    let aux = find(span, b"aux", hash)? + 3;
    let mut i = skip_space(span, aux);
    if span.get(i) == Some(&b'(') {
        let close = span[i..].iter().position(|&b| b == b')')?;
        i = skip_space(span, i + close + 1);
    }
    let start = i;
    while i < span.len() && is_word(span[i]) {
        i += 1;
    }
    if i == start {
        return None;
    }
    let name = &span[start..i];
    let j = skip_space(span, i);
    (span.get(j) == Some(&b'=')).then(|| String::from_utf8_lossy(name).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pragma_code_and_file_level_findings_block_every_function() {
        let src = "#pragma aux trick = 0x90 0x90;
int f(void)
{
    trick();
    return 1;
}
                   int g(void) { _asm nop; return 2; }
int h(void) { return 3; }
";
        let found = find_cheats(src);
        assert_eq!(found.len(), 2, "{found:?}");
        let pragma = &found[0];
        assert_eq!(pragma.kind, CheatKind::PragmaCode);
        for function in ["f", "g", "h", "trick"] {
            assert!(pragma.blocks(function), "{function}");
        }
        assert!(
            pragma.describe("f").contains("blocks every function"),
            "{}",
            pragma.describe("f")
        );
        let asm = &found[1];
        assert!(asm.blocks("g") && !asm.blocks("f") && !asm.blocks("h"));
        assert_eq!(asm.describe("g"), "line 7: inline-asm _asm");

        let file_level = &find_cheats(
            "asm(\"nop\");
int f(void) { return 1; }
",
        )[0];
        assert_eq!(file_level.function, None);
        assert!(file_level.blocks("f"));
        assert!(file_level.describe("f").contains("outside a function"));
    }

    #[test]
    fn finds_inline_asm_in_function() {
        let src = "int x;\nint f(int a)\n{\n    _asm { mov ax, 1 }\n    return a;\n}\n";
        let found = find_cheats(src);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 4);
        assert_eq!(found[0].kind, CheatKind::InlineAssembly);
        assert_eq!(found[0].function.as_deref(), Some("f"));
        assert_eq!(found[0].text, "_asm");

        let found =
            find_cheats("void g(void) { asm volatile (\"nop\"); __emit__(0x90); }\nasm(\"x\");");
        let kinds: Vec<_> = found.iter().map(|f| (f.line, f.kind.id())).collect();
        assert_eq!(kinds, [(1, "emit"), (1, "inline-asm"), (2, "inline-asm")]);
        assert_eq!(found[2].function, None);
        assert_eq!(found[1].function.as_deref(), Some("g"));
    }

    #[test]
    fn pragma_aux_with_code_is_found() {
        let src =
            "#pragma aux halt = \\\n    0xF4 \\\n    modify [ax];\nint f(void) { return 0; }\n";
        let found = find_cheats(src);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, CheatKind::PragmaCode);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[0].function.as_deref(), Some("halt"));
        assert!(found[0].text.starts_with("#pragma aux halt"));
        let with_args = find_cheats("#pragma aux (cdecl) swap = 0x87 0xD8;\n");
        assert_eq!(with_args[0].function.as_deref(), Some("swap"));
    }

    #[test]
    fn pragma_aux_without_code_is_allowed() {
        let src = "#pragma aux f parm [ax] [dx] modify [bx] value [ax];\n#pragma aux g \"*\" aborts;\n#pragma  aux   h \\\n  parm [ax];\n";
        assert!(find_cheats(src).is_empty());
    }

    #[test]
    fn asm_in_comment_or_string_is_ignored() {
        let src = "/* _asm { } */\n// __emit__(1)\nchar *s = \"asm(\";\nchar c = '\\'';\nint f(void) { return 0; } /* asm { */\n";
        assert!(find_cheats(src).is_empty());
    }

    #[test]
    fn knr_function_is_attributed() {
        let src = "int old(a, b)\nint a;\nchar *b;\n{\n    _asm nop\n    return a;\n}\n";
        let found = find_cheats(src);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].function.as_deref(), Some("old"));
    }

    #[test]
    fn control_statements_and_initializers_are_not_functions() {
        let src = "int t[] = { 1, 2 };\nstruct s { int a; };\nint f(void)\n{\n    if (1) { _asm nop }\n}\n";
        let found = find_cheats(src);
        assert_eq!(found[0].function.as_deref(), Some("f"));
    }
}
