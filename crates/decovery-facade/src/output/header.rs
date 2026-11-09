//! The comment header above each generated function file (port of Decomp's `ausgabe.kopf`).

use decovery_core::{
    Address, AnalyzedFunction, BlockerRecord, RebuildRecord, RebuildResult, Symbol, VerdictId,
};

/// Entries shown in a header list before it is cut.
const MAX_LIST: usize = 20;

/// Everything one header shows, already resolved to text where names are involved.
pub(crate) struct HeaderData<'a> {
    pub function: &'a AnalyzedFunction,
    /// File offset of the start, if it lies in the file.
    pub file_offset: Option<u64>,
    /// Display name of the function.
    pub name: String,
    /// The active symbol at the start (may be unnamed).
    pub symbol: Option<&'a Symbol>,
    /// Entries of `@called-by`, see [`per_partner`].
    pub callers: Vec<String>,
    /// Entries of `@calls`, see [`per_partner`].
    pub callees: Vec<String>,
    /// Entries of `@strings`, see [`string_entry`].
    pub strings: Vec<String>,
    /// Entries of `@globals` (`reads|writes <address>[ <name>]`).
    pub globals: Vec<String>,
    pub rebuild: Option<&'a RebuildRecord>,
}

/// The header text, ending with `\n */\n`; the body follows directly.
pub(crate) fn header(d: &HeaderData<'_>) -> String {
    let f = d.function;
    let place = format!(
        "{} .. {} ({}{}",
        f.start,
        f.end,
        size_text(f),
        match d.file_offset {
            Some(off) => format!(", file {off:#x})"),
            None => ")".to_string(),
        }
    );
    let symbol = d.symbol;
    let named = symbol.is_some_and(|s| !s.name.is_empty());
    let status = match symbol {
        Some(s) if named => format!("[{}, {}]", kebab(&s.source), kebab(&s.confidence)),
        _ => "[unnamed]".to_string(),
    };
    let mut lines = vec![
        line("@address", &place).replacen(" * ", "/* ", 1),
        line("@name", &format!("{}  {status}", d.name)),
    ];
    if let Some(sig) = symbol
        .and_then(|s| s.signature.as_deref())
        .filter(|t| !t.is_empty())
    {
        lines.push(line("@signature", sig));
    }
    if let Some(lib) = symbol
        .and_then(|s| s.library.as_deref())
        .filter(|t| !t.is_empty())
    {
        lines.push(line("@library", lib));
    }
    lines.push(line("@called-by", &list(&d.callers)));
    lines.push(line("@calls", &list(&d.callees)));
    lines.push(line("@strings", &list(&d.strings)));
    let globals = if d.globals.is_empty() {
        "(none)".to_string()
    } else {
        d.globals.join("; ")
    };
    lines.push(line("@globals", &globals));
    lines.push(line("@rebuild", &rebuild_line(d.rebuild)));
    if let Some(comment) = symbol
        .and_then(|s| s.comment.as_deref())
        .filter(|t| !t.is_empty())
    {
        lines.push(line("@comment", comment));
    }
    if let Some(evidence) = symbol
        .and_then(|s| s.evidence.as_deref())
        .filter(|t| !t.is_empty())
    {
        lines.push(line("@evidence", evidence));
    }
    safe(&lines.join("\n")) + "\n */\n"
}

/// `*/` inside generated comments would end them early.
pub(crate) fn safe(text: &str) -> String {
    text.replace("*/", "* /")
}

/// One header entry: key padded to 11, continuation lines indented the same way.
pub(crate) fn line(key: &str, value: &str) -> String {
    let parts = split_lines(value);
    let first = parts.first().copied().unwrap_or("");
    let mut out = format!(" * {key:<11} {first}");
    for part in parts.iter().skip(1) {
        out.push_str(&format!("\n * {:<11} {part}", ""));
    }
    out
}

/// Comma-separated list, cut after [`MAX_LIST`] entries, with the total in parentheses.
pub(crate) fn list(entries: &[String]) -> String {
    if entries.is_empty() {
        return "(none)".to_string();
    }
    let mut text = entries
        .iter()
        .take(MAX_LIST)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if entries.len() > MAX_LIST {
        text.push_str(&format!(", … (+{})", entries.len() - MAX_LIST));
    }
    format!("{text}  ({})", entries.len())
}

/// One entry per distinct partner in order of first occurrence; several sites as `(n×)`.
pub(crate) fn per_partner(
    partners: impl IntoIterator<Item = Address>,
    name: impl Fn(Address) -> String,
) -> Vec<String> {
    let mut counts: Vec<(Address, u32)> = Vec::new();
    let mut seen: std::collections::HashMap<Address, usize> = std::collections::HashMap::new();
    for p in partners {
        match seen.get(&p) {
            Some(&i) => counts[i].1 += 1,
            None => {
                seen.insert(p, counts.len());
                counts.push((p, 1));
            }
        }
    }
    counts
        .into_iter()
        .map(|(at, n)| {
            let mut entry = format!("{at} {}", name(at));
            if n > 1 {
                entry.push_str(&format!(" ({n}×)"));
            }
            entry
        })
        .collect()
}

/// `<address> "<first 60 characters>"` with line breaks shown as `\n`.
pub(crate) fn string_entry(at: Address, text: &str) -> String {
    let head: String = text.chars().take(60).collect();
    format!("{at} \"{head}\"").replace('\n', "\\n")
}

/// The `@rebuild` value. Without a verdict (records migrated from Decomp) or with `identical` it is Decomp's
/// `nachbau.ergebnis.kopfzeile` text; any other verdict is decovery's and leads the line with its blockers, the
/// byte facts follow (design 4: verdicts are decovery's, 7.1: blockers next to the verdict).
pub(crate) fn rebuild_line(record: Option<&RebuildRecord>) -> String {
    let Some(e) = record else {
        return "not tried".to_string();
    };
    let bytes = byte_line(e);
    let verdict = match e.verdict {
        None | Some(VerdictId::Identical) => return bytes,
        Some(v) => v,
    };
    let mut lead = match verdict {
        VerdictId::Other => "unknown verdict".to_string(),
        v => v.id().to_string(),
    };
    if !e.blockers.is_empty() {
        let blockers: Vec<String> = e.blockers.iter().map(blocker_text).collect();
        lead.push_str(&format!(": {}", blockers.join(", ")));
    }
    match bytes
        .strip_prefix("identical (")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        Some(inner) => format!("{lead} (bytes identical, {inner})"),
        None => match bytes.strip_prefix("differs: ") {
            Some(rest) => format!("{lead}; bytes differ: {rest}"),
            None => format!("{lead}; {bytes}"),
        },
    }
}

/// `kind@+0x40d`, with `(n×)` for a count.
fn blocker_text(b: &BlockerRecord) -> String {
    let mut text = b.kind.clone();
    if let Some(at) = b.at {
        text.push_str(&format!("@+{at:#x}"));
    }
    if let Some(n) = b.count {
        text.push_str(&format!(" ({n}×)"));
    }
    text
}

/// The byte facts of the last rebuild (port of Decomp's `nachbau.ergebnis.kopfzeile`).
fn byte_line(e: &RebuildRecord) -> String {
    let file = e.file.as_deref().unwrap_or("");
    let date = e.date.as_deref().unwrap_or("");
    match e.result {
        RebuildResult::Error => {
            let first = match e.message.as_deref() {
                Some(m) if !m.is_empty() => split_lines(m).first().copied().unwrap_or(""),
                _ => "?",
            };
            return format!("error: {first} ({file}, {date})");
        }
        RebuildResult::Identical | RebuildResult::Differs => {}
        _ => return format!("unknown result ({file}, {date})"),
    }
    let how = format!(
        "{file}, {} {}",
        e.compiler.as_deref().unwrap_or(""),
        e.flags.as_deref().unwrap_or("")
    )
    .trim_end()
    .to_string();
    if e.result == RebuildResult::Identical {
        let mut open = String::new();
        if e.refs_unchecked != 0 {
            open.push_str(&format!(", {} refs unchecked", e.refs_unchecked));
        }
        if e.padding_bytes != 0 {
            open.push_str(&format!(", {} padding bytes", e.padding_bytes));
        }
        if e.alignment != 0 {
            open.push_str(&format!(", alignment +{}", e.alignment));
        }
        if e.instructions_differing != 0 {
            open.push_str(&format!(", but {}", instructions(e.instructions_differing)));
            if !e.diagnoses.is_empty() {
                open.push_str(&format!(" (diagnosis: {})", e.diagnoses.join(" ")));
            }
        }
        return format!(
            "identical ({how}, {} fixed + {} linker{open}, {date})",
            e.equal, e.gaps
        );
    }
    let mut parts = vec![format!("differs: {} of {} bytes", e.differing, e.bytes)];
    if let Some(first) = e.first_difference {
        parts.push(format!("first at +{first:#x}"));
    }
    match e.refs_wrong {
        0 => {}
        1 => parts.push("1 wrong ref".to_string()),
        n => parts.push(format!("{n} wrong refs")),
    }
    if e.instructions_differing == 0 {
        parts.push("instructions equal".to_string());
    } else {
        parts.push(instructions(e.instructions_differing));
    }
    if !e.diagnoses.is_empty() {
        parts.push(format!("diagnosis: {}", e.diagnoses.join(" ")));
    }
    if let Some(eq) = &e.equivalence
        && let Some(verdict) = eq.verdict.as_deref().filter(|v| !v.is_empty())
    {
        parts.push(format!(
            "equivalence: {verdict} (static {}, dynamic {}, {} cases, {})",
            eq.static_check.as_deref().unwrap_or("-"),
            eq.dynamic.as_deref().unwrap_or("-"),
            eq.cases.unwrap_or(0),
            eq.date.as_deref().unwrap_or("")
        ));
    }
    format!("{} ({how}, {date})", parts.join(", "))
}

fn instructions(n: u32) -> String {
    if n == 1 {
        "1 instruction differs".to_string()
    } else {
        format!("{n} instructions differ")
    }
}

/// `N bytes`, or `S bytes span, N in body` when the span from start to end differs from the body size.
fn size_text(f: &AnalyzedFunction) -> String {
    match span(f.start, f.end) {
        Some(span) if span != u64::from(f.body_size) => {
            format!("{span} bytes span, {} in body", f.body_size)
        }
        _ => format!("{} bytes", f.body_size),
    }
}

/// Bytes from `start` to `end` inclusive, if both lie in one address space.
fn span(start: Address, end: Address) -> Option<u64> {
    match (start, end) {
        (Address::Sel { segment: a, off: s }, Address::Sel { segment: b, off: e }) if a == b => {
            u64::from(e).checked_sub(u64::from(s)).map(|d| d + 1)
        }
        _ => end.linear()?.checked_sub(start.linear()?).map(|d| d + 1),
    }
}

/// The kebab-case id serde writes for an enum value.
pub(crate) fn kebab<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "other".to_string(),
    }
}

/// Lines as Python's `str.splitlines` returns them (Decomp splits values that way).
pub(crate) fn split_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let end = match c {
            '\r' => {
                if let Some(&(_, '\n')) = chars.peek() {
                    chars.next();
                    i + 2
                } else {
                    i + 1
                }
            }
            '\n' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}'
            | '\u{2029}' => i + c.len_utf8(),
            _ => continue,
        };
        out.push(&text[start..i]);
        start = end;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use decovery_core::{Confidence, SymbolKind};

    fn flat(a: u32) -> Address {
        Address::Flat(a)
    }

    fn record(json: serde_json::Value) -> RebuildRecord {
        serde_json::from_value(json).unwrap()
    }

    fn data<'a>(f: &'a AnalyzedFunction, symbol: Option<&'a Symbol>) -> HeaderData<'a> {
        HeaderData {
            function: f,
            file_offset: None,
            name: "fun_00010200".to_string(),
            symbol,
            callers: Vec::new(),
            callees: Vec::new(),
            strings: Vec::new(),
            globals: Vec::new(),
            rebuild: None,
        }
    }

    #[test]
    fn header_line_pads_key_to_11() {
        assert_eq!(
            line("@name", "alpha  [human, confirmed]"),
            " * @name       alpha  [human, confirmed]"
        );
        assert_eq!(line("@called-by", "(none)"), " * @called-by  (none)");
        assert_eq!(line("@called-from", "x"), " * @called-from x");
        assert_eq!(line("@comment", ""), " * @comment    ");
    }

    #[test]
    fn multiline_value_is_indented() {
        assert_eq!(
            line("@comment", "first\nsecond\r\nthird\n"),
            " * @comment    first\n *             second\n *             third"
        );
    }

    #[test]
    fn comment_close_is_escaped() {
        let f = AnalyzedFunction::new(flat(0x10200), flat(0x1023F), 64);
        let mut s = Symbol::new(flat(0x10200), SymbolKind::Function, "beta");
        s.comment = Some("ends */ here".to_string());
        let mut d = data(&f, Some(&s));
        d.name = "beta".to_string();
        let text = header(&d);
        assert!(text.contains("\n * @comment    ends * / here\n"), "{text}");
        assert_eq!(text.matches("*/").count(), 1, "{text}");
        assert!(text.ends_with("\n */\n"));
    }

    #[test]
    fn list_truncates_after_20_with_rest_and_total() {
        let entries: Vec<String> = (0..25).map(|i| format!("e{i}")).collect();
        let expected: Vec<String> = (0..20).map(|i| format!("e{i}")).collect();
        assert_eq!(
            list(&entries),
            format!("{}, … (+5)  (25)", expected.join(", "))
        );
        let twenty: Vec<String> = (0..20).map(|i| format!("e{i}")).collect();
        assert_eq!(list(&twenty), format!("{}  (20)", expected.join(", ")));
    }

    #[test]
    fn repeated_call_site_shows_count() {
        let entries = per_partner([flat(0x10100), flat(0x10200), flat(0x10100)], |a| {
            if a == flat(0x10100) { "alpha" } else { "beta" }.to_string()
        });
        assert_eq!(entries, ["flat:00010100 alpha (2×)", "flat:00010200 beta"]);
        assert_eq!(
            list(&entries),
            "flat:00010100 alpha (2×), flat:00010200 beta  (2)"
        );
    }

    #[test]
    fn empty_list_says_none() {
        assert_eq!(list(&[]), "(none)");
    }

    #[test]
    fn span_differs_from_body() {
        let f = AnalyzedFunction::new(flat(0x10010), flat(0x1010F), 200);
        let mut d = data(&f, None);
        d.file_offset = Some(0x4a10);
        assert!(header(&d).starts_with(
            "/* @address    flat:00010010 .. flat:0001010F (256 bytes span, 200 in body, file 0x4a10)\n"
        ));
        let g = AnalyzedFunction::new(flat(0x10010), flat(0x1010F), 256);
        let mut d = data(&g, None);
        d.file_offset = Some(0x4A10);
        assert!(header(&d).starts_with(
            "/* @address    flat:00010010 .. flat:0001010F (256 bytes, file 0x4a10)\n"
        ));
    }

    #[test]
    fn unnamed_function_header() {
        let f = AnalyzedFunction::new(flat(0x10200), flat(0x1023F), 64);
        assert_eq!(
            header(&data(&f, None)),
            "/* @address    flat:00010200 .. flat:0001023F (64 bytes)\n \
             * @name       fun_00010200  [unnamed]\n \
             * @called-by  (none)\n \
             * @calls      (none)\n \
             * @strings    (none)\n \
             * @globals    (none)\n \
             * @rebuild    not tried\n \
             */\n"
        );
    }

    #[test]
    fn named_header_shows_claim_and_optional_lines() {
        let f = AnalyzedFunction::new(flat(0x10200), flat(0x1023F), 64);
        let mut s = Symbol::new(flat(0x10200), SymbolKind::Function, "beta");
        s.confidence = Confidence::Assumed;
        s.source = decovery_core::ClaimSource::Agent;
        s.signature = Some("int beta(void)".to_string());
        s.library = Some("clib".to_string());
        s.evidence = Some("seen".to_string());
        let mut d = data(&f, Some(&s));
        d.name = "beta".to_string();
        d.globals = vec![
            "reads flat:00020000 counter".to_string(),
            "writes flat:00020004".to_string(),
        ];
        d.strings = vec![string_entry(flat(0x20010), "a\nb")];
        assert_eq!(
            header(&d),
            "/* @address    flat:00010200 .. flat:0001023F (64 bytes)\n \
             * @name       beta  [agent, assumed]\n \
             * @signature  int beta(void)\n \
             * @library    clib\n \
             * @called-by  (none)\n \
             * @calls      (none)\n \
             * @strings    flat:00020010 \"a\\nb\"  (1)\n \
             * @globals    reads flat:00020000 counter; writes flat:00020004\n \
             * @rebuild    not tried\n \
             * @evidence   seen\n \
             */\n"
        );
    }

    #[test]
    fn rebuild_line_identical_with_extras() {
        let plain = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "compiler": "watcom-9.5",
            "flags": "-ox", "result": "identical", "equal": 300, "gaps": 60, "date": "2026-01-02"
        }));
        assert_eq!(
            rebuild_line(Some(&plain)),
            "identical (main.c, watcom-9.5 -ox, 300 fixed + 60 linker, 2026-01-02)"
        );
        let extras = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "compiler": "watcom-9.5",
            "flags": "-ox", "result": "identical", "equal": 300, "gaps": 60, "refs_unchecked": 3,
            "padding_bytes": 2, "alignment": 4, "instructions_differing": 2,
            "diagnoses": ["operand-swap", "constant"], "date": "2026-01-02"
        }));
        assert_eq!(
            rebuild_line(Some(&extras)),
            "identical (main.c, watcom-9.5 -ox, 300 fixed + 60 linker, 3 refs unchecked, \
             2 padding bytes, alignment +4, but 2 instructions differ (diagnosis: operand-swap constant), \
             2026-01-02)"
        );
        let one = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "compiler": "wcc",
            "result": "identical", "equal": 4, "instructions_differing": 1, "date": "d"
        }));
        assert_eq!(
            rebuild_line(Some(&one)),
            "identical (main.c, wcc, 4 fixed + 0 linker, but 1 instruction differs, d)"
        );
    }

    #[test]
    fn rebuild_line_differs() {
        let e = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "draw.c", "compiler": "watcom-9.5",
            "flags": "-ox -ot", "result": "differs", "bytes": 300, "differing": 57,
            "first_difference": 16, "refs_wrong": 3, "instructions_differing": 8,
            "diagnoses": ["operand-swap"], "date": "2026-01-03",
            "equivalence": {"verdict": "unchecked", "static": "different", "dynamic": "no_case",
                            "cases": 0, "date": "2026-01-04", "code": "ab"}
        }));
        assert_eq!(
            rebuild_line(Some(&e)),
            "differs: 57 of 300 bytes, first at +0x10, 3 wrong refs, 8 instructions differ, \
             diagnosis: operand-swap, equivalence: unchecked (static different, dynamic no_case, 0 cases, \
             2026-01-04) (draw.c, watcom-9.5 -ox -ot, 2026-01-03)"
        );
        let small = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "a.c", "compiler": "wcc",
            "result": "differs", "bytes": 10, "differing": 2, "refs_wrong": 1, "date": "2026-01-01"
        }));
        assert_eq!(
            rebuild_line(Some(&small)),
            "differs: 2 of 10 bytes, 1 wrong ref, instructions equal (a.c, wcc, 2026-01-01)"
        );
    }

    #[test]
    fn rebuild_line_without_verdict_or_identical_verdict_is_decomps_text() {
        let mut e = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "compiler": "watcom-9.5",
            "flags": "-ox", "result": "identical", "equal": 300, "gaps": 60, "date": "2026-01-02"
        }));
        let plain = "identical (main.c, watcom-9.5 -ox, 300 fixed + 60 linker, 2026-01-02)";
        assert_eq!(rebuild_line(Some(&e)), plain);
        e.verdict = Some(VerdictId::Identical);
        assert_eq!(rebuild_line(Some(&e)), plain);
    }

    #[test]
    fn rebuild_line_leads_with_the_verdict_and_blockers() {
        let e = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "compiler": "watcom-9.5",
            "flags": "-ox", "result": "identical", "verdict": "differs", "equal": 300, "gaps": 60,
            "date": "2026-01-02",
            "blockers": [{"kind": "data-layout", "at": 1037}, {"kind": "bytes-differ", "count": 2}]
        }));
        assert_eq!(
            rebuild_line(Some(&e)),
            "differs: data-layout@+0x40d, bytes-differ (2×) (bytes identical, main.c, watcom-9.5 -ox, 300 fixed + 60 linker, 2026-01-02)"
        );
        let d = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "a.c", "compiler": "wcc",
            "result": "differs", "verdict": "differs", "bytes": 10, "differing": 2, "date": "d",
            "blockers": [{"kind": "bytes-differ", "count": 2}]
        }));
        assert_eq!(
            rebuild_line(Some(&d)),
            "differs: bytes-differ (2×); bytes differ: 2 of 10 bytes, instructions equal (a.c, wcc, d)"
        );
        let u = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "a.c", "result": "error",
            "verdict": "unchecked", "message": "inline asm", "date": "d"
        }));
        assert_eq!(
            rebuild_line(Some(&u)),
            "unchecked; error: inline asm (a.c, d)"
        );
    }

    #[test]
    fn rebuild_line_error() {
        let e = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "result": "error",
            "message": "link failed\nmore", "date": "2026-01-02"
        }));
        assert_eq!(
            rebuild_line(Some(&e)),
            "error: link failed (main.c, 2026-01-02)"
        );
        let bare = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "result": "error",
            "date": "2026-01-02"
        }));
        assert_eq!(rebuild_line(Some(&bare)), "error: ? (main.c, 2026-01-02)");
        let other = record(serde_json::json!({
            "address": "flat:00010010", "name": "a", "file": "main.c", "result": "exploded",
            "date": "2026-01-02"
        }));
        assert_eq!(
            rebuild_line(Some(&other)),
            "unknown result (main.c, 2026-01-02)"
        );
        assert_eq!(rebuild_line(None), "not tried");
    }

    #[test]
    fn split_lines_follows_python() {
        assert_eq!(split_lines(""), Vec::<&str>::new());
        assert_eq!(split_lines("a\n"), ["a"]);
        assert_eq!(split_lines("a\n\nb"), ["a", "", "b"]);
        assert_eq!(split_lines("a\rb\r\nc"), ["a", "b", "c"]);
    }
}
