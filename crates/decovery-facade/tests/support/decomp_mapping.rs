//! Fixed German-to-English mapping of Decomp's generated function files (`ausgabe/funktionen/**/*.c`) to
//! decovery's `show` text. Shared by the local parity tests of decovery-facade and decovery-cli
//! (`#[path = …] mod decomp_mapping;`). Id tables come from migrate, so the mapping cannot drift from the import.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use decovery_core::Address;
use decovery_core::migrate::tables::{
    DIAGNOSES, EQUIVALENCE_DYNAMIC, EQUIVALENCE_STATIC, EQUIVALENCE_VERDICTS, SOURCES,
};

/// Header keys phase 1 does not generate: runtime results (runtime schemas arrive in phase 5).
pub const EXCLUDED_KEYS: &[&str] = &["@laufzeit", "@beobachtet"];

/// Fixed German phrases of the `@nachbau` line (Decomp `ergebnis.kopfzeile`) and their English form.
const REBUILD: &[(&str, &str)] = &[
    (" fest + ", " fixed + "),
    (" Linker", " linker"),
    (" Verweise ungeprüft", " refs unchecked"),
    (" Füllbytes", " padding bytes"),
    (", Ausrichtung +", ", alignment +"),
    (", aber ", ", but "),
    ("Befehle anders", "instructions differ"),
    ("Befehl anders", "instruction differs"),
    ("Befehle gleich", "instructions equal"),
    ("Befehle abweichend", "instructions differ"),
    ("Befehl abweichend", "instruction differs"),
    ("falsche Verweise", "wrong refs"),
    ("falscher Verweis", "wrong ref"),
    ("erste bei +", "first at +"),
    ("Diagnose: ", "diagnosis: "),
    ("gleichwertig: ", "equivalence: "),
    ("(statisch ", "(static "),
    (", dynamisch ", ", dynamic "),
    (" Fälle, ", " cases, "),
];

/// English key of a Decomp header key; `None` for [`EXCLUDED_KEYS`]. An unknown key fails the test.
pub fn key_en(key: &str) -> Option<&'static str> {
    if EXCLUDED_KEYS.contains(&key) {
        return None;
    }
    Some(match key {
        "@adresse" => "@address",
        "@name" => "@name",
        "@signatur" => "@signature",
        "@bibliothek" => "@library",
        "@gerufen-von" => "@called-by",
        "@ruft" => "@calls",
        "@strings" => "@strings",
        "@globale" => "@globals",
        "@nachbau" => "@rebuild",
        "@kommentar" => "@comment",
        "@beleg" => "@evidence",
        other => panic!("unknown Decomp header key {other}"),
    })
}

fn lookup<'a>(table: &[(&str, &'a str)], de: &'a str) -> &'a str {
    table
        .iter()
        .find(|(d, _)| *d == de)
        .map_or(de, |(_, en)| en)
}

fn replace_all(mut text: String, table: &[(&str, &str)]) -> String {
    for (de, en) in table {
        text = text.replace(de, en);
    }
    text
}

/// Translates the space-separated ids that follow each `marker`, up to the first character in `ends`.
fn map_ids(text: &str, marker: &str, ends: &[char], table: &[(&str, &str)]) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find(marker) {
        let (head, tail) = rest.split_at(i + marker.len());
        out.push_str(head);
        let n = tail.find(|c| ends.contains(&c)).unwrap_or(tail.len());
        let ids: Vec<&str> = tail[..n].split(' ').map(|id| lookup(table, id)).collect();
        out.push_str(&ids.join(" "));
        rest = &tail[n..];
    }
    out.push_str(rest);
    out
}

/// `va:` → `flat:`, `rel:` → `seg:` (only for the address-bearing keys, R18).
pub fn addresses(text: &str) -> String {
    text.replace("va:", "flat:").replace("rel:", "seg:")
}

fn rebuild_en(v: &str) -> String {
    if v == "nicht versucht" {
        return "not tried".to_string();
    }
    if let Some(rest) = v.strip_prefix("fehler: ") {
        return format!("error: {rest}");
    }
    let mut v = v.to_string();
    if let Some(rest) = v.strip_prefix("identisch (") {
        v = format!("identical ({rest}");
    } else if let Some(rest) = v.strip_prefix("abweichend: ") {
        // "N von M Bytes"
        let rest = rest
            .replacen(" von ", " of ", 1)
            .replacen(" Bytes", " bytes", 1);
        v = format!("differs: {rest}");
    }
    // Ids first (exact, per token), then the fixed phrases around them.
    let v = map_ids(&v, "Diagnose: ", &[',', ')'], DIAGNOSES);
    let v = map_ids(&v, "gleichwertig: ", &[' '], EQUIVALENCE_VERDICTS);
    let v = map_ids(&v, "(statisch ", &[','], EQUIVALENCE_STATIC);
    let v = map_ids(&v, ", dynamisch ", &[','], EQUIVALENCE_DYNAMIC);
    replace_all(v, REBUILD)
}

fn name_en(v: &str) -> String {
    if let Some(name) = v.strip_suffix("  [unbenannt]") {
        return format!("{name}  [unnamed]");
    }
    let Some((name, claim)) = v.rsplit_once("  [") else {
        return v.to_string();
    };
    let claim = claim.trim_end_matches(']');
    let (source, confidence) = claim.split_once(", ").unwrap_or((claim, ""));
    let confidence = match confidence {
        "belegt" => "confirmed",
        "vermutet" => "assumed",
        "widerlegt" => "refuted",
        other => other,
    };
    format!("{name}  [{}, {confidence}]", lookup(SOURCES, source))
}

fn globals_en(v: &str) -> String {
    if v == "(keine)" {
        return "(none)".to_string();
    }
    addresses(v)
        .split("; ")
        .map(|e| {
            if let Some(r) = e.strip_prefix("liest ") {
                format!("reads {r}")
            } else if let Some(r) = e.strip_prefix("schreibt ") {
                format!("writes {r}")
            } else {
                e.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// English value of a header entry under its English key. `@comment`, `@evidence`, `@signature` and
/// `@library` are free text and stay as they are.
pub fn value_en(key: &str, v: &str) -> String {
    match key {
        "@address" => addresses(v)
            .replace("Bytes Spanne", "bytes span")
            .replace("im Rumpf", "in body")
            .replace(" Bytes", " bytes")
            .replace(", datei 0x", ", file 0x"),
        "@name" => name_en(v),
        "@called-by" | "@calls" | "@strings" => addresses(v).replace("(keine)", "(none)"),
        "@globals" => globals_en(v),
        "@rebuild" => rebuild_en(v),
        _ => v.to_string(),
    }
}

/// Decomp header (LF) as key/value entries, multi-line values joined with `\n`.
fn entries(header: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in header.lines() {
        if raw == " */" {
            break;
        }
        let rest = raw
            .strip_prefix("/* ")
            .or_else(|| raw.strip_prefix(" * "))
            .unwrap_or(raw);
        if rest.starts_with('@') {
            let key = rest.split(' ').next().unwrap_or("").to_string();
            let start = key.len().max(11) + 1;
            let value = rest.get(start..).unwrap_or("").to_string();
            out.push((key, value));
        } else if let Some(last) = out.last_mut() {
            last.1.push('\n');
            last.1.push_str(rest.get(12..).unwrap_or(""));
        }
    }
    out
}

fn emit(key: &str, value: &str) -> String {
    let mut parts = value.split('\n');
    let mut out = format!(" * {key:<11} {}", parts.next().unwrap_or(""));
    for p in parts {
        out.push_str(&format!("\n * {:<11} {p}", ""));
    }
    out
}

/// decovery's expected `show` text for a Decomp function file (after CRLF→LF, R11): header translated,
/// body kept except for the failure prefix of a failed decompilation (R13).
pub fn expected(decomp: &str) -> String {
    let end = decomp.find("\n */\n").expect("header terminator") + "\n */\n".len();
    let (header, body) = decomp.split_at(end);
    let lines: Vec<String> = entries(header)
        .into_iter()
        .filter_map(|(k, v)| key_en(&k).map(|en| emit(en, &value_en(en, &v))))
        .collect();
    let mut text = lines.join("\n").replacen(" * ", "/* ", 1) + "\n */\n";
    let body = match body.strip_prefix("/* Dekompilieren fehlgeschlagen: ") {
        Some(rest) => format!(
            "/* decompilation failed: {}",
            rest.replacen(
                "/* Disassembly:\n(nicht verfügbar)\n*/",
                "/* Disassembly:\n(not available)\n*/",
                1
            )
        ),
        None => body.to_string(),
    };
    text.push_str(&body);
    text
}

/// Function start encoded in a Decomp file name (`va_0001A2B0_name.c`, `rel_1234_0010_name.c`).
pub fn address_of(file: &Path) -> Option<Address> {
    let name = file.file_stem()?.to_str()?;
    let mut parts = name.split('_');
    let text = match parts.next()? {
        "va" => format!("flat:{}", parts.next()?),
        "rel" => format!("seg:{}:{}", parts.next()?, parts.next()?),
        _ => return None,
    };
    text.parse().ok()
}

/// Every function file below `<workspace>/ausgabe/funktionen`, sorted by address.
pub fn decomp_files(workspace: &Path) -> Vec<(Address, PathBuf)> {
    let mut out = Vec::new();
    let mut stack = vec![workspace.join("ausgabe").join("funktionen")];
    while let Some(dir) = stack.pop() {
        let Ok(list) = std::fs::read_dir(&dir) else {
            continue;
        };
        for f in list {
            let f = f.unwrap().path();
            if f.is_dir() {
                stack.push(f);
            } else if f.extension().is_some_and(|x| x == "c")
                && let Some(at) = address_of(&f)
            {
                out.push((at, f));
            }
        }
    }
    out.sort();
    out
}

/// Reads a Decomp function file with CRLF normalized to LF (R11).
pub fn read_decomp(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap().replace("\r\n", "\n")
}

/// First differing line of `want` (Decomp, translated) and `got` (decovery): the header key it belongs to
/// (`body` below the header), its line number and both lines. `None` when equal.
pub fn first_difference(want: &str, got: &str) -> Option<(String, usize, String, String)> {
    if want == got {
        return None;
    }
    let (w, g): (Vec<_>, Vec<_>) = (want.lines().collect(), got.lines().collect());
    let i = (0..w.len().max(g.len()))
        .find(|&i| w.get(i) != g.get(i))
        .unwrap_or(w.len().min(g.len()));
    let header_end = w.iter().position(|l| *l == " */").unwrap_or(usize::MAX);
    let key = if i > header_end {
        "body".to_string()
    } else {
        // continuation lines belong to the last key above them
        w[..=i.min(w.len().saturating_sub(1))]
            .iter()
            .rev()
            .find_map(|l| {
                l.get(3..)
                    .and_then(|r| r.split(' ').next())
                    .filter(|k| k.starts_with('@'))
            })
            .unwrap_or("body")
            .to_string()
    };
    let line = |v: &[&str]| v.get(i).copied().unwrap_or("<none>").to_string();
    Some((key, i + 1, line(&w), line(&g)))
}
