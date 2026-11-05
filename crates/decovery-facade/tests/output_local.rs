//! Local check against a private Decomp workspace: rendered headers equal Decomp's after a fixed
//! German-to-English mapping. Run with `cargo test -- --ignored`.

use std::path::{Path, PathBuf};

use decovery_core::{Address, migrate_decomp};
use decovery_facade::{Session, render_function};

const SAMPLE: usize = 30;

/// German claim and rebuild ids and their English ids (as migrate translates them), longest first where one
/// contains another.
const IDS: &[(&str, &str)] = &[
    (
        "cw:push-konstante-ueber-register",
        "cw:push-constant-via-register",
    ),
    (
        "cw:ausgerichtete-marke-ohne-code",
        "cw:aligned-label-without-code",
    ),
    (
        "cw:byte-erweitern-zwischenwert",
        "cw:byte-extend-intermediate",
    ),
    ("vergleich-gespiegelt", "comparison-mirrored"),
    ("lokale-reihenfolge", "local-order"),
    ("operanden-tausch", "operand-swap"),
    ("adressrechnung", "address-arithmetic"),
    ("fruehes-return", "early-return"),
    ("gleiche-enden", "same-endings"),
    ("konstante", "constant"),
];

const EQUIVALENCE: &[(&str, &str)] = &[
    (
        "gleichwertig: gleichwertig_getestet",
        "equivalence: equivalent_tested",
    ),
    (
        "gleichwertig: gleichwertig_belegt",
        "equivalence: equivalent_proven",
    ),
    ("gleichwertig: ungeprueft", "equivalence: unchecked"),
    ("gleichwertig: ", "equivalence: "),
    ("statisch anders", "static different"),
    ("statisch unklar", "static unclear"),
    ("statisch nur_register", "static registers_only"),
    ("statisch ", "static "),
    ("dynamisch ohne_fall", "dynamic no_case"),
    ("dynamisch gleich", "dynamic equal"),
    ("dynamisch ", "dynamic "),
    (" Fälle, ", " cases, "),
];

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
    ("(Diagnose: ", "(diagnosis: "),
    ("Diagnose: ", "diagnosis: "),
];

const SOURCES: &[(&str, &str)] = &[
    ("mensch", "human"),
    ("ki", "agent"),
    ("signatur", "signature"),
    ("laufzeit", "runtime"),
    ("aehnlich", "similarity"),
    ("import", "import"),
    ("engine", "analysis"),
];

/// English key of a Decomp header key; `None` for the runtime keys phase 1 does not generate.
fn key_en(key: &str) -> Option<&'static str> {
    Some(match key {
        "@laufzeit" | "@beobachtet" => return None,
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

fn replace_all(mut text: String, table: &[(&str, &str)]) -> String {
    for (de, en) in table {
        text = text.replace(de, en);
    }
    text
}

fn addresses(text: &str) -> String {
    text.replace("va:", "flat:").replace("rel:", "seg:")
}

fn rebuild_en(v: &str) -> String {
    if v == "nicht versucht" {
        return "not tried".to_string();
    }
    let mut v = v.to_string();
    if let Some(rest) = v.strip_prefix("fehler: ") {
        return format!("error: {rest}");
    }
    if let Some(rest) = v.strip_prefix("identisch (") {
        v = format!("identical ({rest}");
    } else if let Some(rest) = v.strip_prefix("abweichend: ") {
        // "N von M Bytes"
        let rest = rest
            .replacen(" von ", " of ", 1)
            .replacen(" Bytes", " bytes", 1);
        v = format!("differs: {rest}");
    }
    let v = replace_all(v, EQUIVALENCE);
    let v = replace_all(v, REBUILD);
    replace_all(v, IDS)
}

fn value_en(key: &str, v: &str) -> String {
    match key {
        "@address" => addresses(v)
            .replace("Bytes Spanne", "bytes span")
            .replace("im Rumpf", "in body")
            .replace(" Bytes", " bytes")
            .replace(", datei 0x", ", file 0x"),
        "@name" => {
            if let Some(name) = v.strip_suffix("  [unbenannt]") {
                return format!("{name}  [unnamed]");
            }
            let Some((name, claim)) = v.rsplit_once("  [") else {
                return v.to_string();
            };
            let claim = claim.trim_end_matches(']');
            let (source, confidence) = claim.split_once(", ").unwrap_or((claim, ""));
            let source = SOURCES
                .iter()
                .find(|(de, _)| *de == source)
                .map_or(source, |(_, en)| en);
            let confidence = match confidence {
                "belegt" => "confirmed",
                "vermutet" => "assumed",
                other => other,
            };
            format!("{name}  [{source}, {confidence}]")
        }
        "@called-by" | "@calls" | "@strings" => addresses(v).replace("(keine)", "(none)"),
        "@globals" => {
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
        "@rebuild" => rebuild_en(v),
        _ => v.to_string(),
    }
}

/// Decomp header (LF) as key/value entries, multi-line values joined with `\n`.
fn entries(header: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in header.lines() {
        let rest = raw
            .strip_prefix("/* ")
            .or_else(|| raw.strip_prefix(" * "))
            .unwrap_or(raw);
        if raw == " */" {
            break;
        }
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

fn expected(decomp: &str) -> String {
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

fn address_of(file: &Path) -> Option<Address> {
    let name = file.file_stem()?.to_str()?;
    let mut parts = name.split('_');
    let text = match parts.next()? {
        "va" => format!("flat:{}", parts.next()?),
        "rel" => format!("seg:{}:{}", parts.next()?, parts.next()?),
        _ => return None,
    };
    text.parse().ok()
}

fn decomp_files(root: &Path) -> Vec<(Address, PathBuf)> {
    let mut out = Vec::new();
    for dir in std::fs::read_dir(root.join("ausgabe").join("funktionen")).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&dir).unwrap() {
            let f = f.unwrap().path();
            if f.extension().is_some_and(|x| x == "c")
                && let Some(at) = address_of(&f)
            {
                out.push((at, f));
            }
        }
    }
    out.sort();
    out
}

#[test]
#[ignore = "local: private Decomp workspace"]
fn header_lines_match_decomp_sample() {
    let from = PathBuf::from(
        std::env::var_os("DECOVERY_LOCAL_WORKSPACE").expect("DECOVERY_LOCAL_WORKSPACE is not set"),
    );
    let to = tempfile::tempdir().unwrap();
    migrate_decomp(&from, to.path()).unwrap();
    let session = Session::open(to.path()).unwrap();

    let limit = std::env::var("DECOVERY_OUTPUT_SAMPLE")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(SAMPLE);
    let mut mismatches: Vec<String> = Vec::new();
    let mut by_key: std::collections::BTreeMap<String, usize> = Default::default();
    let files = decomp_files(&from);
    let mut compared = 0;
    for (at, path) in files.iter().take(limit) {
        let decomp = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let want = expected(&decomp);
        let got = render_function(&session, *at).unwrap();
        compared += 1;
        if got == want {
            continue;
        }
        let (w, g): (Vec<_>, Vec<_>) = (want.lines().collect(), got.lines().collect());
        let i = (0..w.len().max(g.len()))
            .find(|&i| w.get(i) != g.get(i))
            .unwrap_or(0);
        let (wl, gl) = (
            w.get(i).copied().unwrap_or("<none>"),
            g.get(i).copied().unwrap_or("<none>"),
        );
        let key = wl
            .get(3..)
            .and_then(|r| r.split(' ').next())
            .filter(|k| k.starts_with('@'))
            .unwrap_or("body")
            .to_string();
        *by_key.entry(key).or_default() += 1;
        mismatches.push(format!(
            "{at} line {}:\n  decomp:   {wl}\n  decovery: {gl}",
            i + 1
        ));
    }
    assert!(compared > 0, "no Decomp function files found");
    assert!(
        mismatches.is_empty(),
        "{} of {compared} functions differ (by key {by_key:?}); first:\n{}",
        mismatches.len(),
        mismatches[..mismatches.len().min(5)].join("\n")
    );
}
