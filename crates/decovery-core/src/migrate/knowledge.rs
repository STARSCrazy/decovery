//! Table-driven conversion of the Decomp knowledge files that have no typed decovery model yet:
//! `nachbau.toml`, `nachbau-programm.toml`, `laufzeit.toml` and `verweise.toml`.
//!
//! Each file kind is described by a [`Node`] tree: German key, English key, and how the value is treated.
//! Keys that are not in the tree are reported through [`Tbl::finish`]; nothing is dropped silently.

use std::path::Path;

use toml::{Table, Value};

use super::{Ctx, MigrateError, Tbl, read, translate_address};
use crate::workspace::SCHEMA;

/// How a value is converted.
enum F {
    /// Copied unchanged.
    Copy,
    /// Integer; Decomp wrote some as text (`"0x4c"`, `"12"`), which is parsed.
    Number,
    /// Free text: a string copied unchanged and counted.
    Text,
    /// Array of free-text strings.
    TextList,
    /// Address string (`va:`, `rel:`) converted to the canonical form.
    Addr,
    /// String that is an address if it starts with `va:` or `rel:`, otherwise copied (`0x1`).
    Mixed,
    /// Array of [`F::Mixed`].
    MixedList,
    /// String id translated through the table; unknown values are reported and kept.
    Enum(&'static [(&'static str, &'static str)]),
    /// Array of [`F::Enum`].
    EnumList(&'static [(&'static str, &'static str)]),
    /// Nested table.
    Sub(&'static Node),
    /// Array of nested tables.
    Subs(&'static Node),
    /// Table with data-defined keys (file names, segment names), copied unchanged.
    Map,
}

struct Node {
    fields: &'static [(&'static str, &'static str, F)],
}

/// Claim sources (`quelle`).
pub const SOURCES: &[(&str, &str)] = &[
    ("mensch", "human"),
    ("ki", "agent"),
    ("signatur", "signature"),
    ("laufzeit", "runtime"),
    ("aehnlich", "similarity"),
    ("import", "import"),
    ("engine", "analysis"),
];

const RESULTS: &[(&str, &str)] = &[("identisch", "identical"), ("abweichend", "differs")];

/// Rebuild diagnosis ids (`diagnose`).
pub const DIAGNOSES: &[(&str, &str)] = &[
    ("operanden-tausch", "operand-swap"),
    ("gleiche-enden", "same-endings"),
    ("konstante", "constant"),
    ("vergleich-gespiegelt", "comparison-mirrored"),
    ("adressrechnung", "address-arithmetic"),
    ("lokale-reihenfolge", "local-order"),
    ("fruehes-return", "early-return"),
    (
        "cw:byte-erweitern-zwischenwert",
        "cw:byte-extend-intermediate",
    ),
    (
        "cw:push-konstante-ueber-register",
        "cw:push-constant-via-register",
    ),
    (
        "cw:ausgerichtete-marke-ohne-code",
        "cw:aligned-label-without-code",
    ),
];

/// Equivalence verdicts (`gleichwertig.urteil`).
pub const EQUIVALENCE_VERDICTS: &[(&str, &str)] = &[
    ("ungeprueft", "unchecked"),
    ("gleichwertig_getestet", "equivalent_tested"),
    ("gleichwertig_belegt", "equivalent_proven"),
];

/// Static equivalence results (`gleichwertig.statisch`).
pub const EQUIVALENCE_STATIC: &[(&str, &str)] = &[
    ("anders", "different"),
    ("unklar", "unclear"),
    ("nur_register", "registers_only"),
];

/// Dynamic equivalence results (`gleichwertig.dynamisch`).
pub const EQUIVALENCE_DYNAMIC: &[(&str, &str)] = &[("ohne_fall", "no_case"), ("gleich", "equal")];

static EQUIVALENCE: Node = Node {
    fields: &[
        ("urteil", "verdict", F::Enum(EQUIVALENCE_VERDICTS)),
        ("statisch", "static", F::Enum(EQUIVALENCE_STATIC)),
        ("statisch_grund", "static_reason", F::Text),
        ("dynamisch", "dynamic", F::Enum(EQUIVALENCE_DYNAMIC)),
        ("faelle", "cases", F::Copy),
        ("echte", "genuine", F::Copy),
        ("belastbar", "reliable", F::Copy),
        ("gruende", "reasons", F::TextList),
        ("code", "code", F::Copy),
        ("datum", "date", F::Copy),
    ],
};

static REBUILD_FUNCTION: Node = Node {
    fields: &[
        ("adresse", "address", F::Addr),
        ("name", "name", F::Copy),
        ("datei", "file", F::Copy),
        ("compiler", "compiler", F::Copy),
        ("optionen", "flags", F::Copy),
        ("ergebnis", "result", F::Enum(RESULTS)),
        ("bytes", "bytes", F::Copy),
        ("gleich", "equal", F::Copy),
        ("luecken", "gaps", F::Copy),
        ("abweichend", "differing", F::Copy),
        ("verweise_passend", "refs_ok", F::Copy),
        ("verweise_falsch", "refs_wrong", F::Copy),
        ("verweise_ungeprueft", "refs_unchecked", F::Copy),
        ("befehle_abweichend", "instructions_differing", F::Copy),
        ("datum", "date", F::Copy),
        ("ausrichtung", "alignment", F::Copy),
        ("fuellbytes", "padding_bytes", F::Copy),
        ("erste_abweichung", "first_difference", F::Number),
        ("diagnose", "diagnoses", F::EnumList(DIAGNOSES)),
        ("gleichwertig", "equivalence", F::Sub(&EQUIVALENCE)),
    ],
};

static REBUILD: Node = Node {
    fields: &[("funktion", "function", F::Subs(&REBUILD_FUNCTION))],
};

static SHARES: Node = Node {
    fields: &[
        ("c", "c", F::Copy),
        ("bibliothek", "library", F::Copy),
        ("assembler", "assembly", F::Copy),
        ("sonstige_funktionen", "other_functions", F::Copy),
        ("rest", "rest", F::Copy),
    ],
};

static USED: Node = Node {
    fields: &[
        ("funktionen", "functions", F::Copy),
        ("bytes", "bytes", F::Copy),
    ],
};

static PROGRAM: Node = Node {
    fields: &[
        ("ergebnis", "result", F::Enum(RESULTS)),
        ("compiler", "compiler", F::Copy),
        ("bytes_original", "original_bytes", F::Copy),
        ("bytes_nachbau", "rebuilt_bytes", F::Copy),
        ("abweichend", "differing", F::Copy),
        ("datum", "date", F::Copy),
        ("anteile", "shares", F::Sub(&SHARES)),
        ("eingesetzt", "used", F::Sub(&USED)),
    ],
};

static REBUILD_PROGRAM: Node = Node {
    fields: &[("programm", "program", F::Sub(&PROGRAM))],
};

const VALUE_KINDS: &[(&str, &str)] = &[
    ("zahl", "number"),
    ("zeiger", "pointer"),
    ("gemischt", "mixed"),
];

static VALUES: Node = Node {
    fields: &[
        ("art", "kind", F::Enum(VALUE_KINDS)),
        ("werte", "values", F::MixedList),
        ("min", "min", F::Copy),
        ("max", "max", F::Copy),
    ],
};

static CASE: Node = Node {
    fields: &[
        ("ein", "inputs", F::MixedList),
        ("aus", "output", F::Mixed),
        ("aus_zeiger", "output_pointer", F::Mixed),
    ],
};

static RUN_FILE: Node = Node {
    fields: &[
        ("datei", "file", F::Copy),
        (
            "art",
            "mode",
            F::Enum(&[("lesen", "read"), ("schreiben", "write")]),
        ),
        ("direkt", "direct", F::Copy),
        ("zugriffe", "accesses", F::Copy),
        ("offset_min", "offset_min", F::Copy),
        ("offset_max", "offset_max", F::Copy),
        ("laenge_max", "max_length", F::Copy),
    ],
};

static RUN_FUNCTION: Node = Node {
    fields: &[
        ("adresse", "address", F::Addr),
        ("aufrufe", "calls", F::Copy),
        ("weggelassen", "omitted", F::Copy),
        ("parameter", "parameters", F::Subs(&VALUES)),
        ("rueckgabe", "returns", F::Sub(&VALUES)),
        ("fall", "cases", F::Subs(&CASE)),
        ("dateien", "files", F::Subs(&RUN_FILE)),
    ],
};

static PAIR: Node = Node {
    fields: &[
        ("von", "from", F::Addr),
        ("nach", "to", F::Addr),
        ("art", "kind", F::Copy),
        ("anzahl", "count", F::Copy),
    ],
};

static RUN_HASHES: Node = Node {
    fields: &[
        ("abdeckung", "coverage", F::Copy),
        ("aufrufe", "calls", F::Copy),
        ("ereignisse", "events", F::Copy),
        ("indirekt", "indirect", F::Copy),
    ],
};

static RUN: Node = Node {
    fields: &[
        ("name", "name", F::Copy),
        ("eingelesen", "imported", F::Copy),
        ("quelle", "source", F::Copy),
        ("beschreibung", "description", F::Text),
        ("befehle", "instructions", F::Copy),
        ("ausserhalb", "outside_functions", F::Copy),
        ("paar", "pairs", F::Subs(&PAIR)),
        ("zustaende", "states", F::Copy),
        ("dateien", "files", F::Map),
        ("sha256", "sha256", F::Sub(&RUN_HASHES)),
        ("basis", "bases", F::Map),
        ("funktion", "function", F::Subs(&RUN_FUNCTION)),
    ],
};

static RUNS: Node = Node {
    fields: &[("lauf", "run", F::Subs(&RUN))],
};

static REFERENCE: Node = Node {
    fields: &[
        ("von", "from", F::Addr),
        ("nach", "to", F::Addr),
        (
            "art",
            "kind",
            F::Enum(&[("sprung", "jump"), ("aufruf", "call")]),
        ),
        ("quelle", "source", F::Enum(SOURCES)),
        ("beleg", "evidence", F::Text),
    ],
};

static REFERENCES: Node = Node {
    fields: &[("verweis", "reference", F::Subs(&REFERENCE))],
};

/// The four file kinds, by Decomp file name under `wissen/`.
pub(super) const FILES: [(&str, &str); 4] = [
    ("nachbau.toml", "knowledge/rebuild.toml"),
    ("nachbau-programm.toml", "knowledge/rebuild-program.toml"),
    ("laufzeit.toml", "knowledge/runs.toml"),
    ("verweise.toml", "knowledge/references.toml"),
];

/// Reads `path` and returns the converted TOML text with `schema = 1`.
pub(super) fn convert_file(kind: &str, path: &Path, cx: &mut Ctx) -> Result<String, MigrateError> {
    let root = match kind {
        "nachbau.toml" => &REBUILD,
        "nachbau-programm.toml" => &REBUILD_PROGRAM,
        "laufzeit.toml" => &RUNS,
        _ => &REFERENCES,
    };
    let text = read(path)?;
    let table: Table = toml::from_str(&text).map_err(|source| MigrateError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    let mut out = convert_table(
        Tbl {
            path: String::new(),
            map: table,
        },
        root,
        cx,
    );
    out.insert("schema".into(), Value::Integer(i64::from(SCHEMA)));
    toml::to_string(&out).map_err(|source| MigrateError::Serialize {
        path: path.to_path_buf(),
        source: Box::new(source),
    })
}

fn convert_table(mut t: Tbl, node: &Node, cx: &mut Ctx) -> Table {
    let mut out = Table::new();
    for (german, english, kind) in node.fields {
        let Some(value) = t.map.remove(*german) else {
            continue;
        };
        let path = t.key(german);
        if let Some(v) = convert_field(value, &path, kind, cx) {
            out.insert((*english).to_string(), v);
        }
    }
    t.finish(cx);
    out
}

fn mismatch(path: &str, expected: &str, cx: &mut Ctx) -> Option<Value> {
    cx.unmapped.insert(format!("{path} (expected {expected})"));
    None
}

fn address_text(text: &str, path: &str, cx: &mut Ctx) -> String {
    match translate_address(text) {
        Some(a) => a.to_string(),
        None => {
            cx.unmapped.insert(format!("{path}={text}"));
            text.to_string()
        }
    }
}

fn mixed_text(text: &str, path: &str, cx: &mut Ctx) -> String {
    if text.starts_with("va:") || text.starts_with("rel:") {
        address_text(text, path, cx)
    } else {
        text.to_string()
    }
}

fn enum_text(text: &str, table: &[(&str, &str)], path: &str, cx: &mut Ctx) -> String {
    match table.iter().find(|(de, _)| *de == text) {
        Some((_, en)) => (*en).to_string(),
        None => {
            cx.unmapped.insert(format!("{path}={text}"));
            text.to_string()
        }
    }
}

fn convert_field(value: Value, path: &str, kind: &F, cx: &mut Ctx) -> Option<Value> {
    match kind {
        F::Copy => Some(value),
        F::Number => match value {
            Value::Integer(_) => Some(value),
            Value::String(text) => {
                let t = text.trim();
                let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(hex) => i64::from_str_radix(hex, 16),
                    None => t.parse(),
                };
                match parsed {
                    Ok(n) => Some(Value::Integer(n)),
                    Err(_) => mismatch(path, "an integer", cx),
                }
            }
            _ => mismatch(path, "an integer", cx),
        },
        F::Text => match value {
            Value::String(_) => {
                cx.texts += 1;
                Some(value)
            }
            _ => mismatch(path, "a string", cx),
        },
        F::TextList => list(value, path, "an array of strings", cx, |v, cx| match v {
            Value::String(_) => {
                cx.texts += 1;
                Some(v)
            }
            _ => None,
        }),
        F::Addr => match value {
            Value::String(s) => Some(Value::String(address_text(&s, path, cx))),
            _ => mismatch(path, "an address string", cx),
        },
        F::Mixed => match value {
            Value::String(s) => Some(Value::String(mixed_text(&s, path, cx))),
            other => Some(other),
        },
        F::MixedList => list(value, path, "an array", cx, |v, cx| match v {
            Value::String(s) => Some(Value::String(mixed_text(&s, path, cx))),
            other => Some(other),
        }),
        F::Enum(table) => match value {
            Value::String(s) => Some(Value::String(enum_text(&s, table, path, cx))),
            _ => mismatch(path, "a string", cx),
        },
        F::EnumList(table) => list(value, path, "an array of strings", cx, |v, cx| match v {
            Value::String(s) => Some(Value::String(enum_text(&s, table, path, cx))),
            _ => None,
        }),
        F::Sub(node) => {
            let t = Tbl::new(value, path, cx)?;
            Some(Value::Table(convert_table(t, node, cx)))
        }
        F::Subs(node) => match value {
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    if let Some(t) = Tbl::new(item, path, cx) {
                        out.push(Value::Table(convert_table(t, node, cx)));
                    }
                }
                Some(Value::Array(out))
            }
            _ => mismatch(path, "an array of tables", cx),
        },
        F::Map => match value {
            Value::Table(_) => Some(value),
            _ => mismatch(path, "a table", cx),
        },
    }
}

/// Converts every element; an element that does not fit is reported and dropped.
fn list(
    value: Value,
    path: &str,
    expected: &str,
    cx: &mut Ctx,
    mut each: impl FnMut(Value, &mut Ctx) -> Option<Value>,
) -> Option<Value> {
    let Value::Array(items) = value else {
        return mismatch(path, expected, cx);
    };
    let mut out = Vec::new();
    for item in items {
        match each(item, cx) {
            Some(v) => out.push(v),
            None => {
                mismatch(path, expected, cx);
            }
        }
    }
    Some(Value::Array(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(kind: &str, text: &str) -> (Table, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("in.toml");
        std::fs::write(&path, text).unwrap();
        let mut cx = Ctx::default();
        let out = convert_file(kind, &path, &mut cx).unwrap();
        (toml::from_str(&out).unwrap(), cx)
    }

    #[test]
    fn rebuild_functions() {
        let (t, cx) = convert(
            "nachbau.toml",
            r#"
[[funktion]]
adresse = "va:00010010"
name = "choose"
datei = "main.c"
compiler = "watcom-9.5"
optionen = "-ox"
ergebnis = "abweichend"
bytes = 448
gleich = 360
luecken = 88
abweichend = 2
verweise_passend = 7
verweise_falsch = 1
verweise_ungeprueft = 3
befehle_abweichend = 0
datum = "2026-10-30"
erste_abweichung = "0x4c"
diagnose = ["operanden-tausch", "neu"]
[funktion.gleichwertig]
urteil = "gleichwertig_getestet"
statisch = "anders"
statisch_grund = "Grund"
dynamisch = "gleich"
gruende = ["a"]
faelle = 3
zauber = 1
"#,
        );
        assert_eq!(t["schema"].as_integer(), Some(1));
        let f = &t["function"][0];
        assert_eq!(f["address"].as_str(), Some("flat:00010010"));
        assert_eq!(f["file"].as_str(), Some("main.c"));
        assert_eq!(f["flags"].as_str(), Some("-ox"));
        assert_eq!(f["result"].as_str(), Some("differs"));
        assert_eq!(f["refs_ok"].as_integer(), Some(7));
        assert_eq!(f["refs_wrong"].as_integer(), Some(1));
        assert_eq!(f["refs_unchecked"].as_integer(), Some(3));
        assert_eq!(f["instructions_differing"].as_integer(), Some(0));
        assert_eq!(f["differing"].as_integer(), Some(2));
        assert_eq!(f["first_difference"].as_integer(), Some(0x4c));
        assert_eq!(f["diagnoses"][0].as_str(), Some("operand-swap"));
        assert_eq!(f["diagnoses"][1].as_str(), Some("neu"));
        let e = &f["equivalence"];
        assert_eq!(e["verdict"].as_str(), Some("equivalent_tested"));
        assert_eq!(e["static"].as_str(), Some("different"));
        assert_eq!(e["dynamic"].as_str(), Some("equal"));
        assert_eq!(e["reasons"][0].as_str(), Some("a"));
        let unmapped: Vec<_> = cx.unmapped.iter().map(String::as_str).collect();
        assert_eq!(
            unmapped,
            ["funktion.diagnose=neu", "funktion.gleichwertig.zauber"]
        );
        assert_eq!(cx.texts, 2);
    }

    #[test]
    fn rebuild_program() {
        let (t, cx) = convert(
            "nachbau-programm.toml",
            r#"
[programm]
ergebnis = "identisch"
compiler = "watcom-10.6"
bytes_original = 10
bytes_nachbau = 11
abweichend = 1
datum = "2026-11-03"
[programm.anteile]
c = 1
bibliothek = 2
assembler = 3
sonstige_funktionen = 4
rest = 5
[programm.eingesetzt]
funktionen = 6
bytes = 7
"#,
        );
        let p = &t["program"];
        assert_eq!(p["result"].as_str(), Some("identical"));
        assert_eq!(p["original_bytes"].as_integer(), Some(10));
        assert_eq!(p["rebuilt_bytes"].as_integer(), Some(11));
        assert_eq!(p["differing"].as_integer(), Some(1));
        assert_eq!(p["shares"]["library"].as_integer(), Some(2));
        assert_eq!(p["shares"]["assembly"].as_integer(), Some(3));
        assert_eq!(p["shares"]["other_functions"].as_integer(), Some(4));
        assert_eq!(p["used"]["functions"].as_integer(), Some(6));
        assert!(cx.unmapped.is_empty(), "{:?}", cx.unmapped);
    }

    #[test]
    fn runs() {
        let (t, cx) = convert(
            "laufzeit.toml",
            r#"
[[lauf]]
name = "start"
eingelesen = "2026-10-11"
quelle = "D:\\runs\\1"
beschreibung = "Start bis Menue"
befehle = 5
ausserhalb = 1
paar = [{ von = "va:00000010", nach = "va:00000020", art = "call_near", anzahl = 3 }]
zustaende = 2
[lauf.dateien]
"data/a.dat" = 4
[lauf.sha256]
abdeckung = "aa"
aufrufe = "bb"
ereignisse = "cc"
[lauf.basis]
obj1 = "0x154030"
[[lauf.funktion]]
adresse = "va:00025110"
aufrufe = 1
weggelassen = 0
parameter = [{ art = "zeiger", werte = ["va:0005026C", "0x1"], min = 1, max = 2 }]
[[lauf.funktion.dateien]]
datei = "DATA\\PALETTE.DAT"
art = "lesen"
direkt = true
zugriffe = 2
offset_min = 0
offset_max = 0
laenge_max = 768
[lauf.funktion.rueckgabe]
art = "zahl"
werte = ["0xe"]
[[lauf.funktion.fall]]
ein = ["va:000605D4", "0x0"]
aus = "0xe"
aus_zeiger = "va:00050CE9"
"#,
        );
        let r = &t["run"][0];
        assert_eq!(r["imported"].as_str(), Some("2026-10-11"));
        assert_eq!(r["source"].as_str(), Some("D:\\runs\\1"));
        assert_eq!(r["description"].as_str(), Some("Start bis Menue"));
        assert_eq!(r["instructions"].as_integer(), Some(5));
        assert_eq!(r["outside_functions"].as_integer(), Some(1));
        assert_eq!(r["states"].as_integer(), Some(2));
        assert_eq!(r["pairs"][0]["from"].as_str(), Some("flat:00000010"));
        assert_eq!(r["pairs"][0]["count"].as_integer(), Some(3));
        assert_eq!(r["files"]["data/a.dat"].as_integer(), Some(4));
        assert_eq!(r["sha256"]["coverage"].as_str(), Some("aa"));
        assert_eq!(r["sha256"]["calls"].as_str(), Some("bb"));
        assert_eq!(r["sha256"]["events"].as_str(), Some("cc"));
        assert_eq!(r["bases"]["obj1"].as_str(), Some("0x154030"));
        let f = &r["function"][0];
        assert_eq!(f["address"].as_str(), Some("flat:00025110"));
        assert_eq!(f["calls"].as_integer(), Some(1));
        assert_eq!(f["omitted"].as_integer(), Some(0));
        assert_eq!(f["parameters"][0]["kind"].as_str(), Some("pointer"));
        assert_eq!(
            f["parameters"][0]["values"][0].as_str(),
            Some("flat:0005026C")
        );
        assert_eq!(f["parameters"][0]["values"][1].as_str(), Some("0x1"));
        assert_eq!(f["files"][0]["file"].as_str(), Some("DATA\\PALETTE.DAT"));
        assert_eq!(f["files"][0]["mode"].as_str(), Some("read"));
        assert_eq!(f["files"][0]["max_length"].as_integer(), Some(768));
        assert_eq!(f["returns"]["kind"].as_str(), Some("number"));
        assert_eq!(f["cases"][0]["inputs"][0].as_str(), Some("flat:000605D4"));
        assert_eq!(f["cases"][0]["output"].as_str(), Some("0xe"));
        assert_eq!(
            f["cases"][0]["output_pointer"].as_str(),
            Some("flat:00050CE9")
        );
        assert!(cx.unmapped.is_empty(), "{:?}", cx.unmapped);
        assert_eq!(cx.texts, 1);
    }

    #[test]
    fn references() {
        let (t, cx) = convert(
            "verweise.toml",
            r#"
[[verweis]]
von = "va:00010379"
nach = "rel:0010:0020"
art = "sprung"
quelle = "laufzeit"
beleg = "Lauf spiel, 16x"

[[verweis]]
von = "va:00010379"
nach = "va:000103FC"
art = "tabelle"
quelle = "ki"
"#,
        );
        let r = &t["reference"];
        assert_eq!(r[0]["from"].as_str(), Some("flat:00010379"));
        assert_eq!(r[0]["to"].as_str(), Some("seg:0010:0020"));
        assert_eq!(r[0]["kind"].as_str(), Some("jump"));
        assert_eq!(r[0]["source"].as_str(), Some("runtime"));
        assert_eq!(r[0]["evidence"].as_str(), Some("Lauf spiel, 16x"));
        assert_eq!(r[1]["source"].as_str(), Some("agent"));
        let unmapped: Vec<_> = cx.unmapped.iter().map(String::as_str).collect();
        assert_eq!(unmapped, ["verweis.art=tabelle"]);
        assert_eq!(cx.texts, 1);
    }
}
