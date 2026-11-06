//! Parity with Decomp's recorded comparisons of one rebuilt source file of a private Decomp workspace. Run with
//! `DECOVERY_LOCAL_WORKSPACE=<Decomp workspace dir> cargo test -p decovery-diff -- --ignored`.
//!
//! Reads the target named in `decomp.toml`, the rebuilt object of the first source file listed in
//! `wissen/nachbau.toml` (from `cache/nachbau/obj/`), the names from
//! `wissen/symbole.toml`, the recorded metrics from `wissen/nachbau.toml` and each function's span from the
//! generated `ausgabe/funktionen/**` headers (Decomp took it from Ghidra).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use decovery_core::{Address, Program, RelocKind};
use decovery_diff::{
    Blocker, CompareOptions, Comparison, Decoration, NameAt, SymbolView, Verdict, compare,
};
use decovery_loaders::load_le;
use decovery_objects::{ObjectFile, RefTarget, functions, read_omf};

// Decomp's on-disk names (its workspace is German).
const DECOMP_KNOWLEDGE_DIR: &str = "wissen";
const DECOMP_OUTPUT_DIR: &str = "ausgabe";
const DECOMP_FUNCTIONS_DIR: &str = "funktionen";
const DECOMP_REBUILD_DIR: &str = "nachbau";
const DECOMP_SYMBOLS_FILE: &str = "symbole.toml";
const DECOMP_REBUILD_RECORDS_FILE: &str = "nachbau.toml";
const DECOMP_ADDRESS_TAG: &str = "@adresse";
const DECOMP_RECORD_TABLE: &str = "funktion";
const DECOMP_KEY_TARGET: &str = "ziel";
const DECOMP_KEY_ADDRESS: &str = "adresse";
const DECOMP_KEY_FILE: &str = "datei";
const DECOMP_KEY_RESULT: &str = "ergebnis";
const DECOMP_KEY_REFUTED: &str = "widerlegt";
const DECOMP_RESULT_IDENTICAL: &str = "identisch";
/// Decomp's metric keys, in the order of `Metrics`' fields used below.
const DECOMP_METRIC_KEYS: [&str; 7] = [
    "bytes",
    "gleich",
    "luecken",
    "abweichend",
    "verweise_passend",
    "verweise_falsch",
    "befehle_abweichend",
];

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn va(text: &str) -> Option<u32> {
    u32::from_str_radix(text.strip_prefix("va:")?, 16).ok()
}

/// Names from Decomp's knowledge: active (not refuted) symbols, default name `fun_XXXXXXXX`.
#[derive(Clone)]
struct Knowledge {
    by_address: BTreeMap<u32, String>,
}

impl Knowledge {
    fn load(path: &Path) -> Self {
        let doc: toml::Table = std::fs::read_to_string(path).unwrap().parse().unwrap();
        let mut by_address = BTreeMap::new();
        for s in doc["symbol"].as_array().unwrap() {
            let s = s.as_table().unwrap();
            if s.get(DECOMP_KEY_REFUTED).is_some() {
                continue;
            }
            let (Some(a), Some(n)) = (
                s.get(DECOMP_KEY_ADDRESS)
                    .and_then(|v| v.as_str())
                    .and_then(va),
                s.get("name").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            if !n.is_empty() {
                by_address.insert(a, n.to_string());
            }
        }
        Knowledge { by_address }
    }

    fn moved(&self, name: &str, delta: u32) -> Self {
        let mut k = self.clone();
        let (&a, _) = k
            .by_address
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .unwrap();
        let n = k.by_address.remove(&a).unwrap();
        k.by_address.insert(a + delta, n);
        k
    }
}

impl SymbolView for Knowledge {
    fn name_at(&self, at: Address) -> Option<NameAt> {
        let Address::Flat(a) = at else { return None };
        Some(match self.by_address.get(&a) {
            Some(n) => NameAt::new(n.clone(), false),
            None => NameAt::new(format!("fun_{a:08X}"), true),
        })
    }

    fn address_of(&self, name: &str) -> Option<Address> {
        self.by_address
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(&a, _)| Address::Flat(a))
    }
}

/// Function spans from the `@adresse    va:X .. va:Y (N Bytes` in the generated output.
fn spans(dir: &Path) -> BTreeMap<u32, u32> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Some(line) = text.lines().find(|l| l.contains(DECOMP_ADDRESS_TAG)) else {
                continue;
            };
            let words: Vec<&str> = line.split_whitespace().collect();
            let Some(i) = words.iter().position(|w| *w == DECOMP_ADDRESS_TAG) else {
                continue;
            };
            if let (Some(start), Some(end)) = (
                words.get(i + 1).and_then(|w| va(w)),
                words.get(i + 3).and_then(|w| va(w)),
            ) {
                out.insert(start, end - start + 1);
            }
        }
    }
    out
}

struct Setup {
    root: PathBuf,
    program: Program,
    knowledge: Knowledge,
    spans: BTreeMap<u32, u32>,
    recorded: Vec<toml::Table>,
}

impl Setup {
    fn load() -> Self {
        let root = env_path("DECOVERY_LOCAL_WORKSPACE");
        let config: toml::Table = std::fs::read_to_string(root.join("decomp.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let target = config[DECOMP_KEY_TARGET][DECOMP_KEY_FILE].as_str().unwrap();
        let exe = std::fs::read(root.join(target)).unwrap();
        let recorded: toml::Table = std::fs::read_to_string(
            root.join(DECOMP_KNOWLEDGE_DIR)
                .join(DECOMP_REBUILD_RECORDS_FILE),
        )
        .unwrap()
        .parse()
        .unwrap();
        Setup {
            program: load_le(&exe).unwrap().program,
            knowledge: Knowledge::load(&root.join(DECOMP_KNOWLEDGE_DIR).join(DECOMP_SYMBOLS_FILE)),
            spans: spans(&root.join(DECOMP_OUTPUT_DIR).join(DECOMP_FUNCTIONS_DIR)),
            recorded: recorded[DECOMP_RECORD_TABLE]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e.as_table().unwrap().clone())
                .collect(),
            root,
        }
    }

    fn object(&self, stem: &str) -> ObjectFile {
        let path = self
            .root
            .join("cache")
            .join(DECOMP_REBUILD_DIR)
            .join("obj")
            .join(format!("{stem}.obj"));
        read_omf(&std::fs::read(path).unwrap(), &format!("{stem}.obj")).unwrap()
    }

    fn compare(&self, obj: &ObjectFile, name: &str, at: u32, symbols: &Knowledge) -> Comparison {
        let decoration = Decoration::watcom();
        let views = functions(&obj.modules[0]);
        let f = views
            .iter()
            .find(|f| decoration.undecorate(f.name) == name)
            .unwrap_or_else(|| panic!("{name} not in the object"));
        let options = CompareOptions::new(false, self.spans.get(&at).copied());
        compare(
            f,
            Address::Flat(at),
            &self.program,
            symbols,
            &decoration,
            &options,
        )
    }
}

fn num(e: &toml::Table, key: &str) -> u32 {
    e.get(key).and_then(|v| v.as_integer()).unwrap_or(0) as u32
}

impl Setup {
    /// Stem of the first rebuilt source file recorded in `nachbau.toml`.
    fn first_source_file(&self) -> String {
        self.recorded[0][DECOMP_KEY_FILE]
            .as_str()
            .unwrap()
            .to_string()
    }
}

#[test]
#[ignore = "local: private Decomp workspace"]
fn metrics_match_decomp() {
    let setup = Setup::load();
    let file = setup.first_source_file();
    let obj = setup.object(file.trim_end_matches(".c"));
    let mut compared = 0;
    let mut mismatches = Vec::new();
    for e in setup
        .recorded
        .iter()
        .filter(|e| e[DECOMP_KEY_FILE].as_str() == Some(file.as_str()))
    {
        let name = e["name"].as_str().unwrap();
        let at = va(e[DECOMP_KEY_ADDRESS].as_str().unwrap()).unwrap();
        let c = setup.compare(&obj, name, at, &setup.knowledge);
        let m = &c.metrics;
        let ours = [
            m.bytes,
            m.equal,
            m.gaps,
            m.differing,
            m.refs_ok,
            m.refs_wrong,
            m.instructions_differing,
        ];
        let theirs = DECOMP_METRIC_KEYS.map(|k| num(e, k));
        if ours != theirs {
            mismatches.push(format!("{at:#x}: {ours:?} != {theirs:?}"));
        }
        if c.verdict == Verdict::Identical {
            assert_eq!(
                e[DECOMP_KEY_RESULT].as_str(),
                Some(DECOMP_RESULT_IDENTICAL),
                "{at:#x}"
            );
        }
        compared += 1;
    }
    println!("compared {compared} functions of the first rebuilt file");
    assert!(
        compared > 0,
        "no entries for the first file in nachbau.toml"
    );
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

/// Moving a referenced symbol in the knowledge must turn an identical function into `Differs`.
#[test]
#[ignore = "local: private Decomp workspace"]
fn strict_rule_sees_moved_symbols() {
    let setup = Setup::load();
    let decoration = Decoration::watcom();
    let (mut saw_relative, mut saw_absolute) = (false, false);
    for e in setup
        .recorded
        .iter()
        .filter(|e| e[DECOMP_KEY_RESULT].as_str() == Some(DECOMP_RESULT_IDENTICAL))
    {
        let file = e[DECOMP_KEY_FILE].as_str().unwrap();
        let obj = setup.object(file.trim_end_matches(".c"));
        let name = e["name"].as_str().unwrap();
        let at = va(e[DECOMP_KEY_ADDRESS].as_str().unwrap()).unwrap();
        if setup.compare(&obj, name, at, &setup.knowledge).verdict != Verdict::Identical {
            continue;
        }
        let views = functions(&obj.modules[0]);
        let Some(f) = views.iter().find(|f| decoration.undecorate(f.name) == name) else {
            continue;
        };
        for reloc in f.relocs() {
            let RefTarget::Symbol(target) = &reloc.target else {
                continue;
            };
            let target = decoration.undecorate(target).to_string();
            let relative = reloc.kind == RelocKind::Relative;
            if (relative && saw_relative) || (!relative && saw_absolute) {
                continue;
            }
            let moved = setup.knowledge.moved(&target, 0x10);
            let c = setup.compare(&obj, name, at, &moved);
            let expected = |b: &Blocker| {
                if relative {
                    matches!(b, Blocker::WrongRelativeRef { .. })
                } else {
                    matches!(b, Blocker::WrongAbsoluteRef { .. })
                }
            };
            if c.blockers.iter().any(expected) {
                assert_ne!(c.verdict, Verdict::Identical);
                if relative {
                    saw_relative = true;
                } else {
                    saw_absolute = true;
                }
            }
        }
        if saw_relative && saw_absolute {
            return;
        }
    }
    panic!("no identical function with both a relative and an absolute named reference was found");
}
