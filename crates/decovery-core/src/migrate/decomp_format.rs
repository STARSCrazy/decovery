//! Decomp's on-disk vocabulary: the German directory names, file names, TOML keys and ids of the workspace the
//! migration reads. Every German literal of the import sits here behind an English constant; the tables that map
//! values to decovery's ids live in `knowledge.rs`.

/// Directory names below the Decomp workspace root.
pub(super) mod dirs {
    pub(crate) const KNOWLEDGE: &str = "wissen";
    pub(crate) const OUTPUT: &str = "ausgabe";
    pub(crate) const CACHE: &str = "cache";
    pub(crate) const GAME: &str = "spiel";
    pub(crate) const REBUILD: &str = "nachbau";
    pub(crate) const FUNCTIONS: &str = "funktionen";
    pub(crate) const RUNS: &str = "laufzeit";
}

/// File names.
pub(super) mod files {
    pub(crate) const CONFIG: &str = "decomp.toml";
    pub(crate) const SYMBOLS: &str = "symbole.toml";
    pub(crate) const TYPES: &str = "typen.h";
    pub(crate) const NOTES: &str = "notizen.md";
    pub(crate) const STYLE: &str = "programmierstil.md";
    pub(crate) const REBUILD_RECORDS: &str = "nachbau.toml";
    pub(crate) const REBUILD_PROGRAM: &str = "nachbau-programm.toml";
    pub(crate) const RUN_RECORDS: &str = "laufzeit.toml";
    pub(crate) const REFERENCES: &str = "verweise.toml";
    pub(crate) const CALLS: &str = "aufrufe.json";
    pub(crate) const STRINGS: &str = "strings.md";
    pub(crate) const GLOBALS: &str = "globale.md";
    pub(crate) const INDEX: &str = "index.md";
    pub(crate) const STATUS: &str = "stand.json";
    pub(crate) const RUNTIME_REPORT: &str = "laufzeit.md";
    pub(crate) const SYMBOL_DUMP: &str = "decomp-symbole.json";
}

/// TOML and JSON keys of `decomp.toml`, `symbole.toml` (the keys of `ausgabe/aufrufe.json` are serde renames in `analysis_import.rs`).
pub(super) mod keys {
    pub(crate) const TARGET: &str = "ziel";
    pub(crate) const FILE: &str = "datei";
    pub(crate) const PROCESSOR: &str = "prozessor";
    pub(crate) const LENGTH: &str = "laenge";
    pub(crate) const FILE_OFFSET: &str = "datei_offset";
    pub(crate) const FILE_LENGTH: &str = "datei_laenge";
    pub(crate) const PERMISSIONS: &str = "rechte";
    pub(crate) const ANALYSIS: &str = "analyse";
    pub(crate) const PROLOGUES: &str = "prologe";
    pub(crate) const CALLING_CONVENTION: &str = "aufrufart";
    pub(crate) const OUTPUT: &str = "ausgabe";
    pub(crate) const VERSIONED: &str = "versionieren";
    pub(crate) const DETECTION: &str = "erkennung";
    pub(crate) const KIND: &str = "art";
    pub(crate) const VALUE: &str = "wert";
    pub(crate) const CONFIDENCE: &str = "sicherheit";
    pub(crate) const EVIDENCE: &str = "beleg";
    pub(crate) const SOURCE: &str = "quelle";
    pub(crate) const UNPACKED: &str = "entpackt";
    pub(crate) const ENTRY: &str = "einsprung";
    pub(crate) const RUNTIME: &str = "laufzeit";
    pub(crate) const BASES: &str = "basis";
    pub(crate) const LINEAR_BASE: &str = "basis_linear";
    pub(crate) const REBUILD: &str = "nachbau";
    pub(crate) const FLAGS: &str = "optionen";
    pub(crate) const FILE_FLAGS: &str = "optionen_je_datei";
    pub(crate) const LINK: &str = "linken";
    pub(crate) const PROFILE: &str = "profil";
    pub(crate) const LIBRARIES: &str = "bibliotheken";
    pub(crate) const INSERT: &str = "einsetzen";
    pub(crate) const STACK: &str = "stapel";
    pub(crate) const STARTUP: &str = "start";
    pub(crate) const SYMBOL: &str = "symbol";
    pub(crate) const ADDRESS: &str = "adresse";
    pub(crate) const SIGNATURE: &str = "signatur";
    pub(crate) const COMMENT: &str = "kommentar";
    pub(crate) const SIZE: &str = "groesse";
    pub(crate) const LIBRARY: &str = "bibliothek";
    pub(crate) const REFUTED_EARLIER: &str = "widerlegt_frueher";
    pub(crate) const DATA_TYPE: &str = "typ";
    pub(crate) const LOCAL: &str = "lokal";
    pub(crate) const PLACE: &str = "platz";
    pub(crate) const LINE_COMMENT: &str = "zeilenkommentar";
}

/// Enum values of `decomp.toml` and `symbole.toml`.
pub(super) mod values {
    pub(crate) const SOURCE_HUMAN: &str = "mensch";
    pub(crate) const SOURCE_AGENT: &str = "ki";
    pub(crate) const SOURCE_SIGNATURE: &str = "signatur";
    pub(crate) const SOURCE_RUNTIME: &str = "laufzeit";
    pub(crate) const SOURCE_SIMILARITY: &str = "aehnlich";
    pub(crate) const SOURCE_ANALYSIS: &str = "engine";
    pub(crate) const CONFIDENCE_CONFIRMED: &str = "belegt";
    pub(crate) const CONFIDENCE_ASSUMED: &str = "vermutet";
    pub(crate) const CONFIDENCE_REFUTED: &str = "widerlegt";
    pub(crate) const KIND_FUNCTION: &str = "funktion";
    pub(crate) const KIND_LABEL: &str = "marke";
    pub(crate) const DETECTED_CALLING_CONVENTION: &str = "aufrufart";
    pub(crate) const FORMAT_FLAT32: &str = "flach32";
    pub(crate) const DETECTED_SOURCE_PACKED: &str = "gepackt";
}

/// The header of a generated function file (`ausgabe/funktionen/**`) and the German phrases in it.
pub(super) mod header {
    /// First line marker of the address line.
    pub(crate) const ADDRESS_TAG: &str = "@adresse";
    pub(crate) const SPAN_SUFFIX: &str = " Bytes Spanne";
    pub(crate) const BODY_SUFFIX: &str = " im Rumpf";
    /// Decomp's text when decompiling failed; starts the body of the function file.
    pub(crate) const DECOMPILE_ERROR_PREFIX: &str = "/* Dekompilieren fehlgeschlagen: ";
}
