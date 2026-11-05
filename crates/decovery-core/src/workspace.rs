//! Workspace configuration (`decovery.toml`) and opening a workspace.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::address::Address;
use crate::knowledge::{Confidence, Symbol, SymbolsFile};

/// File name of the workspace configuration.
pub const CONFIG_FILE: &str = "decovery.toml";
/// Path of the symbol file relative to the workspace root.
pub const SYMBOLS_FILE: &str = "knowledge/symbols.toml";
/// The only schema version this build reads and writes.
pub const SCHEMA: u32 = 1;

/// A workspace: root directory, configuration and symbols.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Workspace {
    pub root: PathBuf,
    pub config: WorkspaceConfig,
    pub symbols: Vec<Symbol>,
}

/// Errors when opening a workspace.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkspaceError {
    #[error("cannot read {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{}: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("{}: {source}", path.display())]
    Json {
        path: PathBuf,
        source: Box<serde_json::Error>,
    },
    #[error("{}: unsupported schema {found} (expected {SCHEMA})", path.display())]
    Schema { path: PathBuf, found: u32 },
    #[error("workspace is locked by pid {pid}")]
    Locked { pid: u32 },
    #[error("{}: cannot write unknown value: {detail}", file.display())]
    UnknownValue { file: PathBuf, detail: String },
}

impl Workspace {
    /// Reads `decovery.toml` and, if present, `knowledge/symbols.toml` below `root`.
    pub fn open(root: &Path) -> Result<Self, WorkspaceError> {
        let config_path = root.join(CONFIG_FILE);
        let config: WorkspaceConfig = read_toml(&config_path)?;
        check_schema(&config_path, config.schema)?;
        let symbols_path = root.join(SYMBOLS_FILE);
        let symbols = if symbols_path.is_file() {
            let file: SymbolsFile = read_toml(&symbols_path)?;
            check_schema(&symbols_path, file.schema)?;
            file.symbols
        } else {
            Vec::new()
        };
        Ok(Workspace {
            root: root.to_path_buf(),
            config,
            symbols,
        })
    }
}

fn check_schema(path: &Path, found: u32) -> Result<(), WorkspaceError> {
    if found == SCHEMA {
        Ok(())
    } else {
        Err(WorkspaceError::Schema {
            path: path.to_path_buf(),
            found,
        })
    }
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, WorkspaceError> {
    let text = std::fs::read_to_string(path).map_err(|source| WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| WorkspaceError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })
}

/// Content of `decovery.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WorkspaceConfig {
    pub schema: u32,
    pub target: TargetConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild: Option<RebuildConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeConfig>,
    /// The target was unpacked; the cached unpacked image is what gets loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpacked: Option<UnpackedConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detected: Vec<DetectedFact>,
    /// `[plugins.<name>]`: how to start a plugin; overrides the user config entry of the same name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub plugins: BTreeMap<String, PluginConfig>,
}

/// How to start a plugin (`[plugins.<name>]` in `decovery.toml` or the user config).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PluginConfig {
    /// Program and arguments.
    pub command: Vec<String>,
    /// Extra environment variables of the plugin process.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

impl PluginConfig {
    pub fn new(command: Vec<String>) -> Self {
        PluginConfig {
            command,
            env: BTreeMap::new(),
        }
    }
}

/// File format of the target as configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TargetFormat {
    Com,
    Mz,
    Le,
    /// Raw 32-bit flat image described only by `[[target.segment]]`.
    Flat32,
}

/// The program under study.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TargetConfig {
    /// Path to the file, relative to the workspace root unless absolute.
    pub file: String,
    pub sha256: String,
    pub format: TargetFormat,
    pub processor: String,
    #[serde(default, rename = "segment", skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<SegmentConfig>,
}

/// A segment of the target as declared in the configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SegmentConfig {
    pub name: String,
    pub start: Address,
    pub length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_length: Option<u64>,
    /// Access rights as `r`, `w`, `x` letters, for example `rx`.
    pub permissions: String,
}

/// Analysis settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AnalysisConfig {
    #[serde(default)]
    pub prologues: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<String>,
}

/// Output settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OutputConfig {
    #[serde(default = "default_true")]
    pub versioned: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        OutputConfig { versioned: true }
    }
}

fn default_true() -> bool {
    true
}

/// How the program is rebuilt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RebuildConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<LinkConfig>,
    /// Runner ids to try in order; empty = the profile's own list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runners: Vec<String>,
    /// Directory of the compiler; overrides the user config `[toolchains]` entry. Relative to the workspace root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_s: Option<u32>,
    /// Extra compiler flags per source file name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub file_flags: BTreeMap<String, String>,
    /// Frame (stack segment) bases by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub frames: BTreeMap<String, Address>,
}

/// Linker settings of a rebuild.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LinkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libraries: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<String>,
    /// Insert the rebuilt functions into the original image instead of linking a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insert: Option<bool>,
    /// Stack size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<u32>,
}

/// Runtime facts about the target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RuntimeConfig {
    #[serde(default)]
    pub bases: Vec<RuntimeBase>,
}

/// Where a segment was loaded in a runtime run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RuntimeBase {
    pub segment: String,
    #[serde(with = "hex_u32")]
    pub linear_base: u32,
}

/// Facts about the unpacked image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UnpackedConfig {
    pub packer: String,
    pub sha256: String,
    pub entry: Address,
}

/// A fact found by detection (format, compiler, extender, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DetectedFact {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

mod hex_u32 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &u32, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{value:08X}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
        let text = String::deserialize(d)?;
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(&text);
        u32::from_str_radix(digits, 16).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "schema = 1

[target]
file = \"t.exe\"
sha256 = \"aa\"
format = \"le\"
processor = \"x86\"
";

    #[test]
    fn config_without_plugins_loads_and_writes_none() {
        let config: WorkspaceConfig = toml::from_str(BASE).unwrap();
        assert!(config.plugins.is_empty());
        assert!(!toml::to_string(&config).unwrap().contains("plugins"));
    }

    #[test]
    fn plugins_round_trip() {
        let text = format!(
            "{BASE}
[plugins.ghidra]
command = [\"py\", \"-m\", \"decovery_ghidra\"]
env = {{ A = \"1\" }}

[plugins.other]
command = [\"x\"]
"
        );
        let config: WorkspaceConfig = toml::from_str(&text).unwrap();
        let ghidra = &config.plugins["ghidra"];
        assert_eq!(ghidra.command, ["py", "-m", "decovery_ghidra"]);
        assert_eq!(ghidra.env["A"], "1");
        assert!(config.plugins["other"].env.is_empty());
        let again: WorkspaceConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(again, config);
    }
}
