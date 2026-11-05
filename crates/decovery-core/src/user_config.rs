//! The user config (`<config dir>/decovery/config.toml`), written by `decovery setup`.
//!
//! ```toml
//! schema = 1
//!
//! [plugins.ghidra]
//! command = ["python", "-m", "decovery_ghidra"]
//!
//! [toolchains]
//! "watcom-9.5" = "C:/tools/watcom95"
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::workspace::{PluginConfig, SCHEMA, WorkspaceError};

/// The user config; every table is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct UserConfig {
    #[serde(default)]
    pub schema: Option<u32>,
    #[serde(default)]
    pub plugins: BTreeMap<String, PluginConfig>,
    /// Compiler profile id to the directory that holds the compiler.
    #[serde(default)]
    pub toolchains: BTreeMap<String, PathBuf>,
}

/// `%APPDATA%\decovery\config.toml` on Windows; elsewhere `$XDG_CONFIG_HOME/decovery/config.toml`, else
/// `$HOME/.config/decovery/config.toml`. `None` when the variables are unset.
pub fn user_config_path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        non_empty_var("APPDATA").map(PathBuf::from)
    } else {
        non_empty_var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| non_empty_var("HOME").map(|home| Path::new(&home).join(".config")))
    }?;
    Some(base.join("decovery").join("config.toml"))
}

fn non_empty_var(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// The user config; the default when the file (or the config dir) does not exist.
pub fn read_user_config() -> Result<UserConfig, WorkspaceError> {
    match user_config_path() {
        Some(path) => read_user_config_file(&path),
        None => Ok(UserConfig::default()),
    }
}

/// The user config at `path`; the default when the file does not exist.
pub fn read_user_config_file(path: &Path) -> Result<UserConfig, WorkspaceError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(UserConfig::default()),
        Err(source) => {
            return Err(WorkspaceError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let config: UserConfig = toml::from_str(&text).map_err(|source| WorkspaceError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if let Some(found) = config.schema.filter(|&s| s != SCHEMA) {
        return Err(WorkspaceError::Schema {
            path: path.to_path_buf(),
            found,
        });
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_config_path_ends_in_decovery_config_toml() {
        let path = user_config_path().expect("config dir variables set");
        assert!(path.ends_with(Path::new("decovery").join("config.toml")));
        assert!(path.is_absolute());
    }

    #[test]
    fn user_config_reads_toolchains_and_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert_eq!(read_user_config_file(&path).unwrap(), UserConfig::default());
        std::fs::write(
            &path,
            "schema = 1\n\n[plugins.ghidra]\ncommand = [\"py\"]\n\n[toolchains]\n\"watcom-9.5\" = \"C:/t/w95\"\n",
        )
        .unwrap();
        let config = read_user_config_file(&path).unwrap();
        assert_eq!(config.plugins["ghidra"].command, ["py"]);
        assert_eq!(config.toolchains["watcom-9.5"], Path::new("C:/t/w95"));
        std::fs::write(&path, "schema = 2\n").unwrap();
        assert!(read_user_config_file(&path).is_err());
        std::fs::write(&path, "[toolchains]\nx = 1\n").unwrap();
        assert!(read_user_config_file(&path).is_err());
    }
}
