//! Plugin configuration: the user config (written by `decovery setup`) and the workspace's `[plugins.<name>]`.
//!
//! User config format (`<config dir>/decovery/config.toml`):
//!
//! ```toml
//! schema = 1
//!
//! [plugins.ghidra]
//! command = ["python", "-m", "decovery_ghidra"]
//! env = { GHIDRA_INSTALL_DIR = "C:/ghidra" }
//! ```
//!
//! An entry in the workspace's `decovery.toml` replaces the user entry of the same name as a whole.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use decovery_core::{Workspace, WorkspaceError};
use serde::Deserialize;

pub use decovery_core::PluginConfig;

use crate::FacadeError;

#[derive(Deserialize)]
struct UserConfig {
    #[serde(default)]
    schema: Option<u32>,
    #[serde(default)]
    plugins: BTreeMap<String, PluginConfig>,
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

/// The plugins of the user config; empty when there is none or it cannot be read (see [`read_user_plugins`]
/// for the error).
pub fn user_plugins() -> BTreeMap<String, PluginConfig> {
    read_user_plugins().unwrap_or_default()
}

/// The plugins of the user config; empty when the file does not exist.
pub fn read_user_plugins() -> Result<BTreeMap<String, PluginConfig>, FacadeError> {
    match user_config_path() {
        Some(path) => read_plugins_file(&path),
        None => Ok(BTreeMap::new()),
    }
}

/// The `[plugins.*]` tables of a user config file; empty when the file does not exist.
pub fn read_plugins_file(path: &Path) -> Result<BTreeMap<String, PluginConfig>, FacadeError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => {
            return Err(WorkspaceError::Io {
                path: path.to_path_buf(),
                source,
            }
            .into());
        }
    };
    let config: UserConfig = toml::from_str(&text).map_err(|source| WorkspaceError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if let Some(found) = config
        .schema
        .filter(|&s| s != decovery_core::workspace::SCHEMA)
    {
        return Err(WorkspaceError::Schema {
            path: path.to_path_buf(),
            found,
        }
        .into());
    }
    Ok(config.plugins)
}

/// The configuration of plugin `name`: the workspace entry, else the user entry.
pub fn plugin_config(
    workspace: &Workspace,
    user: &BTreeMap<String, PluginConfig>,
    name: &str,
) -> Option<PluginConfig> {
    workspace
        .config
        .plugins
        .get(name)
        .or_else(|| user.get(name))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_config_path_ends_in_decovery_config_toml() {
        // The variables are set on every developer machine and CI runner.
        let path = user_config_path().expect("config dir variables set");
        assert!(path.ends_with(Path::new("decovery").join("config.toml")));
        assert!(path.is_absolute());
    }

    #[test]
    fn plugins_file_is_read_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(read_plugins_file(&path).unwrap().is_empty());
        std::fs::write(
            &path,
            "schema = 1\n\n[plugins.ghidra]\ncommand = [\"py\", \"-m\", \"decovery_ghidra\"]\nenv = { GHIDRA_INSTALL_DIR = \"C:/g h\" }\n",
        )
        .unwrap();
        let plugins = read_plugins_file(&path).unwrap();
        assert_eq!(plugins["ghidra"].command, ["py", "-m", "decovery_ghidra"]);
        assert_eq!(plugins["ghidra"].env["GHIDRA_INSTALL_DIR"], "C:/g h");
        std::fs::write(&path, "schema = 2\n").unwrap();
        assert!(read_plugins_file(&path).is_err());
        std::fs::write(&path, "[plugins.x]\ncommand = 1\n").unwrap();
        assert!(read_plugins_file(&path).is_err());
    }

    #[test]
    fn workspace_entry_overrides_user_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("decovery.toml"),
            "schema = 1\n\n[target]\nfile = \"t\"\nsha256 = \"aa\"\nformat = \"le\"\nprocessor = \"x86\"\n\n[plugins.ghidra]\ncommand = [\"ws\"]\n",
        )
        .unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let user = BTreeMap::from([
            ("ghidra".to_string(), PluginConfig::new(vec!["user".into()])),
            ("other".to_string(), PluginConfig::new(vec!["o".into()])),
        ]);
        assert_eq!(plugin_config(&ws, &user, "ghidra").unwrap().command, ["ws"]);
        assert_eq!(plugin_config(&ws, &user, "other").unwrap().command, ["o"]);
        assert!(plugin_config(&ws, &user, "none").is_none());
    }
}
