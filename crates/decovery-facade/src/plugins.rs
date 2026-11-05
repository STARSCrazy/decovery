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
use std::path::Path;

use decovery_core::{Workspace, read_user_config, read_user_config_file};

pub use decovery_core::{PluginConfig, user_config_path};

use crate::FacadeError;

/// The plugins of the user config; empty when there is none or it cannot be read (see [`read_user_plugins`]
/// for the error).
///
/// Public for the local (`#[ignore]`) tests, which take the user's `[plugins.ghidra]` without failing on a
/// missing or broken config; the tools themselves use [`read_user_plugins`] and report its error.
pub fn user_plugins() -> BTreeMap<String, PluginConfig> {
    read_user_plugins().unwrap_or_default()
}

/// The plugins of the user config; empty when the file does not exist.
pub fn read_user_plugins() -> Result<BTreeMap<String, PluginConfig>, FacadeError> {
    Ok(read_user_config()?.plugins)
}

/// The `[plugins.*]` tables of a user config file; empty when the file does not exist.
pub fn read_plugins_file(path: &Path) -> Result<BTreeMap<String, PluginConfig>, FacadeError> {
    Ok(read_user_config_file(path)?.plugins)
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
