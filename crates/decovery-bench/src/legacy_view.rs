//! A stripped, per-task Decomp source view; only backend resources are linked read-only.
use super::copy::{Secrets, copy_error, copy_tree, read_toml, write, write_toml};
use super::{BenchError, SuiteTask, io};
use decovery_core::Address;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(crate) fn prepare(
    task: &SuiteTask,
    source: &Path,
    view: &Path,
    address: Address,
    secrets: &Secrets,
) -> Result<(), BenchError> {
    let source = super::canonical(source)?;
    if view.starts_with(&source) {
        return Err(copy_error(
            task,
            "legacy view must be outside its source workspace",
        ));
    }
    let mut config = read_toml(&source.join("decomp.toml"))?;
    fn paths(value: &mut toml::Value, source: &Path) {
        match value {
            toml::Value::Table(table) => {
                for (key, value) in table {
                    if key == "datei" {
                        super::copy::absolutize(value, source);
                    } else {
                        paths(value, source);
                    }
                }
            }
            toml::Value::Array(array) => {
                for value in array {
                    paths(value, source);
                }
            }
            _ => {}
        }
    }
    paths(&mut config, &source);
    secrets.sanitize_toml(&mut config);
    write_toml(&view.join("decomp.toml"), &config)?;
    copy_tree(
        &source.join("wissen"),
        &view.join("wissen"),
        secrets,
        &|relative| relative != Path::new("nachbau.toml"),
    )?;
    let path = source.join("wissen/nachbau.toml");
    if path.is_file() {
        let mut rebuild = read_toml(&path)?;
        let legacy_address = match address {
            Address::Flat(at) => format!("va:{at:08X}"),
            Address::Seg { seg, off } => format!("rel:{seg:04X}:{off:04X}"),
            _ => {
                return Err(copy_error(
                    task,
                    "legacy bridge does not support this address kind",
                ));
            }
        };
        super::copy::remove_record(&mut rebuild, "funktion", "adresse", &legacy_address);
        secrets.sanitize_toml(&mut rebuild);
        write_toml(&view.join("wissen/nachbau.toml"), &rebuild)?;
    }
    let unpacked = source.join("cache/entpackt.exe");
    if unpacked.is_file() {
        write(
            &view.join("cache/entpackt.exe"),
            &std::fs::read(&unpacked).map_err(|e| io(&unpacked, e))?,
        )?;
    }
    let project = project_dir(&source)?;
    for (target, link) in [
        (project, view.join("cache/ghidra")),
        (source.join("cache/laufzeit"), view.join("cache/laufzeit")),
    ] {
        if target.is_dir() {
            link_dir(&link, &target)?;
        }
    }
    Ok(())
}

/// Match the bridge's dotted-path project redirection, including Python's non-verbatim Windows path spelling.
fn project_dir(source: &Path) -> Result<PathBuf, BenchError> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    project_dir_at(source, &base)
}

fn project_dir_at(source: &Path, base: &Path) -> Result<PathBuf, BenchError> {
    let cache = source.join("cache");
    let cache = if cache.exists() {
        super::canonical(&cache)?
    } else {
        cache
    };
    let folder = cache.join("ghidra");
    if std::fs::read_link(&folder).is_ok() {
        return super::canonical(&folder);
    }
    if !folder.components().any(
        |p| matches!(p, std::path::Component::Normal(n) if n.to_string_lossy().starts_with('.')),
    ) {
        return Ok(folder);
    }
    let text = folder.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text).to_lowercase();
    let hash: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(base.join("decomp/ghidra").join(&hash[..16]))
}

pub(crate) fn parse_address(text: &str) -> Option<Address> {
    if let Some(hex) = text.strip_prefix("va:") {
        return u32::from_str_radix(hex, 16).ok().map(Address::Flat);
    }
    if let Some(rest) = text.strip_prefix("rel:") {
        let (segment, offset) = rest.split_once(':')?;
        return Some(Address::Seg {
            seg: u16::from_str_radix(segment, 16).ok()?,
            off: u16::from_str_radix(offset, 16).ok()?,
        });
    }
    text.parse().ok()
}

fn link_dir(link: &Path, target: &Path) -> Result<(), BenchError> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "New-Item -ItemType Junction -Path $env:DECOVERY_BENCH_LINK -Target $env:DECOVERY_BENCH_TARGET | Out-Null"])
            .env("DECOVERY_BENCH_LINK", link).env("DECOVERY_BENCH_TARGET", target).output().map_err(|e| io(link, e))?;
        if !output.status.success() {
            return Err(io(
                link,
                std::io::Error::other(String::from_utf8_lossy(&output.stderr).into_owned()),
            ));
        }
    }
    #[cfg(not(windows))]
    std::os::unix::fs::symlink(target, link).map_err(|e| io(link, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn dotted_source_uses_the_redirected_project_even_with_a_stale_local_folder() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join(".source");
        std::fs::create_dir_all(source.join("cache/ghidra")).unwrap();
        let local = root.path().join("local");
        let project = super::project_dir_at(&source, &local).unwrap();
        assert_eq!(project.parent().unwrap(), local.join("decomp/ghidra"));
        assert_ne!(project, source.join("cache/ghidra"));
    }
}
