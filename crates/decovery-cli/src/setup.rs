//! `decovery setup ghidra`: installs Ghidra, a JDK and a pyghidra venv into `extern/` and registers the
//! `ghidra` analyzer plugin in the user config.
//!
//! Every external command (curl, tar, python, pip) goes through [`Runner`] so tests can substitute a fake.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Marker file in the extern dir that records what is installed.
pub const MARKER_FILE: &str = ".decovery-setup.json";

/// One pinned download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub version: &'static str,
    pub file_name: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

/// Everything `setup ghidra` installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pins {
    pub ghidra: Pin,
    pub jdk: Pin,
    /// pyghidra version on PyPI.
    pub pyghidra: &'static str,
}

// Ghidra 12.1.4: asset and SHA-256 from the release page / API
//   https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.1.4_build
const GHIDRA: Pin = Pin {
    version: "12.1.4",
    file_name: "ghidra_12.1.4_PUBLIC_20260921.zip",
    url: "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip",
    sha256: "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
};

// Eclipse Temurin 21.0.13+9 JDK; link and checksum from the Adoptium API
//   https://api.adoptium.net/v3/assets/latest/21/hotspot?os=windows&architecture=x64&image_type=jdk
//   https://api.adoptium.net/v3/assets/latest/21/hotspot?os=linux&architecture=x64&image_type=jdk
const JDK_WINDOWS: Pin = Pin {
    version: "21.0.13+9",
    file_name: "OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip",
    url: "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip",
    sha256: "a4dbaa05fca4bd89d84584e58c459bd732efebb1722af80ab13c6516832004f9",
};
const JDK_LINUX: Pin = Pin {
    version: "21.0.13+9",
    file_name: "OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz",
    url: "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz",
    sha256: "d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c",
};

// Ghidra 12.1.4 bundles pyghidra 3.1.0 (`__version__` in
// Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/__init__.py at tag Ghidra_12.1.4_build);
// release list: https://pypi.org/pypi/pyghidra/json
const PYGHIDRA: &str = "3.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    WindowsX64,
    LinuxX64,
}

impl Platform {
    pub fn current() -> Result<Platform, String> {
        Platform::from_parts(std::env::consts::OS, std::env::consts::ARCH)
    }

    pub fn from_parts(os: &str, arch: &str) -> Result<Platform, String> {
        match (os, arch) {
            ("windows", "x86_64") => Ok(Platform::WindowsX64),
            ("linux", "x86_64") => Ok(Platform::LinuxX64),
            _ => Err(format!(
                "unsupported platform {os}-{arch}; `setup ghidra` supports windows-x64 and linux-x64"
            )),
        }
    }
}

/// The downloads for `platform`.
pub fn plan(platform: Platform) -> Pins {
    Pins {
        ghidra: GHIDRA,
        jdk: match platform {
            Platform::WindowsX64 => JDK_WINDOWS,
            Platform::LinuxX64 => JDK_LINUX,
        },
        pyghidra: PYGHIDRA,
    }
}

#[derive(Debug)]
pub enum SetupError {
    Message(String),
    Checksum {
        file: PathBuf,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetupError::Message(m) => f.write_str(m),
            SetupError::Checksum {
                file,
                expected,
                actual,
            } => write!(
                f,
                "checksum mismatch for {}: expected sha256 {expected}, got {actual}",
                file.display()
            ),
        }
    }
}

impl std::error::Error for SetupError {}

fn fail<T>(message: impl Into<String>) -> Result<T, SetupError> {
    Err(SetupError::Message(message.into()))
}

fn path_str(path: &Path) -> Result<String, SetupError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| SetupError::Message(format!("path {} is not valid UTF-8", path.display())))
}

fn io_err(what: &str, path: &Path, e: std::io::Error) -> SetupError {
    SetupError::Message(format!("{what} {}: {e}", path.display()))
}

/// Runs external commands.
pub trait Runner {
    fn run(&self, program: &OsStr, args: &[OsString]) -> Result<(), String>;
}

/// Runs real processes; their stdout goes to our stderr, stdout stays free for the summary.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &OsStr, args: &[OsString]) -> Result<(), String> {
        let status = std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::from(std::io::stderr()))
            .status()
            .map_err(|e| format!("cannot run {}: {e}", program.to_string_lossy()))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{} failed ({status})", program.to_string_lossy()))
        }
    }
}

pub struct SetupOptions {
    pub extern_dir: PathBuf,
    /// Pre-downloaded Ghidra archive (offline).
    pub ghidra_archive: Option<PathBuf>,
    /// Pre-downloaded JDK archive (offline).
    pub jdk_archive: Option<PathBuf>,
    /// Directory holding `decovery-plugin-sdk` and `ghidra`.
    pub plugins_dir: PathBuf,
    /// Python used to create the venv.
    pub python: String,
    pub config_path: PathBuf,
    pub platform: Platform,
}

#[derive(Debug)]
pub struct SetupReport {
    pub ghidra_dir: PathBuf,
    pub jdk_dir: PathBuf,
    pub venv_python: PathBuf,
    pub config_path: PathBuf,
    pub ghidra_kept: bool,
    pub jdk_kept: bool,
}

/// Installs everything missing and writes the plugin entry.
pub fn run_setup(
    opts: &SetupOptions,
    pins: &Pins,
    runner: &dyn Runner,
    log: &mut dyn FnMut(&str),
) -> Result<SetupReport, SetupError> {
    let extern_dir = &opts.extern_dir;
    std::fs::create_dir_all(extern_dir).map_err(|e| io_err("cannot create", extern_dir, e))?;
    let mut marker = read_marker(extern_dir);

    let (ghidra_dir, ghidra_kept) = install_component(
        "ghidra",
        &pins.ghidra,
        opts.ghidra_archive.as_deref(),
        extern_dir,
        &mut marker,
        runner,
        log,
    )?;
    let (jdk_dir, jdk_kept) = install_component(
        "jdk",
        &pins.jdk,
        opts.jdk_archive.as_deref(),
        extern_dir,
        &mut marker,
        runner,
        log,
    )?;

    let venv = extern_dir.join("ghidra-venv");
    let venv_python = venv_python(&venv, opts.platform);
    let sdk = opts.plugins_dir.join("decovery-plugin-sdk");
    let ghidra_plugin = opts.plugins_dir.join("ghidra");
    let venv_record = json!({
        "python": path_str(&venv_python)?,
        "pyghidra": pins.pyghidra,
        "plugins": [path_str(&sdk)?, path_str(&ghidra_plugin)?],
    });
    if marker["venv"] == venv_record && venv_python.is_file() {
        log("step: venv exists");
    } else {
        // Not recorded: a previous run may have died halfway, so build it again from scratch.
        if let Some(object) = marker.as_object_mut() {
            object.remove("venv");
        }
        write_marker(extern_dir, &marker)?;
        log(&format!("step: creating venv {}", venv.display()));
        run(
            runner,
            OsStr::new(&opts.python),
            &[
                "-m".into(),
                "venv".into(),
                "--clear".into(),
                venv.clone().into_os_string(),
            ],
        )?;
        if !venv_python.is_file() {
            return fail(format!(
                "venv created but {} is missing",
                venv_python.display()
            ));
        }
    }

    for dir in [&sdk, &ghidra_plugin] {
        if !dir.is_dir() {
            return fail(format!(
                "plugin directory {} not found; pass --plugins-dir",
                dir.display()
            ));
        }
    }
    log(&format!(
        "step: pip install pyghidra=={} and the local plugins",
        pins.pyghidra
    ));
    let mut with_extra = ghidra_plugin.into_os_string();
    with_extra.push("[ghidra]");
    run(
        runner,
        venv_python.as_os_str(),
        &[
            "-m".into(),
            "pip".into(),
            "install".into(),
            format!("pyghidra=={}", pins.pyghidra).into(),
            sdk.into_os_string(),
            with_extra,
        ],
    )?;
    marker["pyghidra"] = json!(pins.pyghidra);
    marker["venv"] = venv_record;
    write_marker(extern_dir, &marker)?;

    log(&format!(
        "step: writing [plugins.ghidra] to {}",
        opts.config_path.display()
    ));
    let command = vec![
        path_str(&venv_python)?,
        "-m".into(),
        "decovery_ghidra".into(),
    ];
    let env = BTreeMap::from([
        ("GHIDRA_INSTALL_DIR".to_string(), path_str(&ghidra_dir)?),
        ("JAVA_HOME".to_string(), path_str(&jdk_dir)?),
    ]);
    write_plugin_entry(&opts.config_path, "ghidra", &command, &env)?;

    Ok(SetupReport {
        ghidra_dir,
        jdk_dir,
        venv_python,
        config_path: opts.config_path.clone(),
        ghidra_kept,
        jdk_kept,
    })
}

/// unicorn version on PyPI.
pub const UNICORN: &str = "2.1.1";

pub struct UnicornOptions {
    pub extern_dir: PathBuf,
    /// Directory holding `decovery-plugin-sdk` and `unicorn-dos`.
    pub plugins_dir: PathBuf,
    /// Python (>= 3.12) used to create the venv.
    pub python: String,
    pub config_path: PathBuf,
    pub platform: Platform,
}

#[derive(Debug)]
pub struct UnicornReport {
    pub venv_python: PathBuf,
    pub config_path: PathBuf,
    pub venv_kept: bool,
}

/// Creates `<extern>/unicorn-venv`, installs the SDK, the `unicorn-dos` plugin and the pinned unicorn, and
/// registers `[plugins.unicorn-dos]`. A venv in which the plugin already imports is kept as it is.
pub fn run_unicorn_setup(
    opts: &UnicornOptions,
    runner: &dyn Runner,
    log: &mut dyn FnMut(&str),
) -> Result<UnicornReport, SetupError> {
    let sdk = opts.plugins_dir.join("decovery-plugin-sdk");
    let plugin = opts.plugins_dir.join("unicorn-dos");
    for dir in [&sdk, &plugin] {
        if !dir.is_dir() {
            return fail(format!(
                "plugin directory {} not found; pass --plugins-dir",
                dir.display()
            ));
        }
    }
    std::fs::create_dir_all(&opts.extern_dir)
        .map_err(|e| io_err("cannot create", &opts.extern_dir, e))?;
    let venv = opts.extern_dir.join("unicorn-venv");
    let venv_python = venv_python(&venv, opts.platform);

    let kept = venv_python.is_file()
        && runner
            .run(
                venv_python.as_os_str(),
                &["-c".into(), "import decovery_unicorn_dos".into()],
            )
            .is_ok();
    if kept {
        log("step: venv exists and the plugin imports");
    } else {
        run(
            runner,
            OsStr::new(&opts.python),
            &[
                "-c".into(),
                "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)".into(),
            ],
        )
        .map_err(|_| {
            SetupError::Message(format!(
                "{} is not Python 3.12 or newer; pass --python or set DECOVERY_PYTHON",
                opts.python
            ))
        })?;
        log(&format!("step: creating venv {}", venv.display()));
        run(
            runner,
            OsStr::new(&opts.python),
            &[
                "-m".into(),
                "venv".into(),
                "--clear".into(),
                venv.clone().into_os_string(),
            ],
        )?;
        if !venv_python.is_file() {
            return fail(format!(
                "venv created but {} is missing",
                venv_python.display()
            ));
        }
        log(&format!(
            "step: pip install unicorn=={UNICORN} and the local plugins"
        ));
        run(
            runner,
            venv_python.as_os_str(),
            &[
                "-m".into(),
                "pip".into(),
                "install".into(),
                format!("unicorn=={UNICORN}").into(),
                sdk.into_os_string(),
                plugin.into_os_string(),
            ],
        )?;
    }

    log(&format!(
        "step: writing [plugins.unicorn-dos] to {}",
        opts.config_path.display()
    ));
    let command = vec![
        path_str(&venv_python)?,
        "-m".into(),
        "decovery_unicorn_dos".into(),
    ];
    write_plugin_entry(&opts.config_path, "unicorn-dos", &command, &BTreeMap::new())?;
    Ok(UnicornReport {
        venv_python,
        config_path: opts.config_path.clone(),
        venv_kept: kept,
    })
}

fn run(runner: &dyn Runner, program: &OsStr, args: &[OsString]) -> Result<(), SetupError> {
    runner.run(program, args).map_err(SetupError::Message)
}

/// Download (or take the given archive), verify, unpack. Returns the install dir and whether it was kept.
fn install_component(
    key: &str,
    pin: &Pin,
    archive: Option<&Path>,
    extern_dir: &Path,
    marker: &mut Value,
    runner: &dyn Runner,
    log: &mut dyn FnMut(&str),
) -> Result<(PathBuf, bool), SetupError> {
    let entry = &marker[key];
    if entry["version"] == pin.version
        && entry["sha256"] == pin.sha256
        && let Some(rel) = entry["dir"].as_str()
    {
        let dir = rel
            .split('/')
            .fold(extern_dir.to_path_buf(), |p, c| p.join(c));
        if dir.is_dir() {
            log(&format!("step: {key} {} already installed", pin.version));
            return Ok((dir, true));
        }
    }

    let (file, actual, downloaded) = match archive {
        Some(path) => {
            log(&format!("step: verifying {}", path.display()));
            (path.to_path_buf(), sha256_file(path)?, false)
        }
        None => {
            let downloads = extern_dir.join("downloads");
            std::fs::create_dir_all(&downloads)
                .map_err(|e| io_err("cannot create", &downloads, e))?;
            let file = downloads.join(pin.file_name);
            let cached = if file.is_file() {
                Some(sha256_file(&file)?).filter(|h| h == pin.sha256)
            } else {
                None
            };
            match cached {
                Some(hash) => {
                    log(&format!("step: {key} archive already downloaded"));
                    (file, hash, false)
                }
                None => {
                    log(&format!("step: downloading {}", pin.url));
                    run(
                        runner,
                        OsStr::new("curl"),
                        &[
                            "-fL".into(),
                            "--retry".into(),
                            "3".into(),
                            "-o".into(),
                            file.clone().into_os_string(),
                            pin.url.into(),
                        ],
                    )?;
                    log(&format!("step: verifying {}", file.display()));
                    let hash = sha256_file(&file)?;
                    (file, hash, true)
                }
            }
        }
    };
    if actual != pin.sha256 {
        if downloaded {
            let _ = std::fs::remove_file(&file);
        }
        return Err(SetupError::Checksum {
            file,
            expected: pin.sha256.to_string(),
            actual,
        });
    }

    let target = extern_dir.join(key);
    let partial = extern_dir.join(format!("{key}.partial"));
    remove_dir(&partial)?;
    std::fs::create_dir_all(&partial).map_err(|e| io_err("cannot create", &partial, e))?;
    log(&format!("step: unpacking into {}", target.display()));
    run(
        runner,
        OsStr::new("tar"),
        &[
            "-xf".into(),
            file.into_os_string(),
            "-C".into(),
            partial.clone().into_os_string(),
        ],
    )?;
    let top = sole_subdir(&partial)?;
    remove_dir(&target)?;
    std::fs::rename(&partial, &target).map_err(|e| io_err("cannot rename", &partial, e))?;
    let name = top.file_name().unwrap_or_default().to_owned();
    let dir = target.join(&name);
    marker[key] = json!({
        "version": pin.version,
        "sha256": pin.sha256,
        "dir": format!("{key}/{}", path_str(Path::new(&name))?),
    });
    write_marker(extern_dir, marker)?;
    Ok((dir, false))
}

fn remove_dir(dir: &Path) -> Result<(), SetupError> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("cannot remove", dir, e)),
    }
}

/// The only directory inside `dir` (archives unpack into one top-level folder).
fn sole_subdir(dir: &Path) -> Result<PathBuf, SetupError> {
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io_err("cannot read", dir, e))? {
        let path = entry.map_err(|e| io_err("cannot read", dir, e))?.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }
    if dirs.len() == 1 {
        Ok(dirs.remove(0))
    } else {
        fail(format!(
            "expected one top-level folder in the unpacked archive, found {} in {}",
            dirs.len(),
            dir.display()
        ))
    }
}

pub fn venv_python(venv: &Path, platform: Platform) -> PathBuf {
    match platform {
        Platform::WindowsX64 => venv.join("Scripts").join("python.exe"),
        Platform::LinuxX64 => venv.join("bin").join("python"),
    }
}

fn read_marker(extern_dir: &Path) -> Value {
    std::fs::read_to_string(extern_dir.join(MARKER_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn write_marker(extern_dir: &Path, marker: &Value) -> Result<(), SetupError> {
    let mut marker = marker.clone();
    marker["schema"] = json!(1);
    let mut text =
        serde_json::to_string_pretty(&marker).map_err(|e| SetupError::Message(e.to_string()))?;
    text.push('\n');
    write_atomic(&extern_dir.join(MARKER_FILE), &text)
}

fn write_atomic(path: &Path, text: &str) -> Result<(), SetupError> {
    decovery_core::write_atomic(path, text.as_bytes()).map_err(|e| io_err("cannot write", path, e))
}

/// Sets `[plugins.<name>]` in the user config, keeping everything else.
pub fn write_plugin_entry(
    path: &Path,
    name: &str,
    command: &[String],
    env: &BTreeMap<String, String>,
) -> Result<(), SetupError> {
    let mut root = read_user_table(path)?;
    let plugins = root
        .entry("plugins")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| {
            SetupError::Message(format!("`plugins` in {} is not a table", path.display()))
        })?;
    let mut entry = toml::Table::new();
    entry.insert(
        "command".into(),
        toml::Value::Array(command.iter().cloned().map(toml::Value::String).collect()),
    );
    entry.insert(
        "env".into(),
        toml::Value::Table(
            env.iter()
                .map(|(k, v)| (k.clone(), toml::Value::String(v.clone())))
                .collect(),
        ),
    );
    plugins.insert(name.into(), toml::Value::Table(entry));
    let body = toml::to_string(&root).map_err(|e| SetupError::Message(e.to_string()))?;
    write_atomic(path, &format!("schema = 1\n\n{body}"))
}

/// Sets `[toolchains] "<profile>" = "<dir>"` in the user config, keeping everything else.
pub fn write_toolchain_entry(path: &Path, profile: &str, dir: &Path) -> Result<(), SetupError> {
    let mut root = read_user_table(path)?;
    let toolchains = root
        .entry("toolchains")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| {
            SetupError::Message(format!("`toolchains` in {} is not a table", path.display()))
        })?;
    toolchains.insert(profile.into(), toml::Value::String(path_str(dir)?));
    let body = toml::to_string(&root).map_err(|e| SetupError::Message(e.to_string()))?;
    write_atomic(
        path,
        &format!(
            "schema = 1

{body}"
        ),
    )
}

/// The user config as a table without its `schema` key; empty when the file does not exist.
fn read_user_table(path: &Path) -> Result<toml::Table, SetupError> {
    let mut root: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => text
            .parse()
            .map_err(|e| SetupError::Message(format!("cannot parse {}: {e}", path.display())))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(io_err("cannot read", path, e)),
    };
    if let Some(schema) = root.remove("schema")
        && schema.as_integer() != Some(1)
    {
        return fail(format!(
            "{} has unsupported schema {schema}",
            path.display()
        ));
    }
    Ok(root)
}

/// Default install dir: `extern/` next to the repository containing `start`, if that exists, else
/// `extern/` beside the user config file.
pub fn default_extern_dir(start: &Path, config_path: &Path) -> PathBuf {
    for dir in start.ancestors() {
        if dir.join(".git").exists() {
            if let Some(sibling) = dir
                .parent()
                .map(|p| p.join("extern"))
                .filter(|p| p.is_dir())
            {
                return sibling;
            }
            break;
        }
    }
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("extern")
}

/// `<repo>/plugins` of the decovery repository containing `start`.
pub fn find_plugins_dir(start: &Path) -> Result<PathBuf, String> {
    for dir in start.ancestors() {
        let plugins = dir.join("plugins");
        if ["decovery-plugin-sdk", "ghidra", "unicorn-dos"]
            .iter()
            .all(|name| plugins.join(name).is_dir())
        {
            return Ok(plugins);
        }
    }
    Err("not inside the decovery repository; pass --plugins-dir <dir> (holding decovery-plugin-sdk, ghidra and unicorn-dos)".into())
}

fn sha256_file(path: &Path) -> Result<String, SetupError> {
    let mut file = std::fs::File::open(path).map_err(|e| io_err("cannot open", path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| io_err("cannot read", path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use decovery_facade::plugins::read_plugins_file;
    use std::cell::RefCell;
    use std::path::Path;

    const TEST_PLATFORM: Platform = Platform::LinuxX64;
    const GHIDRA_BYTES: &[u8] = b"ghidra-archive";
    const JDK_BYTES: &[u8] = b"jdk-archive";

    fn test_pins() -> Pins {
        Pins {
            ghidra: Pin {
                version: "1.2.3",
                file_name: "ghidra_1.2.3.zip",
                url: "https://example.invalid/ghidra_1.2.3.zip",
                sha256: Box::leak(sha256_hex(GHIDRA_BYTES).into_boxed_str()),
            },
            jdk: Pin {
                version: "21.0.1",
                file_name: "jdk.zip",
                url: "https://example.invalid/jdk.zip",
                sha256: Box::leak(sha256_hex(JDK_BYTES).into_boxed_str()),
            },
            pyghidra: "9.9.9",
        }
    }

    /// Records every command; `tar` creates `<dest>/top`, `venv` creates the venv python, `curl` writes
    /// the archive.
    #[derive(Default)]
    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        /// `curl` writes wrong bytes.
        bad_download: bool,
        /// pip fails.
        pip_fails: bool,
        /// `import decovery_unicorn_dos` fails.
        import_fails: bool,
        /// The Python version check fails.
        old_python: bool,
    }

    impl FakeRunner {
        fn programs(&self) -> Vec<String> {
            self.calls.borrow().iter().map(|c| c[0].clone()).collect()
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &OsStr, args: &[OsString]) -> Result<(), String> {
            let mut call = vec![program.to_string_lossy().into_owned()];
            call.extend(args.iter().map(|a| a.to_string_lossy().into_owned()));
            self.calls.borrow_mut().push(call);
            match program.to_string_lossy().as_ref() {
                "curl" => {
                    let out = Path::new(&args[args.len() - 2]);
                    let bytes = if self.bad_download {
                        &b"corrupt"[..]
                    } else if args[args.len() - 1].to_string_lossy().contains("ghidra") {
                        GHIDRA_BYTES
                    } else {
                        JDK_BYTES
                    };
                    std::fs::write(out, bytes).map_err(|e| e.to_string())
                }
                "tar" => {
                    let dest = Path::new(&args[3]);
                    std::fs::create_dir_all(dest.join("top")).map_err(|e| e.to_string())
                }
                _ if args.first().is_some_and(|a| a == "-c") => {
                    let code = args[1].to_string_lossy();
                    if (self.import_fails && code.starts_with("import decovery"))
                        || (self.old_python && code.contains("version_info"))
                    {
                        Err("failed".into())
                    } else {
                        Ok(())
                    }
                }
                _ if args.len() >= 3 && args[1] == "venv" => {
                    let python = venv_python(Path::new(&args[args.len() - 1]), TEST_PLATFORM);
                    std::fs::create_dir_all(python.parent().unwrap()).map_err(|e| e.to_string())?;
                    std::fs::write(python, b"").map_err(|e| e.to_string())
                }
                _ if self.pip_fails && args.contains(&OsString::from("pip")) => {
                    Err("pip failed".into())
                }
                _ => Ok(()),
            }
        }
    }

    fn options(root: &Path) -> SetupOptions {
        let plugins = root.join("plugins");
        std::fs::create_dir_all(plugins.join("decovery-plugin-sdk")).unwrap();
        std::fs::create_dir_all(plugins.join("ghidra")).unwrap();
        SetupOptions {
            extern_dir: root.join("extern dir"),
            ghidra_archive: None,
            jdk_archive: None,
            plugins_dir: plugins,
            python: "py".into(),
            config_path: root.join("cfg").join("config.toml"),
            platform: TEST_PLATFORM,
        }
    }

    #[test]
    fn plan_lists_downloads_for_platform() {
        let win = plan(Platform::WindowsX64);
        assert!(win.ghidra.url.contains("12.1.4"));
        assert!(win.ghidra.file_name.ends_with(".zip"));
        assert!(win.jdk.file_name.contains("windows"));
        assert!(win.jdk.file_name.ends_with(".zip"));
        let linux = plan(Platform::LinuxX64);
        assert_eq!(linux.ghidra.sha256, win.ghidra.sha256);
        assert!(linux.jdk.file_name.contains("linux"));
        assert!(linux.jdk.file_name.ends_with(".tar.gz"));
        for pin in [&win.ghidra, &win.jdk, &linux.jdk] {
            assert_eq!(pin.sha256.len(), 64);
            assert!(pin.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(pin.url.starts_with("https://"));
        }
        assert_eq!(win.pyghidra, "3.1.0");
        let err = Platform::from_parts("macos", "aarch64").unwrap_err();
        assert!(err.contains("unsupported platform"), "{err}");
    }

    #[test]
    fn checksum_helper_returns_known_sha256() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(sha256_file(&file).unwrap(), sha256_hex(b"abc"));
    }

    #[test]
    fn checksum_mismatch_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        let bad = dir.path().join("bad.zip");
        std::fs::write(&bad, b"something else").unwrap();
        opts.ghidra_archive = Some(bad);
        let runner = FakeRunner::default();
        let err = run_setup(&opts, &test_pins(), &runner, &mut |_| {}).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("checksum mismatch"), "{text}");
        assert!(text.contains(&sha256_hex(GHIDRA_BYTES)), "{text}");
        assert!(runner.calls.borrow().is_empty());
        assert!(!opts.config_path.exists());
    }

    #[test]
    fn existing_install_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        let first = FakeRunner::default();
        let report = run_setup(&opts, &test_pins(), &first, &mut |_| {}).unwrap();
        assert!(!report.ghidra_kept && !report.jdk_kept);
        assert_eq!(first.programs().iter().filter(|p| *p == "curl").count(), 2);
        assert_eq!(first.programs().iter().filter(|p| *p == "tar").count(), 2);
        assert!(report.ghidra_dir.ends_with("top"));
        assert!(report.ghidra_dir.is_dir());

        let second = FakeRunner::default();
        let report = run_setup(&opts, &test_pins(), &second, &mut |_| {}).unwrap();
        assert!(report.ghidra_kept && report.jdk_kept);
        let programs = second.programs();
        assert!(!programs.contains(&"curl".to_string()));
        assert!(!programs.contains(&"tar".to_string()));

        // A changed pin (new version) is installed again.
        let mut newer = test_pins();
        newer.ghidra.version = "1.2.4";
        let third = FakeRunner::default();
        let report = run_setup(&opts, &newer, &third, &mut |_| {}).unwrap();
        assert!(!report.ghidra_kept && report.jdk_kept);
    }

    #[test]
    fn user_config_gets_plugin_entry() {
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        std::fs::create_dir_all(opts.config_path.parent().unwrap()).unwrap();
        std::fs::write(
            &opts.config_path,
            "schema = 1\n\n[plugins.other]\ncommand = [\"o\", \"x y\"]\n\n[plugins.other.env]\nA = \"1\"\n",
        )
        .unwrap();
        let runner = FakeRunner::default();
        let report = run_setup(&opts, &test_pins(), &runner, &mut |_| {}).unwrap();
        let plugins = read_plugins_file(&opts.config_path).unwrap();
        assert_eq!(plugins["other"].command, ["o", "x y"]);
        assert_eq!(plugins["other"].env["A"], "1");
        let ghidra = &plugins["ghidra"];
        assert_eq!(ghidra.command.len(), 3);
        assert_eq!(ghidra.command[0], report.venv_python.to_string_lossy());
        assert_eq!(ghidra.command[1..], ["-m", "decovery_ghidra"]);
        assert_eq!(
            ghidra.env["GHIDRA_INSTALL_DIR"],
            report.ghidra_dir.to_string_lossy()
        );
        assert_eq!(ghidra.env["JAVA_HOME"], report.jdk_dir.to_string_lossy());
        let text = std::fs::read_to_string(&opts.config_path).unwrap();
        assert!(text.starts_with("schema = 1\n"), "{text}");
        assert!(!text.contains('\r'));
        assert!(!opts.config_path.with_extension("toml.tmp").exists());

        // Idempotent: unchanged inputs give identical bytes.
        run_setup(&opts, &test_pins(), &FakeRunner::default(), &mut |_| {}).unwrap();
        assert_eq!(std::fs::read_to_string(&opts.config_path).unwrap(), text);
    }

    #[test]
    fn pip_installs_pinned_pyghidra_and_local_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        let runner = FakeRunner::default();
        run_setup(&opts, &test_pins(), &runner, &mut |_| {}).unwrap();
        let calls = runner.calls.borrow();
        let pip = calls
            .iter()
            .find(|c| c.contains(&"pip".to_string()))
            .unwrap();
        assert!(pip.contains(&"pyghidra==9.9.9".to_string()));
        assert!(pip.iter().any(|a| a.ends_with("decovery-plugin-sdk")));
        assert!(pip.iter().any(|a| a.ends_with("ghidra[ghidra]")));
    }

    #[test]
    fn default_extern_prefers_sibling_of_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        let cfg = dir.path().join("cfg").join("decovery").join("config.toml");
        let fallback = dir.path().join("cfg").join("decovery").join("extern");
        assert_eq!(default_extern_dir(&repo.join("sub"), &cfg), fallback);
        std::fs::create_dir_all(dir.path().join("extern")).unwrap();
        assert_eq!(
            default_extern_dir(&repo.join("sub"), &cfg),
            dir.path().join("extern")
        );
    }

    #[test]
    fn plugins_dir_is_found_in_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join("plugins/decovery-plugin-sdk")).unwrap();
        std::fs::create_dir_all(repo.join("plugins/ghidra")).unwrap();
        std::fs::create_dir_all(repo.join("plugins/unicorn-dos")).unwrap();
        std::fs::create_dir_all(repo.join("a/b")).unwrap();
        assert_eq!(
            find_plugins_dir(&repo.join("a/b")).unwrap(),
            repo.join("plugins")
        );
        assert!(
            find_plugins_dir(dir.path())
                .unwrap_err()
                .contains("--plugins-dir")
        );
    }

    #[test]
    fn partial_venv_is_recreated() {
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        let failing = FakeRunner {
            pip_fails: true,
            ..Default::default()
        };
        assert!(run_setup(&opts, &test_pins(), &failing, &mut |_| {}).is_err());
        // The venv python exists, but the venv was never recorded.
        assert!(venv_python(&opts.extern_dir.join("ghidra-venv"), TEST_PLATFORM).is_file());
        let runner = FakeRunner::default();
        run_setup(&opts, &test_pins(), &runner, &mut |_| {}).unwrap();
        let calls = runner.calls.borrow();
        let venv = calls
            .iter()
            .find(|c| c.contains(&"venv".to_string()))
            .unwrap();
        assert!(venv.contains(&"--clear".to_string()));
        // Recorded now: a third run keeps the venv.
        let third = FakeRunner::default();
        run_setup(&opts, &test_pins(), &third, &mut |_| {}).unwrap();
        assert!(
            !third
                .calls
                .borrow()
                .iter()
                .any(|c| c.contains(&"venv".to_string()))
        );
    }

    #[test]
    fn downloaded_archive_with_wrong_checksum_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        let runner = FakeRunner {
            bad_download: true,
            ..Default::default()
        };
        let err = run_setup(&opts, &test_pins(), &runner, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
        let file = opts.extern_dir.join("downloads").join("ghidra_1.2.3.zip");
        assert!(!file.exists());
    }

    fn unicorn_options(root: &Path) -> UnicornOptions {
        let plugins = root.join("plugins");
        std::fs::create_dir_all(plugins.join("decovery-plugin-sdk")).unwrap();
        std::fs::create_dir_all(plugins.join("unicorn-dos")).unwrap();
        UnicornOptions {
            extern_dir: root.join("extern dir"),
            plugins_dir: plugins,
            python: "py".into(),
            config_path: root.join("cfg").join("config.toml"),
            platform: TEST_PLATFORM,
        }
    }

    #[test]
    fn unicorn_plan_lists_venv_and_pip_steps() {
        let dir = tempfile::tempdir().unwrap();
        let opts = unicorn_options(dir.path());
        let runner = FakeRunner::default();
        let mut steps = Vec::new();
        let report = run_unicorn_setup(&opts, &runner, &mut |l| steps.push(l.to_string())).unwrap();
        assert!(!report.venv_kept);
        assert!(steps.iter().any(|s| s.contains("creating venv")));
        let calls = runner.calls.borrow();
        let venv = calls
            .iter()
            .find(|c| c.contains(&"venv".to_string()))
            .unwrap();
        assert!(venv.last().unwrap().ends_with("unicorn-venv"));
        let pip = calls
            .iter()
            .find(|c| c.contains(&"pip".to_string()))
            .unwrap();
        assert!(pip.contains(&"unicorn==2.1.1".to_string()));
        assert!(pip.iter().any(|a| a.ends_with("decovery-plugin-sdk")));
        assert!(pip.iter().any(|a| a.ends_with("unicorn-dos")));
    }

    #[test]
    fn existing_unicorn_venv_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let opts = unicorn_options(dir.path());
        run_unicorn_setup(&opts, &FakeRunner::default(), &mut |_| {}).unwrap();
        let second = FakeRunner::default();
        let report = run_unicorn_setup(&opts, &second, &mut |_| {}).unwrap();
        assert!(report.venv_kept);
        let calls = second.calls.borrow();
        assert!(!calls.iter().any(|c| c.contains(&"venv".to_string())));
        assert!(!calls.iter().any(|c| c.contains(&"pip".to_string())));

        // A venv without the importable plugin is rebuilt.
        let broken = FakeRunner {
            import_fails: true,
            ..Default::default()
        };
        let report = run_unicorn_setup(&opts, &broken, &mut |_| {}).unwrap();
        assert!(!report.venv_kept);
        assert!(
            broken
                .calls
                .borrow()
                .iter()
                .any(|c| c.contains(&"pip".to_string()))
        );
    }

    #[test]
    fn old_python_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let opts = unicorn_options(dir.path());
        let runner = FakeRunner {
            old_python: true,
            ..Default::default()
        };
        let err = run_unicorn_setup(&opts, &runner, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("3.12"), "{err}");
        assert!(!opts.config_path.exists());
    }

    #[test]
    fn user_config_gets_unicorn_entry() {
        let dir = tempfile::tempdir().unwrap();
        let opts = unicorn_options(dir.path());
        std::fs::create_dir_all(opts.config_path.parent().unwrap()).unwrap();
        std::fs::write(
            &opts.config_path,
            "schema = 1\n\n[plugins.other]\ncommand = [\"o\"]\n",
        )
        .unwrap();
        let report = run_unicorn_setup(&opts, &FakeRunner::default(), &mut |_| {}).unwrap();
        let plugins = read_plugins_file(&opts.config_path).unwrap();
        assert_eq!(plugins["other"].command, ["o"]);
        let entry = &plugins["unicorn-dos"];
        assert_eq!(entry.command[0], report.venv_python.to_string_lossy());
        assert_eq!(entry.command[1..], ["-m", "decovery_unicorn_dos"]);
        assert!(entry.env.is_empty());
    }
}
