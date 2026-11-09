//! The embedded compiler profiles (`profiles/*.toml`) and the command lines they render.

use std::path::{Path, PathBuf};

use decovery_core::{RebuildConfig, UserConfig, Workspace};
use decovery_diff::Decoration;
use serde::Deserialize;

use crate::ToolchainError;

const EMBEDDED: [(&str, &str); 3] = [
    (
        "watcom-9.5",
        include_str!("../../../profiles/watcom-9.5.toml"),
    ),
    (
        "watcom-10.6",
        include_str!("../../../profiles/watcom-10.6.toml"),
    ),
    (
        "turbo-c-2.0",
        include_str!("../../../profiles/turbo-c-2.0.toml"),
    ),
];

/// Format of the objects a compiler writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ObjectFormat {
    Omf,
}

/// The linker of a profile.
///
/// `command` placeholders: `{response}` (the response file name without extension, rendered as the output
/// name), `{flags}`, `{library_dir}`, `{startup}`, `{objects}`, `{output}`, `{libraries}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct LinkerSpec {
    pub command: String,
    pub library_dir: String,
    /// Pattern of the linked file name, e.g. `{name}.EXE`.
    pub output: String,
    /// Whether the linker accepts `option start=` when linking an LE program (WLINK 9.5 refuses it for DOS/4G;
    /// the entry point then goes into the module end record).
    #[serde(default = "accepts_start_option")]
    pub start_option: bool,
    /// Startup object (name without extension, in `library_dir`) linked when `[rebuild.link] startup` is not
    /// set; `None` when the toolchain has no separate startup object.
    #[serde(default)]
    pub startup: Option<String>,
    /// The map file the linker can write; `None` when decovery does not read this linker's map.
    #[serde(default)]
    pub map: Option<MapSpec>,
}

/// How a linker writes a map file with its public symbols.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct MapSpec {
    /// Layout of the map file.
    pub format: MapFormat,
    /// Pattern of the map file name, e.g. `{name}.MAP`.
    pub file: String,
    /// Option that makes the linker list the public symbols (added to the link flags when missing).
    pub flag: String,
    /// Options that suppress the map (removed from the link flags).
    #[serde(default)]
    pub suppress: Vec<String>,
}

/// Layout of a linker map file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MapFormat {
    /// Borland TLINK: segment list, then publics as `SSSS:OOOO name` relative to the load segment.
    Tlink,
}

impl MapSpec {
    /// `flags` with the suppressing options removed and `flag` added when missing. Options start with `/` or `-`
    /// and may be written together (`/c/x/i`); they compare case-insensitively and with either switch character.
    pub fn flags(&self, flags: &str) -> String {
        fn same(a: &str, b: &str) -> bool {
            !a.is_empty()
                && a.trim_start_matches(['/', '-'])
                    .eq_ignore_ascii_case(b.trim_start_matches(['/', '-']))
        }
        let mut has_flag = false;
        let mut words: Vec<String> = Vec::new();
        for word in flags.split_whitespace() {
            let mut kept = String::new();
            let mut start = 0;
            let bytes = word.as_bytes();
            for i in 1..=bytes.len() {
                if i == bytes.len() || bytes[i] == b'/' || bytes[i] == b'-' {
                    let option = &word[start..i];
                    if !self.suppress.iter().any(|s| same(option, s)) {
                        has_flag |= same(option, &self.flag);
                        kept.push_str(option);
                    }
                    start = i;
                }
            }
            if !kept.is_empty() {
                words.push(kept);
            }
        }
        if !has_flag && !self.flag.is_empty() {
            // written onto the last options when they use the same switch character: the line stays as long
            match words.last_mut() {
                Some(last) if last.chars().next() == self.flag.chars().next() => {
                    last.push_str(&self.flag)
                }
                _ => words.push(self.flag.clone()),
            }
        }
        words.join(" ")
    }
}

fn accepts_start_option() -> bool {
    true
}

/// The assembler: another profile's assembler or an own command (`{output}`, `{input}`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AssemblerSpec {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

/// One compiler: how to run it and what its objects look like.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Profile {
    pub id: String,
    pub family: String,
    pub language: String,
    pub version: String,
    pub bits: u8,
    pub object_format: ObjectFormat,
    pub object_extension: String,
    /// Runner ids in order of preference.
    pub runners: Vec<String>,
    /// Compile command with `{flags}` and `{input}`.
    pub command: String,
    /// DOS commands run before the compiler.
    pub prelude: Vec<String>,
    pub decoration: Decoration,
    /// Bytes every function starts with; empty when the compiler has no fixed prologue.
    pub prologue: Vec<u8>,
    /// Whether the compiler pads functions to an alignment.
    pub padding: bool,
    /// Files (relative to the tool directory) whose presence identifies the compiler.
    pub fingerprint: Vec<String>,
    pub linker: Option<LinkerSpec>,
    pub assembler: Option<AssemblerSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDecoration {
    function: String,
    data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    schema: u32,
    id: String,
    family: String,
    language: String,
    version: String,
    bits: u8,
    object_format: ObjectFormat,
    object_extension: String,
    runners: Vec<String>,
    command: String,
    #[serde(default)]
    prelude: Vec<String>,
    decoration: RawDecoration,
    #[serde(default)]
    prologue: Vec<u8>,
    #[serde(default)]
    padding: bool,
    #[serde(default)]
    fingerprint: Vec<String>,
    #[serde(default)]
    linker: Option<LinkerSpec>,
    #[serde(default)]
    assembler: Option<AssemblerSpec>,
}

fn parse(text: &str) -> Result<Profile, ToolchainError> {
    let raw: RawProfile =
        toml::from_str(text).map_err(|e| ToolchainError::Invalid(e.to_string()))?;
    if raw.schema != decovery_core::workspace::SCHEMA {
        return Err(ToolchainError::Invalid(format!(
            "profile {}: unsupported schema {}",
            raw.id, raw.schema
        )));
    }
    Ok(Profile {
        id: raw.id,
        family: raw.family,
        language: raw.language,
        version: raw.version,
        bits: raw.bits,
        object_format: raw.object_format,
        object_extension: raw.object_extension,
        runners: raw.runners,
        command: raw.command,
        prelude: raw.prelude,
        decoration: Decoration::new(raw.decoration.function, raw.decoration.data),
        prologue: raw.prologue,
        padding: raw.padding,
        fingerprint: raw.fingerprint,
        linker: raw.linker,
        assembler: raw.assembler,
    })
}

/// The embedded profile `id`.
pub fn profile(id: &str) -> Result<Profile, ToolchainError> {
    let (_, text) = EMBEDDED
        .iter()
        .find(|(name, _)| *name == id)
        .ok_or_else(|| ToolchainError::UnknownProfile(id.to_string()))?;
    parse(text)
}

/// All embedded profiles.
pub fn profiles() -> Vec<Profile> {
    EMBEDDED.iter().filter_map(|(_, t)| parse(t).ok()).collect()
}

fn collapse(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Profile {
    /// The compile command with whitespace collapsed.
    pub fn compile_line(&self, flags: &str, input: &str) -> String {
        collapse(
            &self
                .command
                .replace("{flags}", flags)
                .replace("{input}", input),
        )
    }

    /// The object file a source compiles to: `MAIN.C` becomes `MAIN.OBJ`.
    pub fn object_name(&self, source: &str) -> String {
        let stem = source.rsplit_once('.').map_or(source, |(stem, _)| stem);
        format!("{stem}.{}", self.object_extension)
    }

    /// The link command. `{response}` is rendered as `output`; the Watcom profiles take startup and libraries
    /// from the response file instead.
    pub fn link_line(
        &self,
        flags: &str,
        startup: &str,
        objects: &[String],
        output: &str,
        libraries: &[String],
    ) -> Result<String, ToolchainError> {
        let linker = self
            .linker
            .as_ref()
            .ok_or_else(|| ToolchainError::Invalid(format!("profile {} has no linker", self.id)))?;
        let libraries = libraries
            .iter()
            .map(|name| format!("{}\\{name}", linker.library_dir))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(collapse(
            &linker
                .command
                .replace("{response}", output)
                .replace("{flags}", flags)
                .replace("{library_dir}", &linker.library_dir)
                .replace("{startup}", startup)
                .replace("{objects}", &objects.join(" "))
                .replace("{output}", output)
                .replace("{libraries}", &libraries),
        ))
    }
}

/// The directory that holds the compiler of `profile`: the workspace's `[rebuild] tool_dir` (relative to `root`),
/// else the user config's `[toolchains]` entry.
pub fn tool_dir(
    profile: &Profile,
    rebuild: Option<&RebuildConfig>,
    user: &UserConfig,
    root: &Path,
) -> Result<PathBuf, ToolchainError> {
    let path =
        match rebuild.and_then(|r| r.tool_dir.as_deref()) {
            Some(dir) => root.join(dir),
            None => user.toolchains.get(&profile.id).cloned().ok_or_else(|| {
                ToolchainError::NoToolDir {
                    profile: profile.id.clone(),
                }
            })?,
        };
    if path.is_dir() {
        Ok(path)
    } else {
        Err(ToolchainError::ToolDirMissing {
            profile: profile.id.clone(),
            path,
        })
    }
}

/// The profile named by `[rebuild] compiler` and the compiler flags (empty when unset).
pub fn rebuild_profile(ws: &Workspace) -> Result<(Profile, String), ToolchainError> {
    let rebuild = ws
        .config
        .rebuild
        .as_ref()
        .ok_or(ToolchainError::NoRebuildConfig)?;
    let id = rebuild
        .compiler
        .as_deref()
        .ok_or(ToolchainError::NoRebuildConfig)?;
    Ok((profile(id)?, rebuild.flags.clone().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn map_flags_replace_the_suppressing_option() {
        let map = profile("turbo-c-2.0").unwrap().linker.unwrap().map.unwrap();
        assert_eq!(map.flags("/c/x/i"), "/c/i/m");
        assert_eq!(map.flags("/c /X /i"), "/c /i/m");
        assert_eq!(map.flags("/x"), "/m");
        assert_eq!(map.flags(""), "/m");
        assert_eq!(map.flags("/c/M"), "/c/M");
        assert_eq!(map.flags("-x -s"), "-s /m");
        assert_eq!(map.flags("-m"), "-m");
    }

    #[test]
    fn embedded_profiles_parse() {
        assert_eq!(profiles().len(), EMBEDDED.len());
        assert!(profiles().iter().all(|p| !p.padding));
        for (id, text) in EMBEDDED {
            assert!(text.contains("schema = 1"), "{id}");
            assert_eq!(profile(id).unwrap().id, id);
        }
        let w10 = profile("watcom-10.6").unwrap();
        assert_eq!(w10.runners, ["dosbox-lab"]);
        assert!(w10.linker.as_ref().unwrap().start_option);
        assert_eq!(w10.linker.as_ref().unwrap().startup, None);
        assert_eq!(w10.linker.as_ref().unwrap().map, None);
        let tc = profile("turbo-c-2.0").unwrap();
        let tc_linker = tc.linker.unwrap();
        assert_eq!(tc_linker.startup.as_deref(), Some("C0S"));
        let map = tc_linker.map.unwrap();
        assert_eq!(
            (map.format, map.file.as_str()),
            (MapFormat::Tlink, "{name}.MAP")
        );
        assert_eq!(
            w10.assembler.unwrap().command.unwrap(),
            "WASM -zq -fo={output} {input}"
        );
        let w95 = profile("watcom-9.5").unwrap();
        assert!(!w95.linker.as_ref().unwrap().start_option);
        assert_eq!(w95.assembler.unwrap().profile.unwrap(), "watcom-10.6");
        assert_eq!(
            w95.prelude,
            ["SET WATCOM=D:\\", "SET INCLUDE=D:\\H", "SET PATH=D:\\BINW"]
        );
        let tc = profile("turbo-c-2.0").unwrap();
        assert_eq!(tc.bits, 16);
        assert_eq!(tc.prologue, [0x55, 0x8B, 0xEC]);
        assert!(tc.assembler.is_none() && tc.prelude.is_empty());
    }

    #[test]
    fn watcom_decoration() {
        let p = profile("watcom-9.5").unwrap();
        assert_eq!(p.decoration, Decoration::watcom());
        assert_eq!(
            p.compile_line("-ox  -zp4", "MAIN.C"),
            "WCC386 -zq -ox -zp4 MAIN.C"
        );
        assert_eq!(p.object_name("MAIN.C"), "MAIN.OBJ");
        assert_eq!(
            p.link_line("", "", &strings(&["MAIN"]), "REBUILD", &[])
                .unwrap(),
            "WLINK @REBUILD"
        );
        let tc = profile("turbo-c-2.0").unwrap();
        assert_eq!(tc.decoration.undecorate("_main"), "main");
    }

    #[test]
    fn turbo_c_compile_line() {
        let p = profile("turbo-c-2.0").unwrap();
        assert_eq!(
            p.compile_line("-ms -G -Z", "MAIN.C"),
            "D:\\TCC -c -ms -G -Z -ID:\\INCLUDE MAIN.C"
        );
    }

    #[test]
    fn turbo_c_link_line() {
        let p = profile("turbo-c-2.0").unwrap();
        let line = p
            .link_line(
                "/c/x/i",
                "C0S",
                &strings(&["MAIN"]),
                "REBUILD",
                &strings(&["EMU", "MATHS", "CS"]),
            )
            .unwrap();
        assert_eq!(
            line,
            "D:\\TLINK /c/x/i D:\\LIB\\C0S MAIN,REBUILD,,D:\\LIB\\EMU D:\\LIB\\MATHS D:\\LIB\\CS"
        );
    }

    #[test]
    fn unknown_profile_is_named() {
        let err = profile("gcc-2.95").unwrap_err();
        assert!(matches!(err, ToolchainError::UnknownProfile(ref id) if id == "gcc-2.95"));
        assert!(err.to_string().contains("gcc-2.95"));
    }

    #[test]
    fn missing_tool_dir_names_setup_command() {
        let p = profile("watcom-9.5").unwrap();
        let err = tool_dir(&p, None, &UserConfig::default(), Path::new(".")).unwrap_err();
        assert!(matches!(err, ToolchainError::NoToolDir { .. }));
        assert!(
            err.to_string()
                .contains("decovery setup toolchain watcom-9.5 <dir>"),
            "{err}"
        );
    }

    #[test]
    fn workspace_tool_dir_wins_over_user() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("wc")).unwrap();
        let user_dir = tempfile::tempdir().unwrap();
        let text = format!(
            "schema = 1\n[toolchains]\n\"watcom-9.5\" = '{}'\n",
            user_dir.path().display()
        );
        let user: UserConfig = toml::from_str(&text).unwrap();
        let p = profile("watcom-9.5").unwrap();
        assert_eq!(
            tool_dir(&p, None, &user, root.path()).unwrap(),
            user_dir.path()
        );
        let mut rebuild = RebuildConfig::default();
        rebuild.tool_dir = Some("wc".into());
        assert_eq!(
            tool_dir(&p, Some(&rebuild), &user, root.path()).unwrap(),
            root.path().join("wc")
        );
        let mut missing = RebuildConfig::default();
        missing.tool_dir = Some("nope".into());
        assert!(matches!(
            tool_dir(&p, Some(&missing), &user, root.path()),
            Err(ToolchainError::ToolDirMissing { .. })
        ));
    }
}
