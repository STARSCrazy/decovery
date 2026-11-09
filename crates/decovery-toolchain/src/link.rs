//! Linking compiled objects into a program with the profile's linker, in one runner job.

use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_core::{LinkConfig, Workspace, read_user_config};
use decovery_plugin::{CancelToken, Progress};

use crate::build::{absolute, failure};
use crate::{
    DEFAULT_TIMEOUT_S, Mount, Profile, RunJob, RunRequest, Runner, ToolchainError,
    run_with_fallback_reporting, tool_dir,
};

/// Startup object when `[rebuild.link] startup` is not set (Turbo C, small model).
pub const DEFAULT_STARTUP: &str = "C0S";

/// The linked program, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Linked {
    /// The linked file.
    pub program: Option<Vec<u8>>,
    /// Linker output on success, the reason on failure (first line: the short reason).
    pub message: String,
    /// The link command line as run.
    pub line: String,
    /// The linker's map file when the profile names one and the linker wrote it.
    pub map: Option<Vec<u8>>,
}

/// Writes `objects` (stem, object bytes) into `build_dir` as `<stem>.<object extension>`, links them with the
/// profile's linker and `config` (flags, startup, libraries) into `<output>` (rendered with the linker's output
/// pattern, e.g. `REBUILD.EXE`) in one runner job, and reads the linked file. When the profile's linker has a
/// `[linker.map]`, the flags ask for a map with the publics and the map is read as well (a missing map is no
/// error). Returns the result and the runners' warnings; a runner that cannot run at all is an error.
#[allow(clippy::too_many_arguments)]
pub fn link(
    ws: &Workspace,
    profile: &Profile,
    objects: &[(String, Vec<u8>)],
    config: &LinkConfig,
    output: &str,
    build_dir: &Path,
    runners: &[Box<dyn Runner>],
    cancel: Option<CancelToken>,
    progress: &dyn Fn(Progress),
) -> Result<(Linked, Vec<String>), ToolchainError> {
    let linker = profile
        .linker
        .as_ref()
        .ok_or_else(|| ToolchainError::Invalid(format!("profile {} has no linker", profile.id)))?;
    let mut stems = Vec::with_capacity(objects.len());
    for (stem, bytes) in objects {
        let path = build_dir.join(format!("{stem}.{}", profile.object_extension));
        std::fs::write(&path, bytes).map_err(|source| ToolchainError::Io { path, source })?;
        stems.push(stem.clone());
    }
    let flags = config.flags.as_deref().unwrap_or("");
    let flags = linker
        .map
        .as_ref()
        .map_or_else(|| flags.to_string(), |m| m.flags(flags));
    let line = profile.link_line(
        &flags,
        config
            .startup
            .as_deref()
            .or(linker.startup.as_deref())
            .unwrap_or(DEFAULT_STARTUP),
        &stems,
        output,
        &config.libraries,
    )?;
    let file = linker.output.replace("{name}", output);
    let map = linker
        .map
        .as_ref()
        .map(|m| m.file.replace("{name}", output));
    run_linker(
        ws, profile, line, file, map, build_dir, runners, cancel, progress,
    )
}

/// Runs the link command `line` of `profile` in one runner job (build dir `C:`, tool dir `D:`) after the profile's
/// prelude and reads the linked `file` (and the `map` file, when given and written) from `build_dir`. Returns the result and the runners' warnings; a runner that
/// cannot run at all is an error.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_linker(
    ws: &Workspace,
    profile: &Profile,
    line: String,
    file: String,
    map: Option<String>,
    build_dir: &Path,
    runners: &[Box<dyn Runner>],
    cancel: Option<CancelToken>,
    progress: &dyn Fn(Progress),
) -> Result<(Linked, Vec<String>), ToolchainError> {
    let user = read_user_config().map_err(|e| ToolchainError::Invalid(e.to_string()))?;
    let dir = tool_dir(profile, ws.config.rebuild.as_ref(), &user, &ws.root)?;
    let timeout = Duration::from_secs(u64::from(
        ws.config
            .rebuild
            .as_ref()
            .and_then(|r| r.timeout_s)
            .unwrap_or(DEFAULT_TIMEOUT_S),
    ));
    let mut commands = profile.prelude.clone();
    commands.push(line.clone());
    let request = RunRequest::new(
        vec![
            Mount::new('C', absolute(build_dir), true),
            Mount::new('D', absolute(&dir), false),
        ],
        vec![RunJob::new(commands, vec![file.clone()])],
        timeout,
    );
    let (outcomes, warnings) = run_with_fallback_reporting(runners, &request, cancel, progress)
        .map_err(|e| ToolchainError::Invalid(format!("cannot link: {e}")))?;
    let outcome = outcomes
        .into_iter()
        .next()
        .ok_or_else(|| ToolchainError::Invalid("cannot link: the runner returned no job".into()))?;
    let linked = if outcome.succeeded() {
        let path = build_dir.join(&file);
        match std::fs::read(&path) {
            Ok(program) => Linked {
                program: Some(program),
                message: outcome.stdout.trim().to_string(),
                line,
                map: map.and_then(|m| std::fs::read(build_dir.join(m)).ok()),
            },
            Err(e) => Linked {
                program: None,
                message: format!("cannot read {}: {e}", path.display()),
                line,
                map: None,
            },
        }
    } else {
        Linked {
            program: None,
            message: failure(&outcome, "linker", &file),
            line,
            map: None,
        }
    };
    Ok((linked, warnings))
}

/// The host path of the program's startup object: `[rebuild.link] startup`, else the profile linker's `startup`, in
/// the profile's library directory on the tool drive `D:` inside the tool directory. `None` when neither names a
/// startup object, the profile has no linker, or the library directory is not on `D:`.
pub fn startup_object(
    ws: &Workspace,
    profile: &Profile,
) -> Result<Option<PathBuf>, ToolchainError> {
    let Some(linker) = profile.linker.as_ref() else {
        return Ok(None);
    };
    let configured = ws
        .config
        .rebuild
        .as_ref()
        .and_then(|r| r.link.as_ref())
        .and_then(|l| l.startup.as_deref());
    let Some(startup) = configured.or(linker.startup.as_deref()) else {
        return Ok(None);
    };
    let Some(library) = linker
        .library_dir
        .strip_prefix("D:")
        .or_else(|| linker.library_dir.strip_prefix("d:"))
    else {
        return Ok(None);
    };
    let user = read_user_config().map_err(|e| ToolchainError::Invalid(e.to_string()))?;
    let mut path = tool_dir(profile, ws.config.rebuild.as_ref(), &user, &ws.root)?;
    path.extend(library.split(['\\', '/']).filter(|p| !p.is_empty()));
    path.push(format!("{startup}.{}", profile.object_extension));
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workspace with `[rebuild] compiler` and a tool directory `tools`, plus `extra` TOML.
    fn workspace(compiler: &str, extra: &str) -> (tempfile::TempDir, Workspace) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("tools")).unwrap();
        std::fs::write(
            root.path().join("decovery.toml"),
            format!(
                "schema = 1\n[target]\nfile = \"t.exe\"\nsha256 = \"00\"\nformat = \"mz\"\n\
                 processor = \"x86\"\n[rebuild]\ncompiler = \"{compiler}\"\ntool_dir = \"tools\"\n{extra}"
            ),
        )
        .unwrap();
        let ws = Workspace::open(root.path()).unwrap();
        (root, ws)
    }

    #[test]
    fn startup_object_from_profile_without_link_config() {
        let (root, ws) = workspace("turbo-c-2.0", "");
        let profile = crate::profile("turbo-c-2.0").unwrap();
        assert_eq!(
            startup_object(&ws, &profile).unwrap(),
            Some(root.path().join("tools").join("LIB").join("C0S.OBJ"))
        );
    }

    #[test]
    fn startup_object_from_link_config() {
        let (root, ws) = workspace("turbo-c-2.0", "[rebuild.link]\nstartup = \"C0L\"\n");
        let profile = crate::profile("turbo-c-2.0").unwrap();
        assert_eq!(
            startup_object(&ws, &profile).unwrap(),
            Some(root.path().join("tools").join("LIB").join("C0L.OBJ"))
        );
    }

    #[test]
    fn no_startup_object_when_the_profile_has_none() {
        let (_root, ws) = workspace("watcom-10.6", "");
        let profile = crate::profile("watcom-10.6").unwrap();
        assert_eq!(startup_object(&ws, &profile).unwrap(), None);
    }
}
