//! Linking compiled objects into a program with the profile's linker, in one runner job.

use std::path::Path;
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
}

/// Writes `objects` (stem, object bytes) into `build_dir` as `<stem>.<object extension>`, links them with the
/// profile's linker and `config` (flags, startup, libraries) into `<output>` (rendered with the linker's output
/// pattern, e.g. `REBUILD.EXE`) in one runner job, and reads the linked file. Returns the result and the runners'
/// warnings; a runner that cannot run at all is an error.
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
    let line = profile.link_line(
        config.flags.as_deref().unwrap_or(""),
        config.startup.as_deref().unwrap_or(DEFAULT_STARTUP),
        &stems,
        output,
        &config.libraries,
    )?;
    let file = linker.output.replace("{name}", output);
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
            },
            Err(e) => Linked {
                program: None,
                message: format!("cannot read {}: {e}", path.display()),
                line,
            },
        }
    } else {
        Linked {
            program: None,
            message: failure(&outcome, "linker", &file),
            line,
        }
    };
    Ok((linked, warnings))
}
