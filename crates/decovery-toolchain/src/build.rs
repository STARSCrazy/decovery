//! Compiling the staged sources of a build: object cache first, then all misses in one runner request, so that a
//! runner pool (the emulator) runs them on all cores (design 5.13).

use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_core::{Workspace, read_user_config};
use decovery_plugin::CancelToken;

use crate::{
    JobOutcome, JobStatus, Mount, ObjectCache, Profile, RunJob, RunRequest, Runner, ToolchainError,
    run_with_fallback, tool_dir,
};

/// Timeout per compile when `[rebuild] timeout_s` is not set.
pub const DEFAULT_TIMEOUT_S: u32 = 120;

/// What the dosbox-lab runner reports for the jobs of a batch after one that hung or crashed.
const JOB_NOT_RUN: &str = "job not run";

/// The object of one source, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompiledFile {
    /// DOS name of the source (`AI.C`).
    pub file: String,
    pub object: Option<Vec<u8>>,
    /// Compiler output on success, the reason on failure (first line: the short reason).
    pub message: String,
    /// The object came from the object cache.
    pub cached: bool,
}

/// blake3 over the profile's fingerprint files (name and bytes), hex. A missing file is an error: the directory
/// does not hold this compiler.
pub fn tool_fingerprint(profile: &Profile, dir: &Path) -> Result<String, ToolchainError> {
    let mut hasher = blake3::Hasher::new();
    for name in &profile.fingerprint {
        let path = dir.join(name);
        let bytes = std::fs::read(&path).map_err(|_| {
            ToolchainError::Invalid(format!(
                "toolchain {}: {} does not contain {name}",
                profile.id,
                dir.display()
            ))
        })?;
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// A job the runner never started because an earlier job of the same request ended the session (dosbox-lab runs
/// all jobs of a request in one DOS batch). Matched on the message until the runner contract has a status for it.
pub fn is_job_not_run(outcome: &JobOutcome) -> bool {
    outcome.status == JobStatus::Failed
        && outcome
            .message
            .as_deref()
            .is_some_and(|m| m.starts_with(JOB_NOT_RUN))
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn read(path: &Path) -> Result<Vec<u8>, ToolchainError> {
    std::fs::read(path).map_err(|source| ToolchainError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// The staged headers (`*.H`) of `build_dir`, sorted by name.
fn staged_headers(build_dir: &Path) -> Result<Vec<(String, Vec<u8>)>, ToolchainError> {
    let entries = std::fs::read_dir(build_dir).map_err(|source| ToolchainError::Io {
        path: build_dir.to_path_buf(),
        source,
    })?;
    let mut headers = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.to_ascii_uppercase().ends_with(".H") && entry.path().is_file() {
            headers.push((name, read(&entry.path())?));
        }
    }
    headers.sort();
    Ok(headers)
}

/// Why a job did not yield its object.
fn failure(outcome: &JobOutcome, object: &str) -> String {
    let reason = match (outcome.status, outcome.exit_code) {
        (JobStatus::Done, Some(code)) if code != 0 => format!("compiler exit code {code}"),
        (JobStatus::Done, _) => format!("the compiler wrote no {object}"),
        (JobStatus::Timeout, _) => outcome
            .message
            .clone()
            .unwrap_or_else(|| "timeout".to_string()),
        _ => outcome
            .message
            .clone()
            .unwrap_or_else(|| "failed".to_string()),
    };
    let output = outcome.stdout.trim();
    if output.is_empty() {
        reason
    } else {
        format!("{reason}\n{output}")
    }
}

/// Tool directory, fingerprint and object cache keys of the staged `sources`, in order.
struct Keys {
    dir: PathBuf,
    keys: Vec<String>,
    cache: ObjectCache,
}

fn cache_keys(
    ws: &Workspace,
    profile: &Profile,
    sources: &[(String, String)],
    build_dir: &Path,
) -> Result<Keys, ToolchainError> {
    let user = read_user_config().map_err(|e| ToolchainError::Invalid(e.to_string()))?;
    let dir = tool_dir(profile, ws.config.rebuild.as_ref(), &user, &ws.root)?;
    let fingerprint = tool_fingerprint(profile, &dir)?;
    let headers = staged_headers(build_dir)?;
    let keys = sources
        .iter()
        .map(|(name, flags)| {
            let line = profile.compile_line(flags, name);
            let source = read(&build_dir.join(name))?;
            Ok(ObjectCache::key(
                profile,
                &line,
                &source,
                &headers,
                &fingerprint,
            ))
        })
        .collect::<Result<_, ToolchainError>>()?;
    Ok(Keys {
        dir,
        keys,
        cache: ObjectCache::open(&ws.root),
    })
}

/// How many of the staged `sources` the object cache cannot serve, i.e. how many compile jobs [`compile`] would
/// run; lets the caller skip starting a runner.
pub fn cache_misses(
    ws: &Workspace,
    profile: &Profile,
    sources: &[(String, String)],
    build_dir: &Path,
) -> Result<usize, ToolchainError> {
    let k = cache_keys(ws, profile, sources, build_dir)?;
    Ok(k.keys
        .iter()
        .filter(|key| k.cache.get(key).is_none())
        .count())
}

/// Compiles the staged `sources` (DOS name, flags) in `build_dir`. Objects come from the object cache when the
/// inputs are unchanged; all others are compiled in one runner request, one job per source. Jobs the runner did
/// not start ([`is_job_not_run`]) are submitted once more. Returns one [`CompiledFile`] per source, in order, and
/// the runners' warnings.
pub fn compile(
    ws: &Workspace,
    profile: &Profile,
    sources: &[(String, String)],
    build_dir: &Path,
    runners: &[Box<dyn Runner>],
    cancel: Option<CancelToken>,
) -> Result<(Vec<CompiledFile>, Vec<String>), ToolchainError> {
    let rebuild = ws.config.rebuild.as_ref();
    let Keys { dir, keys, cache } = cache_keys(ws, profile, sources, build_dir)?;

    let mut files: Vec<CompiledFile> = Vec::new();
    let mut misses: Vec<(usize, String, RunJob)> = Vec::new();
    for (i, ((name, flags), key)) in sources.iter().zip(keys).enumerate() {
        let line = profile.compile_line(flags, name);
        let object = cache.get(&key);
        let cached = object.is_some();
        files.push(CompiledFile {
            file: name.clone(),
            object,
            message: String::new(),
            cached,
        });
        if !cached {
            // the jobs run in parallel in one directory; a compiler with a fixed work file name (Watcom's
            // __WRK0__.TMP) would collide, so each job gets its own TMP directory
            let tmp = format!("TMP{:05}", misses.len());
            let tmp_dir = build_dir.join(&tmp);
            std::fs::create_dir_all(&tmp_dir).map_err(|source| ToolchainError::Io {
                path: tmp_dir,
                source,
            })?;
            let mut commands = profile.prelude.clone();
            commands.push(format!("SET TMP=C:\\{tmp}"));
            commands.push(line);
            misses.push((
                i,
                key,
                RunJob::new(commands, vec![profile.object_name(name)]),
            ));
        }
    }
    let mut warnings = Vec::new();
    if misses.is_empty() {
        return Ok((files, warnings));
    }

    let timeout = Duration::from_secs(u64::from(
        rebuild
            .and_then(|r| r.timeout_s)
            .unwrap_or(DEFAULT_TIMEOUT_S),
    ));
    let mounts = vec![
        // runners resolve paths from their own working directory
        Mount::new('C', absolute(build_dir), true),
        Mount::new('D', absolute(&dir), false),
    ];
    let run = |jobs: Vec<RunJob>, warnings: &mut Vec<String>| {
        let request = RunRequest::new(mounts.clone(), jobs, timeout);
        let (outcomes, more) = run_with_fallback(runners, &request, cancel.clone())
            .map_err(|e| ToolchainError::Invalid(format!("cannot compile: {e}")))?;
        warnings.extend(more);
        Ok::<_, ToolchainError>(outcomes)
    };
    let job_count = misses.len();
    let mut outcomes = run(misses.iter().map(|m| m.2.clone()).collect(), &mut warnings)?;
    let again: Vec<usize> = (0..outcomes.len())
        .filter(|&j| is_job_not_run(&outcomes[j]))
        .collect();
    if !again.is_empty() {
        warnings.push(format!(
            "{} jobs were not run after a job ended the runner's session; submitted once more",
            again.len()
        ));
        let retried = run(
            again.iter().map(|&j| misses[j].2.clone()).collect(),
            &mut warnings,
        )?;
        for (j, outcome) in again.into_iter().zip(retried) {
            outcomes[j] = outcome;
        }
    }

    for ((i, key, job), outcome) in misses.into_iter().zip(outcomes) {
        let object_name = &job.expected[0];
        let file = &mut files[i];
        if !outcome.succeeded() {
            file.message = failure(&outcome, object_name);
            continue;
        }
        // a produced object that cannot be read fails this file, not the build
        let object = match read(&build_dir.join(object_name)) {
            Ok(object) => object,
            Err(e) => {
                file.message = e.to_string();
                continue;
            }
        };
        if let Err(e) = cache.put(&key, &object) {
            warnings.push(format!("object cache: cannot store {object_name}: {e}"));
        }
        file.message = outcome.stdout.trim().to_string();
        file.object = Some(object);
    }
    for j in 0..job_count {
        let _ = std::fs::remove_dir_all(build_dir.join(format!("TMP{j:05}")));
    }
    Ok((files, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RunnerError;

    /// Reports every job as done with its object produced, but writes nothing: the object cannot be read.
    struct ClaimsSuccess;

    impl Runner for ClaimsSuccess {
        fn name(&self) -> &str {
            "claims-success"
        }

        fn run(
            &self,
            request: &RunRequest,
            _cancel: Option<CancelToken>,
        ) -> Result<Vec<JobOutcome>, RunnerError> {
            Ok(request
                .jobs
                .iter()
                .map(|job| JobOutcome::done_for_test(job.expected.clone()))
                .collect())
        }
    }

    #[test]
    fn unreadable_object_fails_only_its_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("tools")).unwrap();
        std::fs::write(root.path().join("tools/TCC.EXE"), b"fake").unwrap();
        std::fs::write(
            root.path().join("decovery.toml"),
            "schema = 1\n[target]\nfile = \"t.exe\"\nsha256 = \"00\"\nformat = \"mz\"\nprocessor = \"x86\"\n\
             [rebuild]\ncompiler = \"turbo-c-2.0\"\ntool_dir = \"tools\"\n",
        )
        .unwrap();
        let ws = Workspace::open(root.path()).unwrap();
        let build = root.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("A.C"), b"int a;\r\n").unwrap();
        let profile = crate::profile("turbo-c-2.0").unwrap();
        let runners: Vec<Box<dyn Runner>> = vec![Box::new(ClaimsSuccess)];
        let sources = [("A.C".to_string(), String::new())];
        let (files, _) = compile(&ws, &profile, &sources, &build, &runners, None).unwrap();
        assert!(files[0].object.is_none());
        assert!(files[0].message.contains("A.OBJ"), "{}", files[0].message);
    }
}
