//! Compiling the staged sources of a build: object cache first, then all misses in one runner request, so that a
//! runner pool (the emulator) runs them on all cores (design 5.13). [`plan_compile`] reads every input once (tool
//! fingerprint, sources, headers, cached objects); [`compile_planned`] runs what the cache cannot serve.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use decovery_core::{Workspace, read_user_config};
use decovery_plugin::{CancelToken, Progress};

use crate::{
    JobOutcome, JobStatus, Mount, ObjectCache, Profile, RunJob, RunRequest, Runner, ToolchainError,
    run_with_fallback_reporting, tool_dir,
};

/// Timeout per compile when `[rebuild] timeout_s` is not set.
pub const DEFAULT_TIMEOUT_S: u32 = 120;

/// What the dosbox-lab runner reports for the jobs of a batch after one that hung or crashed.
const JOB_NOT_RUN: &str = "job not run";

/// One source to compile: its staged DOS name, its flags and, optionally, the directory of the build directory it is
/// staged in (the compiler runs there, so `__FILE__`, messages and the object name are those of a source in the
/// build directory itself; headers must be staged in that directory too).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceJob {
    pub name: String,
    pub flags: String,
    pub dir: Option<String>,
}

impl SourceJob {
    pub fn new(name: impl Into<String>, flags: impl Into<String>) -> Self {
        SourceJob {
            name: name.into(),
            flags: flags.into(),
            dir: None,
        }
    }

    /// Stages and runs the compile in `dir`, a directory of the build directory. A DOS directory name: 1 to 8
    /// characters of `A-Z a-z 0-9 _ -`.
    pub fn in_dir(mut self, dir: impl Into<String>) -> Result<Self, ToolchainError> {
        let dir = dir.into();
        let valid = (1..=8).contains(&dir.len())
            && dir
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !valid {
            return Err(ToolchainError::Invalid(format!(
                "directory {dir:?}: not a DOS directory name (1 to 8 characters of A-Z a-z 0-9 _ -)"
            )));
        }
        self.dir = Some(dir);
        Ok(self)
    }

    /// The path of the staged source relative to the build directory.
    fn path(&self) -> PathBuf {
        match &self.dir {
            Some(dir) => Path::new(dir).join(&self.name),
            None => PathBuf::from(&self.name),
        }
    }
}

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

/// Size and modification time of each fingerprint file: a fingerprint is hashed again only when one changed.
type FileStamps = Vec<(u64, Option<SystemTime>)>;

/// Fingerprints computed in this process, by tool directory and file list, with the stamps they were hashed at.
type FingerprintMemo = HashMap<(PathBuf, Vec<String>), (FileStamps, String)>;

static FINGERPRINTS: Mutex<Option<FingerprintMemo>> = Mutex::new(None);

/// blake3 over the profile's fingerprint files (name and bytes), hex. A missing file is an error: the directory
/// does not hold this compiler. The files (compiler binaries, megabytes) are hashed once per process; later calls
/// only compare their size and modification time.
pub fn tool_fingerprint(profile: &Profile, dir: &Path) -> Result<String, ToolchainError> {
    let missing = |name: &str| {
        ToolchainError::Invalid(format!(
            "toolchain {}: {} does not contain {name}",
            profile.id,
            dir.display()
        ))
    };
    let mut stamps: FileStamps = Vec::new();
    for name in &profile.fingerprint {
        let meta = std::fs::metadata(dir.join(name)).map_err(|_| missing(name))?;
        stamps.push((meta.len(), meta.modified().ok()));
    }
    let key = (dir.to_path_buf(), profile.fingerprint.clone());
    if let Some((known, hash)) = FINGERPRINTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|m| m.get(&key))
        && *known == stamps
    {
        return Ok(hash.clone());
    }
    let mut hasher = blake3::Hasher::new();
    for name in &profile.fingerprint {
        let bytes = std::fs::read(dir.join(name)).map_err(|_| missing(name))?;
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    let hash = hasher.finalize().to_hex().to_string();
    FINGERPRINTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(key, (stamps, hash.clone()));
    Ok(hash)
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

pub(crate) fn absolute(path: &Path) -> PathBuf {
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

/// Why a job of `tool` (`compiler`, `linker`) did not yield its `output`.
pub(crate) fn failure(outcome: &JobOutcome, tool: &str, output: &str) -> String {
    let reason = match (outcome.status, outcome.exit_code) {
        (JobStatus::Done, Some(code)) if code != 0 => format!("{tool} exit code {code}"),
        (JobStatus::Done, _) => format!("the {tool} wrote no {output}"),
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

/// The staged `sources` of one build with everything read once: tool directory and fingerprint, object cache keys,
/// cached objects and source sizes. [`compile_planned`] consumes it.
#[derive(Debug)]
pub struct CompilePlan {
    dir: PathBuf,
    sources: Vec<SourceJob>,
    keys: Vec<String>,
    /// The cached object per source, if any.
    cached: Vec<Option<Vec<u8>>>,
    /// Size in bytes per source: the job's cost (larger compiles start first).
    sizes: Vec<u64>,
    /// blake3 of every staged source and header read, by DOS name.
    inputs: BTreeMap<String, String>,
    cache: ObjectCache,
}

impl CompilePlan {
    /// How many sources the object cache cannot serve, i.e. how many compile jobs [`compile_planned`] runs; lets the
    /// caller skip starting a runner.
    pub fn misses(&self) -> usize {
        self.cached.iter().filter(|c| c.is_none()).count()
    }

    /// blake3 (hex) of each staged source and header the plan read, by DOS name.
    pub fn input_hashes(&self) -> &BTreeMap<String, String> {
        &self.inputs
    }
}

/// Reads the inputs of compiling the staged `sources` (DOS name, flags) in `build_dir` once: the tool fingerprint
/// (hashed once per process), every source and header, and the cached objects.
pub fn plan_compile(
    ws: &Workspace,
    profile: &Profile,
    sources: &[SourceJob],
    build_dir: &Path,
) -> Result<CompilePlan, ToolchainError> {
    let user = read_user_config().map_err(|e| ToolchainError::Invalid(e.to_string()))?;
    let dir = tool_dir(profile, ws.config.rebuild.as_ref(), &user, &ws.root)?;
    let fingerprint = tool_fingerprint(profile, &dir)?;
    let headers = staged_headers(build_dir)?;
    let cache = ObjectCache::open(&ws.root);
    let mut inputs: BTreeMap<String, String> = headers
        .iter()
        .map(|(name, bytes)| (name.clone(), blake3::hash(bytes).to_hex().to_string()))
        .collect();
    let mut keys = Vec::new();
    let mut cached = Vec::new();
    let mut sizes = Vec::new();
    for job in sources {
        let (name, flags) = (&job.name, &job.flags);
        let line = profile.compile_line(flags, name);
        let source = read(&build_dir.join(job.path()))?;
        inputs.insert(name.clone(), blake3::hash(&source).to_hex().to_string());
        let key = ObjectCache::key(profile, &line, &source, &headers, &fingerprint);
        cached.push(cache.get(&key));
        keys.push(key);
        sizes.push(source.len() as u64);
    }
    Ok(CompilePlan {
        dir,
        sources: sources.to_vec(),
        keys,
        cached,
        sizes,
        inputs,
        cache,
    })
}

/// Compiles the staged `sources` in `build_dir`: [`plan_compile`], then [`compile_planned`].
pub fn compile(
    ws: &Workspace,
    profile: &Profile,
    sources: &[SourceJob],
    build_dir: &Path,
    runners: &[Box<dyn Runner>],
    cancel: Option<CancelToken>,
) -> Result<(Vec<CompiledFile>, Vec<String>), ToolchainError> {
    let plan = plan_compile(ws, profile, sources, build_dir)?;
    compile_planned(ws, profile, plan, build_dir, runners, cancel, &|_| {})
}

/// Compiles what `plan` could not take from the object cache, in one runner request, one job per source (its cost
/// the source size, so runners start the largest first). Jobs the runner did not start ([`is_job_not_run`]) are
/// submitted once more. Returns one [`CompiledFile`] per source, in order, and the runners' warnings. `progress`
/// receives what the runner reports while it works (a plugin runner: one event per finished job).
pub fn compile_planned(
    ws: &Workspace,
    profile: &Profile,
    plan: CompilePlan,
    build_dir: &Path,
    runners: &[Box<dyn Runner>],
    cancel: Option<CancelToken>,
    progress: &dyn Fn(Progress),
) -> Result<(Vec<CompiledFile>, Vec<String>), ToolchainError> {
    let rebuild = ws.config.rebuild.as_ref();
    let CompilePlan {
        dir,
        sources,
        keys,
        cached,
        sizes,
        cache,
        ..
    } = plan;

    let mut files: Vec<CompiledFile> = Vec::new();
    let mut misses: Vec<(usize, String, RunJob)> = Vec::new();
    for (i, ((job, key), object)) in sources.iter().zip(keys).zip(cached).enumerate() {
        let line = profile.compile_line(&job.flags, &job.name);
        let cached = object.is_some();
        files.push(CompiledFile {
            file: job.name.clone(),
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
            if let Some(dir) = &job.dir {
                commands.push(format!("CD {dir}"));
            }
            commands.push(line);
            let object = match &job.dir {
                Some(dir) => format!("{dir}/{}", profile.object_name(&job.name)),
                None => profile.object_name(&job.name),
            };
            misses.push((
                i,
                key,
                RunJob::new(commands, vec![object]).with_cost(sizes[i]),
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
        let (outcomes, more) =
            run_with_fallback_reporting(runners, &request, cancel.clone(), progress)
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
            file.message = failure(&outcome, "compiler", object_name);
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

    /// Records the jobs of every request; answers like [`ClaimsSuccess`].
    #[derive(Default, Clone)]
    struct Records(std::sync::Arc<std::sync::Mutex<Vec<Vec<RunJob>>>>);

    impl Runner for Records {
        fn name(&self) -> &str {
            "records"
        }

        fn run(
            &self,
            request: &RunRequest,
            cancel: Option<CancelToken>,
        ) -> Result<Vec<JobOutcome>, RunnerError> {
            self.0.lock().unwrap().push(request.jobs.clone());
            ClaimsSuccess.run(request, cancel)
        }
    }

    /// A Turbo C workspace with a fake TCC.EXE and a build directory: (root, workspace, build directory).
    fn turbo_c_workspace() -> (tempfile::TempDir, Workspace, PathBuf) {
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
        (root, ws, build)
    }

    #[test]
    fn cache_keys_computed_once() {
        let (root, ws, build) = turbo_c_workspace();
        std::fs::write(build.join("A.C"), b"int a;\r\n").unwrap();
        std::fs::write(build.join("B.H"), b"int b;\r\n").unwrap();
        let profile = crate::profile("turbo-c-2.0").unwrap();
        let sources = [SourceJob::new("A.C", "")];
        let plan = plan_compile(&ws, &profile, &sources, &build).unwrap();
        assert_eq!(plan.misses(), 1);
        assert_eq!(
            plan.input_hashes().keys().collect::<Vec<_>>(),
            ["A.C", "B.H"]
        );
        assert_eq!(
            plan.input_hashes()["A.C"],
            blake3::hash(b"int a;\r\n").to_hex().to_string()
        );

        // compile_planned runs the plan's misses with the plan's keys: one request, one job
        let records = Records::default();
        let runners: Vec<Box<dyn Runner>> = vec![Box::new(records.clone())];
        let (files, _) =
            compile_planned(&ws, &profile, plan, &build, &runners, None, &|_| {}).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(records.0.lock().unwrap().len(), 1);

        // the fingerprint files are hashed once per process: other bytes with the same size and modification time
        // are not read again, a new modification time is
        let tools = root.path().join("tools");
        let tool = tools.join("TCC.EXE");
        let before = tool_fingerprint(&profile, &tools).unwrap();
        let modified = std::fs::metadata(&tool).unwrap().modified().unwrap();
        std::fs::write(&tool, b"FAKE").unwrap();
        let touch = |at: SystemTime| {
            std::fs::File::options()
                .write(true)
                .open(&tool)
                .unwrap()
                .set_modified(at)
                .unwrap();
        };
        touch(modified);
        assert_eq!(tool_fingerprint(&profile, &tools).unwrap(), before);
        touch(modified + Duration::from_secs(2));
        assert_ne!(tool_fingerprint(&profile, &tools).unwrap(), before);
    }

    #[test]
    fn job_with_directory_runs_there() {
        let (_root, ws, build) = turbo_c_workspace();
        for dir in ["V001", "V002"] {
            std::fs::create_dir_all(build.join(dir)).unwrap();
            std::fs::write(
                build.join(dir).join("A.C"),
                format!(
                    "int {dir};
"
                ),
            )
            .unwrap();
        }
        let profile = crate::profile("turbo-c-2.0").unwrap();
        let sources = [
            SourceJob::new("A.C", "-ms").in_dir("V001").unwrap(),
            SourceJob::new("A.C", "-ms").in_dir("V002").unwrap(),
        ];
        let records = Records::default();
        let runners: Vec<Box<dyn Runner>> = vec![Box::new(records.clone())];
        compile(&ws, &profile, &sources, &build, &runners, None).unwrap();
        let requests = records.0.lock().unwrap();
        assert_eq!(requests.len(), 1, "all misses in one request");
        let jobs = &requests[0];
        assert_eq!(jobs[0].expected, ["V001/A.OBJ"]);
        assert_eq!(jobs[1].expected, ["V002/A.OBJ"]);
        // the compile line is the one of a source in the build directory itself, run after the CD
        let last = jobs[0].commands.len() - 1;
        assert_eq!(jobs[0].commands[last - 1], "CD V001");
        assert_eq!(jobs[0].commands[last], profile.compile_line("-ms", "A.C"));
    }

    #[test]
    fn directory_of_a_job_must_be_a_dos_name() {
        for bad in ["", "TOOLONGNAME", "a b", "..", "a/b", r"a\b", "ä"] {
            assert!(
                SourceJob::new("A.C", "").in_dir(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        for good in ["V001", "v_1-2", "12345678"] {
            assert!(SourceJob::new("A.C", "").in_dir(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn compile_jobs_carry_source_size_as_cost() {
        let (_root, ws, build) = turbo_c_workspace();
        std::fs::write(build.join("A.C"), b"int a;\r\n").unwrap();
        std::fs::write(build.join("B.C"), vec![b' '; 300]).unwrap();
        let profile = crate::profile("turbo-c-2.0").unwrap();
        let sources = [SourceJob::new("A.C", ""), SourceJob::new("B.C", "")];
        let records = Records::default();
        let runners: Vec<Box<dyn Runner>> = vec![Box::new(records.clone())];
        compile(&ws, &profile, &sources, &build, &runners, None).unwrap();
        let requests = records.0.lock().unwrap();
        assert_eq!(requests.len(), 1, "all misses in one request");
        assert_eq!(
            requests[0].iter().map(|j| j.cost).collect::<Vec<_>>(),
            [8, 300]
        );
    }

    #[test]
    fn unreadable_object_fails_only_its_file() {
        let (_root, ws, build) = turbo_c_workspace();
        std::fs::write(build.join("A.C"), b"int a;\r\n").unwrap();
        let profile = crate::profile("turbo-c-2.0").unwrap();
        let runners: Vec<Box<dyn Runner>> = vec![Box::new(ClaimsSuccess)];
        let sources = [SourceJob::new("A.C", "")];
        let (files, _) = compile(&ws, &profile, &sources, &build, &runners, None).unwrap();
        assert!(files[0].object.is_none());
        assert!(files[0].message.contains("A.OBJ"), "{}", files[0].message);
    }
}
