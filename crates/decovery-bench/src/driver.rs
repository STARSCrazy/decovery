//! External driver invocation. Commands are argv lists, never shell command strings.
use super::{BenchError, io};
pub use decovery_core::user_config::BenchDriverConfig as DriverConfig;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DriverResult {
    pub schema: u32,
    pub model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub cost_kind: Option<String>,
    pub stop: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
pub(crate) struct Outcome {
    pub result: Option<DriverResult>,
    pub exit: String,
    pub code: Option<i32>,
    pub pid: u32,
    pub warnings: Vec<String>,
}

fn expand(input: &str, bindings: &BTreeMap<&str, String>) -> String {
    let mut remaining = input;
    let mut result = String::new();
    loop {
        let next = bindings
            .iter()
            .filter_map(|(key, value)| remaining.find(key).map(|at| (at, *key, value)))
            .min_by_key(|(at, _, _)| *at);
        let Some((at, key, value)) = next else {
            result.push_str(remaining);
            return result;
        };
        result.push_str(&remaining[..at]);
        result.push_str(value);
        remaining = &remaining[at + key.len()..];
    }
}

pub(crate) fn invoke(
    task: &str,
    driver: &DriverConfig,
    bindings: &BTreeMap<&str, String>,
    workdir: &Path,
    log: &Path,
    wall: Duration,
    actor: &str,
) -> Result<Outcome, BenchError> {
    let args: Vec<_> = driver
        .command
        .iter()
        .map(|arg| expand(arg, bindings))
        .collect();
    let (program, arguments) = args.split_first().ok_or_else(|| BenchError::Driver {
        task: task.into(),
        reason: "driver command is empty".into(),
    })?;
    let output = std::fs::File::create(log).map_err(|e| io(log, e))?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .envs(&driver.env)
        .env("DECOVERY_ACTOR", actor)
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(output.try_clone().map_err(|e| io(log, e))?)
        .stderr(output);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|e| BenchError::Driver {
        task: task.into(),
        reason: e.to_string(),
    })?;
    let pid = child.id();
    let began = Instant::now();
    let mut timeout = false;
    let mut warnings = Vec::new();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| io(log, e))? {
            break status;
        }
        if began.elapsed() >= wall {
            timeout = true;
            if let Some(warning) = kill_tree(&mut child) {
                warnings.push(warning);
            }
            break child.wait().map_err(|e| io(log, e))?;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let path = bindings
        .get("{result}")
        .map(Path::new)
        .ok_or_else(|| BenchError::Driver {
            task: task.into(),
            reason: "result path is missing".into(),
        })?;
    let result = match std::fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice::<DriverResult>(&bytes).map_err(|e| e.to_string()))
    {
        Ok(result)
            if result.schema == 1
                && result.cost_usd.is_none_or(|c| c.is_finite() && c >= 0.0)
                && result
                    .stop
                    .as_deref()
                    .is_none_or(|s| matches!(s, "token-limit" | "cost-limit" | "quota")) =>
        {
            Some(result)
        }
        Ok(_) => {
            warnings.push(format!(
                "{}: byte 0: invalid driver result schema, cost or stop",
                path.display()
            ));
            None
        }
        Err(e) => {
            if !timeout {
                warnings.push(format!("{}: {e}", path.display()));
            }
            None
        }
    };
    let exit = if timeout {
        "timeout"
    } else if let Some(stop) = result.as_ref().and_then(|r| r.stop.as_deref()) {
        stop
    } else if status.success() && result.is_some() {
        "ok"
    } else {
        "driver-error"
    }
    .to_string();
    Ok(Outcome {
        result,
        exit,
        code: status.code(),
        pid,
        warnings,
    })
}

fn kill_tree(child: &mut std::process::Child) -> Option<String> {
    #[cfg(windows)]
    let result = Command::new(
        std::env::var_os("SystemRoot")
            .map(|p| std::path::PathBuf::from(p).join("System32/taskkill.exe"))
            .unwrap_or_else(|| "taskkill.exe".into()),
    )
    .args(["/T", "/F", "/PID", &child.id().to_string()])
    .output();
    #[cfg(not(windows))]
    let result = Command::new("kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .output();
    let warning = match result {
        Ok(result) if result.status.success() => None,
        Ok(result) => Some(format!(
            "process-tree termination unavailable ({}); terminating the driver directly",
            result.status
        )),
        Err(e) => Some(format!(
            "process-tree termination unavailable: {e}; terminating the driver directly"
        )),
    };
    if warning.is_some() {
        let _ = child.kill();
    }
    warning
}
