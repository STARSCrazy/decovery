//! Host side of the plugin protocol: spawns a plugin, routes responses by id, supports overlapping
//! calls, timeouts and cancellation.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::protocol::{CANCELLED, PROTOCOL, PluginInfo, Progress, WireInfo};

/// Failure of a plugin call.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PluginError {
    /// The plugin process could not be started.
    #[error("cannot start plugin: {0}")]
    Spawn(std::io::Error),
    /// The plugin sent something the protocol does not allow.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// No response within [`CallOptions::timeout`]; `$/cancel` was sent.
    #[error("plugin call timed out")]
    Timeout,
    /// Cancelled through the [`CancelToken`] or by the plugin (`-32002`).
    #[error("plugin call cancelled")]
    Cancelled,
    /// The plugin answered with a JSON-RPC error.
    #[error("plugin error {code}: {message}")]
    Remote {
        /// JSON-RPC error code.
        code: i64,
        /// Error message.
        message: String,
    },
    /// The plugin process ended or its pipes closed.
    #[error("plugin process exited")]
    Exited,
}

/// Cooperative cancellation handle; clones share the flag.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// New, not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation of every call holding this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`CancelToken::cancel`] was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Per-call options.
pub struct CallOptions<'a> {
    /// Maximum wait for the response.
    pub timeout: Duration,
    /// Optional cancellation token.
    pub cancel: Option<CancelToken>,
    /// Receives `$/progress` notifications of this call, on the calling thread.
    pub on_progress: Option<&'a dyn Fn(Progress)>,
}

enum Event {
    Progress(Progress),
    Response(Result<Value, PluginError>),
}

#[derive(Default)]
struct Pending {
    senders: HashMap<u64, Sender<Event>>,
    closed: bool,
}

struct Shared {
    pending: Mutex<Pending>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A running plugin process.
pub struct PluginHost {
    child: Child,
    stdin: Mutex<Option<ChildStdin>>,
    shared: Arc<Shared>,
    next_id: AtomicU64,
    reader: Option<JoinHandle<()>>,
    info: PluginInfo,
}

const INIT_TIMEOUT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(10);
/// How long [`PluginHost`] waits for the end of the plugin's output after the plugin ended.
const READER_GRACE: Duration = Duration::from_secs(2);

impl PluginHost {
    /// Start `command` in `cwd` and perform the `initialize` handshake. Plugin stderr is inherited.
    pub fn spawn(command: &[OsString], cwd: &Path) -> Result<Self, PluginError> {
        Self::spawn_with_env(command, cwd, &[])
    }

    /// Like [`PluginHost::spawn`], with `env` added to the inherited environment.
    pub fn spawn_with_env(
        command: &[OsString],
        cwd: &Path,
        env: &[(OsString, OsString)],
    ) -> Result<Self, PluginError> {
        let (program, args) = command.split_first().ok_or_else(|| {
            PluginError::Spawn(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty plugin command",
            ))
        })?;
        let mut child = Command::new(program)
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(PluginError::Spawn)?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
            let _ = child.kill();
            return Err(PluginError::Protocol("plugin pipes unavailable".into()));
        };
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending::default()),
        });
        let reader = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || read_loop(BufReader::new(stdout), &shared))
        };
        let mut host = PluginHost {
            child,
            stdin: Mutex::new(Some(stdin)),
            shared,
            next_id: AtomicU64::new(1),
            reader: Some(reader),
            info: PluginInfo {
                name: String::new(),
                version: String::new(),
                protocol: String::new(),
                capabilities: Default::default(),
                limits: Default::default(),
            },
        };
        match host.handshake() {
            Ok(info) => {
                host.info = info;
                Ok(host)
            }
            Err(e) => {
                host.close();
                Err(e)
            }
        }
    }

    fn handshake(&self) -> Result<PluginInfo, PluginError> {
        let result = self.call(
            "initialize",
            json!({"protocol": PROTOCOL, "host_version": env!("CARGO_PKG_VERSION")}),
            CallOptions {
                timeout: INIT_TIMEOUT,
                cancel: None,
                on_progress: None,
            },
        )?;
        let wire: WireInfo = serde_json::from_value(result)
            .map_err(|e| PluginError::Protocol(format!("bad initialize result: {e}")))?;
        let info = PluginInfo::from(wire);
        if info.protocol != PROTOCOL {
            return Err(PluginError::Protocol(format!(
                "plugin speaks {:?}, host speaks {PROTOCOL:?}",
                info.protocol
            )));
        }
        Ok(info)
    }

    /// What the plugin reported in `initialize`.
    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    /// Call `method` and wait for its response. Safe to call from several threads at once. On timeout
    /// or cancellation `$/cancel` is sent and a late response is discarded.
    pub fn call(
        &self,
        method: &str,
        params: Value,
        options: CallOptions<'_>,
    ) -> Result<Value, PluginError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        {
            let mut pending = lock(&self.shared.pending);
            if pending.closed {
                return Err(PluginError::Exited);
            }
            pending.senders.insert(id, tx);
        }
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        if let Err(e) = self.write(&request) {
            lock(&self.shared.pending).senders.remove(&id);
            return Err(e);
        }
        let deadline = Instant::now() + options.timeout;
        loop {
            let now = Instant::now();
            let slice = deadline.saturating_duration_since(now).min(POLL);
            match rx.recv_timeout(slice) {
                Ok(Event::Progress(p)) => {
                    if let Some(sink) = options.on_progress {
                        sink(p);
                    }
                }
                Ok(Event::Response(r)) => return r,
                Err(RecvTimeoutError::Disconnected) => return Err(PluginError::Exited),
                Err(RecvTimeoutError::Timeout) => {
                    let cancelled = options
                        .cancel
                        .as_ref()
                        .is_some_and(CancelToken::is_cancelled);
                    if cancelled || Instant::now() >= deadline {
                        lock(&self.shared.pending).senders.remove(&id);
                        let _ = self.write(
                            &json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": id}}),
                        );
                        return Err(if cancelled {
                            PluginError::Cancelled
                        } else {
                            PluginError::Timeout
                        });
                    }
                }
            }
        }
    }

    /// Ask the plugin to shut down, then reap the process (killed after a grace period).
    pub fn shutdown(mut self) -> Result<(), PluginError> {
        let result = self.call(
            "shutdown",
            Value::Null,
            CallOptions {
                timeout: Duration::from_secs(5),
                cancel: None,
                on_progress: None,
            },
        );
        self.close();
        match result {
            Ok(_) | Err(PluginError::Exited) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn write(&self, message: &Value) -> Result<(), PluginError> {
        let mut line = serde_json::to_string(message)
            .map_err(|e| PluginError::Protocol(format!("cannot encode message: {e}")))?;
        line.push('\n');
        let mut guard = lock(&self.stdin);
        let stdin = guard.as_mut().ok_or(PluginError::Exited)?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|_| PluginError::Exited)
    }

    fn close(&mut self) {
        drop(lock(&self.stdin).take());
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
                _ => {
                    kill_tree(&mut self.child);
                    break;
                }
            }
        }
        // A descendant of the plugin (an emulator worker, DOSBox) can hold the plugin's stdout open after the plugin
        // ended; its end of file would never come. Wait a moment for the reader, then leave it behind.
        if let Some(reader) = self.reader.take() {
            let deadline = Instant::now() + READER_GRACE;
            while !reader.is_finished() && Instant::now() < deadline {
                std::thread::sleep(POLL);
            }
            if reader.is_finished() {
                let _ = reader.join();
            }
        }
    }
}

/// Ends the plugin process and, where the platform has a way to, everything it started; then reaps it.
fn kill_tree(child: &mut Child) {
    let killed_tree = cfg!(windows)
        && Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
    if !killed_tree {
        let _ = child.kill();
    }
    let _ = child.wait();
}

impl Drop for PluginHost {
    fn drop(&mut self) {
        self.close();
    }
}

fn read_loop(reader: impl BufRead, shared: &Shared) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            eprintln!("decovery-plugin: ignoring non-JSON line from plugin stdout");
            continue;
        };
        route(&message, shared);
    }
    let mut pending = lock(&shared.pending);
    pending.closed = true;
    for (_, tx) in pending.senders.drain() {
        let _ = tx.send(Event::Response(Err(PluginError::Exited)));
    }
}

fn route(message: &Value, shared: &Shared) {
    let id = message.get("id").and_then(Value::as_u64);
    match (message.get("method").and_then(Value::as_str), id) {
        (Some("$/progress"), _) => {
            let params = message.get("params");
            let target = params.and_then(|p| p.get("id")).and_then(Value::as_u64);
            let progress = params.and_then(|p| serde_json::from_value::<Progress>(p.clone()).ok());
            if let (Some(target), Some(progress)) = (target, progress)
                && let Some(tx) = lock(&shared.pending).senders.get(&target)
            {
                let _ = tx.send(Event::Progress(progress));
            }
        }
        (Some(_), _) => {} // requests and other notifications flow host -> plugin only
        (None, Some(id)) => {
            let result = if let Some(error) = message.get("error") {
                let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
                let text = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Err(if code == CANCELLED {
                    PluginError::Cancelled
                } else {
                    PluginError::Remote {
                        code,
                        message: text,
                    }
                })
            } else {
                Ok(message.get("result").cloned().unwrap_or(Value::Null))
            };
            // A late response of a timed-out call finds no sender and is dropped here.
            if let Some(tx) = lock(&shared.pending).senders.remove(&id) {
                let _ = tx.send(Event::Response(result));
            }
        }
        (None, None) => {}
    }
}
