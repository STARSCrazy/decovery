//! `decovery mcp` speaks newline-delimited JSON-RPC over stdio.

#[path = "../../decovery-facade/tests/support/build_fixture.rs"]
mod build_fixture;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use serde_json::{Value, json};

const CONFIG: &str = r#"schema = 1

[target]
file = "t.exe"
sha256 = "aa"
format = "flat32"
processor = "x86"

[[target.segment]]
name = "code"
start = "flat:00010000"
length = 4096
file_offset = 512
file_length = 4096
permissions = "rx"
"#;

const SYMBOLS: &str = r#"schema = 1

[[symbol]]
address = "flat:00010010"
kind = "function"
name = "alpha"
source = "human"
confidence = "confirmed"
"#;

/// Workspace with the analyzed functions `alpha` (named) and one unnamed at `flat:00010200`.
fn workspace() -> tempfile::TempDir {
    use decovery_core::{Address, Analysis, AnalyzedFunction, Provider, Workspace, knowledge_hash};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    std::fs::write(root.join("decovery.toml"), CONFIG).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), SYMBOLS).unwrap();
    let lock = Workspace::open(root).unwrap().lock(Duration::ZERO).unwrap();
    let mut analysis = Analysis::new(
        Provider::new("ghidra", "11.3"),
        "aa",
        knowledge_hash(root).unwrap(),
        "2026-11-05",
    );
    analysis.functions = vec![
        AnalyzedFunction::new(Address::Flat(0x10010), Address::Flat(0x100FF), 240),
        AnalyzedFunction::new(Address::Flat(0x10200), Address::Flat(0x1021F), 32),
    ];
    analysis.save(root, &lock).unwrap();
    Analysis::save_decompiled(
        root,
        Address::Flat(0x10010),
        "\nint alpha(void) { return 0; }\n",
        &lock,
    )
    .unwrap();
    Analysis::save_decompiled(
        root,
        Address::Flat(0x10200),
        "\nvoid FUN_00010200(void) { }\n",
        &lock,
    )
    .unwrap();
    drop(lock);
    dir
}

/// A running `decovery mcp` with its stdout lines arriving on a channel.
struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Server {
    fn start(dir: &tempfile::TempDir) -> Server {
        Server::start_at(dir.path())
    }

    fn start_at(root: &Path) -> Server {
        let mut child = Command::new(env!("CARGO_BIN_EXE_decovery"))
            .arg("mcp")
            .arg("--workspace")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn decovery mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = Server {
            child,
            stdin,
            lines,
        };
        let init = server.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}
            }),
        );
        assert!(
            init["result"]["capabilities"]["tools"].is_object(),
            "{init}"
        );
        server.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        server
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// Sends a request and returns the response with the same id; every stdout line must be JSON.
    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.request_with_notifications(id, method, params).0
    }

    /// [`Server::request`] plus the messages that arrived before the response.
    fn request_with_notifications(
        &mut self,
        id: u64,
        method: &str,
        params: Value,
    ) -> (Value, Vec<Value>) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let mut before = Vec::new();
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(60))
                .expect("response from decovery mcp");
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout line is not JSON-RPC ({e}): {line:?}"));
            if message["id"] == id {
                return (message, before);
            }
            before.push(message);
        }
    }

    fn call(&mut self, id: u64, tool: &str, arguments: Value) -> Value {
        let response = self.request(
            id,
            "tools/call",
            json!({"name": tool, "arguments": arguments}),
        );
        assert!(response["error"].is_null(), "{response}");
        response["result"].clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The envelope carried as the single text content of a tool result.
fn envelope(result: &Value) -> Value {
    let content = result["content"].as_array().expect("content");
    assert_eq!(content.len(), 1, "{result}");
    assert_eq!(content[0]["type"], "text");
    serde_json::from_str(content[0]["text"].as_str().unwrap()).expect("envelope JSON")
}

#[test]
fn lists_nine_tools() {
    let dir = workspace();
    let mut server = Server::start(&dir);
    let response = server.request(2, "tools/list", json!({}));
    let tools = response["result"]["tools"].as_array().expect("tools");
    let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "analyze", "annotate", "build", "detail", "diagnose", "find", "link", "show", "status"
        ]
    );
    for tool in tools {
        assert!(tool["description"].as_str().is_some_and(|d| !d.is_empty()));
        for (param, schema) in tool["inputSchema"]["properties"]
            .as_object()
            .into_iter()
            .flatten()
        {
            assert!(
                schema["description"]
                    .as_str()
                    .is_some_and(|d| !d.is_empty()),
                "{} parameter {param} lacks a description",
                tool["name"]
            );
        }
    }
    let show = tools.iter().find(|t| t["name"] == "show").unwrap();
    assert_eq!(show["inputSchema"]["required"], json!(["target"]));
    let tool = |name: &str| tools.iter().find(|t| t["name"] == name).unwrap();
    let build = tool("build");
    let props = build["inputSchema"]["properties"].as_object().unwrap();
    let mut keys: Vec<&String> = props.keys().collect();
    keys.sort_unstable();
    assert_eq!(keys, ["budget", "files", "function", "variants"]);
    assert!(
        build["inputSchema"]["required"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    let text = format!(
        "{}{}",
        build["description"], props["variants"]["description"]
    );
    for word in ["shrunk", "confirmed_on", "diagnose"] {
        assert!(text.contains(word), "build description lacks {word}");
    }
    let variant = &build["inputSchema"]["$defs"]["VariantParams"]["properties"];
    for key in ["label", "source", "function_source"] {
        assert!(
            variant[key]["description"]
                .as_str()
                .is_some_and(|d| !d.is_empty()),
            "variant field {key} lacks a description"
        );
    }
    let diagnose = tool("diagnose");
    assert_eq!(diagnose["inputSchema"]["required"], json!(["target"]));
    assert!(diagnose["inputSchema"]["properties"]["budget"].is_object());
    assert!(
        tool("link")["inputSchema"]["properties"]
            .as_object()
            .is_none_or(serde_json::Map::is_empty)
    );
    let annotate = tools.iter().find(|t| t["name"] == "annotate").unwrap();
    let props = annotate["inputSchema"]["properties"].as_object().unwrap();
    for key in [
        "target",
        "name",
        "comment",
        "signature",
        "type",
        "local",
        "refute",
        "add_type",
        "confidence",
        "evidence",
        "force",
    ] {
        assert!(props.contains_key(key), "annotate lacks {key}");
    }
    assert!(
        annotate["inputSchema"]["required"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
}

#[test]
fn show_over_stdio_returns_envelope() {
    let dir = workspace();
    let mut server = Server::start(&dir);
    let result = server.call(2, "show", json!({"target": "alpha"}));
    assert_eq!(result["isError"], false, "{result}");
    let v = envelope(&result);
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["data", "handles", "summary"]);
    assert_eq!(v["data"]["name"], "alpha");
    let text = v["data"]["text"].as_str().unwrap();
    assert!(
        text.starts_with("/* @address    flat:00010010"),
        "got {text:?}"
    );
    assert!(
        text.ends_with("int alpha(void) { return 0; }\n"),
        "got {text:?}"
    );

    let result = server.call(3, "show", json!({"target": "nosuch"}));
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(
        result["content"][0]["text"],
        "no function or symbol named nosuch"
    );

    let result = server.call(4, "status", json!({}));
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(envelope(&result)["data"]["named"], 1);

    let result = server.call(
        5,
        "find",
        json!({"what": "functions", "filter": ["unnamed"], "sort": "size"}),
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        envelope(&result)["data"]["items"][0]["address"],
        "flat:00010200"
    );
}

#[test]
fn annotate_over_stdio_uses_agent_source() {
    let dir = workspace();
    let mut server = Server::start(&dir);
    let result = server.call(
        2,
        "annotate",
        json!({"target": "flat:00010200", "name": "beta", "comment": "two actions"}),
    );
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(result["content"][0]["text"], "exactly one action required");
    let result = server.call(3, "annotate", json!({"target": "flat:00010200"}));
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(result["content"][0]["text"], "exactly one action required");

    let result = server.call(
        4,
        "annotate",
        json!({"target": "flat:00010200", "name": "beta", "evidence": "called on start"}),
    );
    assert_eq!(result["isError"], false, "{result}");
    assert!(envelope(&result)["summary"].as_str().is_some());

    let symbols: toml::Value = toml::from_str(
        &std::fs::read_to_string(dir.path().join("knowledge/symbols.toml")).unwrap(),
    )
    .unwrap();
    let beta = symbols["symbol"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"].as_str() == Some("beta"))
        .expect("symbol beta");
    assert_eq!(beta["source"].as_str(), Some("agent"));
    assert_eq!(beta["confidence"].as_str(), Some("assumed"));

    // the next call re-opens the session and sees the new name
    let result = server.call(5, "show", json!({"target": "beta"}));
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(envelope(&result)["data"]["name"], "beta");
}

// -- analyze with the fake analyzer plugin of the facade tests (skipped without Python) ---------------------

fn python() -> Option<String> {
    let candidate = std::env::var("DECOVERY_PYTHON").unwrap_or_else(|_| "python".into());
    let ok = Command::new(&candidate)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then_some(candidate)
}

fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

/// MZ stub + LE header with one 0x100-byte page per object, no fixups; entry `obj1:0x10`.
fn le_image(objects: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    const PAGE: usize = 0x100;
    const HEADER: usize = 0xAC;
    let pages_of = |data: &Vec<u8>| data.len().div_ceil(PAGE);
    let total_pages: usize = objects.iter().map(|o| pages_of(&o.2)).sum();
    let last_page = match objects.last().map_or(0, |o| o.2.len() % PAGE) {
        0 => PAGE,
        rem => rem,
    };
    let k = 0x40usize;
    let obj_tab = HEADER;
    let page_map = obj_tab + 24 * objects.len();
    let fpt = page_map + 4 * total_pages;
    let frt = fpt + 4 * (total_pages + 1);
    let data_pages = k + frt;
    let mut out = vec![0u8; k + HEADER];
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3C, k as u32);
    let h = k;
    out[h..h + 2].copy_from_slice(b"LE");
    for (at, x) in [
        (0x14, total_pages),
        (0x18, 1),
        (0x1C, 0x10),
        (0x20, objects.len()),
        (0x24, 0x40),
        (0x28, PAGE),
        (0x2C, last_page),
        (0x40, obj_tab),
        (0x44, objects.len()),
        (0x48, page_map),
        (0x68, fpt),
        (0x6C, frt),
        (0x80, data_pages),
    ] {
        put32(&mut out, h + at, x as u32);
    }
    let mut first = 0u32;
    for (base, flags, data) in objects {
        for x in [
            data.len() as u32,
            *base,
            *flags,
            first + 1,
            pages_of(data) as u32,
            0,
        ] {
            out.extend_from_slice(&x.to_le_bytes());
        }
        first += pages_of(data) as u32;
    }
    for p in 1..=total_pages as u32 {
        out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8, 0]);
    }
    for _ in 0..=total_pages {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    for (_, _, data) in objects {
        out.extend_from_slice(data);
        out.resize(
            out.len() + data.len().next_multiple_of(PAGE) - data.len(),
            0,
        );
    }
    out.truncate(data_pages + (total_pages - 1) * PAGE + last_page);
    out
}

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

#[test]
fn analyze_over_stdio_forwards_progress() {
    let Some(python) = python() else {
        eprintln!("SKIP: no Python (set DECOVERY_PYTHON or put `python` on PATH)");
        return;
    };
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../decovery-facade/tests/fixtures/fake_analyzer.py");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("knowledge")).unwrap();
    let image = le_image(&[
        (
            0x10000,
            0x2025,
            (0..0x300).map(|i| (i % 251) as u8).collect(),
        ),
        (0x30000, 0x2043, vec![0x11; 0x100]),
    ]);
    std::fs::write(root.join("t.exe"), image).unwrap();
    let config = format!(
        r#"schema = 1

[target]
file = "t.exe"
sha256 = "aa"
format = "le"
processor = "x86"

[[target.segment]]
name = "code"
start = "flat:00010000"
length = 768
permissions = "rx"

[[target.segment]]
name = "data"
start = "flat:00030000"
length = 256
permissions = "rw"

[analysis]
prologues = []
calling_convention = "__watcall"

[plugins.fake]
command = [{}, {}]
"#,
        toml_string(&python),
        toml_string(fixture.to_str().unwrap())
    );
    std::fs::write(root.join("decovery.toml"), config).unwrap();
    std::fs::write(root.join("knowledge/symbols.toml"), SYMBOLS).unwrap();

    let mut server = Server::start(&dir);
    let (response, before) = server.request_with_notifications(
        2,
        "tools/call",
        json!({
            "name": "analyze",
            "arguments": {"plugin": "fake"},
            "_meta": {"progressToken": "p1"}
        }),
    );
    let result = &response["result"];
    assert_eq!(result["isError"], false, "{response}");
    assert_eq!(envelope(result)["data"]["provider"], "fake");
    let progress: Vec<&Value> = before
        .iter()
        .filter(|m| m["method"] == "notifications/progress")
        .collect();
    assert!(
        progress
            .iter()
            .all(|m| m["params"]["progressToken"] == "p1"),
        "{before:?}"
    );
    assert!(
        progress
            .iter()
            .any(|m| m["params"]["message"] == "analyzing 2" && m["params"]["total"] == 3.0),
        "{before:?}"
    );

    // without a progress token no notification is sent
    let (response, before) = server.request_with_notifications(
        3,
        "tools/call",
        json!({"name": "analyze", "arguments": {"plugin": "fake", "functions": ["alpha"]}}),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(before.is_empty(), "{before:?}");

    let result = server.call(4, "analyze", json!({"plugin": "nosuch"}));
    assert_eq!(result["isError"], true, "{result}");
}

#[test]
fn diagnose_over_stdio_needs_rebuilt_object() {
    let dir = workspace();
    let mut server = Server::start(&dir);
    let result = server.call(2, "diagnose", json!({"target": "alpha"}));
    assert_eq!(result["isError"], true, "{result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        text.starts_with("no rebuilt object for alpha; run `decovery build"),
        "{text}"
    );
}

#[test]
fn link_over_stdio_reports_facade_errors() {
    let dir = workspace();
    let mut server = Server::start(&dir);
    let result = server.call(2, "link", json!({}));
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("link supports MZ and LE"),
        "{result}"
    );
}

#[test]
fn build_over_stdio_rejects_bad_variants() {
    let dir = workspace();
    let mut server = Server::start(&dir);
    for variant in [
        json!({"label": "none"}),
        json!({"source": "a", "function_source": "b"}),
    ] {
        let result = server.call(
            2,
            "build",
            json!({"function": "alpha", "variants": [variant]}),
        );
        assert_eq!(result["isError"], true, "{result}");
        assert_eq!(
            result["content"][0]["text"],
            "each variant needs exactly one of source and function_source"
        );
    }
}

const SUB_SOURCE: &str = "int sub(int a, int b)\n{\n    return a - b;\n}\n";

#[test]
fn build_over_stdio_ranks_variants() {
    let python = python_or_skip!();
    let f = build_fixture::fixture(&python, "");
    let mut worse = build_fixture::SUB.to_vec();
    worse[6] = 0x33;
    f.write_obj("V001", &[("_sub", &worse)]);
    f.write_obj("V002", &[("_sub", build_fixture::SUB)]);
    let mut server = Server::start_at(f.root());
    let arguments = json!({
        "function": "sub",
        "variants": [
            {"label": "worse", "source": format!("{SUB_SOURCE}/* 1 */\n")},
            {"label": "better", "source": format!("{SUB_SOURCE}/* 2 */\n")}
        ]
    });
    let (response, before) = server.request_with_notifications(
        2,
        "tools/call",
        json!({"name": "build", "arguments": arguments, "_meta": {"progressToken": "b1"}}),
    );
    let result = &response["result"];
    assert_eq!(result["isError"], false, "{response}");
    let env = envelope(result);
    let d = &env["data"];
    assert_eq!(d["function"], "sub");
    assert_eq!(d["best"], 2);
    assert_eq!(d["variants"][0]["label"], "better");
    assert_eq!(d["variants"][0]["verdict"], "identical");
    assert_eq!(d["variants"][1]["label"], "worse");
    assert!(
        before.iter().all(
            |m| m["method"] == "notifications/progress" && m["params"]["progressToken"] == "b1"
        ),
        "{before:?}"
    );
    // a ranking records nothing
    assert!(!f.root().join("cache/rebuild/obj").exists());

    // the same candidates again: served from the object cache, no new compiler call
    let calls = f.log("calls.log").len();
    let result = server.call(3, "build", arguments);
    assert_eq!(result["isError"], false, "{result}");
    let env = envelope(&result);
    assert_eq!(env["data"]["timing"]["cached"], 2, "{env}");
    assert_eq!(f.log("calls.log").len(), calls);
}

#[test]
fn build_over_stdio_function_source_variant() {
    let python = python_or_skip!();
    let f = build_fixture::fixture(&python, "");
    // the full file (validation) and the shrunk file (the attempt) give the same code
    f.write_obj(
        "F001",
        &[("_add", build_fixture::ADD), ("_sub", build_fixture::SUB)],
    );
    f.write_obj("V001", &[("_sub", build_fixture::SUB)]);
    let mut server = Server::start_at(f.root());
    let result = server.call(
        2,
        "build",
        json!({"function": "sub", "variants": [{"function_source": SUB_SOURCE}]}),
    );
    assert_eq!(result["isError"], false, "{result}");
    let env = envelope(&result);
    let v = &env["data"]["variants"][0];
    assert_eq!(v["verdict"], "identical", "{env}");
    assert_eq!(v["shrunk"], true, "{env}");
    assert_eq!(v["confirmed_on"], "full", "{env}");
}

#[test]
fn build_over_stdio_builds_files() {
    let python = python_or_skip!();
    let f = build_fixture::fixture(&python, "");
    let mut server = Server::start_at(f.root());
    let result = server.call(2, "build", json!({"files": ["a.c"]}));
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        envelope(&result)["summary"],
        "a.c: 2 functions, 2 identical"
    );
    assert!(f.root().join("knowledge/rebuild.toml").is_file());
    let result = server.call(3, "build", json!({"files": ["nosuch.c"]}));
    assert_eq!(result["isError"], true, "{result}");
}
