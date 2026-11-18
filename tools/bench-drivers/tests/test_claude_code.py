"""Contract tests use a Python fake; they never discover or invoke Claude Code."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


DRIVER = Path(__file__).resolve().parents[1] / "claude_code.py"
INIT = {"type": "system", "subtype": "init", "tools": ["mcp__decovery__build"],
        "mcp_servers": [{"name": "decovery", "status": "connected"}], "model": "fake-model"}
USAGE = {"input_tokens": 10, "output_tokens": 4,
         "cache_creation_input_tokens": 7, "cache_read_input_tokens": 20}


@pytest.fixture
def run_driver(tmp_path):
    fake = tmp_path / "fake claude.py"
    fake.write_text('''import json, os, pathlib, subprocess, sys, time
pathlib.Path(os.environ["CAPTURE"]).write_text(json.dumps({
    "argv": sys.argv[1:], "stdin": sys.stdin.read(), "cwd": os.getcwd(),
    "profile": os.environ.get("CLAUDE_CONFIG_DIR"),
    "actor": os.environ.get("DECOVERY_ACTOR"),
    "system": pathlib.Path(sys.argv[sys.argv.index("--system-prompt-file") + 1]).read_text()
}))
if os.environ.get("SPAWN_CHILD"):
    subprocess.Popen([sys.executable, "-c",
        "import pathlib,time; time.sleep(3); pathlib.Path(" + repr(os.environ["CHILD_MARKER"]) + ").write_text('alive')"])
for event in json.loads(os.environ["EVENTS"]):
    print(json.dumps(event), flush=True)
if os.environ.get("HANG"):
    time.sleep(30)
sys.stderr.write(os.environ.get("FAKE_STDERR", ""))
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
''', encoding="utf-8")
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Recover the synthetic function. Unicode: \u03bb", encoding="utf-8")
    mcp = tmp_path / "mcp.json"
    mcp.write_text('{"mcpServers": {}}', encoding="utf-8")
    workdir = tmp_path / "copy"
    workdir.mkdir()
    capture = tmp_path / "capture.json"
    result = tmp_path / "result.json"

    def run(events, *extra, **env):
        process = subprocess.run(
            [sys.executable, str(DRIVER), "--claude", str(fake),
             "--prompt", str(prompt), "--mcp-config", str(mcp),
             "--workdir", str(workdir), "--result", str(result),
             "--profile-dir", str(tmp_path / "profile"), "--seed", "42", *extra],
            env={**os.environ, "CAPTURE": str(capture), "EVENTS": json.dumps(events),
                 "DECOVERY_ACTOR": "bench:synthetic", **env},
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        assert result.exists(), process.stderr
        return process, json.loads(result.read_text(encoding="utf-8")), capture

    return run


def success(**fields):
    return {"type": "result", "subtype": "success", "is_error": False,
            "result": "Done", **fields}


def test_command_line_has_isolation_flags(run_driver):
    process, _, capture = run_driver([INIT, success()], "--model", "chosen", "--max-cost-usd", "1.5")
    assert process.returncode == 0
    observed = json.loads(capture.read_text())
    args = observed["argv"]
    for flag in ("-p", "--verbose", "--strict-mcp-config", "--disable-slash-commands", "--no-session-persistence"):
        assert flag in args
    for flag, value in {"--input-format": "text", "--output-format": "stream-json",
                        "--tools": "", "--allowedTools": "mcp__decovery__*",
                        "--setting-sources": "project", "--model": "chosen",
                        "--max-budget-usd": "1.5"}.items():
        assert args[args.index(flag) + 1] == value
    assert "--bare" not in args
    assert Path(args[args.index("--mcp-config") + 1]).name == "mcp.json"
    assert observed["stdin"] == "Recover the synthetic function. Unicode: \u03bb"
    assert Path(observed["profile"]).name == "profile"
    assert Path(observed["cwd"]).name == "copy"
    assert observed["actor"] == "bench:synthetic"
    assert "decovery" in observed["system"]


def test_result_fields_are_mapped(run_driver):
    process, result, _ = run_driver([INIT, {"type": "assistant", "message": {"usage": USAGE}},
                                    success(usage=USAGE, total_cost_usd=0.25, num_turns=2)])
    assert process.returncode == 0
    assert result == {"schema": 1, "model": "fake-model", "input_tokens": 10,
                      "output_tokens": 4, "cache_write_tokens": 7, "cache_read_tokens": 20,
                      "cost_usd": 0.25, "cost_kind": "estimate", "turns": 2}


def test_usage_of_one_message_counts_once(run_driver):
    # One assistant message with two content blocks arrives as two events with the same id and usage.
    same = {"type": "assistant", "message": {"id": "msg_1", "usage": USAGE}}
    other = {"type": "assistant", "message": {"id": "msg_2", "usage": USAGE}}
    process, result, _ = run_driver([INIT, same, same, other, success()])
    assert process.returncode == 0
    assert result["input_tokens"] == 20
    assert result["output_tokens"] == 8


def test_missing_usage_fields_are_left_out(run_driver):
    process, result, _ = run_driver([success()])
    assert process.returncode == 0
    assert result == {"schema": 1}


def test_token_limit_stops_claude(run_driver, tmp_path):
    marker = tmp_path / "child-survived"
    process, result, _ = run_driver(
        [INIT, {"type": "assistant", "message": {"usage": USAGE}},
         {"type": "assistant", "message": {"usage": USAGE}}],
        "--max-tokens", "20", HANG="1", SPAWN_CHILD="1", CHILD_MARKER=str(marker))
    assert process.returncode == 0
    assert result["stop"] == "token-limit"
    assert result["input_tokens"] == 20
    assert result["output_tokens"] == 8
    assert result["cache_write_tokens"] == 14
    # The child inherits stdout: returning before the test timeout also proves tree cleanup.
    import time
    time.sleep(3.2)
    assert not marker.exists()


@pytest.mark.parametrize("event", [
    {"type": "result", "subtype": "error_during_execution", "is_error": True,
     "result": "You've hit your usage limit. Try again later."},
    {"type": "error", "error": {"type": "rate_limit_error", "message": "Subscription usage limit reached"}},
])
def test_quota_message_becomes_quota_stop(run_driver, event):
    process, result, _ = run_driver([INIT, event], FAKE_EXIT="1")
    assert process.returncode == 0
    assert result["stop"] == "quota"


def test_nonzero_exit_is_reported(run_driver):
    process, result, _ = run_driver([INIT], FAKE_EXIT="7", FAKE_STDERR="synthetic failure")
    assert process.returncode != 0
    assert "7" in process.stderr
    assert "synthetic failure" in process.stderr
    assert result == {"schema": 1, "model": "fake-model"}


def test_cost_limit_stops_claude(run_driver):
    process, result, _ = run_driver([INIT, success(total_cost_usd=2)], "--max-cost-usd", "1", HANG="1")
    assert process.returncode == 0
    assert result["stop"] == "cost-limit"
    assert result["cost_kind"] == "estimate"


def test_error_result_is_not_success(run_driver):
    process, _, _ = run_driver([{"type": "result", "subtype": "error_during_execution",
                                "is_error": True, "result": "Synthetic tool failure"}])
    assert process.returncode != 0
    assert "Synthetic tool failure" in process.stderr


def test_missing_final_result_is_error(run_driver):
    process, _, _ = run_driver([INIT])
    assert process.returncode != 0
    assert "result" in process.stderr.lower()


def test_final_partial_usage_keeps_observed_fields(run_driver):
    process, result, _ = run_driver([
        INIT, {"type": "assistant", "message": {"usage": USAGE}},
        success(usage={"input_tokens": 15})])
    assert process.returncode == 0
    assert result["input_tokens"] == 15
    assert result["output_tokens"] == 4


def test_malformed_stream_is_reported(run_driver):
    process, _, _ = run_driver(["not an event"])
    assert process.returncode != 0
    assert "event" in process.stderr.lower()
