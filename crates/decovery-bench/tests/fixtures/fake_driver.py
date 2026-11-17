"""A deterministic stdlib MCP test client. Never imports or invokes a model SDK/CLI."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--mcp", required=True)
parser.add_argument("--result", required=True)
parser.add_argument("--workdir", required=True)
args = parser.parse_args()
mode = os.environ.get("FAKE_MODE", "solve")
if mode == "hang":
    time.sleep(3)
    raise SystemExit(0)
if mode == "crash":
    raise SystemExit(7)
result = {"schema": 1, "model": "synthetic", "input_tokens": int(os.environ.get("FAKE_INPUT", "12")),
          "output_tokens": 3, "cache_read_tokens": 7, "cache_write_tokens": 2,
          "cost_usd": 0.001, "cost_kind": "estimate"}
if mode == "quota":
    marker = Path(os.environ["FAKE_QUOTA_MARKER"])
    if not marker.exists():
        marker.write_text("used", encoding="utf-8")
        result["stop"] = "quota"
        Path(args.result).write_text(json.dumps(result), encoding="utf-8")
        raise SystemExit(0)
    mode = "solve"
config = json.loads(Path(args.mcp).read_text(encoding="utf-8"))["mcpServers"]["decovery"]
child = subprocess.Popen([config["command"], *config["args"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=sys.stderr, text=True, encoding="utf-8", cwd=args.workdir)

def request(ident, method, params):
    child.stdin.write(json.dumps({"jsonrpc": "2.0", "id": ident, "method": method, "params": params}) + "\n")
    child.stdin.flush()
    while line := child.stdout.readline():
        answer = json.loads(line)
        if answer.get("id") == ident:
            return answer
    raise RuntimeError("MCP ended without a reply")

answers = []
try:
    request(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                              "clientInfo": {"name": "fake-bench", "version": "1"}})
    child.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    child.stdin.flush()
    calls = json.loads(os.environ.get("FAKE_CALLS", "[]")) if mode == "calls" else []
    if mode == "solve":
        calls = [{"name": "build", "arguments": {"function": "sub", "variants": [
            {"function_source": os.environ["FAKE_SOURCE"], "label": "proposed"}]}}]
    for ident, call in enumerate(calls, 2):
        answers.append(request(ident, "tools/call", call))
finally:
    child.stdin.close()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
result["calls"] = answers
Path(args.result).write_text(json.dumps(result), encoding="utf-8")
