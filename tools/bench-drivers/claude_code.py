#!/usr/bin/env python3
"""Claude Code print-mode adapter for ADR 0009 (Python standard library only)."""

import argparse
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


# All stream-json field paths live here (confirmed by the live step-1 run, Claude Code 2.1.327).
FIELDS = {
    "type": "type", "subtype": "subtype", "init": "init",
    "system": "system", "assistant": "assistant", "result": "result", "error": "error",
    "success": "success", "model": "model", "tools": "tools", "mcp_servers": "mcp_servers",
    "assistant_usage": "message.usage", "message_id": "message.id", "final_usage": "usage",
    "rate_limit_event": "rate_limit_event", "rate_limit_status": "rate_limit_info.status",
    "is_error": "is_error", "text": "result", "error_detail": "error",
    "cost_usd": "total_cost_usd", "turns": "num_turns",
    "usage": {"input_tokens": "input_tokens", "output_tokens": "output_tokens",
              "cache_write_tokens": "cache_creation_input_tokens",
              "cache_read_tokens": "cache_read_input_tokens"},
}
# Statuses of a rate_limit_event that mean no more calls are possible ("allowed" and
# warning statuses keep the run going).
RATE_LIMIT_STOPPED = {"rejected", "exhausted"}
SYSTEM_PROMPT = """You are recovering a function in an isolated decovery benchmark workspace.
Use only the supplied mcp__decovery__* tools. Submit source variants through
decovery build. Follow the task prompt and tool limits. Only decovery's build
verdict establishes an identical match; do not claim success without that verdict.
"""


def field(event, name):
    value = event
    for part in FIELDS[name].split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def usage_fields(usage):
    if usage is None:
        return {}
    if not isinstance(usage, dict):
        raise ValueError("usage must be an object")
    result = {}
    for target, source in FIELDS["usage"].items():
        value = usage.get(source)
        if value is not None:
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid token count: {source}")
            result[target] = value
    return result


def windows_kill_descendants(parent_pid):
    """Toolhelp fallback when taskkill cannot use its process enumeration service."""
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    children = {}
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        available = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while available:
            children.setdefault(entry.th32ParentProcessID, []).append(entry.th32ProcessID)
            available = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    pending = [parent_pid]
    descendants = []
    seen = {parent_pid}
    while pending:
        for pid in children.get(pending.pop(), []):
            if pid not in seen:
                seen.add(pid)
                descendants.append(pid)
                pending.append(pid)
    for pid in reversed(descendants):
        handle = kernel.OpenProcess(1, False, pid)  # PROCESS_TERMINATE
        if handle:
            try:
                kernel.TerminateProcess(handle, 1)
            finally:
                kernel.CloseHandle(handle)


def kill_tree(process):
    """Kill descendants too, including MCP servers that inherited stream handles."""
    try:
        if os.name == "nt":
            killed = subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False, timeout=10)
            if killed.returncode != 0:
                windows_kill_descendants(process.pid)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        pass
    if process.poll() is None:
        process.kill()
    process.wait()


def write_result(path, result):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(result, stream, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def limit_number(text):
    if text == "":
        return None
    value = float(text)
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("limit must be a finite non-negative number")
    return value


def token_limit(text):
    if text == "":
        return None
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("token limit must be non-negative")
    return value


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt", type=Path, required=True)
    parser.add_argument("--mcp-config", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, default=Path.cwd())
    parser.add_argument("--seed", default="", help="Recorded by the harness; Claude has no seed flag")
    parser.add_argument("--max-tokens", type=token_limit)
    parser.add_argument("--max-cost-usd", type=limit_number)
    parser.add_argument("--model")
    parser.add_argument("--claude", default="claude", help="CLI path; .py files use this Python interpreter")
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
    parser.add_argument("--profile-dir", type=Path, default=base / "decovery" / "claude-bench")
    return parser.parse_args()


def run(args, result):
    observed = {}
    counted = set()
    final = None
    failure = None
    # Temporary input files avoid blocking a pipe write while stdout fills.
    # stderr goes to disk independently, so a verbose child cannot deadlock stdout.
    with tempfile.TemporaryDirectory(prefix="decovery-bench-") as directory, \
            tempfile.TemporaryFile() as prompt, tempfile.TemporaryFile() as errors:
        system_prompt = Path(directory) / "system-prompt.md"
        system_prompt.write_text(SYSTEM_PROMPT, encoding="utf-8")
        prompt.write(args.prompt.read_bytes())
        prompt.seek(0)
        command = ([sys.executable, args.claude] if args.claude.lower().endswith(".py") else [args.claude])
        command += ["-p", "--input-format", "text", "--output-format", "stream-json", "--verbose",
                    "--strict-mcp-config", "--mcp-config", str(args.mcp_config.resolve()),
                    "--tools", "", "--allowedTools", "mcp__decovery__*", "--disable-slash-commands",
                    "--setting-sources", "project", "--no-session-persistence",
                    "--system-prompt-file", str(system_prompt)]
        if args.model:
            command += ["--model", args.model]
        if args.max_cost_usd is not None:
            command += ["--max-budget-usd", str(args.max_cost_usd)]
        environment = {**os.environ, "CLAUDE_CONFIG_DIR": str(args.profile_dir.resolve()),
                       "PYTHONUTF8": "1"}
        process = subprocess.Popen(command, cwd=args.workdir, env=environment,
                                   stdin=prompt, stdout=subprocess.PIPE, stderr=errors,
                                   text=True, encoding="utf-8", start_new_session=os.name != "nt")
        try:
            for number, line in enumerate(process.stdout, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict) or not isinstance(field(event, "type"), str):
                        raise ValueError("event must be an object with a type")
                    kind = field(event, "type")
                    if kind == FIELDS["system"] and field(event, "subtype") == FIELDS["init"]:
                        model = field(event, "model")
                        if isinstance(model, str):
                            result["model"] = model
                    message_id = field(event, "message_id")
                    if kind == FIELDS["assistant"] and (message_id is None or message_id not in counted):
                        if message_id is not None:
                            counted.add(message_id)  # one message, several content-block events
                        for key, value in usage_fields(field(event, "assistant_usage")).items():
                            observed[key] = observed.get(key, 0) + value
                        result.update(observed)
                    if kind == FIELDS["result"]:
                        final = event
                        result.update(usage_fields(field(event, "final_usage")))
                        model = field(event, "model")
                        if isinstance(model, str):
                            result["model"] = model
                        cost = field(event, "cost_usd")
                        if cost is not None:
                            if type(cost) not in (int, float) or not math.isfinite(cost) or cost < 0:
                                raise ValueError("invalid cost")
                            result.update(cost_usd=cost, cost_kind="estimate")
                        turns = field(event, "turns")
                        if turns is not None:
                            if type(turns) is not int or turns < 0:
                                raise ValueError("invalid turns")
                            result["turns"] = turns
                    if kind == FIELDS["rate_limit_event"]:
                        status = field(event, "rate_limit_status")
                        info = event.get("rate_limit_info")
                        if isinstance(info, dict):
                            # Last window state; the harness keeps unknown keys under driver_extra.
                            result["rate_limit"] = {key: info[key] for key in ("status", "unifiedWindows")
                                                    if key in info}
                        if isinstance(status, str) and status.lower() in RATE_LIMIT_STOPPED:
                            result["stop"] = "quota"
                    if kind == FIELDS["error"] or (kind == FIELDS["result"] and (
                            field(event, "is_error") or field(event, "subtype") != FIELDS["success"])):
                        detail = field(event, "text") or field(event, "error_detail") or field(event, "subtype")
                        message = json.dumps(detail, ensure_ascii=False).lower()
                        if any(phrase in message for phrase in (
                                "usage limit", "subscription limit", "quota", "rate_limit_error", "rate limit",
                                "you've hit your limit", "you have hit your limit")):
                            result["stop"] = "quota"
                        else:
                            failure = f"Claude error event: {detail}"
                    tokens = result.get("input_tokens", 0) + result.get("output_tokens", 0)
                    if "stop" not in result:
                        if args.max_tokens is not None and tokens > args.max_tokens:
                            result["stop"] = "token-limit"
                        elif args.max_cost_usd is not None and result.get("cost_usd", 0) > args.max_cost_usd:
                            result["stop"] = "cost-limit"
                    if "stop" in result or failure:
                        kill_tree(process)
                        break
                except (ValueError, TypeError) as error:
                    raise ValueError(f"stream event at line {number}: {error}") from error
            code = process.wait()
        finally:
            if process.poll() is None:
                kill_tree(process)
            process.stdout.close()
        errors.seek(0)
        diagnostic = errors.read().decode("utf-8", errors="replace")
        if diagnostic:
            print(diagnostic, file=sys.stderr, end="")
        if "stop" in result:
            return 0
        if code != 0:
            print(f"Claude exited with status {code}", file=sys.stderr)
            return 1
        if failure or final is None:
            print(failure or "Claude stream ended without a final result event", file=sys.stderr)
            return 1
        return 0


def main():
    args = arguments()
    result = {"schema": 1}
    try:
        return run(args, result)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Claude driver error: {error}", file=sys.stderr)
        return 1
    finally:
        write_result(args.result, result)


if __name__ == "__main__":
    sys.exit(main())
