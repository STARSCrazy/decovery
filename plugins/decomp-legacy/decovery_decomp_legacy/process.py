"""Decomp subprocesses: the per-shadow server (Decomp tool 40) and the CLI calls forwarded to it."""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

SERVER_FILE = "fernzugang.json"  # Decomp's `fernzugang.DATEI`, in <shadow>/cache
SERVER_LOG = "legacy-server.log"  # in <shadow>/cache
START_TIMEOUT_S = 300
STOP_GRACE_S = 60


def python() -> str:
    """The Python that runs Decomp: this plugin runs under the Decomp checkout's venv (ADR 0007, decision 1)."""
    return sys.executable


def environment() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("DECOMP_WATCOM_EMU", "1")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def popen(args: list[str], cwd: Path, env: dict[str, str], stdout, stderr) -> subprocess.Popen:
    """A child in its own process group, so `kill_tree` reaches everything it starts."""
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, **kwargs)


def kill_tree(proc: subprocess.Popen) -> None:
    """Kill `proc` and its children (a venv python.exe on Windows only starts the real interpreter as a child)."""
    if proc.poll() is None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            import signal

            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _request(info: dict, command: str, timeout: float = 5.0) -> dict:
    """One request of Decomp's server protocol: a JSON line {token, befehl, args, kwargs}, a JSON line back."""
    message = {"token": info["token"], "befehl": command, "args": [], "kwargs": {}}
    with socket.create_connection(("127.0.0.1", int(info["port"])), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall((json.dumps(message) + "\n").encode("utf-8"))
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8"))


def _read_info(path: Path) -> dict | None:
    try:
        info = json.loads(path.read_text(encoding="utf-8"))
        int(info["port"]), str(info["token"]), int(info["pid"])
        return info
    except (OSError, ValueError, KeyError, TypeError):
        return None


def ping(info: dict) -> bool:
    try:
        return _request(info, "ping").get("ok") == "pong"
    except (OSError, ValueError):
        return False


class ServerError(Exception):
    pass


class DecompServer:
    """`python -m decomp --bereich <shadow> mcp --nur-fernzugang --eltern <pid>` for one shadow. A server that
    already answers in `cache/fernzugang.json` (another plugin process on the same shadow) is used, not started
    and not stopped."""

    def __init__(self, shadow: Path):
        self.shadow = shadow
        self.info_path = shadow / "cache" / SERVER_FILE
        self.log_path = shadow / "cache" / SERVER_LOG
        self.proc: subprocess.Popen | None = None
        self.tag = secrets.token_hex(8)
        self._log = None

    def _info(self) -> dict | None:
        return _read_info(self.info_path)

    def running(self) -> bool:
        info = self._info()
        if info is None or not ping(info):
            return False
        if self.proc is not None and self.proc.poll() is not None:
            return False
        return True

    def ensure(self, heartbeat: Callable[[str], None], timeout_s: float = START_TIMEOUT_S) -> None:
        if self.running():
            return
        self.kill()
        self.info_path.parent.mkdir(parents=True, exist_ok=True)
        self.info_path.unlink(missing_ok=True)  # stale: no server answers
        self._log = self.log_path.open("a", encoding="utf-8")
        self._log.write(f"\n=== server start {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        self._log.flush()
        args = [python(), "-m", "decomp", "--bereich", str(self.shadow), "mcp", "--nur-fernzugang",
                "--eltern", str(os.getpid())]
        env = dict(environment(), DECOMP_FERN_KENNUNG=self.tag)
        self.proc = popen(args, self.shadow, env, self._log, self._log)
        deadline = time.monotonic() + timeout_s
        last_beat = 0.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                code = self.proc.returncode
                self.kill()
                raise ServerError(f"Decomp server ended at start (exit code {code}): {self.log_tail()}")
            info = self._info()
            if info is not None and info.get("kennung") == self.tag and ping(info):
                return
            if time.monotonic() - last_beat >= 5:
                heartbeat("starting the Decomp server")
                last_beat = time.monotonic()
            time.sleep(0.2)
        self.kill()
        raise ServerError(f"Decomp server not ready after {timeout_s:g} s: {self.log_tail()}")

    def log_tail(self, lines: int = 20) -> str:
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return "\n".join(text.splitlines()[-lines:])

    def last_log_line(self) -> str | None:
        try:
            with self.log_path.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 4096))
                tail = f.read().decode("utf-8", errors="replace")
        except OSError:
            return None
        for line in reversed(tail.splitlines()):
            if line.strip():
                return line.strip()
        return None

    def stop(self, grace_s: float = STOP_GRACE_S) -> None:
        """Ask our own server to end (`beenden`: it finishes running commands and closes Ghidra), kill it after
        `grace_s`."""
        proc = self.proc
        if proc is None:
            return
        info = self._info()
        if info is not None and info.get("kennung") == self.tag and proc.poll() is None:
            try:
                _request(info, "beenden")
            except (OSError, ValueError):
                pass
        try:
            proc.wait(timeout=grace_s)
        except subprocess.TimeoutExpired:
            pass
        self.kill()

    def kill(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None:
            kill_tree(proc)
            info = self._info()
            if info is not None and info.get("kennung") == self.tag:
                self.info_path.unlink(missing_ok=True)
        if self._log is not None:
            self._log.close()
            self._log = None


class CliCall:
    """One `python -m decomp --bereich <shadow> ...` call; stdout and stderr collected by threads."""

    def __init__(self, shadow: Path, args: list[str]):
        self.proc = popen([python(), "-m", "decomp", "--bereich", str(shadow), *args], shadow, environment(),
                          subprocess.PIPE, subprocess.PIPE)
        self._out: list[bytes] = []
        self._err: deque[str] = deque(maxlen=200)
        self.last_line: str | None = None
        self._threads = [threading.Thread(target=self._read_out, daemon=True),
                         threading.Thread(target=self._read_err, daemon=True)]
        for t in self._threads:
            t.start()

    def _read_out(self) -> None:
        assert self.proc.stdout is not None
        for chunk in iter(lambda: self.proc.stdout.read(65536), b""):
            self._out.append(chunk)

    def _read_err(self) -> None:
        assert self.proc.stderr is not None
        for raw in self.proc.stderr:
            line = raw.decode("utf-8", errors="replace").rstrip()
            self._err.append(line)
            if line.strip():
                self.last_line = line.strip()

    def finish(self) -> tuple[str, str]:
        for t in self._threads:
            t.join(10)
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                stream.close()
        return b"".join(self._out).decode("utf-8", errors="replace"), "\n".join(self._err)

    def stderr_tail(self, lines: int = 30) -> str:
        return "\n".join(list(self._err)[-lines:])
