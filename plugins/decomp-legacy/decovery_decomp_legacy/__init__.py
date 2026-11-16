"""decovery plugin bridging to Decomp (capability `legacy` v1, ADR 0007). See README.md.

`legacy/run` refreshes a shadow Decomp workspace from decovery's sources and names, makes sure one Decomp server
(tool 40) runs on it, runs the one Decomp command its operation maps to through the CLI (which forwards to the
server), and maps the command's output and result files to the protocol's result.
"""

from __future__ import annotations

import importlib
import threading
import time
from pathlib import Path
from typing import Any, Callable

from decovery_plugin import Cancelled, Context, Plugin, RpcError

from . import names as N
from . import shadow as S
from .params import COMMANDS, INVALID_PARAMS, OPTIONS, WORKSPACE_INVALID, Run, parse_run
from .process import CliCall, DecompServer, ServerError, kill_tree
from .results import collect

__all__ = ["COMMANDS", "OPTIONS", "build_plugin", "parse_run"]

__version__ = "0.1.0"

LEGACY_VERSION = 1
MAX_PARALLEL = 2
MEMORY_PER_INSTANCE_MB = 3000
HEARTBEAT_S = 5.0
DECOMP_UNAVAILABLE = -32020
COMMAND_FAILED = -32022
REPORT_LANGUAGE = "de"
FORWARD_NOTE = "Hinweis: läuft über den MCP-Server"  # Decomp CLI's stderr line when it forwards to the server
NEEDS_BUILD = ("equivalence", "behavior")  # operations that read the object file of Decomp's last build


class _Shadow:
    """Per shadow: its server and the runs in flight (a cancelled run leaves its command running inside the
    server, so the server is restarted once no run uses it any more)."""

    def __init__(self, path: Path):
        self.server = DecompServer(path)
        self.active = 0
        self.dirty = False
        self.idle = threading.Condition()
        self.build = threading.Lock()  # one `nachbau bauen` at a time: parallel runs build a file once


def _check_decomp() -> None:
    for module in ("decomp", "decomp.wissen", "decomp.adressen", "decomp.nachbau.ergebnis"):
        try:
            importlib.import_module(module)
        except Exception as exc:
            raise RpcError(DECOMP_UNAVAILABLE,
                           f"Decomp unavailable: import {module} failed ({type(exc).__name__}: {exc}); run this plugin "
                           "with the Python of a Decomp checkout (decovery setup decomp-legacy --decomp <checkout>)")


def _in_thread(ctx: Context, message: str, work: Callable[[], Any]) -> Any:
    """Run `work` with a heartbeat every HEARTBEAT_S seconds (copying a Ghidra project takes a while)."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = work()
        except BaseException as exc:  # handed to the request thread
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    begin = time.monotonic()
    while True:
        thread.join(HEARTBEAT_S)
        if not thread.is_alive():
            break
        ctx.progress(int(time.monotonic() - begin), message=message)
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _progress_message(call: CliCall, sh: _Shadow, log_from: int, operation: str) -> str:
    """The CLI's last stderr line; while it only forwards to the server (its one line is the forwarding note), the
    server log's last line written since the command started, where the command's own progress goes. Older log
    lines (such as the server's `bereit …`) are not this command's progress."""
    line = call.last_line
    if line and not line.startswith(FORWARD_NOTE):
        return line
    return sh.server.last_log_line(log_from) or f"Decomp {operation} running"


def build_plugin() -> Plugin:
    plugin = Plugin("decomp-legacy", __version__)
    plugin.set_limits("legacy", max_parallel=MAX_PARALLEL, memory_per_instance_mb=MEMORY_PER_INSTANCE_MB)
    shadows: dict[Path, _Shadow] = {}
    setup_lock = threading.Lock()  # shadow refresh and server start, one at a time
    slots = threading.BoundedSemaphore(MAX_PARALLEL)

    def shadow_for(path: Path) -> _Shadow:
        key = path.resolve()
        with setup_lock:
            return shadows.setdefault(key, _Shadow(key))

    def prepare(run: Run, sh: _Shadow, ctx: Context) -> dict:
        """Refresh the shadow and start its server; called under `setup_lock`."""
        copy = S.ghidra_needs_copy(run.decomp_workspace, run.shadow_dir)
        if copy:
            # the server holds the shadow's Ghidra project: wait for the other runs, then stop it
            with sh.idle:
                while sh.active > 0:
                    sh.idle.wait(HEARTBEAT_S)
                    ctx.progress(0, message="waiting for other runs before copying the Ghidra project")
                    ctx.check_cancelled()
            sh.server.stop()
        result, state = _in_thread(ctx, "refreshing the shadow workspace (copying the Ghidra project)" if copy
                                   else "refreshing the shadow workspace",
                                   lambda: S.refresh(run.decomp_workspace, run.shadow_dir, run.sources_dir, copy))
        wissen = run.shadow_dir / "wissen"
        mark = N.fingerprint(run.symbols, wissen)
        if state.get("names") != mark:
            result.changed += N.write_names(wissen, run.symbols)
            state["names"] = N.fingerprint(run.symbols, wissen)
        S.save_state(run.shadow_dir, state)
        ctx.check_cancelled()
        kill_if_dirty(sh)
        try:
            sh.server.ensure(lambda message: ctx.progress(0, message=message))
        except ServerError as exc:
            raise RpcError(DECOMP_UNAVAILABLE, str(exc)) from exc
        return {"refreshed": result.refreshed, "ghidra_copied": result.ghidra_copied}

    def kill_if_dirty(sh: _Shadow) -> None:
        """A cancelled or timed-out command still runs inside the server: kill the server once no run uses it (the
        next run starts a fresh one). Called under `setup_lock`."""
        with sh.idle:
            restart = sh.dirty and sh.active == 0
            if restart:
                sh.dirty = False
        if restart:
            sh.server.kill()

    def finish_run(sh: _Shadow) -> None:
        with sh.idle:
            sh.active -= 1
            sh.idle.notify_all()
        if setup_lock.acquire(blocking=False):  # otherwise the run being prepared does it
            try:
                kill_if_dirty(sh)
            finally:
                setup_lock.release()

    @plugin.method("legacy/run", capability_version=LEGACY_VERSION)
    def run_method(params: dict, ctx: Context) -> dict:
        began = time.monotonic()
        started_wall = time.time()
        run = parse_run(params)
        _check_decomp()
        sh = shadow_for(run.shadow_dir)
        with slots:
            ctx.check_cancelled()
            with setup_lock:
                shadow_info = prepare(run, sh, ctx)
                with sh.idle:
                    sh.active += 1
            try:
                return execute(run, sh, ctx, began, started_wall, shadow_info)
            finally:
                finish_run(sh)

    def wait_for(run: Run, sh: _Shadow, ctx: Context, began: float, args: list[str], label: str) -> tuple[bytes, int]:
        """Run one Decomp CLI command on the shadow with heartbeats, cancellation and the run's timeout (counted from
        `began`); returns (stdout, 0) or raises."""
        log_from = sh.server.log_size()
        call = CliCall(run.shadow_dir, args)
        last_beat = time.monotonic()
        while call.proc.poll() is None:
            if ctx.wait_cancelled(0.25):
                kill_tree(call.proc)
                call.finish()
                with sh.idle:
                    sh.dirty = True
                raise Cancelled()
            elapsed = time.monotonic() - began
            if run.timeout_s is not None and elapsed > run.timeout_s:
                kill_tree(call.proc)
                call.finish()
                with sh.idle:
                    sh.dirty = True
                raise RpcError(COMMAND_FAILED, f"Decomp command timed out after {run.timeout_s:g} s",
                               {"exit_code": None, "stderr_tail": call.stderr_tail(), "timed_out": True})
            if time.monotonic() - last_beat >= HEARTBEAT_S:
                ctx.progress(int(elapsed), message=_progress_message(call, sh, log_from, label))
                last_beat = time.monotonic()
        stdout, _ = call.finish()
        code = call.proc.returncode
        if code != 0:
            raise RpcError(COMMAND_FAILED, f"Decomp command failed with exit code {code}: "
                           f"{(call.last_line or '').strip()}", {"exit_code": code, "stderr_tail": call.stderr_tail()})
        return stdout, code

    def build_first(run: Run, sh: _Shadow, ctx: Context, began: float) -> None:
        """`equivalence` and `behavior` read the object file of Decomp's last build: build the function's source file
        on the shadow first, unless it was built from the same sources before (state `built`)."""
        datei = S.function_file(run.shadow_dir, run.function)
        if datei is None:
            return  # Decomp names the missing build itself
        with sh.build:
            mark = S.build_fingerprint(run.shadow_dir)
            with setup_lock:
                if S.load_state(run.shadow_dir).get("built", {}).get(datei) == mark:
                    return
            ctx.progress(int(time.monotonic() - began), message=f"Decomp build: {datei}")
            wait_for(run, sh, ctx, began, ["nachbau", "bauen", datei], f"build {datei}")
            with setup_lock:
                state = S.load_state(run.shadow_dir)
                state.setdefault("built", {})[datei] = mark
                S.save_state(run.shadow_dir, state)

    def execute(run: Run, sh: _Shadow, ctx: Context, began: float, started_wall: float, shadow_info: dict) -> dict:
        run_dir = run.shadow_dir / "cache" / "legacy-runs" / f"{time.strftime('%Y%m%d-%H%M%S')}-{ctx.id}"
        json_path = None
        if run.operation == "registers":
            run_dir.mkdir(parents=True, exist_ok=True)
            json_path = run_dir / "registers.json"
        if run.operation in NEEDS_BUILD:
            build_first(run, sh, ctx, began)
        stdout, code = wait_for(run, sh, ctx, began, run.command(json_path), run.operation)
        name = N.result_name(run.shadow_dir / "wissen", run.function)
        mapped = collect(run.operation, run.shadow_dir, name, stdout, started_wall, json_path)
        return {
            "exit_code": code,
            "report": mapped["report"],
            "report_language": REPORT_LANGUAGE,
            "json": mapped["json"],
            "candidate": mapped["candidate"],
            "artifacts": mapped["artifacts"],
            "shadow": shadow_info,
            "seconds": round(time.monotonic() - began, 3),
        }

    @plugin.on_shutdown
    def stop_servers() -> None:
        for sh in list(shadows.values()):
            sh.server.stop()

    return plugin


# re-exported for tests and callers that check codes
ERRORS = {"invalid_params": INVALID_PARAMS, "decomp_unavailable": DECOMP_UNAVAILABLE,
          "workspace_invalid": WORKSPACE_INVALID, "command_failed": COMMAND_FAILED}
