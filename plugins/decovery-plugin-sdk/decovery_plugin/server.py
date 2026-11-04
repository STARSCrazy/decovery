"""Stdio JSON-RPC server implementing the decovery plugin protocol (stdlib only)."""

from __future__ import annotations

import base64
import io
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

PROTOCOL = "decovery-plugin/1"
INLINE_LIMIT = 64 * 1024

METHOD_NOT_FOUND = -32601
CAPABILITY_NOT_SUPPORTED = -32001
CANCELLED = -32002
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INTERNAL_ERROR = -32603


class RpcError(Exception):
    """Raise from a handler to answer with a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_json(self) -> dict:
        error = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


class Cancelled(RpcError):
    """Raised by `Context.check_cancelled()`; answered with -32002."""

    def __init__(self) -> None:
        super().__init__(CANCELLED, "cancelled")


class Context:
    """Per-request handle: progress reporting and cancellation."""

    def __init__(self, request_id: Any, emit: Callable[[dict], None]):
        self.id = request_id
        self._emit = emit
        self._cancelled = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def wait_cancelled(self, timeout: float | None = None) -> bool:
        """Block until cancelled or `timeout` seconds pass; returns whether cancelled."""
        return self._cancelled.wait(timeout)

    def check_cancelled(self) -> None:
        if self.cancelled:
            raise Cancelled()

    def progress(self, done: int, total: int | None = None, message: str | None = None) -> None:
        params: dict[str, Any] = {"id": self.id, "done": done}
        if total is not None:
            params["total"] = total
        if message is not None:
            params["message"] = message
        self._emit({"jsonrpc": "2.0", "method": "$/progress", "params": params})


Handler = Callable[[dict, Context], Any]


class Plugin:
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self._methods: dict[str, Handler] = {}
        self._capabilities: dict[str, int] = {}

    def method(self, name: str, capability_version: int = 1) -> Callable[[Handler], Handler]:
        """Register `<capability>/<op>`; the capability's version is announced in `initialize`."""
        capability, sep, op = name.partition("/")
        if not sep or not capability or not op:
            raise ValueError(f"method name must be '<capability>/<op>': {name!r}")

        def register(handler: Handler) -> Handler:
            known = self._capabilities.get(capability)
            if known is not None and known != capability_version:
                raise ValueError(
                    f"capability {capability!r} already registered with version {known}, not {capability_version}"
                )
            self._capabilities[capability] = capability_version
            self._methods[name] = handler
            return handler

        return register

    def initialize_result(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "protocol": PROTOCOL,
            "capabilities": {c: {"version": v} for c, v in self._capabilities.items()},
        }

    def serve(self, stdin: io.TextIOBase | None = None, stdout: io.TextIOBase | None = None) -> None:
        """Blocking stdio loop. Returns after `shutdown` or end of input."""
        if stdin is None:
            stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
        if stdout is None:
            stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n", write_through=True)
        _Session(self, stdin, stdout).run()


class _Session:
    def __init__(self, plugin: Plugin, stdin: Any, stdout: Any):
        self.plugin = plugin
        self.stdin = stdin
        self.stdout = stdout
        self.write_lock = threading.Lock()
        self.contexts: dict[Any, Context] = {}
        self.workers: list[threading.Thread] = []

    def emit(self, message: dict) -> None:
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self.write_lock:
            self.stdout.write(line)
            self.stdout.flush()

    def reply(self, request_id: Any, result: Any = None, error: RpcError | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
        if error is not None:
            message["error"] = error.to_json()
        else:
            message["result"] = result
        self.emit(message)

    def run(self) -> None:
        for line in self.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError as exc:
                self.reply(None, error=RpcError(PARSE_ERROR, f"parse error: {exc}"))
                continue
            if not isinstance(message, dict) or not isinstance(message.get("method"), str):
                request_id = message.get("id") if isinstance(message, dict) else None
                if isinstance(message, dict) and "method" not in message and "id" in message:
                    continue  # stray response; requests flow host -> plugin only
                self.reply(request_id, error=RpcError(INVALID_REQUEST, "invalid request"))
                continue
            if self.dispatch(message):
                break
        self.finish()

    def dispatch(self, message: dict) -> bool:
        """Handle one message; returns True when the loop must end."""
        method = message["method"]
        params = message.get("params")
        if params is None:
            params = {}
        if "id" not in message:
            if method == "$/cancel" and isinstance(params, dict):
                context = self.contexts.get(params.get("id"))
                if context is not None:
                    context._cancelled.set()
            return False
        request_id = message["id"]
        if method == "initialize":
            self.reply(request_id, self.plugin.initialize_result())
            return False
        if method == "shutdown":
            self.reply(request_id, None)
            return True
        handler = self.plugin._methods.get(method)
        if handler is None:
            capability = method.partition("/")[0] if "/" in method else None
            if capability is not None and capability not in self.plugin._capabilities:
                error = RpcError(CAPABILITY_NOT_SUPPORTED, f"capability not supported: {capability}")
            else:
                error = RpcError(METHOD_NOT_FOUND, f"method not found: {method}")
            self.reply(request_id, error=error)
            return False
        context = Context(request_id, self.emit)
        self.contexts[request_id] = context  # registered before the worker starts, so $/cancel cannot miss it
        worker = threading.Thread(target=self.work, args=(handler, params, context), daemon=True)
        self.workers.append(worker)
        worker.start()
        return False

    def work(self, handler: Handler, params: Any, context: Context) -> None:
        try:
            try:
                result = handler(params, context)
            except RpcError as exc:
                self.reply(context.id, error=exc)
            except Exception as exc:  # handler bugs must not kill the server
                self.reply(context.id, error=RpcError(INTERNAL_ERROR, f"{type(exc).__name__}: {exc}"))
            else:
                self.reply(context.id, result)
        finally:
            self.contexts.pop(context.id, None)

    def finish(self) -> None:
        for context in list(self.contexts.values()):
            context._cancelled.set()
        deadline = time.monotonic() + 5
        for worker in self.workers:
            worker.join(max(0.0, deadline - time.monotonic()))


def decode_blob(blob: dict) -> bytes:
    """Bytes of a protocol blob. Path blobs are checked against their blake3 when the
    optional `blake3` package is installed (the standard library has no blake3)."""
    if "inline_base64" in blob:
        return base64.b64decode(blob["inline_base64"], validate=True)
    spec = blob["blob"]
    data = Path(spec["path"]).read_bytes()
    try:
        import blake3  # type: ignore[import-not-found]
    except ImportError:
        return data
    if blake3.blake3(data).hexdigest() != spec["blake3"]:
        raise RpcError(INTERNAL_ERROR, f"blake3 mismatch for {spec['path']}")
    return data


def inline_blob(data: bytes) -> dict:
    """Inline blob for data below 64 KiB; larger data must go through a file blob."""
    if len(data) >= INLINE_LIMIT:
        raise ValueError(f"{len(data)} bytes exceed the inline limit; write a file blob instead")
    return {"inline_base64": base64.b64encode(data).decode("ascii")}
