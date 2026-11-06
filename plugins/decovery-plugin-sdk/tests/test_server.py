import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from decovery_plugin import Plugin, RpcError  # noqa: E402


def run(plugin, *messages):
    """Feed messages (dicts) to a plugin over in-memory streams; return the parsed output lines."""
    stdin = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    stdout = io.StringIO()
    plugin.serve(stdin, stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def req(id_, method, params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


def by_id(lines, id_):
    return next(m for m in lines if m.get("id") == id_)


class ServerTests(unittest.TestCase):
    def make(self):
        plugin = Plugin("demo", "1.2.3")

        @plugin.method("echo/ping", capability_version=1)
        def ping(params, ctx):
            return params

        @plugin.method("analyzer/functions", capability_version=2)
        def functions(params, ctx):
            return []

        return plugin

    def test_initialize_lists_versioned_capabilities(self):
        out = run(self.make(), req(1, "initialize", {"protocol": "decovery-plugin/1", "host_version": "0"}))
        self.assertEqual(
            by_id(out, 1)["result"],
            {
                "name": "demo",
                "version": "1.2.3",
                "protocol": "decovery-plugin/1",
                "capabilities": {"echo": {"version": 1}, "analyzer": {"version": 2}},
            },
        )

    def test_initialize_declares_limits(self):
        plugin = self.make()
        plugin.set_limits("analyzer", max_parallel=4, memory_per_instance_mb=512)
        out = run(plugin, req(1, "initialize", {"protocol": "decovery-plugin/1", "host_version": "0"}))
        capabilities = by_id(out, 1)["result"]["capabilities"]
        self.assertEqual(
            capabilities["analyzer"],
            {"version": 2, "limits": {"max_parallel": 4, "memory_per_instance_mb": 512}},
        )
        self.assertEqual(capabilities["echo"], {"version": 1})  # no limits declared: the host assumes 1

    def test_limits_must_be_positive(self):
        with self.assertRaises(ValueError):
            Plugin("demo", "1").set_limits("a", max_parallel=0)

    def test_dispatches_registered_method(self):
        out = run(self.make(), req(1, "echo/ping", {"x": 1}))
        self.assertEqual(by_id(out, 1)["result"], {"x": 1})

    def test_unknown_capability_is_32001(self):
        out = run(self.make(), req(1, "nope/thing"))
        self.assertEqual(by_id(out, 1)["error"]["code"], -32001)

    def test_unknown_method_is_32601(self):
        out = run(self.make(), req(1, "echo/other"), req(2, "noslash"))
        self.assertEqual(by_id(out, 1)["error"]["code"], -32601)
        self.assertEqual(by_id(out, 2)["error"]["code"], -32601)

    def test_handler_errors(self):
        plugin = self.make()

        @plugin.method("echo/boom", capability_version=1)
        def boom(params, ctx):
            raise RpcError(-32000, "custom", {"k": 1})

        @plugin.method("echo/crash", capability_version=1)
        def crash(params, ctx):
            raise ValueError("bad")

        out = run(plugin, req(1, "echo/boom"), req(2, "echo/crash"))
        self.assertEqual(by_id(out, 1)["error"], {"code": -32000, "message": "custom", "data": {"k": 1}})
        self.assertEqual(by_id(out, 2)["error"]["code"], -32603)

    def test_progress_notifications_are_written(self):
        plugin = Plugin("demo", "1")

        @plugin.method("echo/work", capability_version=1)
        def work(params, ctx):
            ctx.progress(1, total=2, message="half")
            ctx.progress(2)
            return "done"

        out = run(plugin, req(7, "echo/work"))
        progress = [m for m in out if m.get("method") == "$/progress"]
        self.assertEqual(
            [m["params"] for m in progress],
            [{"id": 7, "done": 1, "total": 2, "message": "half"}, {"id": 7, "done": 2}],
        )
        self.assertNotIn("id", progress[0])
        self.assertEqual(by_id(out, 7)["result"], "done")

    def test_cancel_marks_context(self):
        plugin = Plugin("demo", "1")

        @plugin.method("echo/wait", capability_version=1)
        def wait(params, ctx):
            return {"cancelled": ctx.wait_cancelled(5)}

        out = run(plugin, req(3, "echo/wait"), {"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": 3}})
        self.assertEqual(by_id(out, 3)["result"], {"cancelled": True})

    def test_check_cancelled_answers_32002(self):
        plugin = Plugin("demo", "1")
        started = threading.Event()

        @plugin.method("echo/wait", capability_version=1)
        def wait(params, ctx):
            started.set()
            ctx.wait_cancelled(5)
            ctx.check_cancelled()
            return "not reached"

        out = run(plugin, req(3, "echo/wait"), {"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": 3}})
        self.assertEqual(by_id(out, 3)["error"]["code"], -32002)

    def test_shutdown_ends_loop(self):
        out = run(self.make(), req(1, "shutdown"), req(2, "echo/ping", {"x": 1}))
        self.assertEqual(by_id(out, 1)["result"], None)
        self.assertEqual([m for m in out if m.get("id") == 2], [])

    def test_shutdown_hooks_run_on_shutdown_and_end_of_input(self):
        for messages in ([req(1, "echo/ping"), req(2, "shutdown")], [req(1, "echo/ping")]):
            plugin = self.make()
            calls = []
            plugin.on_shutdown(lambda: calls.append("closed"))
            plugin.on_shutdown(lambda: 1 / 0)  # a failing hook does not stop the others
            plugin.on_shutdown(lambda: calls.append("second"))
            out = run(plugin, *messages)
            self.assertEqual(by_id(out, 1)["result"], {})
            self.assertEqual(calls, ["closed", "second"], messages)

    def test_capability_version_conflict_is_rejected(self):
        plugin = Plugin("demo", "1")
        plugin.method("a/x", capability_version=1)(lambda p, c: 1)
        with self.assertRaises(ValueError):
            plugin.method("a/y", capability_version=2)(lambda p, c: 1)


# A plugin process whose handler touches C-runtime fd 0 the way JNI_CreateJavaVM does (`_setmode` on the standard
# fds). The Windows C runtime holds a per-fd lock during a blocking read, so a server reading fd 0 itself would
# block the handler until the host sends another line; the host waits for the answer first.
STDIN_TOUCHING_PLUGIN = """
import msvcrt, os, sys, time
sys.path.insert(0, sys.argv[1])
from decovery_plugin import Plugin
plugin = Plugin("touch", "1")

@plugin.method("touch/stdin")
def touch(params, ctx):
    time.sleep(0.5)  # like the JVM's startup: the server is back in its read of the next line
    msvcrt.setmode(0, os.O_BINARY)
    return "ok"

plugin.serve()
"""


# A handler that starts a child process the way multiprocessing's spawn pools do. The child inherits the standard
# input; if that were the protocol pipe, the child would block on it while the server waits for the next line.
SPAWNING_PLUGIN = """
import multiprocessing, sys, time
sys.path.insert(0, sys.argv[1])
from decovery_plugin import Plugin
plugin = Plugin("spawn", "1")

@plugin.method("spawn/child")
def child(params, ctx):
    p = multiprocessing.get_context("spawn").Process(target=time.sleep, args=(0.1,))
    p.start()
    p.join(20)
    return p.exitcode

plugin.serve()
"""


# A handler that prints, and a spawned child that prints and writes to fd 1 directly: none of it may reach the
# protocol stream.
PRINTING_PLUGIN = """
import multiprocessing, os, sys
sys.path.insert(0, sys.argv[1])
from decovery_plugin import Plugin
plugin = Plugin("noisy", "1")

def child():
    print("child print")
    sys.stdout.flush()
    os.write(1, b"child fd 1\\n")

@plugin.method("noisy/print")
def noisy(params, ctx):
    print("handler print")
    os.write(1, b"handler fd 1\\n")
    p = multiprocessing.get_context("spawn").Process(target=child)
    p.start()
    p.join(20)
    return p.exitcode

if __name__ == "__main__":
    plugin.serve()
"""


def ask(proc, request, seconds):
    """Writes `request` and returns the parsed answer, or None when none comes within `seconds`."""
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    answer = []
    reader = threading.Thread(target=lambda: answer.append(proc.stdout.readline()), daemon=True)
    reader.start()
    reader.join(seconds)
    return json.loads(answer[0]) if answer else None


@unittest.skipUnless(sys.platform == "win32", "the C-runtime fd lock is a Windows behaviour")
class StdioProcessTests(unittest.TestCase):
    def test_spawned_child_does_not_block_on_protocol_pipe(self):
        sdk = os.path.join(os.path.dirname(__file__), "..")
        proc = subprocess.Popen(
            [sys.executable, "-c", SPAWNING_PLUGIN, sdk],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            encoding="utf-8",
        )
        try:
            answer = ask(proc, req(1, "spawn/child"), 30)
            self.assertIsNotNone(answer, "no answer within 30 s")
            self.assertEqual(answer["result"], 0, "the child did not end: it blocked on the protocol pipe")
            self.assertIsNotNone(ask(proc, req(2, "shutdown"), 10))
            self.assertEqual(proc.wait(10), 0)
        finally:
            proc.kill()
            proc.wait()
            proc.stdin.close()
            proc.stdout.close()

    def test_handler_touching_stdin_fd_does_not_block_on_pending_read(self):
        sdk = os.path.join(os.path.dirname(__file__), "..")
        proc = subprocess.Popen(
            [sys.executable, "-c", STDIN_TOUCHING_PLUGIN, sdk],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            encoding="utf-8",
        )
        try:
            proc.stdin.write(json.dumps(req(1, "touch/stdin")) + "\n")
            proc.stdin.flush()
            answer = []
            reader = threading.Thread(target=lambda: answer.append(proc.stdout.readline()), daemon=True)
            reader.start()
            reader.join(10)
            self.assertTrue(answer, "no answer within 10 s: the handler blocked on the server's read of fd 0")
            self.assertEqual(json.loads(answer[0])["result"], "ok")
            proc.stdin.write(json.dumps(req(2, "shutdown")) + "\n")
            proc.stdin.flush()
            self.assertEqual(proc.wait(10), 0)
        finally:
            proc.kill()
            proc.wait()
            proc.stdin.close()
            proc.stdout.close()


class StdoutGuardTests(unittest.TestCase):
    def test_worker_print_does_not_corrupt_protocol(self):
        sdk = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        script = os.path.join(tmp.name, "noisy_plugin.py")  # a file: spawned children import its `child`
        with open(script, "w", encoding="utf-8") as f:
            f.write(PRINTING_PLUGIN)
        proc = subprocess.Popen(
            [sys.executable, script, sdk],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
        try:
            out, err = proc.communicate(
                json.dumps(req(1, "noisy/print")) + "\n" + json.dumps(req(2, "shutdown")) + "\n", timeout=60
            )
        finally:
            proc.kill()
        lines = [json.loads(line) for line in out.splitlines()]  # every stdout line is a protocol message
        self.assertEqual(by_id(lines, 1)["result"], 0)
        for text in ("handler print", "handler fd 1", "child print", "child fd 1"):
            self.assertIn(text, err)  # what the code printed went to stderr (logs)


if __name__ == "__main__":
    unittest.main()
