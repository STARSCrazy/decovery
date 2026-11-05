import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

import asm  # noqa: E402

try:
    import unicorn  # noqa: F401
except ImportError:
    unicorn = None

from decovery_unicorn_dos import build_plugin  # noqa: E402
from decovery_unicorn_dos.pool import JobPool  # noqa: E402

PRELUDE = ["SET PATH=D:\\BINW"]


def run(plugin, *messages):
    """Feeds `messages` to the plugin and returns the answers by id."""
    stdin = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    stdout = io.StringIO()
    plugin.serve(stdin=stdin, stdout=stdout)
    answers = {}
    for line in stdout.getvalue().splitlines():
        message = json.loads(line)
        if "id" in message and "method" not in message:
            answers[message["id"]] = message
    return answers


def request(request_id, method, params=None):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}


def die(job):
    """Worker that ends its process: stands in for a crashed emulator."""
    os._exit(3)


class Workspace:
    def __init__(self, test):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.c = root / "build"
        self.d = root / "tools"
        self.c.mkdir()
        (self.d / "BINW").mkdir(parents=True)
        (self.d / "BINW" / "WRITER.EXE").write_bytes(asm.write_file_program())
        (self.d / "BINW" / "LOOP.EXE").write_bytes(asm.loop_program())
        (self.d / "BINW" / "BAD.EXE").write_bytes(asm.call_program(0x99))
        (self.d / "BINW" / "REAL.EXE").write_bytes(asm.plain_mz())

    def params(self, *jobs, timeout_s=10.0):
        return {
            "mounts": [
                {"drive": "C", "path": str(self.c), "writable": True},
                {"drive": "D", "path": str(self.d), "writable": False},
            ],
            "current_drive": "C",
            "timeout_s": timeout_s,
            "jobs": [{"commands": list(commands)} for commands in jobs],
        }


class PluginProtocolTest(unittest.TestCase):
    def test_initialize_announces_runner_v1(self):
        answers = run(build_plugin(), request(1, "initialize"), request(2, "shutdown"))
        result = answers[1]["result"]
        self.assertEqual(result["name"], "unicorn-dos")
        self.assertEqual(result["capabilities"], {"runner": {"version": 1}})

    def test_unsupported_program_is_refused_before_any_job(self):
        ws = Workspace(self)
        params = ws.params(PRELUDE + ["WRITER"], PRELUDE + ["REAL"])
        answers = run(build_plugin(), request(1, "runner/run", params))
        self.assertEqual(answers[1]["error"]["code"], -32020)
        self.assertFalse((ws.c / "OUT.TXT").exists())

    def test_invalid_params(self):
        answers = run(build_plugin(), request(1, "runner/run", {"jobs": "x"}))
        self.assertEqual(answers[1]["error"]["code"], -32602)


@unittest.skipIf(unicorn is None, "unicorn not installed")
class PluginRunTest(unittest.TestCase):
    def setUp(self):
        self.machines = []

        def factory(p3):
            from decovery_unicorn_dos.pharlap import Machine

            machine = Machine(p3)
            self.machines.append(machine)
            return machine

        self.factory = factory

    def test_runs_jobs_in_worker_processes(self):
        ws = Workspace(self)
        params = ws.params(
            PRELUDE + ["WRITER -x A.C"],
            ["SET PATH=D:\\BINW", "@ECHO OFF", "ECHO before", "BAD"],
        )
        plugin = build_plugin()
        answers = run(plugin, request(1, "runner/run", params))
        jobs = answers[1]["result"]["jobs"]
        self.assertEqual(jobs[0]["status"], "done")
        self.assertEqual(jobs[0]["exit_code"], 3)
        self.assertEqual(jobs[0]["stdout"], "C:\\>SET PATH=D:\\BINW\r\nC:\\>WRITER -x A.C\r\nOK")
        self.assertIsNone(jobs[0]["message"])
        self.assertEqual((ws.c / "OUT.TXT").read_bytes(), b"OK")
        self.assertEqual(jobs[1]["status"], "failed")
        self.assertIsNone(jobs[1]["exit_code"])
        self.assertTrue(jobs[1]["message"].startswith("unsupported INT 21h AH=99h at 000C:00001002"))
        self.assertEqual(jobs[1]["stdout"], "C:\\>SET PATH=D:\\BINW\r\nbefore\r\n")

    def test_machine_is_reused_between_jobs(self):
        ws = Workspace(self)
        params = ws.params(PRELUDE + ["WRITER"], PRELUDE + ["WRITER", "WRITER"])
        answers = run(build_plugin(self.factory), request(1, "runner/run", params))
        jobs = answers[1]["result"]["jobs"]
        self.assertEqual([j["exit_code"] for j in jobs], [3, 3])
        self.assertEqual(len(self.machines), 1)
        self.assertEqual(self.machines[0].runs, 2)  # the job ends at the first non-zero exit code

    def test_timeout_and_later_jobs(self):
        ws = Workspace(self)
        params = ws.params(PRELUDE + ["LOOP"], PRELUDE + ["WRITER"], timeout_s=0.3)
        answers = run(build_plugin(self.factory), request(1, "runner/run", params))
        jobs = answers[1]["result"]["jobs"]
        self.assertEqual(jobs[0]["status"], "timeout")
        self.assertIsNone(jobs[0]["exit_code"])
        self.assertIn("no end after 0.3 s", jobs[0]["message"])
        self.assertEqual(jobs[1]["status"], "done")

    def test_missing_program_fails_the_job(self):
        ws = Workspace(self)
        answers = run(build_plugin(self.factory), request(1, "runner/run", ws.params(PRELUDE + ["NOPE A.C"])))
        job = answers[1]["result"]["jobs"][0]
        self.assertEqual(job["status"], "failed")
        self.assertIn("NOPE", job["message"])

    def test_broken_worker_fails_the_job(self):
        pool = JobPool(workers=1, worker=die)
        self.addCleanup(pool.close)
        outcomes = pool.run([{"steps": []}])
        self.assertEqual(outcomes[0]["status"], "failed")
        self.assertIn("worker process", outcomes[0]["message"])


if __name__ == "__main__":
    unittest.main()
