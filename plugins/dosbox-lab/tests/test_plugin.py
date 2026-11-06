import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_dosbox_lab import Backend, BatchResult, build_plugin, build_script, parse_output  # noqa: E402
from decovery_dosbox_lab.backend import BACKEND_UNAVAILABLE, BackendError, DosboxLabBackend  # noqa: E402


def run(plugin, *messages):
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


class FakeBackend(Backend):
    """Records the calls and the batch file as it is while the backend runs; answers with `reply`."""

    def __init__(self, reply):
        self.reply = reply
        self.calls = []
        self.scripts = []

    def run_batch(self, mounts, command, timeout_s):
        self.calls.append((mounts, command, timeout_s))
        self.scripts.append((mounts[0].path / command).read_bytes().decode("cp437"))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class Workspace:
    def __init__(self, test):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.c = root / "build"
        self.d = root / "tools"
        self.c.mkdir()
        self.d.mkdir()

    def params(self, *jobs, timeout_s=10.0):
        return {
            "mounts": [
                {"drive": "D", "path": str(self.d), "writable": False},
                {"drive": "C", "path": str(self.c), "writable": True},
            ],
            "current_drive": "C",
            "timeout_s": timeout_s,
            "jobs": [{"commands": list(commands)} for commands in jobs],
        }


def serve(test, backend, params):
    plugin = build_plugin(lambda: backend)
    return run(plugin, request(1, "runner/run", params))[1]


class ProtocolTest(unittest.TestCase):
    def test_initialize_announces_runner_v1(self):
        answers = run(build_plugin(), request(1, "initialize"), request(2, "shutdown"))
        result = answers[1]["result"]
        self.assertEqual(result["name"], "dosbox-lab")
        self.assertEqual(result["capabilities"], {"runner": {"version": 1}})

    def test_invalid_params(self):
        answers = run(build_plugin(), request(1, "runner/run", {"jobs": "x"}))
        self.assertEqual(answers[1]["error"]["code"], -32602)

    def test_read_only_current_drive_is_invalid(self):
        ws = Workspace(self)
        params = ws.params(["ECHO x"])
        params["current_drive"] = "D"
        answers = run(build_plugin(lambda: FakeBackend(None)), request(1, "runner/run", params))
        self.assertEqual(answers[1]["error"]["code"], -32602)


class RunTest(unittest.TestCase):
    def test_jobs_run_in_one_batch(self):
        ws = Workspace(self)
        backend = FakeBackend(
            BatchResult(
                "done",
                "DECOVERY-JOB-0\r\nDECOVERY-JOB-0-END\r\nDECOVERY-JOB-1\r\nDECOVERY-JOB-1-END\r\n",
            )
        )
        answer = serve(self, backend, ws.params(["SET PATH=D:\\BIN", "WCC386 A.C"], ["TCC B.C"], timeout_s=5))
        self.assertEqual(len(backend.calls), 1)
        mounts, command, timeout_s = backend.calls[0]
        self.assertEqual(command, "NB.BAT")
        self.assertEqual(timeout_s, 10)  # per-job limit times the number of jobs
        self.assertEqual([(m.drive, m.read_only) for m in mounts], [("C", False), ("D", True)])
        script = backend.scripts[0]
        self.assertIn("@ECHO DECOVERY-JOB-0\r\n", script)
        self.assertIn("@ECHO DECOVERY-JOB-1\r\n", script)
        self.assertIn("SET PATH=D:\\BIN\r\nCALL WCC386 A.C\r\nIF ERRORLEVEL 1 GOTO F0\r\n", script)
        self.assertIn("CALL TCC B.C\r\nIF ERRORLEVEL 1 GOTO F1\r\n", script)
        self.assertNotIn("CALL SET", script)
        self.assertEqual([j["status"] for j in answer["result"]["jobs"]], ["done", "done"])
        self.assertFalse((ws.c / "NB.BAT").exists())  # removed again

    def test_per_job_exit_codes(self):
        ws = Workspace(self)
        stdout = (
            "DECOVERY-JOB-0\r\nOK\r\nDECOVERY-JOB-0-END\r\n"
            "DECOVERY-JOB-1\r\nboom\r\nDECOVERY-EXIT-3-FAILED\r\n"
            "DECOVERY-JOB-2\r\nno newline" "DECOVERY-JOB-2-END\r\n"
        )
        answer = serve(self, FakeBackend(BatchResult("done", stdout)), ws.params(["A"], ["B"], ["C"]))
        jobs = answer["result"]["jobs"]
        self.assertEqual(jobs[0], {"status": "done", "exit_code": 0, "stdout": "OK\r\n", "message": None})
        self.assertEqual(jobs[1], {"status": "done", "exit_code": 3, "stdout": "boom\r\n", "message": None})
        self.assertEqual(jobs[2], {"status": "done", "exit_code": 0, "stdout": "no newline", "message": None})

    def test_timeout_status(self):
        ws = Workspace(self)
        stdout = "DECOVERY-JOB-0\r\nDECOVERY-JOB-0-END\r\nDECOVERY-JOB-1\r\nhang"
        answer = serve(self, FakeBackend(BatchResult("timeout", stdout)), ws.params(["A"], ["B"], ["C"], timeout_s=2))
        jobs = answer["result"]["jobs"]
        self.assertEqual(jobs[0]["status"], "done")
        self.assertEqual(jobs[1]["status"], "timeout")
        self.assertIsNone(jobs[1]["exit_code"])
        self.assertEqual(jobs[1]["stdout"], "hang")
        self.assertIn("no end after 2 s", jobs[1]["message"])
        self.assertEqual(jobs[2]["status"], "failed")
        self.assertIn("not run", jobs[2]["message"])

    def test_crashed_batch_fails_unfinished_jobs(self):
        ws = Workspace(self)
        answer = serve(self, FakeBackend(BatchResult("crashed", "DECOVERY-JOB-0\r\nx", "emulator died")), ws.params(["A"]))
        job = answer["result"]["jobs"][0]
        self.assertEqual(job["status"], "failed")
        self.assertIn("emulator died", job["message"])

    def test_backend_unavailable_is_error_32010(self):
        ws = Workspace(self)
        backend = FakeBackend(BackendError(BACKEND_UNAVAILABLE, "dosbox-lab is not installed"))
        answer = serve(self, backend, ws.params(["A"]))
        self.assertEqual(answer["error"]["code"], -32010)
        self.assertIn("not installed", answer["error"]["message"])
        self.assertFalse((ws.c / "NB.BAT").exists())

    def test_missing_package_is_unavailable(self):
        ws = Workspace(self)
        try:
            import dosbox_lab  # noqa: F401
        except ImportError:
            pass
        else:
            self.skipTest("dosbox_lab is installed")
        answer = run(build_plugin(), request(1, "runner/run", ws.params(["A"])))[1]
        self.assertEqual(answer["error"]["code"], -32010)


class ScriptTest(unittest.TestCase):
    def test_ladder_reports_exact_errorlevel(self):
        script = build_script([["A"]], "C")
        self.assertIn("IF ERRORLEVEL 255 GOTO E255\r\n", script)
        self.assertIn(":E3\r\n@ECHO DECOVERY-EXIT-3-FAILED\r\nGOTO N%DJ%\r\n", script)
        self.assertIn(":E1\r\n@ECHO DECOVERY-EXIT-1-FAILED\r\n", script)

    def test_parse_ignores_unknown_job_numbers(self):
        jobs = parse_output("DECOVERY-JOB-7\r\nx\r\nDECOVERY-JOB-7-END\r\n", 1)
        self.assertEqual(jobs, [{"started": False, "exit_code": None, "stdout": ""}])

    def test_real_backend_without_package_names_setup(self):
        try:
            import dosbox_lab  # noqa: F401
        except ImportError:
            pass
        else:
            self.skipTest("dosbox_lab is installed")
        with self.assertRaises(BackendError) as caught:
            DosboxLabBackend().run_batch([], "NB.BAT", 1.0)
        self.assertEqual(caught.exception.code, BACKEND_UNAVAILABLE)
        self.assertIn("decovery setup dosbox-lab", caught.exception.message)


if __name__ == "__main__":
    unittest.main()
