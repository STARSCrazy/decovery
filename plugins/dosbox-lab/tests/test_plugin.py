import io
import json
import os
import re
import sys
import threading
import time
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_dosbox_lab import (  # noqa: E402
    MEMORY_PER_INSTANCE_MB,
    Backend,
    BatchResult,
    build_plugin,
    build_script,
    parse_output,
    split_jobs,
)
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


def run_open(plugin, message):
    """Like `run` for one request, but the input stays open until the answer is written (end of input cancels the
    running requests)."""
    answered = threading.Event()

    class Output(io.StringIO):
        def write(self, text):
            written = super().write(text)
            if '"result"' in text or '"error"' in text:
                answered.set()
            return written

    def lines():
        yield json.dumps(message) + "\n"
        answered.wait(30)

    stdout = Output()
    plugin.serve(stdin=lines(), stdout=stdout)
    return json.loads(stdout.getvalue().splitlines()[-1])


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


class ScriptBackend(Backend):
    """Plays each batch file: echoes its job begin/end markers in order (every job succeeds). Records per call the
    script name, the job numbers in run order, the script text, what the TMP directory held, and how many calls ran
    at the same time. `stop_in` maps a job number to a batch status: the batch stops there (once) with that status."""

    def __init__(self, delay=0.2, stop_in=None):
        self.delay = delay
        self.stop_in = dict(stop_in or {})
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.calls = []

    def run_batch(self, mounts, command, timeout_s):
        script = (mounts[0].path / command).read_bytes().decode("cp437")
        tmp = re.search(r"SET TMP=C:\\(\w+)", script).group(1)
        tmp_files = sorted(f.name for f in (mounts[0].path / tmp).iterdir())
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(self.delay)
        out, order, status = [], [], "done"
        for line in script.split("\r\n"):
            marker = re.fullmatch(r"@ECHO (DECOVERY-JOB-(\d+)(-END)?)", line)
            if not marker:
                continue
            number = int(marker.group(2))
            out.append(marker.group(1) + "\r\n")
            if marker.group(3) is None:
                order.append(number)
                with self.lock:
                    stop = self.stop_in.pop(number, None)
                if stop is not None:
                    status = stop
                    break
        with self.lock:
            self.active -= 1
            self.calls.append(
                {"command": command, "order": order, "script": script, "tmp": tmp, "tmp_files": tmp_files,
                 "timeout_s": timeout_s}
            )
        return BatchResult(status, "".join(out))


class Workspace:
    def __init__(self, test):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.c = root / "build"
        self.d = root / "tools"
        self.c.mkdir()
        self.d.mkdir()

    def params(self, *jobs, timeout_s=10.0, share=1, costs=None):
        params = {
            "mounts": [
                {"drive": "D", "path": str(self.d), "writable": False},
                {"drive": "C", "path": str(self.c), "writable": True},
            ],
            "current_drive": "C",
            "timeout_s": timeout_s,
            "jobs": [{"commands": list(commands)} for commands in jobs],
        }
        if share is not None:
            params["options"] = {"jobs": share}
        for job, cost in zip(params["jobs"], costs or []):
            job["cost"] = cost
        return params


def serve(test, backend, params):
    plugin = build_plugin(lambda: backend)
    return run(plugin, request(1, "runner/run", params))[1]


class ProtocolTest(unittest.TestCase):
    def test_initialize_announces_runner_v1(self):
        answers = run(build_plugin(), request(1, "initialize"), request(2, "shutdown"))
        result = answers[1]["result"]
        self.assertEqual(result["name"], "dosbox-lab")
        self.assertEqual(set(result["capabilities"]), {"runner"})

    def test_initialize_declares_limits(self):
        answers = run(build_plugin(), request(1, "initialize"), request(2, "shutdown"))
        runner = answers[1]["result"]["capabilities"]["runner"]
        self.assertEqual(runner["version"], 1)
        # one DOSBox instance per core at most, fewer when the free memory does not hold that many
        self.assertTrue(1 <= runner["limits"]["max_parallel"] <= os.cpu_count(), runner)
        self.assertEqual(runner["limits"]["memory_per_instance_mb"], MEMORY_PER_INSTANCE_MB)

    def test_goto_and_labels_are_invalid(self):
        ws = Workspace(self)
        for line in ("GOTO X", "@goto x", ":X"):
            answers = run(build_plugin(lambda: FakeBackend(None)), request(1, "runner/run", ws.params([line])))
            self.assertEqual(answers[1]["error"]["code"], -32602, line)

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
        self.assertEqual(command, "NB0.BAT")
        self.assertEqual(timeout_s, 10)  # per-job limit times the number of jobs
        self.assertEqual([(m.drive, m.read_only) for m in mounts], [("C", False), ("D", True)])
        script = backend.scripts[0]
        self.assertIn("@ECHO DECOVERY-JOB-0\r\n", script)
        self.assertIn("@ECHO DECOVERY-JOB-1\r\n", script)
        self.assertIn("SET PATH=D:\\BIN\r\nCALL WCC386 A.C\r\nIF ERRORLEVEL 1 GOTO F0\r\n", script)
        self.assertIn("CALL TCC B.C\r\nIF ERRORLEVEL 1 GOTO F1\r\n", script)
        self.assertNotIn("CALL SET", script)
        self.assertEqual([j["status"] for j in answer["result"]["jobs"]], ["done", "done"])
        self.assertFalse((ws.c / "NB0.BAT").exists())  # removed again

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
        self.assertFalse((ws.c / "NB0.BAT").exists())

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


class InstanceTest(unittest.TestCase):
    def test_dosbox_jobs_split_over_instances(self):
        ws = Workspace(self)
        backend = ScriptBackend()
        jobs = [["CC A.C"], ["CC B.C"], ["CC C.C"], ["CC D.C"], ["CC E.C"]]
        params = ws.params(*jobs, share=2, costs=[100, 10, 50, 30, 20], timeout_s=5)
        answer = run(build_plugin(lambda: backend), request(1, "runner/run", params))[1]
        self.assertEqual([j["status"] for j in answer["result"]["jobs"]], ["done"] * 5)  # merged in job order
        self.assertEqual(backend.peak, 2)  # two DOSBox instances at the same time
        calls = sorted(backend.calls, key=lambda c: c["command"])
        self.assertEqual([c["command"] for c in calls], ["NB0.BAT", "NB1.BAT"])
        # longest first, each job to the instance with the least work so far
        self.assertEqual([c["order"] for c in calls], [[0, 1], [2, 3, 4]])
        self.assertEqual([c["timeout_s"] for c in calls], [10, 15])  # per-job limit times the instance's jobs
        self.assertEqual([c["tmp"] for c in calls], ["NBT0", "NBT1"])  # a TMP directory per instance
        self.assertEqual(calls[0]["tmp_files"], ["ZERO.COM"])
        self.assertEqual(sorted(p.name for p in ws.c.iterdir()), [])  # scripts and TMP directories removed

    def test_share_and_job_count_cap_instances(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0.05)
        run(build_plugin(lambda: backend), request(1, "runner/run", ws.params(["A"], ["B"], share=8)))
        self.assertEqual(len(backend.calls), 2)  # not more instances than jobs
        backend = ScriptBackend(delay=0.05)
        run(build_plugin(lambda: backend), request(1, "runner/run", ws.params(["A"], ["B"], ["C"], share=1)))
        self.assertEqual([c["order"] for c in backend.calls], [[0, 1, 2]])

    def test_longest_job_first(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0)
        params = ws.params(["A"], ["B"], ["C"], ["D"], share=1, costs=[5, 700, 0, 40])
        run(build_plugin(lambda: backend), request(1, "runner/run", params))
        self.assertEqual(backend.calls[0]["order"], [1, 3, 0, 2])

    def test_errorlevel_is_reset_before_each_job(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0)
        run(build_plugin(lambda: backend), request(1, "runner/run", ws.params(["CALL X.BAT"], ["Y"])))
        script = backend.calls[0]["script"]
        for number in (0, 1):
            self.assertIn(f"@ECHO DECOVERY-JOB-{number}\r\nC:\r\nCD \\\r\nSET TMP=C:\\NBT0\r\n"
                          "C:\\NBT0\\ZERO.COM\r\n", script)

    def test_jobs_of_a_stopped_batch_run_again(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0, stop_in={1: "timeout"})
        params = ws.params(["A"], ["B"], ["C"], ["D"])
        answer = run_open(build_plugin(lambda: backend), request(1, "runner/run", params))
        jobs = answer["result"]["jobs"]
        self.assertEqual([j["status"] for j in jobs], ["done", "timeout", "done", "done"])
        self.assertIn("no end after 10 s", jobs[1]["message"])
        self.assertIn("batch of 4 jobs", jobs[1]["message"])
        self.assertEqual([c["order"] for c in backend.calls], [[0, 1], [2, 3]])  # a new session for the rest
        self.assertEqual([c["timeout_s"] for c in backend.calls], [40, 20])

    def test_batch_that_starts_no_job_is_not_repeated(self):
        ws = Workspace(self)
        backend = FakeBackend(BatchResult("crashed", "", "emulator died"))
        answer = serve(self, backend, ws.params(["A"], ["B"]))
        self.assertEqual(len(backend.calls), 1)
        self.assertTrue(all(j["status"] == "failed" for j in answer["result"]["jobs"]))


class SplitTest(unittest.TestCase):
    def test_split_balances_cost(self):
        self.assertEqual(split_jobs([100, 10, 50, 30, 20], 2), [[0, 1], [2, 3, 4]])

    def test_split_without_costs_is_round_robin(self):
        self.assertEqual(split_jobs([0, 0, 0, 0, 0], 2), [[0, 2, 4], [1, 3]])


class ScriptTest(unittest.TestCase):
    def test_internal_commands_are_whole_words(self):
        script = build_script([["TYPE.EXE A", "MD5SUM X", "CD\\SUB", "TYPE A.TXT", "IF EXIST A.OBJ DEL A.OBJ",
                                "FOR %%F IN (*.C) DO ECHO %%F"]], "C")
        self.assertIn("CALL TYPE.EXE A\r\n", script)
        self.assertIn("CALL MD5SUM X\r\n", script)
        self.assertIn("\r\nCD\\SUB\r\n", script)
        self.assertIn("\r\nTYPE A.TXT\r\n", script)
        self.assertIn("\r\nIF EXIST A.OBJ DEL A.OBJ\r\n", script)
        self.assertIn("\r\nFOR %%F IN (*.C) DO ECHO %%F\r\n", script)

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
            DosboxLabBackend().run_batch([], "NB0.BAT", 1.0)
        self.assertEqual(caught.exception.code, BACKEND_UNAVAILABLE)
        self.assertIn("decovery setup dosbox-lab", caught.exception.message)


if __name__ == "__main__":
    unittest.main()
