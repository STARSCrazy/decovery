import io
import json
import os
import re
import sys
import threading
import time
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_dosbox_lab import (  # noqa: E402
    MEMORY_PER_INSTANCE_MB,
    SESSION_SLACK_S,
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

    def run_batch(self, mounts, command, timeout_s, watch=None):
        self.calls.append((mounts, command, timeout_s))
        self.scripts.append((mounts[0].path / command).read_bytes().decode("cp437"))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class ScriptBackend(Backend):
    """Plays each batch file line by line, like the DOS shell would: echoes the job markers and `ECHO` text, keeps
    `SET` variables (with `%NAME%` expansion), follows `GOTO N<i>` and a failing job's path to its `:N<i>` label, and
    runs `CALL RUN <seconds> [<exit code>]` on a per-thread clock (`clock`), asking the plugin's watch every half
    second; when the watch says stop, the session ends with status `timeout`. Any other `CALL` ends at once with 0.
    Records per call the script name, the job numbers in run order, the script text, what the TMP directory held,
    the limit, the clock at the end, and how many calls ran at the same time."""

    def __init__(self, delay=0.2):
        self.delay = delay
        self.lock = threading.Lock()
        self.local = threading.local()
        self.active = 0
        self.peak = 0
        self.calls = []

    def clock(self):
        return self.local.now

    def run_batch(self, mounts, command, timeout_s, watch=None):
        self.local.now = 0.0
        script = (mounts[0].path / command).read_bytes().decode("cp437")
        tmp = re.search(r"SET TMP=C:\\(\w+)", script).group(1)
        tmp_files = sorted(f.name for f in (mounts[0].path / tmp).iterdir())
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(self.delay)
        out, order = [], []
        status = self.play(script.split("\r\n"), out, order, watch)
        with self.lock:
            self.active -= 1
            self.calls.append(
                {"command": command, "order": order, "script": script, "tmp": tmp, "tmp_files": tmp_files,
                 "timeout_s": timeout_s, "ended_at": self.local.now}
            )
        return BatchResult(status, "".join(out))

    def play(self, lines, out, order, watch):
        env = {}

        def expand(text):
            return re.sub(r"%(\w+)%", lambda m: env.get(m.group(1).upper(), ""), text)

        def stop():
            return watch is not None and watch("".join(out))

        job = None
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            if marker := re.fullmatch(r"@ECHO (DECOVERY-JOB-(\d+)(-END)?)", line):
                out.append(marker.group(1) + "\r\n")
                if marker.group(3) is None:
                    job = int(marker.group(2))
                    order.append(job)
                if stop():
                    return "timeout"
            elif line == "GOTO FINISH":
                break
            elif jump := re.fullmatch(r"GOTO (N\d+)", line):
                i = lines.index(f":{jump.group(1)}") + 1
            elif assign := re.fullmatch(r"SET ([^=]+)=(.*)", line):
                value = expand(assign.group(2))
                if value:
                    env[assign.group(1).upper()] = value
                else:
                    env.pop(assign.group(1).upper(), None)
            elif echo := re.fullmatch(r"ECHO (.*)", line):
                out.append(expand(echo.group(1)) + "\r\n")
            elif program := re.fullmatch(r"CALL RUN ([\d.]+)(?: (\d+))?", line):
                remaining = float(program.group(1))
                while remaining > 0:
                    step = min(0.5, remaining)
                    self.local.now += step
                    remaining -= step
                    if stop():
                        return "timeout"
                code = int(program.group(2) or 0)
                if code:
                    out.append(f"DECOVERY-EXIT-{code}-FAILED\r\n")
                    i = lines.index(f":N{job}") + 1
        return "done"


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
        for line in ("GOTO X", "@goto x", ":X", "IF X==X GOTO FINISH", "if exist a.c goto n0",
                     "FOR %%F IN (*.C) DO GOTO X"):
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
        self.assertEqual(timeout_s, 10 + SESSION_SLACK_S)  # backstop: per-job limit times the jobs, plus start-up
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


class ProgressTest(unittest.TestCase):
    def test_one_progress_event_per_ended_job(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0)
        answered = threading.Event()

        class Output(io.StringIO):
            def write(self, text):
                written = super().write(text)
                if '"result"' in text:
                    answered.set()
                return written

        def lines():
            yield json.dumps(request(1, "runner/run", ws.params(["A"], ["B"], ["C"], share=1))) + chr(10)
            answered.wait(30)

        stdout = Output()
        build_plugin(lambda: backend).serve(stdin=lines(), stdout=stdout)
        messages = [json.loads(line) for line in stdout.getvalue().splitlines()]
        progress = [m["params"] for m in messages if m.get("method") == "$/progress"]
        self.assertEqual([p["done"] for p in progress], [1, 2, 3])
        self.assertTrue(all(p["message"].startswith("job ") and " ended after " in p["message"] for p in progress))


class InstanceTest(unittest.TestCase):
    def test_dosbox_jobs_split_over_instances(self):
        ws = Workspace(self)
        backend = ScriptBackend()
        jobs = [["CC A.C"], ["CC B.C"], ["CC C.C"], ["CC D.C"], ["CC E.C"]]
        params = ws.params(*jobs, share=2, costs=[100, 10, 50, 30, 20], timeout_s=5)
        answer = run_open(build_plugin(lambda: backend), request(1, "runner/run", params))
        self.assertEqual([j["status"] for j in answer["result"]["jobs"]], ["done"] * 5)  # merged in job order
        self.assertEqual(backend.peak, 2)  # two DOSBox instances at the same time
        calls = sorted(backend.calls, key=lambda c: c["command"])
        self.assertEqual([c["command"] for c in calls], ["NB0.BAT", "NB1.BAT"])
        # longest first, each job to the instance with the least work so far
        self.assertEqual([c["order"] for c in calls], [[0, 1], [2, 3, 4]])
        self.assertEqual([c["timeout_s"] for c in calls], [10 + SESSION_SLACK_S, 15 + SESSION_SLACK_S])
        self.assertEqual([c["tmp"] for c in calls], ["NBT0", "NBT1"])  # a TMP directory per instance
        self.assertEqual(calls[0]["tmp_files"], ["ZERO.COM"])
        self.assertEqual(sorted(p.name for p in ws.c.iterdir()), [])  # scripts and TMP directories removed

    def test_no_instance_runs_more_rounds_than_the_host_counts(self):
        from decovery_dosbox_lab import HOST_SLACK_S

        # one huge job and many small ones: by cost alone one instance would get six of the seven jobs
        costs = [1000, 1, 1, 1, 1, 1, 1]
        for instances in (1, 2, 3, 7, 12):
            split = split_jobs(costs, instances)
            cap = -(-len(costs) // min(instances, len(costs)))
            self.assertEqual(sorted(i for part in split for i in part), list(range(7)))
            self.assertLessEqual(max(len(part) for part in split), cap, (instances, split))
        ws = Workspace(self)
        backend = ScriptBackend(delay=0)
        timeout_s = 5
        params = ws.params(*[["X"] for _ in costs], share=2, costs=costs, timeout_s=timeout_s)
        run_open(build_plugin(lambda: backend), request(1, "runner/run", params))
        host_limit = timeout_s * -(-len(costs) // 2) + HOST_SLACK_S
        self.assertTrue(backend.calls)
        for call in backend.calls:
            self.assertLessEqual(call["timeout_s"], host_limit)

    def test_share_and_job_count_cap_instances(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0.05)
        run_open(build_plugin(lambda: backend), request(1, "runner/run", ws.params(["A"], ["B"], share=8)))
        self.assertEqual(len(backend.calls), 2)  # not more instances than jobs
        backend = ScriptBackend(delay=0.05)
        run_open(build_plugin(lambda: backend), request(1, "runner/run", ws.params(["A"], ["B"], ["C"], share=1)))
        self.assertEqual([c["order"] for c in backend.calls], [[0, 1, 2]])

    def test_longest_job_first(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0)
        params = ws.params(["A"], ["B"], ["C"], ["D"], share=1, costs=[5, 700, 0, 40])
        run_open(build_plugin(lambda: backend), request(1, "runner/run", params))
        self.assertEqual(backend.calls[0]["order"], [1, 3, 0, 2])

    def test_errorlevel_is_reset_before_each_job(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0)
        run_open(build_plugin(lambda: backend), request(1, "runner/run", ws.params(["CALL X.BAT"], ["Y"])))
        script = backend.calls[0]["script"]
        for number in (0, 1):
            self.assertIn(f"@ECHO DECOVERY-JOB-{number}\r\nC:\r\nCD \\\r\nSET DECOVERY_SAVED0=%TMP%\r\n"
                          "SET TMP=C:\\NBT0\r\nC:\\NBT0\\ZERO.COM\r\n", script)

    def test_hang_stops_the_session_within_the_call_budget(self):
        ws = Workspace(self)
        backend = ScriptBackend(delay=0)
        params = ws.params(["RUN 1"], ["RUN 1000"], ["RUN 1"], ["RUN 1"], timeout_s=10)
        answer = run_open(build_plugin(lambda: backend, clock=backend.clock), request(1, "runner/run", params))
        jobs = answer["result"]["jobs"]
        self.assertEqual([j["status"] for j in jobs], ["done", "timeout", "failed", "failed"])
        self.assertEqual(jobs[1]["message"], "no end after 10 s")
        for job in jobs[2:]:  # the host submits these once more (`is_job_not_run`)
            self.assertTrue(job["message"].startswith("job not run"), job["message"])
        self.assertEqual(len(backend.calls), 1)  # no second session inside the call
        call = backend.calls[0]
        self.assertLessEqual(call["timeout_s"], 4 * 10 + 30)  # within the host's call budget (T x jobs + 30 s)
        self.assertLess(call["ended_at"], 1 + 10 + 1)  # stopped by the per-job limit, not by the backstop

    def test_results_do_not_depend_on_the_number_of_instances(self):
        jobs = [
            ["SET FOO=one", "SET PATH=D:\\BIN", "ECHO [%FOO%] [%PATH%]", "RUN 3"],
            ["ECHO [%FOO%] [%PATH%]", "RUN 9"],  # 9 s: within its own limit, whatever ran before it
            ["RUN 2 3"],
            ["RUN 15"],  # over the limit
        ]
        costs = [40, 30, 20, 10]  # one instance runs them in this order; four run one each
        results = {}
        for share in (1, 4):
            ws = Workspace(self)
            backend = ScriptBackend(delay=0)
            params = ws.params(*jobs, timeout_s=10, share=share, costs=costs)
            answer = run_open(build_plugin(lambda: backend, clock=backend.clock), request(1, "runner/run", params))
            self.assertEqual(len(backend.calls), share)
            results[share] = answer["result"]["jobs"]
        self.assertEqual(results[1], results[4])
        self.assertEqual([j["status"] for j in results[1]], ["done", "done", "done", "timeout"])
        self.assertEqual(results[1][0]["stdout"], "[one] [D:\\BIN]\r\n")
        self.assertEqual(results[1][1]["stdout"], "[] []\r\n")  # nothing left over from the job before
        self.assertEqual(results[1][2]["exit_code"], 3)
        self.assertEqual(results[1][3]["message"], "no end after 10 s")

    def test_batch_that_starts_no_job_is_not_repeated(self):
        ws = Workspace(self)
        backend = FakeBackend(BatchResult("crashed", "", "emulator died"))
        answer = serve(self, backend, ws.params(["A"], ["B"]))
        self.assertEqual(len(backend.calls), 1)
        self.assertTrue(all(j["status"] == "failed" for j in answer["result"]["jobs"]))


class BackendTest(unittest.TestCase):
    """`DosboxLabBackend` against a stand-in `dosbox_lab` module."""

    def lab(self, run_batch):
        module = types.ModuleType("dosbox_lab")
        module.Mount = lambda drive, host, cdrom=False: (drive, host, cdrom)
        module.DmcpError = type("DmcpError", (Exception,), {})
        module.run_batch = run_batch
        patcher = mock.patch.dict(sys.modules, {"dosbox_lab": module})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_watch_is_passed_and_stopped_is_a_timeout(self):
        calls = []

        def run_batch(mounts, command, timeout_s=60.0, watch=None, snapshot=True):
            calls.append((command, timeout_s, snapshot))
            return {"status": "stopped" if watch("DECOVERY-JOB-0\r\n") else "done", "stdout_text": "x"}

        self.lab(run_batch)
        result = DosboxLabBackend().run_batch([], "NB0.BAT", 20.0, watch=lambda stdout: "JOB-0" in stdout)
        self.assertEqual((result.status, result.stdout), ("timeout", "x"))
        self.assertEqual(calls, [("NB0.BAT", 20.0, False)])  # the host snapshots its files itself

    def test_dosbox_lab_without_watch_is_unavailable(self):
        self.lab(lambda mounts, command, timeout_s=60.0: {"status": "done"})
        with self.assertRaises(BackendError) as caught:
            DosboxLabBackend().run_batch([], "NB0.BAT", 20.0)
        self.assertEqual(caught.exception.code, BACKEND_UNAVAILABLE)
        self.assertIn("too old", caught.exception.message)


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

    def test_echo_dot_and_cd_dot_dot_are_internal(self):
        script = build_script([["ECHO.", "CD..", "@CD.."]], "C")
        self.assertIn("\r\nECHO.\r\n", script)
        self.assertIn("\r\nCD..\r\n", script)
        self.assertIn("\r\n@CD..\r\n", script)
        self.assertNotIn("CALL", script)

    def test_set_variables_are_restored_after_the_job(self):
        script = build_script([["SET PATH=D:\\BIN", "@set foo=1", "A"]], "C", tmp_dir="NBT0")
        self.assertIn(
            "SET DECOVERY_SAVED0=%TMP%\r\nSET DECOVERY_SAVED1=%PATH%\r\nSET DECOVERY_SAVED2=%FOO%\r\n",
            script,
        )
        self.assertIn(
            ":N0\r\nSET TMP=%DECOVERY_SAVED0%\r\nSET DECOVERY_SAVED0=\r\nSET PATH=%DECOVERY_SAVED1%\r\n",
            script,
        )
        self.assertIn("SET FOO=%DECOVERY_SAVED2%\r\nSET DECOVERY_SAVED2=\r\nSET DJ=\r\n", script)

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
