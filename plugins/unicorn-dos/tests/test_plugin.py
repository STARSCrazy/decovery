import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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
from decovery_unicorn_dos.batch import plan  # noqa: E402
from decovery_unicorn_dos.pool import JobPool, execute_job  # noqa: E402

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


def pid_of(job):
    """Worker that answers with its process id."""
    return {"status": "done", "exit_code": 0, "stdout": str(os.getpid()), "message": None}


def timed(job):
    """Worker that sleeps `sleep` seconds and answers with its start and end time (in stdout)."""
    start = time.time()
    time.sleep(job.get("sleep", 0))
    return {"status": "done", "exit_code": 0, "stdout": f"{start} {time.time()}", "message": None}


def noisy(job):
    """Worker that prints and writes to fd 1 directly."""
    print("worker print", flush=True)
    os.write(1, b"worker fd 1\n")
    return {"status": "done", "exit_code": 0, "stdout": "", "message": None}


def die(job):
    """Worker that ends its process: stands in for a crashed emulator."""
    os._exit(3)


def timeout_of(job):
    """Worker that dies on its first attempt (`die_once`, a marker file) and answers with its time limit."""
    marker = job.get("die_once")
    if marker and not os.path.exists(marker):
        Path(marker).touch()
        os._exit(3)
    return {"status": "done", "exit_code": 0, "stdout": str(job["timeout_s"]), "message": None}


def answer_or_die(job):
    """Worker that dies for a job with `die`, or with `die_once` (a marker file) on the first attempt only, and
    answers every other job with exit code `n` after `sleep` seconds."""
    marker = job.get("die_once")
    if marker and not os.path.exists(marker):
        Path(marker).touch()
        os._exit(3)
    if job.get("die"):
        os._exit(3)
    time.sleep(job.get("sleep", 0))
    return {"status": "done", "exit_code": job["n"], "stdout": "", "message": None}


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
        (self.d / "BINW" / "REAL.EXE").write_bytes(asm.write_file_program16(b"REAL.TXT", b"16", 0))
        (self.d / "BINW" / "LE.EXE").write_bytes(asm.le_exe())

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
        self.assertEqual(set(result["capabilities"]), {"runner"})

    def test_initialize_declares_limits(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("DECOVERY_UNICORN_PARALLEL", None)
            answers = run(build_plugin(), request(1, "initialize"), request(2, "shutdown"))
        runner = answers[1]["result"]["capabilities"]["runner"]
        self.assertEqual(runner["version"], 1)
        self.assertEqual(runner["limits"]["max_parallel"], os.cpu_count())  # scales with the cores
        self.assertGreaterEqual(runner["limits"]["memory_per_instance_mb"], 1)

    def test_unsupported_program_is_refused_before_any_job(self):
        ws = Workspace(self)
        params = ws.params(PRELUDE + ["WRITER"], PRELUDE + ["LE"])
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

        def factory(image):
            from decovery_unicorn_dos.pool import new_machine

            machine = new_machine(image)
            self.machines.append(machine)
            return machine

        self.factory = factory

    def test_runs_jobs_in_worker_processes(self):
        ws = Workspace(self)
        params = ws.params(
            PRELUDE + ["WRITER -x A.C"],
            ["SET PATH=D:\\BINW", "@ECHO OFF", "ECHO before", "BAD"],
            ["@SET PATH=D:\\BINW", "@REAL"],
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
        self.assertEqual(jobs[2], {"status": "done", "exit_code": 0, "stdout": "16", "message": None})
        self.assertEqual((ws.c / "REAL.TXT").read_bytes(), b"16")

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

    def test_real_mode_and_phar_lap_machines_side_by_side(self):
        ws = Workspace(self)
        params = ws.params(PRELUDE + ["REAL", "WRITER"], PRELUDE + ["REAL"])
        answers = run(build_plugin(self.factory), request(1, "runner/run", params))
        jobs = answers[1]["result"]["jobs"]
        self.assertEqual([j["exit_code"] for j in jobs], [3, 0])
        self.assertEqual(len(self.machines), 2)  # one per program, reused
        self.assertEqual(sorted(m.runs for m in self.machines), [1, 2])


class JobPoolTest(unittest.TestCase):
    """Pool behaviour with stand-in workers (no emulator needed)."""

    def test_broken_worker_fails_the_job(self):
        pool = JobPool(workers=1, worker=die)
        self.addCleanup(pool.close)
        outcomes = pool.run([{"steps": []}])
        self.assertEqual(outcomes[0]["status"], "failed")
        self.assertIn("worker process", outcomes[0]["message"])

    def test_crashed_worker_fails_only_its_own_job(self):
        pool = JobPool(workers=2, worker=answer_or_die)
        self.addCleanup(pool.close)
        outcomes = pool.run([{"n": 1, "sleep": 1}, {"die": True}, {"n": 3, "sleep": 1}, {"n": 4, "sleep": 1}])
        self.assertEqual([o["status"] for o in outcomes], ["done", "failed", "done", "done"])
        self.assertEqual([o["exit_code"] for o in outcomes], [1, None, 3, 4])
        self.assertIn("worker process ended unexpectedly", outcomes[1]["message"])
        self.assertEqual(pool.run([{"n": 5}])[0]["exit_code"], 5)  # a fresh pool for the next call

    def test_job_that_crashes_once_is_run_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = JobPool(workers=1, worker=answer_or_die)
            self.addCleanup(pool.close)
            outcomes = pool.run([{"n": 7, "die_once": str(Path(tmp) / "marker")}])
        self.assertEqual(outcomes[0]["status"], "done")
        self.assertEqual(outcomes[0]["exit_code"], 7)

    def test_pool_is_reused_across_requests(self):
        pool = JobPool(workers=2, worker=pid_of)
        self.addCleanup(pool.close)
        first = {o["stdout"] for o in pool.run([{}, {}, {}, {}])}
        second = {o["stdout"] for o in pool.run([{}, {}, {}, {}])}
        self.assertTrue(second <= first, f"new worker processes for the second request: {second - first}")
        self.assertLessEqual(len(first), 2)

    def test_plugin_keeps_one_pool(self):
        pools = []
        original = JobPool.__init__

        def record(self, *args, **kwargs):
            original(self, *args, **kwargs)
            pools.append(self)

        JobPool.__init__ = record
        self.addCleanup(setattr, JobPool, "__init__", original)
        ws = Workspace(self)
        plugin = build_plugin()
        run(plugin, request(1, "runner/run", ws.params(["ECHO a"])), request(2, "runner/run", ws.params(["ECHO b"])))
        self.assertEqual(len(pools), 1)

    def test_rerun_after_a_broken_pool_gets_only_the_time_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = str(Path(tmp) / "marker")
            pool = JobPool(workers=1, worker=timeout_of)
            self.addCleanup(pool.close)
            # dies once, the budget is 5 s: the second try may take at most that, not the job's 100 s
            job = {"timeout_s": 100.0, "die_once": marker}
            outcome = pool.run([job], budget_s=5.0)[0]
        self.assertEqual(outcome["status"], "done")
        self.assertLessEqual(float(outcome["stdout"]), 5.0)
        self.assertGreater(float(outcome["stdout"]), 0.0)

    def test_no_job_is_run_again_after_the_budget_is_used_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = str(Path(tmp) / "marker")
            pool = JobPool(workers=1, worker=timeout_of)
            self.addCleanup(pool.close)
            outcome = pool.run([{"timeout_s": 100.0, "die_once": marker}], budget_s=0.0)[0]
            self.assertTrue(Path(marker).exists())  # the first try ran (and died)
        self.assertEqual(outcome["status"], "failed")
        self.assertIn("budget", outcome["message"])

    def test_on_done_reports_each_job_as_it_ends(self):
        pool = JobPool(workers=2, worker=answer_or_die)
        self.addCleanup(pool.close)
        seen = []
        pool.run([{"n": 1}, {"n": 2}, {"n": 3}], on_done=lambda i, outcome: seen.append((i, outcome["exit_code"])))
        self.assertEqual(sorted(seen), [(0, 1), (1, 2), (2, 3)])

    def test_plugin_reports_one_progress_event_per_job(self):
        ws = Workspace(self)
        plugin = build_plugin()
        stdin = io.StringIO(json.dumps(request(1, "runner/run", ws.params(["ECHO a"], ["ECHO b"], ["ECHO c"]))) + chr(10))
        stdout = io.StringIO()
        plugin.serve(stdin=stdin, stdout=stdout)
        messages = [json.loads(line) for line in stdout.getvalue().splitlines()]
        progress = [m["params"] for m in messages if m.get("method") == "$/progress"]
        self.assertEqual([p["done"] for p in progress], [1, 2, 3])
        self.assertTrue(all(p["total"] == 3 and " of 3 done after " in p["message"] for p in progress), progress)

    def test_in_flight_jobs_stay_within_request_share(self):
        pool = JobPool(workers=4, worker=timed)
        self.addCleanup(pool.close)
        outcomes = pool.run([{"sleep": 0.4} for _ in range(4)], parallel=2)
        spans = [tuple(map(float, o["stdout"].split())) for o in outcomes]
        most = max(sum(1 for s, e in spans if s <= t < e) for t, _ in spans)
        self.assertEqual(most, 2)

    def test_longest_job_first(self):
        pool = JobPool(workers=1, worker=timed)
        self.addCleanup(pool.close)
        jobs = [{"cost": 10}, {"cost": 300}, {"cost": 20}, {}]
        outcomes = pool.run([dict(job, sleep=0.05) for job in jobs])
        starts = [float(o["stdout"].split()[0]) for o in outcomes]
        self.assertEqual(sorted(range(4), key=lambda i: starts[i]), [1, 2, 0, 3])  # results stay in job order

    def test_worker_print_does_not_corrupt_protocol(self):
        script = (
            "import json, sys\n"
            f"sys.path[:0] = {[str(HERE), str(HERE.parent), str(HERE.parent.parent / 'decovery-plugin-sdk')]!r}\n"
            "from decovery_unicorn_dos.pool import JobPool\n"
            "from test_plugin import noisy\n"
            "if __name__ == '__main__':\n"
            "    pool = JobPool(workers=2, worker=noisy)\n"
            "    outcomes = pool.run([{}, {}])\n"
            "    pool.close()\n"
            "    print(json.dumps([o['status'] for o in outcomes]))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pool_main.py"
            path.write_text(script, encoding="utf-8")
            proc = subprocess.run([sys.executable, str(path)], capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), ["done", "done"])  # nothing but the parent's own line
        self.assertIn("worker print", proc.stderr)
        self.assertIn("worker fd 1", proc.stderr)

    def test_unexpected_exception_is_an_emulation_error(self):
        ws = Workspace(self)
        job = {
            "drives": {"C": str(ws.c), "D": str(ws.d)},
            "read_only": ["D"],
            "current": "C",
            "timeout_s": 5.0,
            "steps": plan(PRELUDE + ["WRITER"], {"C": ws.c, "D": ws.d}),
        }

        def broken(program, image):
            raise RuntimeError("boom")

        outcome = execute_job(job, broken)
        self.assertEqual(outcome["status"], "failed")
        self.assertEqual(outcome["message"], "emulation error: RuntimeError: boom")


if __name__ == "__main__":
    unittest.main()
