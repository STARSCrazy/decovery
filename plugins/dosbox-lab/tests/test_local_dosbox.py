"""Against a real dosbox-lab: skipped unless DOSBOX_LAB_PACKAGE (the directory holding `dosbox_lab/`) is set and the
emulator executable exists (see dosbox-lab's DOSBOX_LAB_EXE). Drive D: holds programs from dosbox-lab's `testprogs/`
(BATCH.COM prints ABTTY, writes BATCH.OUT and exits with 7; VIDEO.COM waits for a key)."""

import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

PACKAGE = os.environ.get("DOSBOX_LAB_PACKAGE")
if PACKAGE:
    sys.path.insert(0, PACKAGE)

from decovery_dosbox_lab import build_plugin  # noqa: E402


def call(params):
    """One `runner/run` request; the input stays open until the answer is written (end of input cancels)."""
    answered = threading.Event()

    class Output(io.StringIO):
        def write(self, text):
            written = super().write(text)
            if '"result"' in text or '"error"' in text:
                answered.set()
            return written

    def lines():
        yield json.dumps({"jsonrpc": "2.0", "id": 1, "method": "runner/run", "params": params}) + "\n"
        answered.wait(300)

    stdout = Output()
    build_plugin().serve(stdin=lines(), stdout=stdout)
    return json.loads(stdout.getvalue().splitlines()[-1])


@unittest.skipUnless(PACKAGE, "needs DOSBOX_LAB_PACKAGE")
class LocalDosboxTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "d").mkdir()
        for name in ("BATCH.COM", "VIDEO.COM"):
            shutil.copy(Path(PACKAGE).parent / "testprogs" / name, self.root / "d" / name)
        (self.root / "d" / "QUIET.BAT").write_bytes(b"@ECHO quiet\r\n")  # only internal commands: no errorlevel

    def run_jobs(self, jobs, share, costs=None, timeout_s=60):
        c = self.root / f"c{share}"
        c.mkdir()
        params = {
            "mounts": [
                {"drive": "C", "path": str(c), "writable": True},
                {"drive": "D", "path": str(self.root / "d"), "writable": False},
            ],
            "current_drive": "C",
            "timeout_s": timeout_s,
            "options": {"jobs": share},
            "jobs": [{"commands": commands, "cost": cost} for commands, cost in zip(jobs, costs or [0] * len(jobs))],
        }
        answer = call(params)
        if answer.get("error", {}).get("code") == -32010:
            self.skipTest(answer["error"]["message"])
        self.assertIn("result", answer, answer)
        self.assertEqual(sorted(p.name for p in c.iterdir() if p.name.upper().startswith("NB")), [])
        return answer["result"]["jobs"], c

    def test_echo_job_in_real_emulator(self):
        jobs, _ = self.run_jobs([["ECHO hello from dosbox"]], share=1)
        self.assertEqual((jobs[0]["status"], jobs[0]["exit_code"]), ("done", 0), jobs[0])
        self.assertIn("hello from dosbox", jobs[0]["stdout"])

    def test_one_and_five_instances_give_the_same_results(self):
        jobs = [
            ["ECHO.", "CD..", "ECHO dots-ok"],
            ["SET FOO=one", 'IF "%FOO%"=="one" ECHO if-ok', "FOR %%F IN (a b) DO ECHO for-%%F"],
            ["D:\\BATCH.COM"],
            ["ECHO [%FOO%]", "D:\\BATCH.COM", "ECHO not-reached"],
            ["D:\\QUIET.BAT"],  # right after a job that ended with 7: the errorlevel was reset
        ]
        costs = [40, 30, 20, 10, 5]  # one instance runs them in this order
        results = {}
        for share in (1, 5):
            results[share], c = self.run_jobs(jobs, share, costs)
            self.assertEqual((c / "BATCH.OUT").read_bytes(), b"DMCP")
        print(f"\n1 instance:  {results[1]}\n5 instances: {results[5]}", file=sys.stderr)
        self.assertEqual(results[1], results[5])
        first, second, third, fourth, fifth = results[1]
        self.assertEqual((fifth["status"], fifth["exit_code"], fifth["stdout"]), ("done", 0, "quiet\r\n"))
        self.assertEqual((first["status"], first["exit_code"]), ("done", 0))
        self.assertIn("dots-ok", first["stdout"])
        self.assertNotIn("Illegal", first["stdout"])
        self.assertEqual((second["status"], second["exit_code"]), ("done", 0))
        for text in ("if-ok", "for-a", "for-b"):
            self.assertIn(text, second["stdout"])
        self.assertEqual((third["status"], third["exit_code"]), ("done", 7))
        self.assertIn("ABTTY", third["stdout"])
        self.assertEqual((fourth["status"], fourth["exit_code"]), ("done", 7))
        self.assertIn("[]", fourth["stdout"])  # FOO of the job before was restored
        self.assertNotIn("not-reached", fourth["stdout"])

    def test_hanging_job_stops_its_session(self):
        jobs, _ = self.run_jobs([["ECHO first"], ["D:\\VIDEO.COM"], ["ECHO third"]], share=1, timeout_s=5)
        print(f"\nhang: {jobs}", file=sys.stderr)
        self.assertEqual([j["status"] for j in jobs], ["done", "timeout", "failed"])
        self.assertEqual(jobs[1]["message"], "no end after 5 s")
        self.assertTrue(jobs[2]["message"].startswith("job not run"), jobs[2])


if __name__ == "__main__":
    unittest.main()
