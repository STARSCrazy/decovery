"""Against a real dosbox-lab: skipped unless DOSBOX_LAB_PACKAGE (the directory holding `dosbox_lab/`) is set and the
emulator executable exists (see dosbox-lab's DOSBOX_LAB_EXE)."""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

PACKAGE = os.environ.get("DOSBOX_LAB_PACKAGE")
if PACKAGE:
    sys.path.insert(0, PACKAGE)

from decovery_dosbox_lab import build_plugin  # noqa: E402


@unittest.skipUnless(PACKAGE, "needs DOSBOX_LAB_PACKAGE")
class LocalDosboxTest(unittest.TestCase):
    def test_echo_job_in_real_emulator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "c").mkdir()
            (root / "d").mkdir()
            params = {
                "mounts": [
                    {"drive": "C", "path": str(root / "c"), "writable": True},
                    {"drive": "D", "path": str(root / "d"), "writable": False},
                ],
                "current_drive": "C",
                "timeout_s": 60,
                "jobs": [{"commands": ["ECHO hello from dosbox"]}],
            }
            message = {"jsonrpc": "2.0", "id": 1, "method": "runner/run", "params": params}
            stdout = io.StringIO()
            build_plugin().serve(stdin=io.StringIO(json.dumps(message) + "\n"), stdout=stdout)
            answer = json.loads(stdout.getvalue().splitlines()[0])
            if answer.get("error", {}).get("code") == -32010:
                self.skipTest(answer["error"]["message"])
            job = answer["result"]["jobs"][0]
            self.assertEqual(job["status"], "done", job)
            self.assertEqual(job["exit_code"], 0)
            self.assertIn("hello from dosbox", job["stdout"])


if __name__ == "__main__":
    unittest.main()
