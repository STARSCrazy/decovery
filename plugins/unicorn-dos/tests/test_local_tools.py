"""Local tests with the original compilers; skipped unless the tool directory is set (never in CI)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from test_plugin import request, run  # noqa: E402

try:
    import unicorn  # noqa: F401
except ImportError:
    unicorn = None

from decovery_unicorn_dos import build_plugin  # noqa: E402

WATCOM95 = os.environ.get("DECOVERY_TOOLCHAIN_WATCOM95")

TWO_FUNCTIONS = (
    b"#include <stdio.h>\r\n"
    b"\r\n"
    b"int add(int a, int b)\r\n"
    b"{\r\n"
    b"    return a + b;\r\n"
    b"}\r\n"
    b"\r\n"
    b"int twice(int a)\r\n"
    b"{\r\n"
    b"    return add(a, a);\r\n"
    b"}\r\n"
)


@unittest.skipIf(unicorn is None, "unicorn not installed")
@unittest.skipUnless(WATCOM95, "local: set DECOVERY_TOOLCHAIN_WATCOM95 to the Watcom 9.5 directory")
class Watcom95Test(unittest.TestCase):
    def test_wcc386_compiles_two_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            build = Path(tmp)
            (build / "ADD.C").write_bytes(TWO_FUNCTIONS)
            (build / "BROKEN.C").write_bytes(b"int g( { return 1; }\r\n")
            prelude = ["SET WATCOM=D:\\", "SET INCLUDE=D:\\H", "SET PATH=D:\\BINW"]
            params = {
                "mounts": [
                    {"drive": "C", "path": str(build), "writable": True},
                    {"drive": "D", "path": WATCOM95, "writable": False},
                ],
                "current_drive": "C",
                "timeout_s": 120,
                "jobs": [
                    {"commands": prelude + ["WCC386 -zq -ox -3r ADD.C"]},
                    {"commands": prelude + ["WCC386 -zq -ox -3r BROKEN.C"]},
                ],
            }
            answers = run(build_plugin(), request(1, "runner/run", params))
            good, bad = answers[1]["result"]["jobs"]
            self.assertEqual(good["status"], "done", good)
            self.assertEqual(good["exit_code"], 0, good)
            obj = (build / "ADD.OBJ").read_bytes()
            self.assertEqual(obj[0], 0x80)  # THEADR
            self.assertIn(b"add_", obj)
            self.assertIn(b"twice_", obj)
            self.assertEqual(bad["status"], "done", bad)
            self.assertNotEqual(bad["exit_code"], 0)
            self.assertIn("Error!", bad["stdout"])
            self.assertFalse((build / "BROKEN.OBJ").exists())


if __name__ == "__main__":
    unittest.main()
