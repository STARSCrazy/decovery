import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

import asm  # noqa: E402
from decovery_plugin import RpcError  # noqa: E402

from decovery_unicorn_dos import batch  # noqa: E402
from decovery_unicorn_dos.batch import choose_host, plan  # noqa: E402

PRELUDE = ["SET WATCOM=D:\\", "SET INCLUDE=D:\\H", "SET PATH=D:\\BINW"]


class BatchTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.c = root / "c"
        self.d = root / "d"
        self.c.mkdir()
        (self.d / "binw").mkdir(parents=True)
        (self.d / "binw" / "wcc386.exe").write_bytes(asm.write_file_program())
        (self.d / "binw" / "realtool.exe").write_bytes(asm.plain_mz())
        (self.d / "binw" / "letool.exe").write_bytes(asm.le_exe())
        self.drives = {"C": self.c, "D": self.d}

    def test_program_is_read_once_per_version(self):
        reads = []
        original = batch._program_kind

        def counting(data):
            reads.append(len(data))
            return original(data)

        with mock.patch.object(batch, "_program_kind", counting):
            for name in ("A.C", "B.C", "C.C"):
                plan(PRELUDE + [f"WCC386 {name}"], self.drives)
            self.assertEqual(len(reads), 1)  # three jobs, one read of the compiler
            program = self.d / "binw" / "wcc386.exe"
            stat = program.stat()
            os.utime(program, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))
            plan(PRELUDE + ["WCC386 D.C"], self.drives)
            self.assertEqual(len(reads), 2)  # a changed program is read again

    def test_set_lines_build_the_environment(self):
        steps = plan(PRELUDE + ["SET WATCOM=", "WCC386 -zq -ox -3r A.C"], self.drives)
        self.assertEqual([s.kind for s in steps], ["set", "set", "set", "set", "run"])
        run = steps[-1]
        self.assertEqual(
            run.env,
            (("COMSPEC", "Z:\\COMMAND.COM"), ("INCLUDE", "D:\\H"), ("PATH", "D:\\BINW")),
        )
        self.assertEqual(run.args, "-zq -ox -3r A.C")

    def test_program_is_found_on_the_path(self):
        run = plan(PRELUDE + ["wcc386 A.C"], self.drives)[-1]
        self.assertEqual(run.kind, "run")
        self.assertEqual(Path(run.program), self.d / "binw" / "wcc386.exe")
        self.assertEqual(run.dos_path, "D:\\BINW\\WCC386.EXE")
        self.assertEqual(run.host, "pharlap")
        explicit = plan(["D:\\BINW\\WCC386.EXE A.C"], self.drives)[-1]
        self.assertEqual(explicit.dos_path, "D:\\BINW\\WCC386.EXE")

    def test_missing_program_fails_at_its_line(self):
        steps = plan(["SET PATH=D:\\", "WCC386 A.C"], self.drives)
        self.assertEqual(steps[-1].kind, "missing")
        self.assertIn("WCC386", steps[-1].text)

    def test_echo_lines(self):
        steps = plan(["@SET PATH=D:\\BINW", "REM note", "ECHO hello", "@ECHO OFF", "WCC386 A.C"], self.drives)
        self.assertEqual([s.echo for s in steps], [None, "REM note", "ECHO hello", None, None])
        self.assertEqual(steps[2].kind, "echo")
        self.assertEqual(steps[2].text, "hello")

    def test_batch_file_is_read_from_c(self):
        (self.c / "BUILD.BAT").write_bytes(b"@ECHO OFF\r\nSET PATH=D:\\BINW\r\nWCC386 -zq A.C\r\nWCC386 -zq B.C\r\n")
        steps = plan(["BUILD.BAT"], self.drives)
        runs = [s for s in steps if s.kind == "run"]
        self.assertEqual([r.args for r in runs], ["-zq A.C", "-zq B.C"])
        self.assertEqual(steps[0].echo, "BUILD.BAT")
        self.assertTrue(all(s.echo is None for s in steps[1:]))

    def test_unsupported_program_is_rejected_before_running(self):
        with self.assertRaises(RpcError) as caught:
            plan(PRELUDE + ["LETOOL X"], self.drives)
        self.assertEqual(caught.exception.code, -32020)
        self.assertIn("LETOOL", caught.exception.message)

    def test_real_mode_program_gets_the_realmode_host(self):
        run = plan(PRELUDE + ["REALTOOL X"], self.drives)[-1]
        self.assertEqual((run.kind, run.host, run.args), ("run", "realmode", "X"))

    def test_choose_host(self):
        self.assertEqual(choose_host(asm.write_file_program()), "pharlap")
        self.assertEqual(choose_host(asm.plain_mz()), "realmode")
        self.assertEqual(choose_host(b"\xb8\x00\x4c\xcd\x21"), "realmode")  # COM
        self.assertIsNone(choose_host(asm.p3_exe(b"", level=2)))
        self.assertIsNone(choose_host(asm.p3_exe(b"", relocations=16)))
        self.assertIsNone(choose_host(asm.le_exe()))


if __name__ == "__main__":
    unittest.main()
