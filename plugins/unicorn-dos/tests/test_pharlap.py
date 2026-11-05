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

from decovery_unicorn_dos.dosfs import DosFs  # noqa: E402
from decovery_unicorn_dos.errors import EmulatorError, EmulatorTimeout  # noqa: E402


@unittest.skipIf(unicorn is None, "unicorn not installed")
class PharLapTest(unittest.TestCase):
    def setUp(self):
        from decovery_unicorn_dos import pharlap

        self.pharlap = pharlap
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.c = self.root / "c"
        self.c.mkdir()

    def emu(self, program: bytes, timeout_s: float = 10.0, args: str = "-x FILE.C"):
        exe = self.root / "PROG.EXE"
        exe.write_bytes(program)
        p3 = self.pharlap.load_p3(exe.read_bytes())
        fs = DosFs({"C": self.c, "D": self.root}, {"D"})
        return self.pharlap.PharLapEmu(p3, fs, args, [("PATH", "D:\\")], "D:\\PROG.EXE", timeout_s=timeout_s)

    def test_writes_file_and_exit_code(self):
        result = self.emu(asm.write_file_program()).run()
        self.assertEqual(result.exit_code, 3)
        self.assertEqual(result.output, b"OK")
        self.assertEqual((self.c / "OUT.TXT").read_bytes(), b"OK")
        self.assertEqual(result.calls["21/3C"], 1)

    def test_read_only_drive_sets_carry(self):
        result = self.emu(asm.create_and_report_carry(b"D:\\X.TXT")).run()
        self.assertEqual(result.exit_code, 1)
        self.assertFalse((self.root / "X.TXT").exists())

    def test_reset_reuses_the_machine(self):
        emu = self.emu(asm.counter_program())
        machine = self.pharlap.Machine(emu.p3)
        self.assertEqual(emu.run(machine).exit_code, 1)
        again = self.emu(asm.counter_program())
        self.assertEqual(again.run(machine).exit_code, 1)  # memory was reset
        self.assertEqual(machine.runs, 2)

    def test_timeout_on_endless_loop(self):
        emu = self.emu(asm.loop_program(), timeout_s=0.3)
        machine = self.pharlap.Machine(emu.p3)
        with self.assertRaises(EmulatorTimeout) as caught:
            emu.run(machine)
        self.assertIn("no end after 0.3 s", str(caught.exception))
        self.assertTrue(machine.spent)

    def test_tiny_time_limit_still_times_out(self):
        with self.assertRaises(EmulatorTimeout):
            self.emu(asm.loop_program(), timeout_s=1e-9).run()

    def test_stop_without_exit_is_an_error(self):
        emu = self.emu(asm.halt_program(), timeout_s=30)
        machine = self.pharlap.Machine(emu.p3)
        with self.assertRaises(EmulatorError) as caught:
            emu.run(machine)
        self.assertNotIsInstance(caught.exception, EmulatorTimeout)
        self.assertRegex(str(caught.exception), r"^stopped without exit at 000C:00001001 \(EAX=")
        self.assertTrue(machine.spent)

    def test_unknown_function_aborts_with_address(self):
        emu = self.emu(asm.call_program(0x99))
        machine = self.pharlap.Machine(emu.p3)
        with self.assertRaises(EmulatorError) as caught:
            emu.run(machine)
        self.assertRegex(str(caught.exception), r"^unsupported INT 21h AH=99h at 000C:00001002 \(EAX=")
        self.assertTrue(machine.spent)

    def test_unknown_interrupt_aborts(self):
        with self.assertRaisesRegex(EmulatorError, r"^unsupported interrupt INT 13h at 000C:00001000"):
            self.emu(asm.interrupt_program(0x13)).run()

    def test_command_line_and_environment(self):
        emu = self.emu(asm.counter_program(), args="-zq A.C")
        emu.begin()
        try:
            psp = emu.mu.mem_read(self.pharlap.PSP_LIN, 0x100)
            self.assertEqual(bytes(psp[0x80 : 0x82 + 8]), b"\x08 -zq A.C\r")
            env = bytes(emu.mu.mem_read(self.pharlap.ENV_LIN, 32))
            self.assertTrue(env.startswith(b"PATH=D:\\\0\0\x01\0D:\\PROG.EXE\0"))
        finally:
            emu.finish()

    def test_command_line_over_126_characters_is_refused(self):
        with self.assertRaisesRegex(EmulatorError, "command line too long"):
            self.emu(asm.counter_program(), args="x" * 127).run()

    def test_load_p3_rejects_other_images(self):
        with self.assertRaisesRegex(EmulatorError, "level 2"):
            self.pharlap.load_p3(asm.p3_exe(b"", level=2))
        with self.assertRaisesRegex(EmulatorError, "relocations"):
            self.pharlap.load_p3(asm.p3_exe(b"", relocations=8))
        with self.assertRaisesRegex(EmulatorError, "no Phar Lap P3 header"):
            self.pharlap.load_p3(asm.plain_mz())


if __name__ == "__main__":
    unittest.main()
