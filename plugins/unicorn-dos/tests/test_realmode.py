import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

import asm  # noqa: E402
from asm import PUSH_CS_POP_DS, PUSH_DS_POP_ES, int21, mov16, mov_ah  # noqa: E402

try:
    import unicorn  # noqa: F401
except ImportError:
    unicorn = None

from decovery_unicorn_dos.dosfs import DosFs  # noqa: E402
from decovery_unicorn_dos.errors import EmulatorError, EmulatorTimeout  # noqa: E402

CARRY, ZERO = 0x0001, 0x0040
MOV_ES_AX = b"\x8e\xc0"


def es(value: int) -> bytes:
    return mov16("AX", value) + MOV_ES_AX


@unittest.skipIf(unicorn is None, "unicorn not installed")
class RealModeTest(unittest.TestCase):
    def setUp(self):
        from decovery_unicorn_dos import realmode

        self.realmode = realmode
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.c = self.root / "c"
        self.c.mkdir()
        self.fs = DosFs({"C": self.c, "D": self.root}, {"D"})
        self.addCleanup(self.fs.close_all)

    def emu(self, program: bytes, timeout_s: float = 10.0, args: str = "-c A.C"):
        return self.realmode.RealModeEmu(program, self.fs, args, [("PATH", "D:\\")], "D:\\PROG.EXE", timeout_s)

    def run_program(self, program: bytes, **kwargs):
        """(result, machine) of one run; the machine keeps the memory of the ended program."""
        machine = self.realmode.RealModeMachine(program)
        return self.emu(program, **kwargs).run(machine), machine

    def memory(self, machine, seg: int, off: int, n: int) -> bytes:
        return bytes(machine.mu.mem_read((seg << 4) + off, n))

    def dumps(self, machine, count: int) -> list[dict[str, int]]:
        raw = self.memory(machine, asm.DATA_SEG, asm.DUMP, 16 * count)
        return [dict(zip(asm.DUMP_NAMES, struct.unpack_from("<8H", raw, 16 * i))) for i in range(count)]

    def run_calls(self, calls, data=b""):
        result, machine = self.run_program(asm.calls16(calls, data))
        self.assertEqual(result.exit_code, 0)
        return result, machine, self.dumps(machine, len(calls))

    # --- loading and running -------------------------------------------------------------------------------------
    def test_writes_file_and_exit_code(self):
        result, _ = self.run_program(asm.write_file_program16())
        self.assertEqual(result.exit_code, 3)
        self.assertEqual(result.output, b"OK")
        self.assertEqual((self.c / "OUT.TXT").read_bytes(), b"OK")
        self.assertEqual(result.calls["21/3C"], 1)

    def test_run_realmode_without_machine(self):
        result = self.realmode.run_realmode(
            asm.write_file_program16(exit_code=0), self.fs, "", [], "D:\\PROG.EXE", 10.0
        )
        self.assertEqual((result.exit_code, result.output), (0, b"OK"))

    def test_relocations_are_applied(self):
        # data:0 = far pointer 0004:DATA (segment word relocated), data:4 = 2Ah
        data = struct.pack("<HH", 4, asm.DATA_PARA) + b"\x2a"
        code = asm.SET_DS_DATA + b"\xc4\x1e\x00\x00" + b"\x26\x8a\x07" + mov_ah(0x4C) + int21()  # les bx; mov al
        program = asm.mz_exe(code, data, [asm.DATA_RELOCATION, (asm.DATA_PARA, 2)])
        result, _ = self.run_program(program)
        self.assertEqual(result.exit_code, 0x2A)

    def test_psp_environment_and_registers(self):
        emu = self.emu(asm.loop_program16(), args="-ms A.C")
        emu.begin()
        try:
            r = emu.regs
            psp = bytes(emu.mu.mem_read(0x1000, 0x100))
            self.assertEqual(psp[0:2], b"\xcd\x20")
            self.assertEqual(struct.unpack_from("<H", psp, 2)[0], 0xA000)  # memory top
            self.assertEqual(struct.unpack_from("<H", psp, 0x2C)[0], self.realmode.ENV_SEG)
            self.assertEqual(psp[0x80 : 0x82 + 8], b"\x08 -ms A.C\r")
            env = bytes(emu.mu.mem_read(self.realmode.ENV_SEG << 4, 32))
            self.assertTrue(env.startswith(b"PATH=D:\\\0\0\x01\0D:\\PROG.EXE\0"))
            regs = {n: r.get(n) & 0xFFFF for n in ("CS", "IP", "SS", "SP", "DS", "ES")}
            self.assertEqual(regs, {"CS": 0x110, "IP": 0, "SS": 0x170, "SP": 0x100, "DS": 0x100, "ES": 0x100})
        finally:
            emu.finish()

    def test_com_program_returns_to_the_psp(self):
        # mov ah, 9; mov dx, 108h; int 21h; ret; "Hi$"  -> ret jumps to PSP:0 (int 20h)
        program = mov_ah(0x09) + mov16("DX", 0x108) + int21() + b"\xc3" + b"Hi$"
        result, _ = self.run_program(program)
        self.assertEqual((result.exit_code, result.output), (0, b"Hi"))
        self.assertEqual(result.calls["20"], 1)

    def test_reset_reuses_the_machine(self):
        # inc byte [0]; mov al, [0]; exit with AL
        code = asm.SET_DS_DATA + b"\xfe\x06\x00\x00" + b"\xa0\x00\x00" + mov_ah(0x4C) + int21()
        program = asm.mz_exe(code, b"\0", [asm.DATA_RELOCATION])
        machine = self.realmode.RealModeMachine(program)
        self.assertEqual(self.emu(program).run(machine).exit_code, 1)
        self.assertEqual(self.emu(program).run(machine).exit_code, 1)  # memory was reset
        self.assertEqual(machine.runs, 2)

    def test_timeout_on_endless_loop(self):
        program = asm.loop_program16()
        machine = self.realmode.RealModeMachine(program)
        with self.assertRaises(EmulatorTimeout) as caught:
            self.emu(program, timeout_s=0.3).run(machine)
        self.assertIn("no end after 0.3 s", str(caught.exception))
        self.assertTrue(machine.spent)

    def test_tiny_time_limit_still_times_out(self):
        with self.assertRaises(EmulatorTimeout):
            self.emu(asm.loop_program16(), timeout_s=1e-9).run()

    def test_stop_without_exit_is_an_error(self):
        program = asm.mz_exe(asm.HLT)
        machine = self.realmode.RealModeMachine(program)
        with self.assertRaises(EmulatorError) as caught:
            self.emu(program, timeout_s=30).run(machine)
        self.assertNotIsInstance(caught.exception, EmulatorTimeout)
        self.assertRegex(str(caught.exception), r"^stopped without exit at 0110:0001 \(AX=")
        self.assertTrue(machine.spent)

    def test_unknown_function_fails_with_message(self):
        program = asm.mz_exe(mov_ah(0x99) + int21())
        machine = self.realmode.RealModeMachine(program)
        with self.assertRaises(EmulatorError) as caught:
            self.emu(program).run(machine)
        self.assertRegex(str(caught.exception), r"^unsupported INT 21h AH=99h at 0110:0002 \(AX=99")
        self.assertTrue(machine.spent)

    def test_unknown_interrupt_fails(self):
        with self.assertRaisesRegex(EmulatorError, r"^unsupported interrupt INT 13h at 0110:0000"):
            self.run_program(asm.mz_exe(b"\xcd\x13"))
        with self.assertRaisesRegex(EmulatorError, r"^unsupported INT 10h AH=00h"):
            self.run_program(asm.mz_exe(mov_ah(0) + b"\xcd\x10"))

    def test_cpu_exception_without_handler_fails(self):
        # xor cx, cx; div cx -> INT 0 at the div
        with self.assertRaisesRegex(EmulatorError, r"^unsupported interrupt INT 00h at 0110:0002"):
            self.run_program(asm.mz_exe(b"\x31\xc9\xf7\xf1"))

    # --- interrupt vectors ---------------------------------------------------------------------------------------
    def test_program_vector_is_called(self):
        main = PUSH_CS_POP_DS + mov16("DX", 0) + mov16("AX", 0x2560) + int21() + b"\xcd\x60" + mov_ah(0x4C) + int21()
        handler = b"\xb0\x2a\xcf"  # mov al, 2Ah; iret
        main = main.replace(mov16("DX", 0), mov16("DX", len(main)))
        result, machine = self.run_program(asm.mz_exe(main + handler))
        self.assertEqual(result.exit_code, 0x2A)
        self.assertEqual(struct.unpack("<HH", self.memory(machine, 0, 0x60 * 4, 4)), (len(main), asm.LOAD_SEG))

    def test_hooked_int21_chains_to_dos(self):
        # handler: inc byte cs:[COUNT]; jmp far cs:[OLD]
        count, old = 0x200, 0x204
        handler = b"\x2e\xfe\x06" + struct.pack("<H", count) + b"\x2e\xff\x2e" + struct.pack("<H", old)
        main = (
            mov16("AX", 0x3521) + int21()
            + b"\x2e\x89\x1e" + struct.pack("<H", old)  # mov cs:[OLD], bx
            + b"\x2e\x8c\x06" + struct.pack("<H", old + 2)  # mov cs:[OLD+2], es
            + PUSH_CS_POP_DS + mov16("DX", 0x100) + mov16("AX", 0x2521) + int21()
            + mov_ah(0x19) + int21()  # through the handler: count = 1
            + b"\x2e\xa0" + struct.pack("<H", count)  # mov al, cs:[COUNT]
            + mov_ah(0x4C) + int21()  # through the handler as well
        )
        code = (main.ljust(0x100, b"\x90") + handler).ljust(count, b"\x90") + bytes(8)  # COUNT = 0
        result, _ = self.run_program(asm.mz_exe(code))
        self.assertEqual(result.exit_code, 1)

    def test_chained_int21_returns_the_carry_of_dos(self):
        # handler: jmp far cs:[OLD]; main: open a missing file through it, exit with CF
        old = 0x200
        handler = b"\x2e\xff\x2e" + struct.pack("<H", old)
        main = (
            mov16("AX", 0x3521) + int21()
            + b"\x2e\x89\x1e" + struct.pack("<H", old)  # mov cs:[OLD], bx
            + b"\x2e\x8c\x06" + struct.pack("<H", old + 2)  # mov cs:[OLD+2], es
            + PUSH_CS_POP_DS + mov16("DX", 0x100) + mov16("AX", 0x2521) + int21()
            + mov16("DX", 0x300) + mov16("AX", 0x3D00) + int21()  # open "NONE.TXT": error 2, CF set
            + b"\x0f\x92\xc0"  # setc al
            + mov_ah(0x4C) + int21()
        )
        code = (main.ljust(0x100, b"\x90") + handler).ljust(0x300, b"\x90") + b"NONE.TXT\0"
        result, _ = self.run_program(asm.mz_exe(code))
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.calls["21/3D00"], 1)

    def test_get_and_set_vector(self):
        _, _, d = self.run_calls(
            [
                (mov16("AX", 0x3561), 0x21),
                (mov16("AX", 0x2561) + mov16("DX", 0x1234), 0x21),
                (mov16("AX", 0x3561), 0x21),
            ]
        )
        self.assertEqual((d[0]["ES"], d[0]["BX"]), (self.realmode.STUB_SEG, 0x61 * 8))
        self.assertEqual((d[2]["ES"], d[2]["BX"]), (asm.DATA_SEG, 0x1234))

    # --- console -------------------------------------------------------------------------------------------------
    def test_print_string_goes_to_output(self):
        code = (
            asm.SET_DS_DATA
            + mov_ah(0x09) + mov16("DX", 0) + int21()
            + mov_ah(0x02) + b"\xb2!" + int21()  # mov dl, '!'
            + mov_ah(0x06) + b"\xb2?" + int21()
            + mov16("AX", 0x0E78) + b"\xcd\x10"  # teletype 'x'
            + asm.exit16(0)
        )
        result, _ = self.run_program(asm.mz_exe(code, b"Hello$", [asm.DATA_RELOCATION]))
        self.assertEqual(result.output, b"Hello!?x")

    # --- memory --------------------------------------------------------------------------------------------------
    def test_allocate_resize_free(self):
        _, _, d = self.run_calls(
            [
                (es(0x100) + mov16("BX", 0x80) + mov_ah(0x4A), 0x21),  # shrink the program block
                (mov16("BX", 0x100) + mov_ah(0x48), 0x21),  # allocate
                (mov16("BX", 0xFFFF) + mov_ah(0x48), 0x21),  # too much: largest block
                (asm.mov_es_from(asm.DUMP + 16) + mov16("BX", 0x200) + mov_ah(0x4A), 0x21),  # grow
                (mov_ah(0x49), 0x21),  # free
                (mov16("BX", 0xFFFF) + mov_ah(0x48), 0x21),  # everything is free again
                (es(0x1234) + mov_ah(0x49), 0x21),  # not a block
                (es(0x100) + mov16("BX", 0xA000) + mov_ah(0x4A), 0x21),  # cannot grow that far
                (mov16("BX", 1) + mov_ah(0x48), 0x21),  # the block took all memory
            ]
        )
        free_after_shrink = 0xA000 - 0x180 - 1
        self.assertFalse(d[0]["FLAGS"] & CARRY)
        self.assertEqual((d[1]["FLAGS"] & CARRY, d[1]["AX"]), (0, 0x181))
        self.assertEqual((d[2]["FLAGS"] & CARRY, d[2]["AX"], d[2]["BX"]), (1, 8, free_after_shrink - 0x101))
        self.assertFalse(d[3]["FLAGS"] & CARRY)
        self.assertFalse(d[4]["FLAGS"] & CARRY)
        self.assertEqual((d[5]["FLAGS"] & CARRY, d[5]["BX"]), (1, free_after_shrink))
        self.assertEqual((d[6]["FLAGS"] & CARRY, d[6]["AX"]), (1, 9))
        self.assertEqual((d[7]["FLAGS"] & CARRY, d[7]["AX"], d[7]["BX"]), (1, 8, 0xA000 - 0x100))
        self.assertEqual((d[8]["FLAGS"] & CARRY, d[8]["BX"]), (1, 0))

    def test_program_block_follows_max_alloc(self):
        # max_alloc 0: the program gets PSP + image only; the rest is a free block
        program = asm.mz_exe(asm.SET_DS_DATA + mov16("BX", 0xFFFF) + mov_ah(0x48) + int21() + asm.dump_registers(0)
                             + asm.exit16(0), relocations=[asm.DATA_RELOCATION], max_alloc=0)
        _, machine = self.run_program(program)
        self.assertEqual(self.dumps(machine, 1)[0]["BX"], 0xA000 - 0x180 - 1)
        self.assertEqual(struct.unpack("<H", self.memory(machine, 0x100, 2, 2))[0], 0x180)

    def test_program_too_large_fails(self):
        with self.assertRaisesRegex(EmulatorError, "not enough memory"):
            self.run_program(asm.mz_exe(b"", min_alloc=0xA000))

    # --- file services -------------------------------------------------------------------------------------------
    def test_handle_services(self):
        (self.c / "IN.TXT").write_bytes(b"ABCDEFGH")
        result, _, d = self.run_calls(
            [
                (mov16("AX", 0x3D00) + mov16("DX", 0), 0x21),  # 0 open
                (mov_ah(0x3F) + mov16("BX", 5) + mov16("CX", 4) + mov16("DX", 0x40), 0x21),  # 1 read 4
                (mov16("AX", 0x4202) + mov16("BX", 5) + mov16("CX", 0) + mov16("DX", 0), 0x21),  # 2 seek end
                (mov16("AX", 0x5700) + mov16("BX", 5), 0x21),  # 3 file time
                (mov_ah(0x45) + mov16("BX", 5), 0x21),  # 4 dup
                (mov_ah(0x3E) + mov16("BX", 5), 0x21),  # 5 close the original
                (mov16("AX", 0x4200) + mov16("BX", 6) + mov16("CX", 0) + mov16("DX", 1), 0x21),  # 6 seek dup
                (mov_ah(0x3F) + mov16("BX", 6) + mov16("CX", 2) + mov16("DX", 0x48), 0x21),  # 7 read dup
                (mov_ah(0x46) + mov16("BX", 1) + mov16("CX", 6), 0x21),  # 8 force dup stdout onto 6
                (mov_ah(0x40) + mov16("BX", 6) + mov16("CX", 2) + mov16("DX", 0x40), 0x21),  # 9 write 6
                (mov_ah(0x3E) + mov16("BX", 6), 0x21),  # 10 close 6
                (mov_ah(0x40) + mov16("BX", 1) + mov16("CX", 1) + mov16("DX", 0x42), 0x21),  # 11 stdout
                (mov_ah(0x3F) + mov16("BX", 5) + mov16("CX", 1) + mov16("DX", 0x40), 0x21),  # 12 closed
                (mov16("AX", 0x4400) + mov16("BX", 1), 0x21),  # 13 IOCTL device info
            ],
            b"IN.TXT\0",
        )
        self.assertEqual(d[0]["AX"], 5)
        self.assertEqual(d[1]["AX"], 4)
        self.assertEqual((d[2]["DX"], d[2]["AX"]), (0, 8))
        self.assertFalse(d[3]["FLAGS"] & CARRY)
        self.assertNotEqual(d[3]["DX"], 0)
        self.assertEqual(d[4]["AX"], 6)
        self.assertFalse(d[5]["FLAGS"] & CARRY)
        self.assertEqual((d[6]["FLAGS"] & CARRY, d[6]["AX"]), (0, 1))
        self.assertEqual(d[7]["AX"], 2)
        self.assertFalse(d[8]["FLAGS"] & CARRY)
        self.assertEqual(result.output, b"ABC")
        self.assertEqual((d[12]["FLAGS"] & CARRY, d[12]["AX"]), (1, 6))
        self.assertEqual(d[13]["DX"], 0x80D3)
        self.assertEqual(self.fs.handles.keys(), {0, 1, 2, 3, 4})  # 4Ch closed everything

    def test_name_services(self):
        (self.c / "IN.TXT").write_bytes(b"x")
        _, machine, d = self.run_calls(
            [
                (mov_ah(0x5B) + mov16("CX", 0) + mov16("DX", 0), 0x21),  # 0 create new
                (mov_ah(0x3E) + mov16("BX", 5), 0x21),  # 1 close
                (mov_ah(0x5B) + mov16("CX", 0) + mov16("DX", 0), 0x21),  # 2 exists
                (PUSH_DS_POP_ES + mov_ah(0x56) + mov16("DX", 0) + mov16("DI", 0x10), 0x21),  # 3 rename
                (mov16("AX", 0x4300) + mov16("DX", 0x10), 0x21),  # 4 attributes
                (mov_ah(0x4E) + mov16("CX", 0) + mov16("DX", 0x20), 0x21),  # 5 find first
                (mov_ah(0x4F), 0x21),  # 6 find next
                (mov_ah(0x4F), 0x21),  # 7 no more
                (mov_ah(0x41) + mov16("DX", 0x10), 0x21),  # 8 delete
                (mov_ah(0x41) + mov16("DX", 0x10), 0x21),  # 9 delete again
                (mov_ah(0x47) + b"\xb2\x00" + mov16("SI", 0x80), 0x21),  # 10 current directory
                (mov_ah(0x2F), 0x21),  # 11 DTA address
                (mov_ah(0x1A) + mov16("DX", 0x40), 0x21),  # 12 set DTA
                (mov_ah(0x2F), 0x21),  # 13
                (mov_ah(0x4E) + mov16("CX", 0) + mov16("DX", 0x20), 0x21),  # 14 find first into the new DTA
            ],
            b"NEW.TXT".ljust(0x10, b"\0") + b"REN.TXT".ljust(0x10, b"\0") + b"*.TXT\0",
        )
        self.assertEqual(d[0]["AX"], 5)
        self.assertEqual((d[2]["FLAGS"] & CARRY, d[2]["AX"]), (1, 80))
        self.assertFalse(d[3]["FLAGS"] & CARRY)
        self.assertEqual(d[4]["CX"], 0x20)
        self.assertFalse(d[5]["FLAGS"] & CARRY)
        self.assertFalse(d[6]["FLAGS"] & CARRY)
        self.assertEqual(self.memory(machine, 0x100, 0x80 + 0x1E, 8), b"REN.TXT\0")  # default DTA = PSP:80h
        self.assertEqual((d[7]["FLAGS"] & CARRY, d[7]["AX"]), (1, 0x12))
        self.assertFalse(d[8]["FLAGS"] & CARRY)
        self.assertEqual((d[9]["FLAGS"] & CARRY, d[9]["AX"]), (1, 2))
        self.assertFalse(d[10]["FLAGS"] & CARRY)
        self.assertEqual((d[11]["ES"], d[11]["BX"]), (0x100, 0x80))
        self.assertEqual((d[13]["ES"], d[13]["BX"]), (asm.DATA_SEG, 0x40))
        self.assertEqual(self.memory(machine, asm.DATA_SEG, 0x40 + 0x1E, 7), b"IN.TXT\0")
        self.assertEqual(sorted(p.name for p in self.c.iterdir()), ["IN.TXT"])

    def test_find_next_continues_from_a_copied_dta(self):
        (self.c / "A.TXT").write_bytes(b"a")
        (self.c / "B.TXT").write_bytes(b"b")
        copy = PUSH_DS_POP_ES + mov16("SI", 0x40) + mov16("DI", 0x80) + mov16("CX", 43) + b"\xfc\xf3\xa4"  # rep movsb
        _, machine, d = self.run_calls(
            [
                (mov_ah(0x1A) + mov16("DX", 0x40), 0x21),
                (mov_ah(0x4E) + mov16("CX", 0) + mov16("DX", 0), 0x21),
                (copy + mov_ah(0x1A) + mov16("DX", 0x80), 0x21),
                (mov_ah(0x4F), 0x21),
                (mov_ah(0x4F), 0x21),
            ],
            b"*.TXT\0",
        )
        self.assertEqual(self.memory(machine, asm.DATA_SEG, 0x40 + 0x1E, 6), b"A.TXT\0")
        self.assertFalse(d[3]["FLAGS"] & CARRY)
        self.assertEqual(self.memory(machine, asm.DATA_SEG, 0x80 + 0x1E, 6), b"B.TXT\0")
        self.assertEqual((d[4]["FLAGS"] & CARRY, d[4]["AX"]), (1, 0x12))

    def test_console_input_status(self):
        _, _, d = self.run_calls([(mov16("AX", 0x0BFF), 0x21)])
        self.assertEqual(d[0]["AX"], 0x0B00)

    def test_parse_file_name(self):
        _, machine, d = self.run_calls(
            [
                (PUSH_DS_POP_ES + mov16("AX", 0x2901) + mov16("SI", 0) + mov16("DI", 0x40), 0x21),
                (PUSH_DS_POP_ES + mov16("AX", 0x2900) + mov16("SI", 0x20) + mov16("DI", 0x60), 0x21),
                (PUSH_DS_POP_ES + mov16("AX", 0x2900) + mov16("SI", 0x30) + mov16("DI", 0x80), 0x21),
            ],
            b" c:foo*.c x".ljust(0x20, b"\0") + b"README".ljust(0x10, b"\0") + b"Q:A.B",
        )
        self.assertEqual((d[0]["AX"] & 0xFF, d[0]["SI"]), (1, 9))
        self.assertEqual(self.memory(machine, asm.DATA_SEG, 0x40, 12), b"\x03FOO?????C  ")
        self.assertEqual((d[1]["AX"] & 0xFF, d[1]["SI"]), (0, 0x26))
        self.assertEqual(self.memory(machine, asm.DATA_SEG, 0x60, 12), b"\x00README     ")
        self.assertEqual(d[2]["AX"] & 0xFF, 0xFF)  # invalid drive

    def test_parse_file_name_without_zero_in_reach(self):
        # 128 blanks up to the end of the read window: no IndexError, nothing parsed
        _, _, d = self.run_calls(
            [(PUSH_DS_POP_ES + mov16("AX", 0x2901) + mov16("SI", 0x80) + mov16("DI", 0), 0x21)],
            bytes(0x80) + b" " * 0x80,
        )
        self.assertEqual((d[0]["AX"] & 0xFF, d[0]["SI"]), (0, 0x100))

    def test_ctrl_break_subfunctions(self):
        _, _, d = self.run_calls([(mov16("AX", 0x3301) + mov16("DX", 1), 0x21), (mov16("AX", 0x3305), 0x21)])
        self.assertEqual((d[0]["DX"], d[1]["DX"] & 0xFF), (1, 3))
        with self.assertRaisesRegex(EmulatorError, r"^unsupported INT 21h AH=33h AL=02h at "):
            self.run_program(asm.calls16([(mov16("AX", 0x3302), 0x21)]))

    def test_system_services(self):
        _, _, d = self.run_calls(
            [
                (mov_ah(0x30), 0x21),  # 0 version
                (mov_ah(0x62), 0x21),  # 1 PSP
                (mov_ah(0x36) + b"\xb2\x00", 0x21),  # 2 free space, current drive
                (mov_ah(0x36) + b"\xb2\x1a", 0x21),  # 3 Z: not mounted
                (mov16("AX", 0x3300), 0x21),  # 4 Ctrl-Break state
                (mov_ah(0x00), 0x1A),  # 5 BIOS ticks
                (mov_ah(0x01), 0x16),  # 6 key available?
                (mov16("AX", 0x1686), 0x2F),  # 7 DPMI mode check
                (mov_ah(0x0F), 0x10),  # 8 video mode
                (mov_ah(0x06) + b"\xb2\xff", 0x21),  # 9 console input
            ]
        )
        self.assertEqual(d[0]["AX"], 0x0005)
        self.assertEqual(d[1]["BX"], 0x100)
        self.assertEqual(d[2]["CX"], 512)
        self.assertGreater(d[2]["AX"] * d[2]["BX"] * 512, 100 * 1024 * 1024)
        self.assertLessEqual(d[2]["BX"], d[2]["DX"])
        self.assertEqual(d[3]["AX"], 0xFFFF)
        self.assertEqual(d[4]["DX"] & 0xFF, 0)
        self.assertLessEqual((d[5]["CX"] << 16) | d[5]["DX"], 0x1800B0)
        self.assertEqual(d[5]["AX"] & 0xFF, 0)
        self.assertTrue(d[6]["FLAGS"] & ZERO)
        self.assertEqual(d[7]["AX"], 0x1686)
        self.assertEqual(d[8]["AX"], 0x5003)
        self.assertEqual(d[9]["AX"] & 0xFF, 0)
        self.assertTrue(d[9]["FLAGS"] & ZERO)


if __name__ == "__main__":
    unittest.main()
