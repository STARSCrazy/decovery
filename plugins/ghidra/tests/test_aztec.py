"""Pure tests of the Aztec C86 pattern scanner (no Ghidra)."""

import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_ghidra import aztec  # noqa: E402
from decovery_ghidra.mapping import GhidraAddress, MemoryBlockSpec  # noqa: E402

# Hand-assembled helpers with the shape Aztec C86's run-time library uses (written for these tests).
CSAV = bytes.fromhex("5B 55 8B EC 03 E0 57 56 FF D3 5E 5F 8B E5 5D C3")
SWITCH = bytes.fromhex("5B 57 06 8C CF 8E C7 8B FB 8B D9 D1 E3 FC F2 AF 26 8B 49 FC 07 5F FF E1")

# The sign handling of `$ldv` and the signed remainder up to their `call` (operand bytes filled by the test).
LONG_DIVIDE = bytes.fromhex("57 2B FF 85 D2 79 08 F7 DA F7 D8 83 DA 00 47 85 DB 79 0B F7 DB F7 D9 83 DB 00 81 F7 01"
                            " 00 E8 00 00")
LONG_REMAINDER = bytes.fromhex("57 BF 00 00 85 D2 79 08 F7 DA F7 D8 83 DA 00 47 85 DB 79 07 F7 DB F7 D9 83 DB 00 E8"
                               " 00 00")


def near_call(at: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<H", (target - (at + 3)) & 0xFFFF)


def DENSE(table: int) -> bytes:
    return bytes.fromhex("73 08 93 D1 E3 2E FF A7") + struct.pack("<H", table)


def switch_image() -> bytes:
    """`mov cx,3; call switch; dw 1, 2, 0x19, 0x1D, 0x21` at 0x009, helper at 0x200."""
    image = bytearray(b"\x90" * 0x220)
    image[0x009:0x00C] = b"\xb9\x03\x00"
    image[0x00C:0x00F] = near_call(0x00C, 0x200)
    image[0x00F:0x019] = struct.pack("<5H", 1, 2, 0x19, 0x1D, 0x21)
    image[0x200:0x200 + len(SWITCH)] = SWITCH
    return bytes(image)


def block(name, start, data, perms="r-x"):
    return MemoryBlockSpec(name, start, len(data), "r" in perms, "w" in perms, "x" in perms, data)


class AztecTests(unittest.TestCase):
    def test_finds_csav_prologue_helper(self):
        image = b"\x90" * 0x100 + CSAV
        self.assertEqual(aztec.find_csav(image), [0x100])
        self.assertEqual(aztec.find_csav(CSAV[:5]), [])

    def test_finds_switch_helper(self):
        self.assertEqual(aztec.find_switch_helpers(switch_image()), [0x200])

    def test_switch_sites_decode_the_inline_table(self):
        image = switch_image()
        sites = aztec.switch_sites(image, 0, [0x200])
        self.assertEqual(
            sites, [aztec.SwitchSite(call=0x00C, table=0x00F, size=10, cases=[1, 2], targets=[0x19, 0x1D, 0x21])]
        )
        self.assertEqual(sites[0].comment(), "switch (AX): 0x1 -> 0019, 0x2 -> 001D; default -> 0021")

    def test_case_labels_by_target(self):
        self.assertEqual(aztec.case_labels([1, 2], [0x19, 0x1D, 0x21]), {0x19: "0x1", 0x1D: "0x2", 0x21: "default"})
        self.assertEqual(aztec.case_labels([0x52, 0x53, 7], [0x19, 0x19, 0x21, 0x21]),
                         {0x19: "0x52: case 0x53", 0x21: "0x7: default"})

    def test_case_label_for_a_token(self):
        labels = aztec.case_labels([0, 0x12, 0x64], [0x89, 0x91, 0x99, 0xA0])
        self.assertEqual(aztec.case_label(labels, 0x91, 0x91), "0x12")
        self.assertEqual(aztec.case_label(labels, 0xFFFF0091, 0x91), "0x12")  # sign-extended address
        # the decompiler could not back the switch value up to the table: the case token sits at its target, or
        # past it when the first instruction of the case was folded away
        self.assertEqual(aztec.case_label(labels, aztec.BAD_LABEL, 0x99), "0x64")
        self.assertEqual(aztec.case_label(labels, aztec.BAD_LABEL, 0x9C), "0x64")
        self.assertIsNone(aztec.case_label(labels, aztec.BAD_LABEL, 0x80))
        self.assertIsNone(aztec.case_label(labels, aztec.BAD_LABEL, None))
        self.assertIsNone(aztec.case_label(labels, 7, 0x91))  # a value the decompiler recovered itself

    def test_expected_warnings(self):
        lines = [
            "/* WARNING: Function: fun_1000_0200 replaced with injection: decovery_aztec_switch */",
            "/* WARNING (jumptable): Removing unreachable block (ram,0x0001000c) */",
            "/* WARNING: Removing unreachable block (ram,0x0001000c) */",
            "/* WARNING (jumptable): Removing unreachable block (ram,0x00010040) */",
            "/* WARNING: Removing unreachable block (ram,0x00010040) */",
            "",
            "                    /* WARNING: Switch is manually overridden */",
            "                    /* WARNING: Switch is manually overridden */",
            "/* WARNING: Bad instruction */",
        ]
        self.assertEqual(aztec.expected_warnings(lines, {0x1000C}), {0, 1, 2, 3, 6, 7})
        self.assertEqual(aztec.expected_warnings(lines, set()), {0, 1, 3, 7})
        other = ["/* WARNING: Function: f replaced with injection: alloca_probe */"]
        self.assertEqual(aztec.expected_warnings(other, set()), set())

    def test_finds_long_helpers(self):
        image = bytearray(b"\x90" * 0x300)
        image[0x100:0x100 + len(LONG_DIVIDE)] = LONG_DIVIDE
        image[0x11E:0x121] = near_call(0x11E, 0x200)
        image[0x140:0x140 + len(LONG_REMAINDER)] = LONG_REMAINDER
        image[0x15B:0x15E] = near_call(0x15B, 0x200)
        image[0x1F8:0x200] = near_call(0x1F8, 0x200) + bytes.fromhex("8B C1 8B D3 C3")
        image[0x200:0x204] = bytes.fromhex("85 DB 75 1E")
        image[0x280:0x288] = near_call(0x280, 0x290) + bytes.fromhex("8B C1 8B D3 C3")  # calls something else
        found = aztec.find_helpers(bytes(image), 0x1000)
        self.assertEqual([(h.offset, h.kind) for h in found],
                         [(0x1100, "long"), (0x1140, "long"), (0x11F8, "long"), (0x1200, "long")])
        self.assertTrue(found[0].role.startswith("$ldv"))
        both = aztec.find_helpers(b"\x90" + CSAV + SWITCH, 0)
        self.assertEqual([(h.offset, h.kind) for h in both], [(1, "csav"), (1 + len(CSAV), "switch")])

    def test_stub_names_the_role(self):
        self.assertEqual(aztec.stub("$ldv: x", "long f(long a)"),
                         "/* Aztec C86 run-time helper: $ldv: x */\n\nlong f(long a);\n")

    def test_dense_switch_with_table_in_front(self):
        # table of 3 targets at 0x100, then sub ax,-1; cmp ax,3; jae; xchg; shl; jmp cs:[bx+0x100]
        image = bytearray(b"\x90" * 0x100) + struct.pack("<3H", 0x130, 0x134, 0x138)
        image += b"\x2d\xff\xff\x3d\x03\x00" + DENSE(0x100) + b"\xc3"
        sites = aztec.dense_switch_sites(bytes(image), 0)
        self.assertEqual(sites, [aztec.SwitchSite(call=0x111, table=0x100, size=6, cases=[0xFFFF, 0, 1],
                                                  targets=[0x130, 0x134, 0x138, 0x116])])
        self.assertEqual(aztec.case_labels(sites[0].cases, sites[0].targets)[0x130], "-0x1")
        self.assertEqual(aztec.dense_switch_sites(bytes(image[0x106:]), 0x106), [])  # table not in front

    def test_switch_sites_respect_the_block_offset(self):
        image = switch_image()
        sites = aztec.switch_sites(image[0x009:], 0x009, [0x200])
        self.assertEqual([s.call for s in sites], [0x00C])

    def test_switch_table_running_past_the_block_is_ignored(self):
        image = switch_image()[:0x014]
        self.assertEqual(aztec.switch_sites(image, 0, [0x200]), [])

    def test_absurd_count_is_ignored(self):
        image = bytearray(switch_image())
        image[0x00A:0x00C] = b"\x00\x00"
        self.assertEqual(aztec.switch_sites(bytes(image), 0, [0x200]), [])

    def test_data_segment_from_overlay_data_blocks(self):
        code = block("A.code", GhidraAddress(0, 0x100, "A"), b"\xc3")
        data_a = block("A.data", GhidraAddress(0x0FF6, 0x909C, "A"), b"\0", "rw-")
        data_b = block("B.data", GhidraAddress(0x0FF6, 0x909C, "B"), b"\0", "rw-")
        main = block("image", GhidraAddress(0, 0), b"\xc3", "rwx")
        self.assertEqual(aztec.data_segment([main, code, data_a, data_b]), 0x0FF6)
        self.assertIsNone(aztec.data_segment([main, code]))
        other = block("C.data", GhidraAddress(0x1000, 0, "C"), b"\0", "rw-")
        self.assertIsNone(aztec.data_segment([data_a, other]))

    def test_uncovered_parts_of_the_data_segment(self):
        main = block("image", GhidraAddress(0, 0), b"\0" * 0x10100, "rwx")
        overlay = block("A.data", GhidraAddress(0x0FF6, 0x909C, "A"), b"\0", "rw-")
        self.assertEqual(aztec.uncovered([main, overlay], 0x0FF6), [(0x01A0, 0x10000 - 0x01A0)])
        self.assertEqual(aztec.uncovered([overlay], 0x0FF6), [(0, 0x10000)])
        inside = block("x", GhidraAddress(0x1000, 0x10), b"\0" * 0x10, "rw-")
        self.assertEqual(aztec.uncovered([inside], 0x1000), [(0, 0x10), (0x20, 0x10000 - 0x20)])

    def test_data_label_name(self):
        self.assertEqual(aztec.data_label(GhidraAddress(0x0FF6, 0x9202, "VTREA")), "DAT_VTREA_0ff6_9202")
        self.assertEqual(aztec.data_label(GhidraAddress(0x0FF6, 0x8302)), "DAT_0ff6_8302")


if __name__ == "__main__":
    unittest.main()
