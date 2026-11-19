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


def near_call(at: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<H", (target - (at + 3)) & 0xFFFF)


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
