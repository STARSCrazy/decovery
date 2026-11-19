"""Against a real Ghidra: skipped unless GHIDRA_INSTALL_DIR is set and pyghidra is importable."""

import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_plugin import inline_blob  # noqa: E402

from decovery_ghidra import build_plugin  # noqa: E402
from decovery_ghidra.backend import GhidraBackend  # noqa: E402
from decovery_ghidra.hashing import blake3_hex  # noqa: E402
from decovery_ghidra.mapping import from_ghidra_address, merged_ranges  # noqa: E402
from test_plugin import by_id, req, run  # noqa: E402

GHIDRA = bool(os.environ.get("GHIDRA_INSTALL_DIR")) and importlib.util.find_spec("pyghidra") is not None


def tiny_program() -> bytes:
    """64 bytes of flat-32 code at 0x10000: `call 0x10010; ret`, padding, then `ret` at 0x10010."""
    code = bytearray(b"\xcc" * 64)
    code[0:6] = b"\xe8\x0b\x00\x00\x00\xc3"  # call +0x0B (-> 0x10010); ret
    code[0x10] = 0xC3  # ret
    return bytes(code)


@unittest.skipUnless(GHIDRA, "needs GHIDRA_INSTALL_DIR and pyghidra")
class LocalGhidraTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("DECOVERY_TARGET_MZ") and os.environ.get("DECOVERY_GOLDEN_DIR"),
        "local: second target; needs DECOVERY_TARGET_MZ and DECOVERY_GOLDEN_DIR",
    )
    def test_second_target_line_coverage_five_functions(self):
        """Record real instruction-start coverage, including segmented aliases; holes are evidence, not failure.

        The private executable and report stay outside the repository. Uses Ghidra's MZ loader rather than a
        synthetic memory image, so relocations and the target's real-mode segment addresses are preserved.
        """
        import pyghidra

        binary = Path(os.environ["DECOVERY_TARGET_MZ"])
        self.assertTrue(binary.is_file(), binary)
        report_path = Path(os.environ["DECOVERY_GOLDEN_DIR"]) / "ghidra-v2-line-coverage.json"
        report = []
        with tempfile.TemporaryDirectory() as tmp:
            with pyghidra.open_program(binary, project_location=tmp, project_name="line-coverage") as api:
                from ghidra.app.decompiler import DecompileOptions, DecompInterface

                backend = GhidraBackend()
                backend._pyghidra = pyghidra
                backend._program = api.getCurrentProgram()
                backend._decompiler = DecompInterface()
                backend._decompiler.setOptions(DecompileOptions())
                backend._decompiler.openProgram(backend._program)

                def linear(address):
                    return (address.segment or 0) * 16 + address.offset

                try:
                    for function in backend._program.getFunctionManager().getFunctions(True):
                        if function.isExternal() or function.isThunk():
                            continue
                        start = backend._to_spec(function.getEntryPoint())
                        self.assertIsNotNone(start)
                        self.assertIsNotNone(start.segment, "the second target must use segmented addresses")
                        instructions = [backend._to_spec(ins.getAddress()) for ins in
                                        backend._program.getListing().getInstructions(function.getBody(), True)]
                        if not instructions:
                            continue
                        result = backend.decompile(start)
                        self.assertIsNotNone(result.code, result.error)
                        self.assertIsNotNone(result.lines)
                        self.assertEqual([line.line for line in result.lines],
                                         list(range(1, len(result.code.splitlines()) + 1)))
                        ranges = [pair for line in result.lines for pair in line.ranges]
                        missing = [at for at in instructions if not any(
                            linear(low) <= linear(at) <= linear(high) for low, high in ranges
                        )]
                        report.append({
                            "address": from_ghidra_address(start, "x86-real-16"),
                            "instructions": len(instructions), "covered": len(instructions) - len(missing),
                            "coverage": (len(instructions) - len(missing)) / len(instructions),
                            "unmapped": [from_ghidra_address(at, "x86-real-16") for at in missing],
                            "lines": [{"line": line.line, "ranges": merged_ranges(line.ranges, "x86-real-16")}
                                      for line in result.lines],
                        })
                        if len(report) == 5:
                            break
                finally:
                    backend._decompiler.dispose()
                    report_path.parent.mkdir(parents=True, exist_ok=True)
                    report_path.write_text(json.dumps({"functions": report}, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(len(report), 5, "the second target must supply five nonempty functions")

    def test_tiny_flat_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program = {
                "format": "flat",
                "entry_points": ["flat:00010000"],
                "regions": [
                    {
                        "name": "code",
                        "start": "flat:00010000",
                        "size": 64,
                        "arch": "x86-flat-32",
                        "permissions": "r-x",
                        "blob": inline_blob(tiny_program()),
                    }
                ],
            }
            opening = req(
                2, "analyzer/open", {"program": program, "project_dir": str(root / "ghidra"), "program_hash": "f" * 64}
            )
            symbols = [{"address": "flat:00010010", "kind": "function", "name": "helper", "locals": [],
                        "line_comments": []}]
            out_path = root / "export.json"
            out = run(
                build_plugin(),
                opening,
                req(3, "analyzer/apply", {"symbols": symbols, "types_h": "", "references": []}),
                req(4, "analyzer/export", {"out_path": str(out_path)}),
                req(5, "decompiler/decompile", {"addresses": ["flat:00010000"], "out_dir": str(root / "c")}),
                req(6, "shutdown"),  # releases the project lock for the next session
            )
            opened = by_id(out, 2)
            self.assertEqual(opened.get("result", {}).get("reused"), False, opened)
            applied = by_id(out, 3)["result"]
            self.assertEqual(applied["applied"], 1, applied)
            exported = by_id(out, 4)["result"]
            self.assertEqual(exported["blake3"], blake3_hex(out_path.read_bytes()))
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual([f["start"] for f in data["functions"]], ["flat:00010000", "flat:00010010"], data)
            self.assertEqual(data["functions"][1]["name"], "helper")
            self.assertEqual(
                data["calls"], [{"site": "flat:00010000", "caller": "flat:00010000", "callee": "flat:00010010"}]
            )
            decompiled = by_id(out, 5)["result"][0]
            self.assertIn("path", decompiled, decompiled)
            self.assertIn("helper", Path(decompiled["path"]).read_text(encoding="utf-8"))

            # the saved project is reused by the next open
            again = run(build_plugin(), opening, req(3, "shutdown"))
            self.assertEqual(by_id(again, 2)["result"]["reused"], True)

    def test_two_overlays_at_one_address(self):
        """ADR 0011: overlays sharing a processor address get their own address spaces and `ovl:` addresses."""

        def overlay_code(filler: int) -> bytes:
            code = bytearray([filler]) * 32
            code[0:4] = b"\xe8\x0d\x00\xc3"  # call 0010; ret
            code[0x10] = 0xC3  # ret
            return bytes(code)

        def region(name, start, data):
            return {"name": name, "start": start, "size": len(data), "arch": "x86-real-16", "permissions": "r-x",
                    "blob": inline_blob(data)}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program = {
                "format": "mz",
                "entry_points": ["seg:1000:0000"],
                "regions": [
                    region("image", "seg:1000:0000", b"\xc3" + b"\x90" * 15),
                    region("OVA.code", "ovl:OVA:2000:0000", overlay_code(0x90)),
                    region("OVB.code", "ovl:OVB:2000:0000", overlay_code(0xCC)),
                ],
            }
            symbols = [
                {"address": a, "kind": "function", "name": n, "locals": [], "line_comments": []}
                for a, n in (("ovl:OVA:2000:0000", "a_main"), ("ovl:OVA:2000:0010", "a_helper"),
                             ("ovl:OVB:2000:0000", "b_main"), ("ovl:OVB:2000:0010", "b_helper"))
            ]
            out_path = root / "export.json"
            out = run(
                build_plugin(),
                req(2, "analyzer/open", {"program": program, "project_dir": str(root / "ghidra"),
                                         "program_hash": "e" * 64}),
                req(3, "analyzer/apply", {"symbols": symbols, "types_h": "", "references": []}),
                req(4, "analyzer/export", {"out_path": str(out_path)}),
                req(5, "decompiler/decompile", {"addresses": ["ovl:OVB:2000:0000"], "out_dir": str(root / "c")}),
                req(6, "shutdown"),
            )
            self.assertEqual(by_id(out, 3)["result"]["applied"], 4, by_id(out, 3))
            data = json.loads(out_path.read_text(encoding="utf-8"))
            starts = {f["start"]: f.get("name") for f in data["functions"]}
            for address, name in (("ovl:OVA:2000:0000", "a_main"), ("ovl:OVA:2000:0010", "a_helper"),
                                  ("ovl:OVB:2000:0000", "b_main"), ("ovl:OVB:2000:0010", "b_helper")):
                self.assertEqual(starts.get(address), name, data["functions"])
            calls = {(c["caller"], c["callee"]) for c in data["calls"]}
            self.assertEqual(
                calls,
                {("ovl:OVA:2000:0000", "ovl:OVA:2000:0010"), ("ovl:OVB:2000:0000", "ovl:OVB:2000:0010")},
            )
            decompiled = by_id(out, 5)["result"][0]
            self.assertIn("path", decompiled, decompiled)
            self.assertIn("b_helper", Path(decompiled["path"]).read_text(encoding="utf-8"))

    def test_aztec_overlay_reads_its_data_segment(self):
        """Overlay data blocks give DS: `mov ax,[0x0020]` reads OVA.data, and the label shows the DS offset."""

        def region(name, start, data, permissions):
            return {"name": name, "start": start, "size": len(data), "arch": "x86-real-16",
                    "permissions": permissions, "blob": inline_blob(data)}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program = {
                "format": "mz",
                "entry_points": ["ovl:OVA:0000:0100"],
                "regions": [
                    region("image", "seg:1000:0000", b"\xc3" + b"\x90" * 15, "rwx"),
                    # mov ax,[0x0020]; add ax,[0x0300]; ret
                    region("OVA.code", "ovl:OVA:0000:0100", b"\xa1\x20\x00\x03\x06\x00\x03\xc3", "r-x"),
                    region("OVA.data", "ovl:OVA:0050:0000", b"\x07" * 0x40, "rw-"),
                ],
            }
            out_path = root / "export.json"
            out = run(
                build_plugin(),
                req(2, "analyzer/open", {"program": program, "project_dir": str(root / "ghidra"),
                                         "program_hash": "d" * 64}),
                req(3, "analyzer/export", {"out_path": str(out_path)}),
                req(4, "decompiler/decompile", {"addresses": ["ovl:OVA:0000:0100"], "out_dir": str(root / "c")}),
                req(5, "analyzer/apply", {"symbols": [
                    {"address": "seg:0050:0300", "kind": "global", "name": "word_0300", "locals": [],
                     "line_comments": []},
                    {"address": "ovl:OVA:0050:0020", "kind": "global", "name": "ova_word", "locals": [],
                     "line_comments": []},
                ], "types_h": "", "references": []}),
                req(6, "decompiler/decompile", {"addresses": ["ovl:OVA:0000:0100"], "out_dir": str(root / "c2")}),
                req(7, "shutdown"),
            )
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertIn({"function": "ovl:OVA:0000:0100", "address": "ovl:OVA:0050:0020", "kind": "read"},
                          data["data_accesses"])
            decompiled = by_id(out, 4)["result"][0]
            self.assertIn("path", decompiled, decompiled)
            code = Path(decompiled["path"]).read_text(encoding="utf-8")
            self.assertIn("DAT_OVA_0050_0020", code)
            self.assertIn("DAT_0050_0300", code)  # outside the overlay's data: the main program's DS
            self.assertIn("result", by_id(out, 5), by_id(out, 5))
            named = Path(by_id(out, 6)["result"][0]["path"]).read_text(encoding="utf-8")
            self.assertIn("word_0300", named)
            self.assertIn("ova_word", named)

    def test_aztec_csav_frame_and_inline_switch_table(self):
        """`mov ax,-4; call $csav` gives BP; `mov cx,3; call $swt` with an inline table becomes a switch."""
        from test_aztec import CSAV, SWITCH, near_call

        image = bytearray(b"\xcc" * 0x400)
        image[0x000:0x003] = b"\xb8\xfc\xff"  # mov ax,-4
        image[0x003:0x006] = near_call(0x003, 0x100)  # call $csav
        image[0x006:0x009] = b"\x8b\x46\x04"  # mov ax,[bp+4]
        image[0x009:0x00C] = b"\xb9\x03\x00"  # mov cx,3
        image[0x00C:0x00F] = near_call(0x00C, 0x200)  # call $swt
        image[0x00F:0x019] = struct.pack("<5H", 1, 2, 0x19, 0x1D, 0x21)
        image[0x019:0x01C] = near_call(0x019, 0x300)  # case 1: call g1
        image[0x01C] = 0xC3
        image[0x01D:0x020] = near_call(0x01D, 0x310)  # case 2: call g2
        image[0x020] = 0xC3
        image[0x021:0x025] = b"\xb8\x00\x00\xc3"  # default: return 0
        image[0x100:0x100 + len(CSAV)] = CSAV
        image[0x200:0x200 + len(SWITCH)] = SWITCH
        image[0x300] = image[0x310] = 0xC3
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program = {
                "format": "mz",
                "entry_points": ["seg:1000:0000"],
                "regions": [{"name": "image", "start": "seg:1000:0000", "size": len(image), "arch": "x86-real-16",
                             "permissions": "rwx", "blob": inline_blob(bytes(image))}],
            }
            symbols = [{"address": a, "kind": "function", "name": n, "locals": [], "line_comments": []}
                       for a, n in (("seg:1000:0300", "g1"), ("seg:1000:0310", "g2"))]
            symbols.append({"address": "seg:1000:0000", "kind": "function", "name": "dispatch",
                            "signature": "int dispatch(int key, char *text)", "locals": [], "line_comments": []})
            out_path = root / "export.json"
            out = run(
                build_plugin(),
                req(2, "analyzer/open", {"program": program, "project_dir": str(root / "ghidra"),
                                         "program_hash": "c" * 64}),
                req(3, "analyzer/apply", {"symbols": symbols, "types_h": "", "references": []}),
                req(4, "analyzer/export", {"out_path": str(out_path)}),
                req(5, "decompiler/decompile", {"addresses": ["seg:1000:0000"], "out_dir": str(root / "c")}),
                req(6, "shutdown"),
            )
            self.assertIn("result", by_id(out, 2), by_id(out, 2))
            data = json.loads(out_path.read_text(encoding="utf-8"))
            calls = {(c["caller"], c["callee"]) for c in data["calls"]}
            self.assertIn(("seg:1000:0000", "seg:1000:0300"), calls)
            self.assertIn(("seg:1000:0000", "seg:1000:0310"), calls)
            self.assertNotIn("seg:1000:000F", [f["start"] for f in data["functions"]])
            decompiled = by_id(out, 5)["result"][0]
            self.assertIn("path", decompiled, decompiled)
            code = Path(decompiled["path"]).read_text(encoding="utf-8")
            self.assertIn("g1", code)
            self.assertIn("g2", code)
            self.assertNotIn("unaff_BP", code)
            self.assertIn("int __cdecl16near dispatch(int key,char *text)", code)
            self.assertIn("switch(key)", code)
            self.assertIn("case 0x1:", code)
            self.assertIn("case 0x2:", code)
            self.assertIn("default:", code)
            self.assertNotIn("case 0x1001", code)
            self.assertNotIn("case default", code)
            self.assertNotIn("Switch is manually overridden", code)
            self.assertNotIn("Removing unreachable block", code)
            self.assertIn("switch (AX): 0x1 -> 0019, 0x2 -> 001D; default -> 0021", code)


if __name__ == "__main__":
    unittest.main()
