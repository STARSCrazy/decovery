"""Against a real Ghidra: skipped unless GHIDRA_INSTALL_DIR is set and pyghidra is importable."""

import importlib.util
import json
import os
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
from decovery_ghidra.hashing import blake3_hex  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
