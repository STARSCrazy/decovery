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

from decovery_plugin import inline_blob  # noqa: E402

from decovery_ghidra import build_plugin  # noqa: E402
from decovery_ghidra.backend import (  # noqa: E402
    EXPECTED_GHIDRA_VERSION,
    DecompileResult,
    GhidraBackend,
    GhidraFunction,
    check_ghidra_version,
)


class FakeBackend:
    """Stands in for GhidraBackend; records what the plugin passes down."""

    def __init__(self):
        self.opened = None
        self.functions_ = [
            GhidraFunction(segment=None, offset=0x10040, name="sub_10040", size=8),
            GhidraFunction(segment=None, offset=0x10010, name="main", size=0x30),
        ]
        self.failing = set()

    def open_program(self, language_id, blocks, entry_points, project_dir, progress):
        self.opened = (language_id, blocks, entry_points, project_dir)
        progress(1, 2, "importing")
        progress(2, 2, "analyzing")
        return len(self.functions_)

    def functions(self):
        return list(self.functions_)

    def decompile(self, address):
        if address.offset in self.failing:
            raise RuntimeError("decompiler timed out")
        return DecompileResult(code=f"void f_{address.offset:X}(void) {{}}", error=None)


def run(plugin, *messages):
    stdin = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    stdout = io.StringIO()
    plugin.serve(stdin, stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def req(id_, method, params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


def by_id(lines, id_):
    return next(m for m in lines if m.get("id") == id_)


def program(arch="x86-flat-32", regions=None):
    return {
        "format": "le",
        "entry_points": ["flat:00010010"] if arch == "x86-flat-32" else ["seg:1000:0010"],
        "regions": regions
        or [
            {
                "name": "code",
                "start": "flat:00010000" if arch == "x86-flat-32" else "seg:1000:0000",
                "size": 0x100,
                "arch": arch,
                "permissions": "r-x",
                "blob": inline_blob(b"\x90" * 0x100),
            }
        ],
    }


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.plugin = build_plugin(lambda: self.backend)

    def open_msg(self, id_=2, **kw):
        return req(id_, "analyzer/open", {"program": program(**kw), "project_dir": "/tmp/proj"})

    def test_initialize_lists_capabilities(self):
        out = run(self.plugin, req(1, "initialize", {"protocol": "decovery-plugin/1", "host_version": "0"}))
        result = by_id(out, 1)["result"]
        self.assertEqual(result["name"], "ghidra")
        self.assertEqual(result["capabilities"], {"analyzer": {"version": 1}, "decompiler": {"version": 1}})

    def test_open_maps_arch_to_language(self):
        for arch, language in (("x86-flat-32", "x86:LE:32:default"), ("x86-real-16", "x86:LE:16:Real Mode")):
            self.backend = FakeBackend()
            out = run(self.plugin_for(self.backend), self.open_msg(arch=arch))
            self.assertEqual(by_id(out, 2)["result"], {"functions": 2}, out)
            language_id, blocks, entries, project_dir = self.backend.opened
            self.assertEqual(language_id, language)
            self.assertEqual(project_dir, "/tmp/proj")
            self.assertEqual(len(blocks), 1)
            self.assertEqual(blocks[0].name, "code")
            self.assertEqual(blocks[0].size, 0x100)
            self.assertEqual(blocks[0].data, b"\x90" * 0x100)
            self.assertEqual((blocks[0].read, blocks[0].write, blocks[0].execute), (True, False, True))
            if arch == "x86-flat-32":
                self.assertEqual(blocks[0].start.text(), "00010000")
                self.assertEqual([e.text() for e in entries], ["00010010"])
            else:
                self.assertEqual(blocks[0].start.text(), "1000:0000")
                self.assertEqual([e.text() for e in entries], ["1000:0010"])

    def plugin_for(self, backend):
        return build_plugin(lambda: backend)

    def test_open_reports_progress(self):
        out = run(self.plugin, self.open_msg())
        progress = [m["params"] for m in out if m.get("method") == "$/progress"]
        self.assertEqual([p["done"] for p in progress], [1, 2])
        self.assertTrue(all(p["id"] == 2 for p in progress))

    def test_open_rejects_unknown_arch(self):
        out = run(self.plugin, self.open_msg(arch="mips-be-32"))
        self.assertEqual(by_id(out, 2)["error"]["code"], -32602)

    def test_functions_are_flat_addresses(self):
        out = run(self.plugin, self.open_msg(), req(3, "analyzer/functions"))
        self.assertEqual(
            by_id(out, 3)["result"],
            [
                {"address": "flat:00010010", "name": "main", "size": 0x30},
                {"address": "flat:00010040", "name": "sub_10040", "size": 8},
            ],
        )

    def test_functions_before_open_is_an_error(self):
        out = run(self.plugin, req(3, "analyzer/functions"))
        self.assertEqual(by_id(out, 3)["error"]["code"], -32011)

    def test_decompile_reports_per_function_errors(self):
        self.backend.failing.add(0x10040)
        out = run(
            self.plugin,
            self.open_msg(),
            req(3, "decompiler/decompile", {"addresses": ["flat:00010010", "flat:00010040", "sel:0001:00000000"]}),
        )
        result = by_id(out, 3)["result"]
        self.assertEqual(result[0], {"address": "flat:00010010", "code": "void f_10010(void) {}"})
        self.assertEqual(result[1]["address"], "flat:00010040")
        self.assertIn("timed out", result[1]["error"])
        self.assertNotIn("code", result[1])
        self.assertEqual(result[2]["address"], "sel:0001:00000000")
        self.assertIn("error", result[2])

    def test_open_without_ghidra_install_dir_errors_cleanly(self):
        saved = os.environ.pop("GHIDRA_INSTALL_DIR", None)
        try:
            out = run(build_plugin(GhidraBackend), self.open_msg())
        finally:
            if saved is not None:
                os.environ["GHIDRA_INSTALL_DIR"] = saved
        error = by_id(out, 2)["error"]
        self.assertEqual(error["code"], -32010)
        self.assertIn("GHIDRA_INSTALL_DIR", error["message"])

    def test_version_mismatch_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            props = Path(tmp) / "Ghidra" / "application.properties"
            props.parent.mkdir()
            props.write_text("application.name=Ghidra\napplication.version=11.0.0\n", encoding="utf-8")
            warnings = []
            check_ghidra_version(Path(tmp), warnings.append)
            self.assertEqual(len(warnings), 1)
            self.assertIn(EXPECTED_GHIDRA_VERSION, warnings[0])
            props.write_text(f"application.version={EXPECTED_GHIDRA_VERSION}\n", encoding="utf-8")
            warnings.clear()
            check_ghidra_version(Path(tmp), warnings.append)
            self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
