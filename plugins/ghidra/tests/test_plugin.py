import io
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_plugin import inline_blob  # noqa: E402

from decovery_ghidra import build_plugin  # noqa: E402
from decovery_ghidra import apply as apply_mod  # noqa: E402
from decovery_ghidra import project as project_mod  # noqa: E402
from decovery_ghidra.backend import (  # noqa: E402
    EXPECTED_GHIDRA_VERSION,
    Backend,
    DecompileResult,
    GhidraBackend,
    GhidraFunction,
    OpenOutcome,
    check_ghidra_version,
)
from decovery_ghidra.export import (  # noqa: E402
    AccessRecord,
    CallRecord,
    ExportData,
    FunctionRecord,
    StringRecord,
)
from decovery_ghidra.hashing import blake3_hex  # noqa: E402
from decovery_ghidra.mapping import GhidraAddress, default_name  # noqa: E402


def flat(offset):
    return GhidraAddress(None, offset)


class FakeBackend(Backend):
    """Stands in for GhidraBackend; records what the plugin passes down. The "Ghidra project" is a marker file."""

    def __init__(self):
        self.version = EXPECTED_GHIDRA_VERSION
        self.opened = None
        self.analyzed = 0
        self.closed = 0
        self.functions_ = [
            GhidraFunction(segment=None, offset=0x10040, name="sub_10040", size=8),
            GhidraFunction(segment=None, offset=0x10010, name="main", size=0x30),
        ]
        self.failing = set()
        self.apply_failing = set()
        self.applied = None
        self.export = ExportData([], [], [], [])

    def ghidra_version(self):
        return self.version

    def open_program(self, language_id, blocks, entry_points, location, options, reuse, progress):
        marker = Path(location) / "decovery.gpr"
        reused = reuse and marker.exists()
        if not reused:
            Path(location).mkdir(parents=True, exist_ok=True)
            marker.write_text("project", encoding="utf-8")
            self.analyzed += 1
            progress(1, 2, "importing")
            progress(2, 2, "analyzing")
        self.opened = (language_id, blocks, entry_points, location, options, reuse)
        return OpenOutcome(functions=len(self.functions_), reused=reused)

    def functions(self):
        return list(self.functions_)

    def apply(self, symbols, types_h, references, calling_convention):
        self.applied = (symbols, types_h, references, calling_convention)
        failing = [s for s in symbols if s.address.offset in self.apply_failing]
        warnings = [f"{s.address.text()}: rejected by Ghidra" for s in failing]
        return len(symbols) + len(references) - len(warnings), warnings

    def export_data(self):
        return self.export

    def decompile(self, address):
        if address.offset in self.failing:
            raise RuntimeError("decompiler crashed")
        if address.offset == 0x10040:
            return DecompileResult(None, "decompiler timed out", [(flat(0x10040), "PUSH EBP"), (flat(0x10041), "RET")])
        return DecompileResult(f"void f_{address.offset:X}(void) {{}}\n", None, [])

    def close(self):
        self.closed += 1


class _Output(io.StringIO):
    """stdout that lets the feeder wait for a response."""

    def __init__(self):
        super().__init__()
        self.changed = threading.Condition()

    def write(self, text):
        with self.changed:
            written = super().write(text)
            self.changed.notify_all()
        return written

    def answered(self, id_):
        messages = (json.loads(line) for line in self.getvalue().splitlines())
        return any(m.get("id") == id_ and "method" not in m for m in messages)


def run(plugin, *messages):
    """Serve `messages` one request at a time: the SDK runs requests concurrently and cancels running ones at end
    of input, so each request is sent only after the previous one was answered."""
    stdout = _Output()

    def feed():
        for message in messages:
            yield json.dumps(message) + "\n"
            if "id" in message:
                with stdout.changed:
                    if not stdout.changed.wait_for(lambda: stdout.answered(message["id"]), timeout=30):
                        raise AssertionError(f"no response to {message['id']}")

    plugin.serve(feed(), stdout)
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
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backend = FakeBackend()
        self.plugin = build_plugin(lambda: self.backend)

    def open_msg(self, id_=2, project_dir=None, program_hash="a" * 64, options=None, **kw):
        params = {
            "program": program(**kw),
            "project_dir": str(project_dir or self.root / "proj"),
            "program_hash": program_hash,
        }
        if options is not None:
            params["options"] = options
        return req(id_, "analyzer/open", params)

    def plugin_for(self, backend):
        return build_plugin(lambda: backend)

    # -- handshake ---------------------------------------------------------------------------------------------

    def test_capabilities_are_version_2(self):
        out = run(self.plugin, req(1, "initialize", {"protocol": "decovery-plugin/1", "host_version": "0"}))
        result = by_id(out, 1)["result"]
        self.assertEqual(result["name"], "ghidra")
        self.assertEqual(result["capabilities"], {"analyzer": {"version": 2}, "decompiler": {"version": 2}})

    # -- open ----------------------------------------------------------------------------------------------------

    def test_open_maps_arch_to_language(self):
        for arch, language in (("x86-flat-32", "x86:LE:32:default"), ("x86-real-16", "x86:LE:16:Real Mode")):
            backend = FakeBackend()
            out = run(self.plugin_for(backend), self.open_msg(arch=arch, project_dir=self.root / arch))
            self.assertEqual(by_id(out, 2)["result"], {"functions": 2, "reused": False}, out)
            language_id, blocks, entries, location, options, reuse = backend.opened
            self.assertEqual(language_id, language)
            self.assertEqual(Path(location), (self.root / arch).resolve())
            self.assertEqual(
                options, {"calling_convention": None, "aggressive_instruction_finder": arch == "x86-flat-32"}
            )
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

    def test_open_passes_calling_convention(self):
        out = run(self.plugin, self.open_msg(options={"calling_convention": "__watcall"}))
        self.assertIn("result", by_id(out, 2), out)
        self.assertEqual(self.backend.opened[4]["calling_convention"], "__watcall")
        out = run(self.plugin, self.open_msg(options={"calling_convention": 5}))
        self.assertEqual(by_id(out, 2)["error"]["code"], -32602)

    def test_open_reports_progress(self):
        out = run(self.plugin, self.open_msg())
        progress = [m["params"] for m in out if m.get("method") == "$/progress"]
        self.assertEqual([p["done"] for p in progress], [1, 2])
        self.assertTrue(all(p["id"] == 2 for p in progress))

    def test_open_rejects_unknown_arch(self):
        out = run(self.plugin, self.open_msg(arch="mips-be-32"))
        self.assertEqual(by_id(out, 2)["error"]["code"], -32602)

    def test_open_requires_program_hash(self):
        message = self.open_msg()
        del message["params"]["program_hash"]
        out = run(self.plugin, message)
        self.assertEqual(by_id(out, 2)["error"]["code"], -32602)

    def test_open_reuses_saved_project(self):
        first = run(self.plugin, self.open_msg())
        self.assertEqual(by_id(first, 2)["result"], {"functions": 2, "reused": False})
        stored = json.loads((self.root / "proj" / "project.json").read_text(encoding="utf-8"))
        self.assertEqual(
            stored,
            {
                "schema": 1,
                "program_hash": "a" * 64,
                "ghidra_version": EXPECTED_GHIDRA_VERSION,
                "calling_convention": None,
            },
        )
        before = (self.root / "proj" / "project.json").read_bytes()
        second = run(self.plugin, self.open_msg())
        self.assertEqual(by_id(second, 2)["result"], {"functions": 2, "reused": True})
        self.assertTrue(self.backend.opened[5], "reuse must be requested")
        self.assertEqual(self.backend.analyzed, 1)
        self.assertEqual((self.root / "proj" / "project.json").read_bytes(), before)
        self.assertNotIn(b"\r", before)

    def test_open_reanalyzes_on_hash_change(self):
        run(self.plugin, self.open_msg())
        stale = self.root / "proj" / "decovery.rep"
        stale.mkdir()
        (self.root / "proj" / "unrelated.txt").write_text("keep", encoding="utf-8")
        (self.root / "proj" / "decovery.notes").write_text("keep", encoding="utf-8")
        out = run(self.plugin, self.open_msg(program_hash="b" * 64))
        self.assertEqual(by_id(out, 2)["result"], {"functions": 2, "reused": False})
        self.assertFalse(self.backend.opened[5], "a stale project must not be reused")
        self.assertFalse(stale.exists(), "the stale Ghidra project is deleted")
        self.assertTrue((self.root / "proj" / "unrelated.txt").exists(), "only the project's own files are deleted")
        self.assertTrue((self.root / "proj" / "decovery.notes").exists(), "only the project's own files are deleted")
        self.assertEqual(self.backend.analyzed, 2)
        stored = json.loads((self.root / "proj" / "project.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["program_hash"], "b" * 64)
        # another Ghidra version invalidates the project as well
        self.backend.version = "99.0"
        out = run(self.plugin, self.open_msg(program_hash="b" * 64))
        self.assertEqual(by_id(out, 2)["result"], {"functions": 2, "reused": False})
        self.assertEqual(self.backend.analyzed, 3)
        # and so does another calling convention
        out = run(self.plugin, self.open_msg(program_hash="b" * 64, options={"calling_convention": "__cdecl"}))
        self.assertEqual(by_id(out, 2)["result"], {"functions": 2, "reused": False})
        self.assertEqual(self.backend.analyzed, 4)

    def test_open_reanalyzes_on_unreadable_project_json(self):
        run(self.plugin, self.open_msg())
        (self.root / "proj" / "project.json").write_text("{not json", encoding="utf-8")
        out = run(self.plugin, self.open_msg())
        self.assertEqual(by_id(out, 2)["result"], {"functions": 2, "reused": False})

    def test_dot_path_project_is_relocated(self):
        local = self.root / "local"
        project_dir = self.root / ".work" / "cache" / "ghidra"
        env = {"LOCALAPPDATA": str(local), "XDG_CACHE_HOME": str(local)}
        with mock.patch.dict(os.environ, env):
            out = run(self.plugin, self.open_msg(project_dir=project_dir))
            expected = project_mod.project_location(str(project_dir))
        self.assertIn("result", by_id(out, 2), out)
        location = Path(self.backend.opened[3])
        self.assertEqual(location, expected)
        self.assertEqual(location.parent, local.resolve() / "decovery" / "ghidra")
        self.assertRegex(location.name, r"^[0-9a-f]{64}$")
        self.assertTrue((location / "project.json").is_file())
        self.assertFalse((self.root / ".work").exists(), "nothing is written below the dot path")

    def test_project_location_rules(self):
        plain = self.root / "plain" / "cache"
        self.assertEqual(project_mod.project_location(str(plain), env={}, windows=True), plain.resolve())
        dotted = self.root / ".hidden" / "cache"
        windows = project_mod.project_location(str(dotted), env={"LOCALAPPDATA": str(self.root / "la")}, windows=True)
        self.assertEqual(windows.parent, (self.root / "la").resolve() / "decovery" / "ghidra")
        again = project_mod.project_location(str(dotted), env={"LOCALAPPDATA": str(self.root / "la")}, windows=True)
        self.assertEqual(windows, again, "the relocated path is stable")
        other = project_mod.project_location(
            str(self.root / ".other"), env={"LOCALAPPDATA": str(self.root / "la")}, windows=True
        )
        self.assertNotEqual(windows, other)
        posix = project_mod.project_location(str(dotted), env={"XDG_CACHE_HOME": str(self.root / "xdg")}, windows=False)
        self.assertEqual(posix.parent, (self.root / "xdg").resolve() / "decovery" / "ghidra")
        # a cache base that itself has a dot component is skipped
        fallback = project_mod.project_location(
            str(dotted), env={"XDG_CACHE_HOME": str(self.root / ".cache")}, windows=False
        )
        self.assertFalse(any(part.startswith(".") for part in fallback.parts[1:]), fallback)

    # -- functions -------------------------------------------------------------------------------------------------

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
        for method in ("analyzer/functions", "analyzer/apply", "analyzer/export", "decompiler/decompile"):
            out = run(self.plugin, req(3, method, {"out_path": "x", "out_dir": "x", "addresses": []}))
            self.assertEqual(by_id(out, 3)["error"]["code"], -32011, method)

    # -- apply -----------------------------------------------------------------------------------------------------

    def test_apply_reports_warnings_per_item(self):
        self.backend.apply_failing.add(0x10050)
        params = {
            "symbols": [
                {
                    "address": "flat:00010010",
                    "kind": "function",
                    "name": "main",
                    "signature": "int main(int argc)",
                    "comment": "entry",
                    "locals": [
                        {"place": "stack:-0x14", "name": "mode", "data_type": "int"},
                        {"place": "param:1", "name": "argc"},
                        {"name": "missing_place"},
                    ],
                    "line_comments": [{"address": "flat:00010012", "text": "loop"}, {"address": "bogus", "text": "x"}],
                },
                {"address": "flat:00020000", "kind": "global", "name": "g_count", "data_type": "int"},
                {"address": "flat:00010050", "kind": "label", "name": "retry"},
                {"address": "seg:1000:0000", "kind": "label", "name": "wrong_kind_of_address"},
                {"address": "flat:00010060", "kind": "constant", "name": "unknown_kind"},
                {"kind": "function", "name": "no_address"},
            ],
            "types_h": "typedef int score;\n",
            "references": [
                {"from": "flat:00010020", "to": "flat:00010040", "kind": "call"},
                {"from": "flat:00010024", "to": "flat:00010040", "kind": "teleport"},
            ],
        }
        opening = self.open_msg(options={"calling_convention": "__watcall"})
        out = run(self.plugin, opening, req(3, "analyzer/apply", params))
        result = by_id(out, 3)["result"]
        symbols, types_h, references, calling_convention = self.backend.applied
        self.assertEqual([s.address.text() for s in symbols], ["00010010", "00020000", "00010050"])
        self.assertEqual([s.kind for s in symbols], ["function", "global", "label"])
        main = symbols[0]
        self.assertEqual((main.name, main.signature, main.comment), ("main", "int main(int argc)", "entry"))
        self.assertEqual([(l.place, l.name, l.data_type) for l in main.locals],
                         [("stack:-0x14", "mode", "int"), ("param:1", "argc", None)])
        self.assertEqual([(c.address.text(), c.text) for c in main.line_comments], [("00010012", "loop")])
        self.assertEqual(symbols[1].data_type, "int")
        self.assertEqual(types_h, "typedef int score;\n")
        self.assertEqual(
            [(r.from_.text(), r.to.text(), r.kind) for r in references], [("00010020", "00010040", "call")]
        )
        self.assertEqual(calling_convention, "__watcall")
        # three symbols + one reference reached the backend, one of them failed there
        self.assertEqual(result["applied"], 3)
        warnings = result["warnings"]
        self.assertEqual(len(warnings), 7, warnings)
        joined = "\n".join(warnings)
        for needle in ("missing_place", "bogus", "wrong_kind_of_address", "unknown_kind", "no_address", "teleport",
                       "rejected by Ghidra"):
            self.assertIn(needle, joined)

    def test_apply_rejects_malformed_params(self):
        for params in ({"symbols": {}}, {"references": "x"}, {"types_h": 3}):
            out = run(self.plugin, self.open_msg(), req(3, "analyzer/apply", params))
            self.assertEqual(by_id(out, 3)["error"]["code"], -32602, params)

    # -- export ----------------------------------------------------------------------------------------------------

    def test_export_writes_file_with_hash(self):
        self.backend.export = ExportData(
            functions=[
                FunctionRecord(flat(0x10040), flat(0x10047), 8, None),
                FunctionRecord(flat(0x10010), flat(0x1003F), 0x30, "main"),
            ],
            calls=[
                CallRecord(site=flat(0x10030), caller=flat(0x10010), callee=flat(0x10040)),
                CallRecord(site=flat(0x10020), caller=flat(0x10010), callee=flat(0x10040)),
            ],
            strings=[
                StringRecord(flat(0x20010), "bär", (flat(0x10040), flat(0x10010), flat(0x10040))),
                StringRecord(flat(0x20000), "hello", ()),
            ],
            accesses=[
                AccessRecord(flat(0x10040), flat(0x20020), "write"),
                AccessRecord(flat(0x10010), flat(0x20020), "write"),
                AccessRecord(flat(0x10010), flat(0x20020), "read"),
            ],
        )
        out_path = self.root / "cache" / "analysis export.json"
        out = run(self.plugin, self.open_msg(), req(3, "analyzer/export", {"out_path": str(out_path)}))
        result = by_id(out, 3)["result"]
        data = out_path.read_bytes()
        self.assertEqual(result, {"path": str(out_path), "blake3": blake3_hex(data)})
        self.assertNotIn(b"\r", data)
        self.assertFalse(out_path.with_name(out_path.name + ".tmp").exists())
        exported = json.loads(data.decode("utf-8"))
        self.assertEqual(
            exported,
            {
                "schema": 1,
                "functions": [
                    {"start": "flat:00010010", "end": "flat:0001003F", "body_size": 0x30, "name": "main"},
                    {"start": "flat:00010040", "end": "flat:00010047", "body_size": 8, "name": None},
                ],
                "calls": [
                    {"site": "flat:00010020", "caller": "flat:00010010", "callee": "flat:00010040"},
                    {"site": "flat:00010030", "caller": "flat:00010010", "callee": "flat:00010040"},
                ],
                "strings": [
                    {"address": "flat:00020000", "text": "hello", "users": []},
                    {"address": "flat:00020010", "text": "bär", "users": ["flat:00010010", "flat:00010040"]},
                ],
                "data_accesses": [
                    {"function": "flat:00010010", "address": "flat:00020020", "kind": "read"},
                    {"function": "flat:00010010", "address": "flat:00020020", "kind": "write"},
                    {"function": "flat:00010040", "address": "flat:00020020", "kind": "write"},
                ],
            },
        )
        # unchanged data gives identical bytes
        run(self.plugin, self.open_msg(), req(3, "analyzer/export", {"out_path": str(out_path)}))
        self.assertEqual(out_path.read_bytes(), data)

    def test_shutdown_closes_backend(self):
        run(self.plugin, self.open_msg(), req(3, "shutdown"))
        self.assertEqual(self.backend.closed, 1)
        backend = FakeBackend()
        run(self.plugin_for(backend), self.open_msg())  # end of input
        self.assertEqual(backend.closed, 1)
        backend = FakeBackend()
        run(self.plugin_for(backend), req(3, "shutdown"))  # nothing open: nothing to close
        self.assertEqual(backend.closed, 0)

    def test_aggressive_finder_only_for_flat32(self):
        for arch, expected in (("x86-flat-32", True), ("x86-real-16", False)):
            backend = FakeBackend()
            run(self.plugin_for(backend), self.open_msg(arch=arch, project_dir=self.root / arch))
            self.assertIs(backend.opened[4]["aggressive_instruction_finder"], expected, arch)

    def test_io_errors_are_32012(self):
        blocker = self.root / "blocker"
        blocker.write_text("a file, not a folder", encoding="utf-8")
        out = run(self.plugin, self.open_msg(project_dir=blocker / "proj"))
        error = by_id(out, 2)["error"]
        self.assertEqual(error["code"], -32012, error)
        self.assertIn("project or file I/O failed", error["message"])
        out = run(self.plugin, self.open_msg(), req(3, "analyzer/export", {"out_path": str(blocker / "x.json")}))
        self.assertEqual(by_id(out, 3)["error"]["code"], -32012)
        out = run(
            self.plugin,
            self.open_msg(),
            req(3, "decompiler/decompile", {"addresses": ["flat:00010010"], "out_dir": str(blocker)}),
        )
        self.assertEqual(by_id(out, 3)["error"]["code"], -32012)

    def test_applied_document_round_trip(self):
        wanted = {"line": {"00010012"}, "function": set(), "signature": {"00010010"}, "reference": set()}
        raw = apply_mod.applied_document(wanted)
        self.assertEqual(json.loads(raw)["schema"], 1)
        self.assertEqual(
            apply_mod.parse_applied(raw.decode("utf-8")),
            {"function": [], "line": ["00010012"], "reference": [], "signature": ["00010010"]},
        )
        # files written before the schema key are still read
        self.assertEqual(apply_mod.parse_applied('{"line": ["00010012"]}'), {"line": ["00010012"]})
        with self.assertRaises(ValueError):
            apply_mod.parse_applied('{"line": 3}')

    def test_export_requires_out_path(self):
        out = run(self.plugin, self.open_msg(), req(3, "analyzer/export", {}))
        self.assertEqual(by_id(out, 3)["error"]["code"], -32602)

    def test_blake3_matches_reference_vectors(self):
        # official BLAKE3 test vectors: input byte i is i % 251
        vectors = {
            0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        }
        vectors.update(REFERENCE_VECTORS)
        for length, expected in vectors.items():
            data = bytes(i % 251 for i in range(length))
            self.assertEqual(blake3_hex(data), expected, length)

    # -- decompile -------------------------------------------------------------------------------------------------

    def test_decompile_writes_files_and_fallback_disassembly(self):
        self.backend.failing.add(0x10080)
        out_dir = self.root / "out dir"
        addresses = ["flat:00010010", "flat:00010040", "flat:00010080", "sel:0001:00000000"]
        out = run(
            self.plugin,
            self.open_msg(),
            req(3, "decompiler/decompile", {"addresses": addresses, "out_dir": str(out_dir)}),
        )
        result = by_id(out, 3)["result"]
        code_path = out_dir / "flat_00010010.c"
        self.assertEqual(result[0], {"address": "flat:00010010", "path": str(code_path)})
        self.assertEqual(code_path.read_bytes(), b"void f_10010(void) {}\n")
        self.assertEqual(
            result[1],
            {
                "address": "flat:00010040",
                "error": "decompiler timed out",
                "disassembly": [["flat:00010040", "PUSH EBP"], ["flat:00010041", "RET"]],
            },
        )
        self.assertFalse((out_dir / "flat_00010040.c").exists())
        self.assertEqual(result[2]["address"], "flat:00010080")
        self.assertIn("crashed", result[2]["error"])
        self.assertNotIn("path", result[2])
        self.assertEqual(result[3]["address"], "sel:0001:00000000")
        self.assertIn("error", result[3])
        progress = [m["params"] for m in out if m.get("method") == "$/progress" and m["params"]["id"] == 3]
        self.assertEqual([(p["done"], p["total"]) for p in progress], [(0, 4), (1, 4), (2, 4), (3, 4), (4, 4)])

    def test_decompile_real_mode_file_name(self):
        out_dir = self.root / "out"
        out = run(
            self.plugin,
            self.open_msg(arch="x86-real-16"),
            req(3, "decompiler/decompile", {"addresses": ["seg:1000:0010"], "out_dir": str(out_dir)}),
        )
        expected = [{"address": "seg:1000:0010", "path": str(out_dir / "seg_1000_0010.c")}]
        self.assertEqual(by_id(out, 3)["result"], expected)

    def test_decompile_requires_out_dir(self):
        out = run(self.plugin, self.open_msg(), req(3, "decompiler/decompile", {"addresses": ["flat:00010010"]}))
        self.assertEqual(by_id(out, 3)["error"]["code"], -32602)

    # -- Ghidra-free helpers ---------------------------------------------------------------------------------------

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
        props = self.root / "Ghidra" / "application.properties"
        props.parent.mkdir()
        props.write_text("application.name=Ghidra\napplication.version=11.0.0\n", encoding="utf-8")
        warnings = []
        check_ghidra_version(self.root, warnings.append)
        self.assertEqual(len(warnings), 1)
        self.assertIn(EXPECTED_GHIDRA_VERSION, warnings[0])
        props.write_text(f"application.version={EXPECTED_GHIDRA_VERSION}\n", encoding="utf-8")
        warnings.clear()
        check_ghidra_version(self.root, warnings.append)
        self.assertEqual(warnings, [])

    def test_default_names(self):
        self.assertEqual(default_name(GhidraAddress(None, 0x1A2B0)), "fun_0001A2B0")
        self.assertEqual(default_name(GhidraAddress(0x1000, 0x10)), "fun_1000_0010")
        self.assertEqual(GhidraAddress.parse("0001A2B0"), GhidraAddress(None, 0x1A2B0))
        self.assertEqual(GhidraAddress.parse("1000:0010"), GhidraAddress(0x1000, 0x10))

    def test_signature_for_ghidra(self):
        self.assertEqual(apply_mod.signature_for_ghidra("int __cdecl f(int a)"), ("int f(int a)", "__cdecl"))
        self.assertEqual(apply_mod.signature_for_ghidra("char *strcpy(char *d, const char *s)"),
                         ("char * strcpy(char *d, char *s)", None))
        self.assertEqual(
            apply_mod.signature_for_ghidra("struct foo *__watcall g(void)"), ("foo * g(void)", "__watcall")
        )

    def test_clean_c_and_declarations(self):
        text = "#include <x.h>\n/* c */ typedef int far score; // trailing\nstruct s { int a; /* +0x0 */ };\n"
        cleaned = apply_mod.clean_c(text)
        self.assertNotIn("#include", cleaned)
        self.assertNotIn("far", cleaned)
        self.assertEqual(
            apply_mod.split_declarations(cleaned),
            ["typedef int score;", "struct s { int a; };"],
        )

    def test_struct_offsets(self):
        text = (
            "struct packed {\n    char tag; /* +0x0 */\n    int value; /* +0x1 */\n    char gap_5[3];\n};\n"
            "struct loose {\n    int a;\n};\n"
        )
        self.assertEqual(apply_mod.struct_offsets(text), {"packed": [("tag", 0), ("value", 1), ("gap_5", 5)]})


# Reference values from the Rust `blake3` crate (the hash the host verifies with).
REFERENCE_VECTORS: dict[int, str] = {
    1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    63: "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    64: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    65: "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
    1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    2049: "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
    3072: "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
    3073: "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
    4096: "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
    4097: "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
    5121: "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff",
    8193: "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b",
    31744: "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
    102400: "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
}


if __name__ == "__main__":
    unittest.main()
