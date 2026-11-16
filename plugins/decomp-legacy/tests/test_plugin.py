"""Tests against the fake Decomp in tests/fake (no Decomp checkout, no proprietary data)."""

import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake"
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))
sys.path.insert(0, str(FAKE))

from decovery_decomp_legacy import build_plugin  # noqa: E402
from decovery_decomp_legacy import names as N  # noqa: E402
from decovery_decomp_legacy import shadow as S  # noqa: E402
from decovery_decomp_legacy.params import decomp_address, default_name, parse_run  # noqa: E402
from decovery_plugin import RpcError  # noqa: E402

SYMBOLE = """# Decomp-Wissen: Symbole. Sortiert nach Adresse, von decomp geschrieben.
[[symbol]]
adresse = "va:00016E40"
art = "funktion"
name = "suche_auftrag"
quelle = "mensch"
sicherheit = "belegt"

[[symbol]]
adresse = "va:00017000"
art = "funktion"
name = "ai_find_next_order"
quelle = "ki"
sicherheit = "vermutet"

[[symbol]]
adresse = "va:00050000"
art = "variable"
name = "order_table"
quelle = "mensch"
sicherheit = "vermutet"
"""

NACHBAU = """[[funktion]]
adresse = "va:00016E40"
name = "suche_auftrag"
datei = "ai.c"
ergebnis = "abweichend"
"""


def request(request_id, method, params=None):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}


def serve(plugin, messages, until=None, timeout=60):
    """Feed `messages` (dicts, or callables run between lines with a `wait_answer(id)` function); keep the input open until every request among them
    has an answer, then end the session. Returns (answers by id, progress notifications)."""
    out_lines = []
    answered = threading.Condition()
    wanted = {m["id"] for m in messages if isinstance(m, dict) and "id" in m}

    class Output(io.StringIO):
        def write(self, text):
            written = super().write(text)
            with answered:
                out_lines.append(text)
                answered.notify_all()
            return written

    def answered_ids():
        ids = set()
        for line in "".join(out_lines).splitlines():
            message = json.loads(line)
            if "id" in message and "method" not in message:
                ids.add(message["id"])
        return ids

    def wait_answer(request_id):
        with answered:
            answered.wait_for(lambda: request_id in answered_ids(), timeout)

    def lines():
        for message in messages:
            if callable(message):
                message(wait_answer)
                continue
            yield json.dumps(message) + "\n"
        with answered:
            answered.wait_for(lambda: wanted <= answered_ids(), timeout)

    stdout = Output()
    plugin.serve(stdin=lines(), stdout=stdout)
    answers, progress = {}, []
    for line in stdout.getvalue().splitlines():
        message = json.loads(line)
        if message.get("method") == "$/progress":
            progress.append(message["params"])
        elif "id" in message:
            answers[message["id"]] = message
    return answers, progress


class Workspace:
    """A temporary source Decomp workspace, decovery sources and shadow dir."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="legacy-test-"))
        self.source = self.root / "decomp-ws"
        self.sources = self.root / "dv" / "src"
        self.shadow = self.root / "dv" / "cache" / "legacy" / "decomp"
        (self.source / "wissen").mkdir(parents=True)
        (self.source / "decomp.toml").write_text('[ziel]\ndatei = "spiel/MAIN.EXE"\nformat = "le"\n', encoding="utf-8")
        (self.source / "wissen" / "symbole.toml").write_text(SYMBOLE, encoding="utf-8")
        (self.source / "wissen" / "nachbau.toml").write_text(NACHBAU, encoding="utf-8")
        (self.source / "wissen" / "laufzeit").mkdir()
        (self.source / "wissen" / "laufzeit" / "login.toml").write_text("x = 1\n", encoding="utf-8")
        ghidra = self.source / "cache" / "ghidra"
        (ghidra / "decomp.rep").mkdir(parents=True)
        (ghidra / "meta.json").write_text('{"version": 4, "sha256": "aa"}', encoding="utf-8")
        (ghidra / "decomp.gpr").write_text("project", encoding="utf-8")
        (ghidra / "decomp.lock").write_text("locked", encoding="utf-8")
        (ghidra / "decomp.rep" / "data.bin").write_bytes(b"\0" * 100)
        (self.source / "cache" / "laufzeit" / "login").mkdir(parents=True)
        (self.source / "cache" / "laufzeit" / "login" / "calls.jsonl").write_text("{}\n", encoding="utf-8")
        (self.sources / "build").mkdir(parents=True)
        (self.sources / "ai.c").write_text("void ai_find_next_order(void) {}\n", encoding="utf-8")
        (self.sources / "ai.h").write_text("void ai_find_next_order(void);\n", encoding="utf-8")
        (self.sources / "build" / "seg.asm").write_text("; seg\n", encoding="utf-8")
        (self.sources / "README.md").write_text("not mirrored\n", encoding="utf-8")

    def params(self, operation="context", function="flat:00016E40", options=None, **extra):
        params = {"decomp_workspace": str(self.source), "shadow_dir": str(self.shadow),
                  "sources_dir": str(self.sources), "operation": operation, "function": function,
                  "symbols": [{"address": "flat:00016E40", "kind": "function", "name": "ai_find_next_order"},
                              {"address": "flat:00050000", "kind": "global", "name": "order_table"}],
                  "options": options or {}, "timeout_s": 60}
        params.update(extra)
        return params

    def tree(self, root):
        return {p.relative_to(root).as_posix(): (p.stat().st_size, p.stat().st_mtime_ns, p.read_bytes())
                for p in sorted(root.rglob("*")) if p.is_file()}

    def calls(self):
        path = self.shadow / "cache" / "fake-calls.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


class FakeEnv(unittest.TestCase):
    """Runs the fake Decomp: PYTHONPATH points at tests/fake for the CLI and server subprocesses."""

    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)
        env = {"PYTHONPATH": os.pathsep.join([str(FAKE), os.environ.get("PYTHONPATH", "")]),
               "FAKE_DECOMP_MODE": "ok"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("DECOMP_WATCOM_EMU", None)
        os.environ.pop("FAKE_DECOMP_SERVER", None)


class AddressTest(unittest.TestCase):
    def test_conversion(self):
        self.assertEqual(decomp_address("flat:0001a2b0"), "va:0001A2B0")
        self.assertEqual(decomp_address("flat:16E40"), "va:00016E40")
        self.assertEqual(decomp_address("seg:1234:0010"), "rel:1234:0010")
        self.assertEqual(decomp_address("seg:12:10"), "rel:0012:0010")
        for bad in ("va:00016E40", "flat:123456789", "seg:1234", "", None, 5):
            with self.assertRaises(RpcError) as caught:
                decomp_address(bad)
            self.assertEqual(caught.exception.code, -32602)

    def test_default_name(self):
        self.assertEqual(default_name("va:0001A2B0"), "fun_0001A2B0")
        self.assertEqual(default_name("rel:1234:0010"), "fun_1234_0010")


class ParamsTest(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def code(self, params):
        with self.assertRaises(RpcError) as caught:
            parse_run(params)
        return caught.exception.code

    def test_valid_and_command(self):
        run = parse_run(self.ws.params("chain", options={"minutes": 2.5, "rounds": 3}))
        self.assertEqual(run.function, "va:00016E40")
        self.assertEqual(run.command(None), ["nachbau", "kette", "va:00016E40", "--minuten", "2.5", "--runden", "3"])
        run = parse_run(self.ws.params("registers", options={"all": True, "source": "ai.c"}))
        self.assertEqual(run.command(Path("J.json")), ["nachbau", "vergabe", "va:00016E40", "--json", "J.json",
                                                       "--alle", "--datei", str(self.ws.sources / "ai.c")])
        self.assertEqual(parse_run(self.ws.params("registers", options={"all": False})).command(Path("J")),
                         ["nachbau", "vergabe", "va:00016E40", "--json", "J"])
        self.assertEqual(parse_run(self.ws.params("joint")).command(None), ["nachbau", "gemeinsam", "va:00016E40", "--json"])
        self.assertEqual(parse_run(self.ws.params("equivalence", options={"minutes": 1})).command(None),
                         ["nachbau", "gleichwertig", "va:00016E40", "--json", "--minuten", "1"])
        self.assertEqual(parse_run(self.ws.params("behavior", function="seg:0010:0020", options={"run": "login"}))
                         .command(None), ["nachbau", "verhalten", "rel:0010:0020", "--lauf", "login"])
        self.assertEqual(parse_run(self.ws.params("forms", options={"rounds": 1})).command(None),
                         ["nachbau", "formen", "va:00016E40", "--runden", "1"])

    def test_rejections(self):
        p = self.ws.params
        self.assertEqual(self.code(p("disassemble")), -32602)
        self.assertEqual(self.code(p(options={"minutes": 1})), -32602)  # context takes no minutes
        self.assertEqual(self.code(p("forms", options={"minutes": 1})), -32602)  # Decomp's formen has none
        self.assertEqual(self.code(p("joint", options={"source": "ai.c"})), -32602)  # gemeinsam has no --datei
        self.assertEqual(self.code(p("chain", options={"bogus": 1})), -32602)
        self.assertEqual(self.code(p("chain", options={"minutes": -1})), -32602)
        self.assertEqual(self.code(p("chain", options={"minutes": True})), -32602)
        self.assertEqual(self.code(p("chain", options={"rounds": 1.5})), -32602)
        self.assertEqual(self.code(p("registers", options={"all": "yes"})), -32602)
        self.assertEqual(self.code(p("registers", options={"source": "missing.c"})), -32602)
        self.assertEqual(self.code(p("behavior", options={"run": "a b"})), -32602)
        self.assertEqual(self.code(p(function="va:00016E40")), -32602)
        self.assertEqual(self.code(p(timeout_s=0)), -32602)
        self.assertEqual(self.code(p(symbols=[{"address": "flat:1", "kind": "type", "name": "x"}])), -32602)
        self.assertEqual(self.code(p(symbols=[{"address": "flat:1", "kind": "function", "name": "a-b"}])), -32602)
        self.assertEqual(self.code(p(sources_dir="relative/src")), -32602)
        self.assertEqual(self.code(p(shadow_dir=str(self.ws.source / "shadow"))), -32602)
        self.assertEqual(self.code(p(shadow_dir=str(self.ws.sources / "shadow"))), -32602)
        self.assertEqual(self.code(p(decomp_workspace=str(self.ws.root / "nowhere"))), -32021)


class ShadowTest(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def refresh(self):
        copy = S.ghidra_needs_copy(self.ws.source, self.ws.shadow)
        result, state = S.refresh(self.ws.source, self.ws.shadow, self.ws.sources, copy)
        S.save_state(self.ws.shadow, state)
        return result

    def test_first_refresh_and_idempotence(self):
        before = self.ws.tree(self.ws.source), self.ws.tree(self.ws.sources)
        first = self.refresh()
        self.assertTrue(first.refreshed)
        self.assertTrue(first.ghidra_copied)
        nachbau = self.ws.shadow / "nachbau"
        self.assertEqual(sorted(p.relative_to(nachbau).as_posix() for p in nachbau.rglob("*") if p.is_file()),
                         ["ai.c", "ai.h", "build/seg.asm"])
        self.assertTrue((self.ws.shadow / "wissen" / "laufzeit" / "login.toml").is_file())
        ghidra = self.ws.shadow / "cache" / "ghidra"
        self.assertTrue((ghidra / "decomp.rep" / "data.bin").is_file())
        self.assertFalse((ghidra / "decomp.lock").exists())
        link = self.ws.shadow / "cache" / "laufzeit"
        self.assertTrue(S._is_link(link))
        self.assertTrue((link / "login" / "calls.jsonl").is_file())
        toml = (self.ws.shadow / "decomp.toml").read_text(encoding="utf-8")
        self.assertIn(f'datei = "{(self.ws.source / "spiel/MAIN.EXE").resolve().as_posix()}"', toml)
        mtimes = self.ws.tree(self.ws.shadow)
        second = self.refresh()
        self.assertFalse(second.refreshed)
        self.assertEqual(self.ws.tree(self.ws.shadow), mtimes)
        self.assertEqual((self.ws.tree(self.ws.source), self.ws.tree(self.ws.sources)), before)

    def test_mirror_add_change_remove(self):
        self.refresh()
        nachbau = self.ws.shadow / "nachbau"
        (nachbau / "decomp-made.obj").write_bytes(b"obj")  # not a source extension: left alone
        keep = (nachbau / "ai.h").stat().st_mtime_ns
        (self.ws.sources / "ai.c").write_text("void ai_find_next_order(void) { int x; }\n", encoding="utf-8")
        (self.ws.sources / "new.inc").write_text("; inc\n", encoding="utf-8")
        shutil.rmtree(self.ws.sources / "build")
        self.assertEqual(S.mirror_sources(self.ws.sources, nachbau), 3)
        self.assertIn("int x", (nachbau / "ai.c").read_text(encoding="utf-8"))
        self.assertTrue((nachbau / "new.inc").is_file())
        self.assertFalse((nachbau / "build").exists())
        self.assertTrue((nachbau / "decomp-made.obj").is_file())
        self.assertEqual((nachbau / "ai.h").stat().st_mtime_ns, keep)
        self.assertEqual(S.mirror_sources(self.ws.sources, nachbau), 0)

    def test_wissen_tracked(self):
        self.refresh()
        wissen = self.ws.shadow / "wissen"
        (wissen / "nachbau-programm.toml").write_text("made by decomp\n", encoding="utf-8")
        (wissen / "symbole.toml").write_text("changed in the shadow\n", encoding="utf-8")
        self.assertFalse(self.refresh().refreshed)  # source unchanged: the shadow's own state stays
        self.assertEqual((wissen / "symbole.toml").read_text(encoding="utf-8"), "changed in the shadow\n")
        src = self.ws.source / "wissen" / "symbole.toml"
        src.write_text(SYMBOLE + "\n", encoding="utf-8")
        os.utime(src, ns=(time.time_ns(), time.time_ns() + 10**9))
        (self.ws.source / "wissen" / "laufzeit" / "login.toml").unlink()
        result = self.refresh()
        self.assertEqual(result.changed, 2)
        self.assertEqual((wissen / "symbole.toml").read_text(encoding="utf-8"), SYMBOLE + "\n")
        self.assertFalse((wissen / "laufzeit" / "login.toml").exists())
        self.assertTrue((wissen / "nachbau-programm.toml").is_file())

    def test_ghidra_copy_once(self):
        self.refresh()
        ghidra = self.ws.shadow / "cache" / "ghidra"
        (ghidra / "angewendet.json").write_text("shadow state", encoding="utf-8")
        self.assertFalse(S.ghidra_needs_copy(self.ws.source, self.ws.shadow))
        self.assertFalse(self.refresh().ghidra_copied)
        self.assertTrue((ghidra / "angewendet.json").is_file())
        (self.ws.source / "cache" / "ghidra" / "meta.json").write_text('{"version": 4, "sha256": "bb"}',
                                                                         encoding="utf-8")
        self.assertTrue(S.ghidra_needs_copy(self.ws.source, self.ws.shadow))
        self.assertTrue(self.refresh().ghidra_copied)
        self.assertFalse((ghidra / "angewendet.json").exists())
        self.assertIn('"bb"', (ghidra / "meta.json").read_text(encoding="utf-8"))

    def test_no_ghidra_in_source(self):
        shutil.rmtree(self.ws.source / "cache" / "ghidra")
        self.assertFalse(S.ghidra_needs_copy(self.ws.source, self.ws.shadow))
        self.assertFalse(self.refresh().ghidra_copied)

    def test_dot_path_uses_local_app_data(self):
        local = self.ws.root / "local"
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
            folder = S.ghidra_project_dir(self.ws.root / ".worktrees" / "x" / "cache")
            self.assertEqual(folder.parent, local / "decomp" / "ghidra")
            self.assertEqual(S.ghidra_project_dir(self.ws.shadow / "cache"), (self.ws.shadow / "cache" / "ghidra").resolve())

    def test_link_recreated_when_target_moves(self):
        self.refresh()
        other = self.ws.root / "other-recordings"
        other.mkdir()
        link = self.ws.shadow / "cache" / "laufzeit"
        self.assertTrue(S.make_link(link, other))
        self.assertFalse(S.make_link(link, other))
        self.assertTrue((self.ws.source / "cache" / "laufzeit" / "login" / "calls.jsonl").is_file())


class ProgressMessageTest(unittest.TestCase):
    """Heartbeats show the command's own progress, not the server's `bereit …` line from before the command."""

    def test_only_log_lines_since_the_command_started(self):
        from decovery_decomp_legacy import FORWARD_NOTE, _progress_message
        from decovery_decomp_legacy.process import DecompServer
        with tempfile.TemporaryDirectory() as tmp:
            server = DecompServer(Path(tmp))
            server.log_path.parent.mkdir(parents=True)
            server.log_path.write_text("=== server start ===\nbereit pid=1 port=2 code=3\n", encoding="utf-8")
            sh = mock.Mock(server=server)
            call = mock.Mock(last_line=f"{FORWARD_NOTE} …")
            start = server.log_size()
            self.assertEqual(_progress_message(call, sh, start, "permute"), "Decomp permute running")
            with server.log_path.open("a", encoding="utf-8") as f:
                f.write("Runde 3 von 20\n")
            self.assertEqual(_progress_message(call, sh, start, "permute"), "Runde 3 von 20")
            call.last_line = "eigene Zeile"
            self.assertEqual(_progress_message(call, sh, start, "permute"), "eigene Zeile")


class NamesTest(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)
        self.wissen = self.ws.root / "wissen"
        shutil.copytree(self.ws.source / "wissen", self.wissen)

    def test_write_through(self):
        run = parse_run(self.ws.params(symbols=[
            {"address": "flat:00016E40", "kind": "function", "name": "ai_find_next_order"},
            {"address": "flat:00050000", "kind": "global", "name": "order_table"},
            {"address": "flat:00060000", "kind": "global", "name": "new_global"}]))
        self.assertEqual(N.result_name(self.wissen, "va:00016E40"), "suche_auftrag")
        changed = N.write_names(self.wissen, run.symbols)
        self.assertEqual(changed, 4)  # name moved off va:00017000, renamed, added, nachbau.toml entry
        from decomp import wissen as W
        from decomp.adressen import parse

        w = W.laden(self.wissen)
        self.assertEqual(w.symbole[parse("va:00016E40")].name, "ai_find_next_order")
        self.assertEqual(w.symbole[parse("va:00016E40")].quelle, "import")
        self.assertIsNone(w.symbole[parse("va:00017000")].name)
        self.assertEqual(w.symbole[parse("va:00060000")].art, "variable")
        self.assertEqual(w.symbole[parse("va:00050000")].quelle, "mensch")  # unchanged entry keeps its source
        self.assertEqual(N.result_name(self.wissen, "va:00016E40"), "ai_find_next_order")
        self.assertEqual(N.result_name(self.wissen, "va:00099990"), "fun_00099990")
        self.assertEqual(N.write_names(self.wissen, run.symbols), 0)

    def test_fingerprint(self):
        run = parse_run(self.ws.params())
        mark = N.fingerprint(run.symbols, self.wissen)
        self.assertEqual(mark, N.fingerprint(run.symbols, self.wissen))
        self.assertNotEqual(mark, N.fingerprint(run.symbols[:1], self.wissen))


class PluginTest(FakeEnv):
    def run_ops(self, *params_list):
        plugin = build_plugin()
        messages = [request(i + 1, "legacy/run", p) for i, p in enumerate(params_list)]
        return serve(plugin, messages)

    def test_initialize(self):
        answers, _ = serve(build_plugin(), [request(1, "initialize", {"protocol": "decovery-plugin/1"})])
        caps = answers[1]["result"]["capabilities"]
        self.assertEqual(caps, {"legacy": {"version": 1, "limits": {"max_parallel": 2,
                                                                      "memory_per_instance_mb": 3000}}})

    def test_operations_and_mapping(self):
        os.environ["FAKE_DECOMP_MODE"] = "improve"
        ws = self.ws
        ops = ["context", "registers", "joint", "chain", "permute", "beam", "forms", "equivalence", "slots"]
        plugin = build_plugin()
        answers, _ = serve(  # one session: the server starts once
plugin, [request(i + 1, "legacy/run", ws.params(op)) for i, op in enumerate(ops)])
        results = {op: answers[i + 1].get("result") or self.fail(answers[i + 1]) for i, op in enumerate(ops)}
        name = "ai_find_next_order"  # decovery's name, written into the shadow
        folder = ws.shadow / "cache" / "nachbau"
        self.assertEqual(results["context"]["report"].strip(), f"Bericht kontext {name}")
        self.assertEqual(results["context"]["report_language"], "de")
        self.assertIsNone(results["context"]["json"])
        self.assertIsNone(results["context"]["candidate"])
        self.assertEqual(results["registers"]["json"], {name: {"zuordnung": {"count": "ESI"}}})
        self.assertTrue(results["registers"]["artifacts"][0].endswith("registers.json"))
        self.assertEqual(results["joint"]["json"], {"treffer": [], "funktion": name})
        self.assertEqual(results["joint"]["report"].strip(), f"Bericht gemeinsam {name} (Datei)")
        self.assertEqual(results["equivalence"]["report"], f"Bericht gleichwertig {name} gleichwertig")
        self.assertEqual(results["equivalence"]["json"]["urteil"], "ungeprueft")
        self.assertEqual(results["chain"]["candidate"], {"path": str(folder / "kette" / name / "beste.c"),
                                                         "kind": "module"})
        self.assertEqual(results["chain"]["json"], {"kennzahl": [3, 10]})
        self.assertIn(str(folder / "kette" / name / "ergebnis.txt"), results["chain"]["artifacts"])
        for op, step in (("permute", "permutieren"), ("beam", "strahl"), ("forms", "formen")):
            self.assertEqual(results[op]["candidate"]["path"], str(folder / step / name / "beste.c"))
        self.assertIsNone(results["slots"]["candidate"])  # slots is no search: its beste.c is an artifact
        self.assertIn(str(folder / "plaetze" / name / "beste.c"), results["slots"]["artifacts"])
        self.assertEqual(sum(r["shadow"]["ghidra_copied"] for r in results.values()), 1)  # first prepared run
        self.assertEqual(sum(r["shadow"]["refreshed"] for r in results.values()), 1)
        for r in results.values():
            self.assertEqual(r["exit_code"], 0)
            self.assertGreaterEqual(r["seconds"], 0)
        calls = ws.calls()
        self.assertEqual(len(calls), len(ops) + 1)  # equivalence builds ai.c first
        self.assertTrue(all(c["emu"] == "1" and c["server"] for c in calls))
        starts = (ws.shadow / "cache" / "fake-server-starts.txt").read_text().split()
        self.assertEqual(len(starts), 1)
        self.assertFalse((ws.shadow / "cache" / "fernzugang.json").exists())  # stopped at shutdown

    def test_verify_builds_the_file_once_per_source_state(self):
        """equivalence/behavior read the OBJ of Decomp's last build: the shadow had none, Decomp answered
        `ungeprueft` / "OBJ fehlt". The function's file is built first, again only after a source change."""
        ws = self.ws
        answers, _ = self.run_ops(ws.params("equivalence"), ws.params("behavior"))
        self.assertIn("result", answers[1])
        self.assertIn("result", answers[2])
        befehle = [c["args"][:2] for c in ws.calls()]
        self.assertEqual(befehle, [["bauen", "ai.c"], ["gleichwertig", "va:00016E40"],
                                   ["verhalten", "va:00016E40"]])
        (ws.sources / "ai.h").write_text("void ai_find_next_order(int);\n", encoding="utf-8")
        self.run_ops(ws.params("behavior"))
        self.assertEqual([c["args"][:2] for c in ws.calls()][3:], [["bauen", "ai.c"], ["verhalten", "va:00016E40"]])

    def test_no_candidate_without_improvement(self):
        answers, _ = self.run_ops(self.ws.params("chain"), self.ws.params("permute"))
        self.assertIsNone(answers[1]["result"]["candidate"])
        self.assertIsNone(answers[2]["result"]["candidate"])
        # the two runs are prepared in either order (parallel): only the first one refreshes
        self.assertEqual(sum(answers[i]["result"]["shadow"]["refreshed"] for i in (1, 2)), 1)

    def test_stale_candidate_not_reported(self):
        stale = self.ws.shadow / "cache" / "nachbau" / "kette" / "ai_find_next_order" / "beste.c"
        stale.parent.mkdir(parents=True)
        stale.write_text("old", encoding="utf-8")
        os.utime(stale, (time.time() - 3600, time.time() - 3600))
        answers, _ = self.run_ops(self.ws.params("chain"))
        self.assertIsNone(answers[1]["result"]["candidate"])

    def test_caller_sets_emu(self):
        os.environ["DECOMP_WATCOM_EMU"] = "0"
        self.run_ops(self.ws.params())
        self.assertEqual(self.ws.calls()[0]["emu"], "0")

    def test_command_failed(self):
        os.environ["FAKE_DECOMP_MODE"] = "fail"
        answers, _ = self.run_ops(self.ws.params())
        error = answers[1]["error"]
        self.assertEqual(error["code"], -32022)
        self.assertEqual(error["data"]["exit_code"], 1)
        self.assertIn("weder Adresse", error["data"]["stderr_tail"])

    def test_server_fails(self):
        os.environ["FAKE_DECOMP_SERVER"] = "fail"
        answers, _ = self.run_ops(self.ws.params())
        self.assertEqual(answers[1]["error"]["code"], -32020)
        self.assertIn("Server kaputt", answers[1]["error"]["message"])

    def test_decomp_missing(self):
        real = __import__("importlib").import_module

        def fail(name, *args):
            if name.startswith("decomp"):
                raise ImportError("no module named decomp")
            return real(name, *args)

        with mock.patch("importlib.import_module", fail):
            answers, _ = self.run_ops(self.ws.params())
        self.assertEqual(answers[1]["error"]["code"], -32020)

    def test_bad_params_answer(self):
        answers, _ = self.run_ops(self.ws.params(options={"rounds": 2}))
        self.assertEqual(answers[1]["error"]["code"], -32602)
        answers, _ = self.run_ops(self.ws.params(decomp_workspace=str(self.ws.root / "missing")))
        self.assertEqual(answers[1]["error"]["code"], -32021)

    def test_timeout_and_heartbeat(self):
        os.environ["FAKE_DECOMP_MODE"] = "sleep"
        with mock.patch("decovery_decomp_legacy.HEARTBEAT_S", 0.5):
            answers, progress = self.run_ops(self.ws.params(timeout_s=3))
        error = answers[1]["error"]
        self.assertEqual(error["code"], -32022)
        self.assertTrue(error["data"]["timed_out"])
        self.assertTrue(any(p.get("message", "").startswith("Runde") for p in progress))
        self.assertTrue(self.process_gone())

    def process_gone(self):
        pid = int((self.ws.shadow / "cache" / "fake-sleeping.txt").read_text())
        sys.path.insert(0, str(FAKE))
        from decomp.__main__ import _lebt

        deadline = time.monotonic() + 10
        while _lebt(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        return not _lebt(pid)

    def test_cancel_kills_and_restarts_server(self):
        os.environ["FAKE_DECOMP_MODE"] = "sleep"
        sleeping = self.ws.shadow / "cache" / "fake-sleeping.txt"

        def wait_running(wait_answer):
            deadline = time.monotonic() + 30
            while not sleeping.exists() and time.monotonic() < deadline:
                time.sleep(0.05)

        def after_cancel(wait_answer):
            wait_answer(1)
            os.environ["FAKE_DECOMP_MODE"] = "ok"

        answers, _ = serve(build_plugin(), [
            request(1, "legacy/run", self.ws.params()), wait_running,
            {"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": 1}}, after_cancel,
            request(2, "legacy/run", self.ws.params())])
        self.assertEqual(answers[1]["error"]["code"], -32002)
        self.assertTrue(self.process_gone())
        self.assertEqual(answers[2]["result"]["exit_code"], 0)
        starts = (self.ws.shadow / "cache" / "fake-server-starts.txt").read_text().split()
        self.assertEqual(len(starts), 2)  # the cancelled command ran inside the first server: replaced

    def test_parallel_runs(self):
        answers, _ = self.run_ops(self.ws.params(), self.ws.params("structure"), self.ws.params("slots"))
        self.assertTrue(all("result" in answers[i] for i in (1, 2, 3)))
        starts = (self.ws.shadow / "cache" / "fake-server-starts.txt").read_text().split()
        self.assertEqual(len(starts), 1)


if __name__ == "__main__":
    unittest.main()
