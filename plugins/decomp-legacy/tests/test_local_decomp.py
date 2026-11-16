"""Against a real Decomp checkout and workspace: skipped unless DECOVERY_DECOMP_WORKSPACE (a Decomp workspace, read
only) and DECOVERY_DECOMP_PYTHON (the Python of the Decomp checkout's venv) are set.

Optional: DECOVERY_DECOMP_SHADOW (shadow directory, reused between runs so the Ghidra project is copied once;
default: a temporary directory), DECOVERY_DECOMP_SOURCES (decovery's rebuild sources; default: a copy of the
workspace's `nachbau/`), DECOVERY_DECOMP_SYMBOLS (a decovery `knowledge/symbols.toml` whose names are written into
the shadow), DECOVERY_DECOMP_FUNCTION (default flat:00016E40), DECOVERY_DECOMP_OPERATION (default registers)."""

import json
import os
import shutil
import subprocess
import tempfile
import time
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKSPACE = os.environ.get("DECOVERY_DECOMP_WORKSPACE")
PYTHON = os.environ.get("DECOVERY_DECOMP_PYTHON")


def symbols(path):
    if not path:
        return []
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return [{"address": s["address"], "kind": s["kind"], "name": s["name"]}
            for s in data.get("symbol", []) if s.get("name") and s.get("kind") in ("function", "global", "label")]


@unittest.skipUnless(WORKSPACE and PYTHON, "local: set DECOVERY_DECOMP_WORKSPACE and DECOVERY_DECOMP_PYTHON")
class LocalDecompTest(unittest.TestCase):
    def test_run(self):
        temp = Path(tempfile.mkdtemp(prefix="legacy-local-"))
        self.addCleanup(shutil.rmtree, temp, True)
        shadow = Path(os.environ.get("DECOVERY_DECOMP_SHADOW") or temp / "shadow")
        sources = os.environ.get("DECOVERY_DECOMP_SOURCES")
        if not sources:
            sources = temp / "src"
            shutil.copytree(Path(WORKSPACE) / "nachbau", sources)
        params = {"decomp_workspace": WORKSPACE, "shadow_dir": str(shadow), "sources_dir": str(sources),
                  "symbols": symbols(os.environ.get("DECOVERY_DECOMP_SYMBOLS")),
                  "operation": os.environ.get("DECOVERY_DECOMP_OPERATION", "registers"),
                  "function": os.environ.get("DECOVERY_DECOMP_FUNCTION", "flat:00016E40"), "options": {},
                  "timeout_s": 1800}
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(HERE.parent), str(HERE.parent.parent / "decovery-plugin-sdk")]))
        proc = subprocess.Popen([PYTHON, "-m", "decovery_decomp_legacy"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, env=env, text=True, encoding="utf-8")
        began = time.monotonic()
        send = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocol": "decovery-plugin/1"}},
                {"jsonrpc": "2.0", "id": 2, "method": "legacy/run", "params": params}]
        for message in send:
            proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()
        answer, progress = None, 0
        for line in proc.stdout:
            message = json.loads(line)
            if message.get("method") == "$/progress":
                progress += 1
                print("progress:", message["params"].get("message"), flush=True)
            elif message.get("id") == 2:
                answer = message
                break
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}) + "\n")
        proc.stdin.close()
        proc.wait(180)
        proc.stdout.close()
        seconds = time.monotonic() - began
        self.assertIsNotNone(answer)
        self.assertIn("result", answer, answer)
        result = answer["result"]
        print(f"local {params['operation']} {params['function']}: {seconds:.1f} s total, decomp {result['seconds']} s, "
              f"shadow {result['shadow']}, {progress} progress notes, report {len(result['report'])} chars")
        self.assertEqual(result["exit_code"], 0)
        if params["operation"] == "registers":
            self.assertIsInstance(result["json"], dict)
        self.assertFalse((shadow / "cache" / "fernzugang.json").exists())


if __name__ == "__main__":
    unittest.main()
