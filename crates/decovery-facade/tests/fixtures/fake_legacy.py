"""Fake `decomp-legacy` plugin for the bridge tests: speaks capability `legacy` v1 without Decomp.

Every `legacy/run` appends its params as one JSON line to `<shadow_dir>/requests.jsonl` and sends one `$/progress`
("Schritt 1 von 2"). What it answers comes from `<shadow_dir>/answer.json` when that exists:

- `{"error": {"code": C, "message": M, "data": D}}` answers with that JSON-RPC error;
- `{"candidate": {"text": T, "kind": K}}` writes T to `<shadow_dir>/cache/nachbau/kette/<f>/beste.c` and returns it
  as the candidate of kind K;
- `{"json": J}` returns J as `json`;
- `{"artifacts": [P, ...]}` returns those paths as `artifacts`;
- `{"block": true}` first appends a line to `<shadow_dir>/block.log` and waits (up to 60 s) for `$/cancel`; when
  cancelled it appends `cancelled` to `<shadow_dir>/cancel.log` and answers -32002 (like the real plugin after
  killing the Decomp subprocess).

Without it the answer is a report naming the operation and the function, with `json = null` and no candidate.
"""

import json
import os
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "plugins", "decovery-plugin-sdk"))

from decovery_plugin import Plugin, RpcError  # noqa: E402

plugin = Plugin("decomp-legacy-fake", "0.0.1")
plugin.set_limits("legacy", 2, 3000)


@plugin.method("legacy/run", capability_version=1)
def run(params, ctx):
    shadow = Path(params["shadow_dir"])
    shadow.mkdir(parents=True, exist_ok=True)
    with open(shadow / "requests.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(params, sort_keys=True) + "\n")
    ctx.progress(1, 2, "Schritt 1 von 2")
    answer_path = shadow / "answer.json"
    answer = json.loads(answer_path.read_text(encoding="utf-8")) if answer_path.is_file() else {}
    if answer.get("block"):
        with open(shadow / "block.log", "a", encoding="utf-8") as f:
            f.write("blocked\n")
        if ctx.wait_cancelled(60):
            with open(shadow / "cancel.log", "a", encoding="utf-8") as f:
                f.write("cancelled\n")
            ctx.check_cancelled()
    if "error" in answer:
        e = answer["error"]
        raise RpcError(e["code"], e["message"], e.get("data"))
    function = params["function"]
    candidate = None
    if "candidate" in answer:
        folder = shadow / "cache" / "nachbau" / "kette" / function.replace(":", "_")
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "beste.c"
        path.write_text(answer["candidate"]["text"], encoding="utf-8")
        candidate = {"path": str(path), "kind": answer["candidate"]["kind"]}
    return {
        "exit_code": 0,
        "report": f"Bericht {params['operation']} für {function}\nZeile 2\n",
        "report_language": "de",
        "json": answer.get("json"),
        "candidate": candidate,
        "artifacts": answer.get("artifacts", []),
        "shadow": {"refreshed": True, "ghidra_copied": False},
        "seconds": 1.5,
    }


if __name__ == "__main__":
    plugin.serve()
