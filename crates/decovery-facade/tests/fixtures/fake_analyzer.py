"""Fake analyzer plugin for the `analyze` tests: speaks analyzer v2 / decompiler v2 like the Ghidra plugin.

It records the params of open, apply and decompile as JSON files in `project_dir` so tests can inspect what the
host sent, writes a small deterministic export, and fails the decompilation of one function (with disassembly).
`project_dir/runs.txt` counts decompile calls across runs; every body names its run.
"""

import json
import os
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "plugins", "decovery-plugin-sdk"))

from decovery_plugin import Plugin, RpcError, decode_blob  # noqa: E402

plugin = Plugin("fake", os.environ.get("FAKE_VERSION", "0.0.1"))
state = {"project": None}

FAILING = "flat:00010200"

EXPORT = {
    "schema": 1,
    "functions": [
        {"start": "flat:00010010", "end": "flat:000100FF", "body_size": 240, "name": None, "extra": 1},
        {"start": "flat:00010100", "end": "flat:0001017F", "body_size": 128, "name": "FUN_helper"},
        {"start": "flat:00010200", "end": "flat:0001023F", "body_size": 64, "name": None},
    ],
    "calls": [
        {"site": "flat:00010020", "caller": "flat:00010010", "callee": "flat:00010100"},
        {"site": "flat:00010040", "caller": "flat:00010010", "callee": "flat:00010200"},
    ],
    "strings": [{"address": "flat:00030010", "text": "hello", "users": ["flat:00010100"]}],
    "data_accesses": [
        {"function": "flat:00010010", "address": "flat:00030000", "kind": "read"},
        {"function": "flat:00010100", "address": "flat:00030000", "kind": "write"},
    ],
}


def record(name, params):
    path = Path(state["project"]) / name
    path.write_text(json.dumps(params, indent=1, sort_keys=True), encoding="utf-8")


@plugin.on_shutdown
def shutdown():
    if state["project"]:
        (Path(state["project"]) / "shutdown.txt").write_text("bye", encoding="utf-8")


@plugin.method("analyzer/open", capability_version=2)
def open_program(params, ctx):
    project = Path(params["project_dir"])
    project.mkdir(parents=True, exist_ok=True)
    state["project"] = str(project)
    sizes = []
    for region in params["program"]["regions"]:
        sizes.append(len(decode_blob(region["blob"])))
    record("open.json", dict(params, blob_sizes=sizes))
    for i in range(1, 4):
        ctx.progress(i, total=3, message=f"analyzing {i}")
    return {"functions": len(EXPORT["functions"]), "reused": False}


@plugin.method("analyzer/apply", capability_version=2)
def apply(params, ctx):
    if state["project"] is None:
        raise RpcError(-32011, "no program is open; call analyzer/open first")
    record("apply.json", params)
    return {"applied": len(params["symbols"]) + len(params["references"]), "warnings": ["fake warning"]}


@plugin.method("analyzer/export", capability_version=2)
def export(params, ctx):
    raw = (json.dumps(EXPORT, separators=(",", ":")) + "\n").encode("utf-8")
    Path(params["out_path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(params["out_path"]).write_bytes(raw)
    try:
        import blake3  # type: ignore[import-not-found]

        digest = blake3.blake3(raw).hexdigest()
    except ImportError:
        digest = None
    result = {"path": params["out_path"]}
    if digest:
        result["blake3"] = digest
    return result


@plugin.method("decompiler/decompile", capability_version=2)
def decompile(params, ctx):
    runs = Path(state["project"]) / "runs.txt"
    run = int(runs.read_text(encoding="utf-8")) + 1 if runs.exists() else 1
    runs.write_text(str(run), encoding="utf-8")
    record(f"decompile-{run}.json", params)
    out = Path(params["out_dir"])
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for index, address in enumerate(params["addresses"]):
        ctx.progress(index, len(params["addresses"]))
        if address == FAILING:
            results.append(
                {
                    "address": address,
                    "error": "fake timeout */ here",
                    "disassembly": [[address, "PUSH EBP"], ["flat:00010201", "RET"]],
                }
            )
            continue
        stem = address.replace(":", "_")
        path = out / f"{stem}.c"
        path.write_bytes(f"\r\nvoid {stem}(void)\r\n{{\r\n  /* run {run} */\r\n}}\r\n".encode("utf-8"))
        results.append({"address": address, "path": str(path)})
    ctx.progress(len(params["addresses"]), len(params["addresses"]))
    return results


plugin.serve()
