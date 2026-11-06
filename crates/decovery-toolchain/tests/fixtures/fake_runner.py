"""Fake `runner` plugin for the toolchain tests.

Job commands: `WRITE <NAME> <text>` writes a file into the C mount, `EXIT <n>` sets the exit code,
`SLEEP <s>` waits (a job over the timeout ends with status `timeout`), `UNSUPPORTED` answers error -32020
before any job runs (so does every call when FAKE_REFUSE_ALL=1), `ECHO <text>` appends a line to stdout,
`SHARE` appends `share=<options.jobs>`, `COST` appends `cost=<the job's cost>`. FAKE_MAX_PARALLEL=<n> declares
`max_parallel` for the runner capability.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "plugins", "decovery-plugin-sdk"))

from decovery_plugin import Plugin, RpcError  # noqa: E402

RUNNER_UNSUPPORTED = -32020

plugin = Plugin("fake-runner", "0.0.1")
if os.environ.get("FAKE_MAX_PARALLEL"):
    plugin.set_limits("runner", max_parallel=int(os.environ["FAKE_MAX_PARALLEL"]))


def run_job(job, mounts, timeout_s, ctx, options):
    stdout = []
    exit_code = 0
    deadline = time.monotonic() + timeout_s
    c_root = mounts["C"]
    for line in job["commands"]:
        word, _, rest = line.partition(" ")
        if word == "WRITE":
            name, _, text = rest.partition(" ")
            with open(os.path.join(c_root, name), "w", encoding="utf-8") as f:
                f.write(text)
        elif word == "EXIT":
            exit_code = int(rest)
        elif word == "SHARE":
            stdout.append(f"share={options.get('jobs')}")
        elif word == "COST":
            stdout.append(f"cost={job.get('cost')}")
        elif word == "ECHO":
            stdout.append(rest + "\r\n")
        elif word == "SLEEP":
            wanted = float(rest)
            if time.monotonic() + wanted > deadline:
                ctx.wait_cancelled(max(0.0, deadline - time.monotonic()))
                return {"status": "timeout", "exit_code": None, "stdout": "".join(stdout),
                        "message": f"no end after {timeout_s} s"}
            ctx.wait_cancelled(wanted)
        else:
            return {"status": "failed", "exit_code": None, "stdout": "".join(stdout),
                    "message": f"unknown command {word}"}
        if exit_code != 0:
            break
    return {"status": "done", "exit_code": exit_code, "stdout": "".join(stdout), "message": None}


@plugin.method("runner/run", capability_version=1)
def run(params, ctx):
    jobs = params["jobs"]
    refuse = os.environ.get("FAKE_REFUSE_ALL") == "1"
    if refuse or any(c.strip() == "UNSUPPORTED" for job in jobs for c in job["commands"]):
        raise RpcError(RUNNER_UNSUPPORTED, "program not supported by fake runner")
    mounts = {m["drive"]: m["path"] for m in params["mounts"]}
    options = params.get("options") or {}
    return {"jobs": [run_job(j, mounts, params["timeout_s"], ctx, options) for j in jobs]}


plugin.serve()
