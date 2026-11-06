import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "plugins", "decovery-plugin-sdk"))

from decovery_plugin import Plugin  # noqa: E402

plugin = Plugin("echo", "0.0.1")
plugin.set_limits("echo", max_parallel=3, memory_per_instance_mb=64)


@plugin.method("echo/ping", capability_version=1)
def ping(params, ctx):
    return params


@plugin.method("echo/sleep", capability_version=1)
def sleep(params, ctx):
    """Waits up to `seconds`; writes `marker` when $/cancel arrives."""
    cancelled = ctx.wait_cancelled(params["seconds"])
    if cancelled and params.get("marker"):
        with open(params["marker"], "w", encoding="utf-8") as f:
            f.write("cancelled")
    return {"slept": params["seconds"], "cancelled": cancelled}


@plugin.method("echo/count", capability_version=1)
def count(params, ctx):
    for i in range(1, params["n"] + 1):
        ctx.progress(i, total=params["n"], message=f"step {i}")
        time.sleep(0.01)
    return params["n"]


@plugin.method("echo/block", capability_version=1)
def block(params, ctx):
    """Starts a worker process, tells its pid (writes `marker`), then ignores everything for `seconds`."""
    import subprocess

    child = subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({params['seconds']})"])
    with open(params["marker"], "w", encoding="utf-8") as f:
        f.write(str(child.pid))
    time.sleep(params["seconds"])
    return {}


plugin.serve()
