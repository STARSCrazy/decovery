# decovery-plugin

Python SDK for decovery plugins: framing, capability dispatch, `$/progress`, `$/cancel`. Standard library only,
Python 3.12 or newer. Protocol: `docs/plugin-protocol.md`.

```python
from decovery_plugin import Plugin

plugin = Plugin("echo", "0.1.0")

@plugin.method("echo/ping", capability_version=1)
def ping(params, ctx):
    ctx.progress(1, total=1, message="pong")
    return params

plugin.serve()  # blocks; stdout carries the protocol, write logs to stderr
```

Handlers run in worker threads. Poll `ctx.cancelled` or call `ctx.check_cancelled()` (answers `-32002`).

Run the tests: `python -m unittest discover -s tests`.
