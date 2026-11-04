# decovery plugin protocol, version 1

Protocol id: `decovery-plugin/1`. Machine-readable form: `schemas/plugin-protocol.schema.json`.
Design background: `docs/design/0001-decovery-design.md`, sections 5.1 and 5.11 (item 4).

## Transport

- JSON-RPC 2.0, one JSON object per line (UTF-8, `\n` terminated, no embedded newlines), over the plugin's
  stdin (host to plugin) and stdout (plugin to host).
- stderr is for logs only; the host inherits or captures it and never parses it.
- Requests flow host to plugin only. A plugin never sends requests, only responses and the `$/progress`
  notification. A host ignores any other message a plugin sends.
- Request ids are integers chosen by the host, unique per plugin process.
- Plugins are long-lived and may serve several requests at once. Responses may arrive in any order; the host
  routes them by id.

## Handshake

`initialize` is the first request.

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol":"decovery-plugin/1","host_version":"0.1.0"}}
{"jsonrpc":"2.0","id":1,"result":{"name":"ghidra","version":"0.1.0","protocol":"decovery-plugin/1",
  "capabilities":{"analyzer":{"version":1},"decompiler":{"version":1}}}}
```

`capabilities` maps a capability name to `{"version": <u32>}`. A capability version changes when its method
set or message shapes change incompatibly. The host refuses a plugin whose `protocol` differs from its own.

`shutdown` (no params) answers `null`. The plugin then stops reading and exits; the host closes stdin and kills
the process after a grace period.

## Methods

Methods are named `<capability>/<op>`, for example `analyzer/open`. Parameters are a JSON object. A plugin
answers a method of a capability it does not announce with `-32001`, and an unknown operation of an announced
capability (or a name without `/`) with `-32601`.

## Notifications

| Method | Direction | Params |
|---|---|---|
| `$/progress` | plugin to host | `{id, done, total?, message?}`; `id` is the id of the running request, `done` and `total` are unit counts |
| `$/cancel` | host to plugin | `{id}`; the request with that id is no longer wanted |

Notifications carry no `id` of their own. `$/cancel` is advisory: the plugin should stop early and may answer
with `-32002`, or answer normally if it already finished. A plugin ignores a cancel for an unknown id.

## Timeouts and cancellation

Timeouts are the host's business. When a call times out or its cancel token fires, the host sends `$/cancel`
for that id, forgets the call, and discards any later response with that id. The next call on the same plugin
works normally. The host has one reader thread and routes responses by id, so calls from several threads
overlap.

## Errors

| Code | Meaning |
|---|---|
| `-32601` | unknown method (or unknown operation of a supported capability) |
| `-32001` | capability not supported |
| `-32002` | cancelled |
| `-32700`, `-32600`, `-32603` | parse error, invalid request, internal error (a handler raised) as in JSON-RPC 2.0 |

Other codes are plugin-defined; `error.data` may carry structured detail.

## Blobs: inline or by path

Binary data in params and results is a blob object, one of:

```json
{"inline_base64": "TWFu"}
{"blob": {"path": "C:\\work\\cache\\0f3a.bin", "blake3": "<64 lowercase hex digits>"}}
```

Below 64 KiB (65536 bytes) the payload is inline; at or above, it is a file in the workspace cache with an
absolute path and the blake3 of its contents. The receiver verifies the hash before use. The Python SDK
verifies it when the optional `blake3` package is installed (the standard library has no blake3).

## Coarse calls

Plugin calls are batches ("decompile these 200 functions"), not per-instruction round trips.
