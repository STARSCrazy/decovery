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
{"jsonrpc":"2.0","id":1,"result":{"name":"ghidra","version":"0.2.0","protocol":"decovery-plugin/1",
  "capabilities":{"analyzer":{"version":2},"decompiler":{"version":2}}}}
```

`capabilities` maps a capability name to `{"version": <u32>, "limits"?: {"max_parallel": <u32>,
"memory_per_instance_mb": <u32> | null}}`. A capability version changes when its method set or message shapes
change incompatibly. The host refuses a plugin whose `protocol` differs from its own.

`limits` declares how many jobs of the capability the plugin runs at once (`max_parallel`, at least 1) and how
much memory one running instance needs (`memory_per_instance_mb`, null when negligible or unknown). A capability
without `limits` runs one job at a time. The host keeps the jobs it has in flight within each provider's
`max_parallel` and their sum within its global limit (`--jobs`, default: the number of logical cores), and tells
the plugin its share per request (`options.jobs` of `runner/run`).

```json
"capabilities": {"runner": {"version": 1, "limits": {"max_parallel": 16, "memory_per_instance_mb": null}}}
```

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

## Capabilities `analyzer` v2 and `decompiler` v2

Served by the Ghidra plugin (`plugins/ghidra`). Addresses are decovery address strings (`flat:0001A2B0`,
`seg:1234:0010`); all regions of a program share one arch (`x86-flat-32`, `x86-real-16`). Per-item problems are
warnings or per-function `error` entries; only malformed params or an unusable backend fail a call.

### `analyzer/open`

Params: `{program: {format, entry_points: [addr], regions: [{name, start, size, arch, permissions, blob}]},
project_dir: string, program_hash: string, options?: {calling_convention?: string}}`.
Result: `{functions: int, reused: bool}`, with `$/progress` while a program is built and analyzed.

The Ghidra project is kept in `project_dir` next to `project.json`
(`{"schema": 1, "program_hash", "ghidra_version", "calling_convention"}`). When that file matches the request, the
saved program is reopened without analysis (`reused: true`); otherwise the old project is deleted (only its own
files) and the program is rebuilt and analyzed. Ghidra rejects paths with a component that starts with a dot, so
such a `project_dir` is replaced by `%LOCALAPPDATA%/decovery/ghidra/<blake3 of the absolute project_dir>` on
Windows (`$XDG_CACHE_HOME/...` elsewhere, else the temp dir). `calling_convention` is a name from the compiler
spec (for example `__cdecl`) or `__watcall`, which the plugin installs as a spec extension; it also becomes the
default convention of every function whose applied signature names none.

### `analyzer/functions`

Params: `{}`. Result: `[{address, name, size}]`, ordered by address.

### `analyzer/apply`

Params: `{symbols: [{address, kind, name?, signature?, comment?, data_type?, locals: [{place, name,
data_type?}], line_comments: [{address, text}]}], types_h: string, references: [{from, to, kind}]}`.
Result: `{applied: int, warnings: [string]}`.

- `kind` is `function`, `global` or `label`; `place` is `param:<n>` (1-based) or `stack:<offset>` (hex, may be
  negative); `reg:` places are reported as warnings. Reference `kind` is `call` or `jump`.
- `types_h` is parsed by Ghidra's C parser; when the whole text fails, each top-level declaration is parsed on its
  own and every failing one becomes a warning. Structs whose fields carry `/* +0xN */` offset comments are packed
  or laid out to match them.
- What a previous apply set and the current knowledge no longer carries (labels, comments, signatures,
  references) is taken back; functions without a knowledge name get the default name (`fun_0001A2B0`).
- `applied` counts the symbols and references that went in without error.

### `analyzer/export`

Params: `{out_path: string}`. Result: `{path, blake3}` (blake3 of the written file).

The file is UTF-8 JSON, written atomically, identical bytes for identical data:
`{"schema": 1, "functions": [{start, end, body_size, name}], "calls": [{site, caller, callee}],
"strings": [{address, text, users: [addr]}], "data_accesses": [{function, address, kind}]}`.
`end` is inclusive; `name` is null when Ghidra has only a default name; `kind` is `read` or `write`. Order:
functions by `start`, calls by (`caller`, `site`, `callee`), strings by `address` (users sorted), data accesses by
(`function`, `address`, `kind`).

### `decompiler/decompile`

Params: `{addresses: [addr], out_dir: string}`. Result: `[{address, path?, error?, disassembly?: [[addr, text]]}]`
in request order. The C code of each function goes to `out_dir/<address with : replaced by _>.c` (`path`). A
function that fails (60 s decompiler timeout, no function there, unmappable address) carries `error`, plus its
disassembly when the function exists. Progress is reported per function; a `$/cancel` takes effect between
functions.

### Error codes

| Code | Meaning |
|---|---|
| `-32602` | invalid params, unmappable program description, unknown calling convention |
| `-32010` | Ghidra unavailable (`GHIDRA_INSTALL_DIR` unset or wrong, pyghidra missing, project locked by another process) |
| `-32011` | no program open (`analyzer/open` not called yet) |
| `-32012` | project or file I/O failed (project folder, `project.json`, export file, `out_dir`, `applied.json`) |

On `shutdown` or end of input the plugin closes the decompiler, the program and the Ghidra project (releasing its
lock).

## Capability `runner` v1

Served by plugins that run the original DOS compilers: `unicorn-dos` (emulator) and `dosbox-lab`. The built-in
`native` runner of `decovery-toolchain` needs no plugin. Drive `C:` is the build directory (writable), drive `D:`
the tool directory (read-only).

### `runner/run`

Params: `{mounts: [{drive, path, writable}], current_drive: "C", timeout_s, options?: {jobs?},
jobs: [{commands: [string], cost?}]}`. `path` is an absolute host directory, `timeout_s` applies to each job.
`options.jobs` is the most jobs of this request the plugin may run at once (the host's share of its global limit;
absent = the plugin's `max_parallel`). `cost` is the relative size of a job (the host sends the source size in
bytes; absent = 0): a plugin starts larger jobs first, so the largest job does not finish last. Each job is a DOS session of its own: its
command lines run one after another, a `SET NAME=value` line sets the environment for the following lines of the
same job, and the job ends at the first line with a non-zero exit code. The host rejects command lines over 126
characters before calling, so the plugin never sees them.

Result: `{jobs: [{status: "done" | "timeout" | "failed", exit_code, stdout, message}]}`, one entry per job in
request order. `done` carries the exit code of the last command that ran, `timeout` means the job did not end
within `timeout_s` (the plugin stops it), `failed` carries a `message` (the emulator faulted, an unknown
instruction, ...). `stdout` is the console output as text. The plugin does not report which files a job produced:
the host snapshots drive `C:` before the call and derives that itself, and for a `timeout` it deletes the expected
files that did not exist before.

A plugin that cannot run some job's program (an unsupported CPU mode or DOS extender) answers error `-32020`
before running any job; the host then tries the next runner of its list.

| Code | Meaning |
|---|---|
| `-32010` | `dosbox-lab` only: the dosbox-lab package or the DOSBox executable is missing; nothing was run |
| `-32020` | `RUNNER_UNSUPPORTED`: some job's program cannot be run by this plugin; nothing was run |
