# decovery-unicorn-dos

decovery plugin that runs original DOS compilers in the [unicorn](https://www.unicorn-engine.org/) CPU emulator,
with DOS and the DOS extender emulated in Python. Run as `python -m decovery_unicorn_dos` (stdio, protocol in
`docs/plugin-protocol.md`). Licensed **GPL-2.0-only** (`LICENSE`) because it uses unicorn; decovery only talks to
it over the plugin protocol (ADR 0004).

## Setup

`pip install plugins/decovery-plugin-sdk plugins/unicorn-dos` into a venv of its own (Python 3.12 or later). This
pulls `unicorn==2.1.1`: 2.1.4 writes guest memory about 20x slower, which costs most of the compile time.

## Capability

`{"runner": 1}`: `runner/run` with `{mounts, current_drive, timeout_s, jobs: [{commands}]}` answers
`{jobs: [{status, exit_code, stdout, message}]}` (full shape in `docs/plugin-protocol.md`). Drive `C:` is the build
directory, `D:` the tool directory (read-only); the command lines of a job run like a batch file (`SET`, `@`,
`ECHO`, `REM`, `.BAT` files, programs found on `PATH`) and stop at the first non-zero exit code.

Hosts:

| Host | Programs | Status |
|---|---|---|
| `pharlap` | bound Phar Lap 386\|DOS-Extender programs with a flat P3 image (Watcom WCC386 9.5) | phase 2 |
| `realmode` | real-mode MZ and COM programs (Turbo C) | planned |

Before running anything, every program of every job is checked; one that no host runs (an LE/DOS4GW program, a
P3 image with relocations, ...) answers `-32020` (`RUNNER_UNSUPPORTED`), so decovery tries its next runner. A DOS
or extender call the emulation does not provide ends the job with status `failed` and a message such as
`unsupported INT 21h AH=45h at 000C:0001A2B3 (EAX=...)`; it never continues silently.

Jobs run in parallel in spawned worker processes (`DECOVERY_UNICORN_PARALLEL`, default 8); each worker keeps one
emulated machine per program and resets it between runs by rewriting only the changed 4 KiB pages.

## Layout

| Module | Content |
|---|---|
| `dosfs.py` | drives on host folders, 8.3 names, handles, DOS error codes |
| `services.py` | INT 21h services shared by the hosts, over a register/memory adapter |
| `pharlap.py` | P3 loader, reusable machine (GDT/LDT, selectors, heap), Phar Lap services |
| `batch.py` | command lines to steps, program lookup, host choice |
| `pool.py` | job execution, worker processes, machine reuse |

## Tests

`python -m unittest discover -s tests`. Tests that need unicorn skip without it ("unicorn not installed");
`tests/test_local_tools.py` compiles with the real Watcom 9.5 and runs only when `DECOVERY_TOOLCHAIN_WATCOM95`
points to its directory. The test programs are assembled from bytes in `tests/asm.py`.
