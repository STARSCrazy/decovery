# decovery-dosbox-lab

decovery plugin that runs original DOS compilers in [dosbox-lab](https://github.com/STARSCrazy/dosbox-lab) (a
headless DOSBox-X fork). Run as `python -m decovery_dosbox_lab` (stdio, protocol in `docs/plugin-protocol.md`).
Capability `{"runner": 1}`, the same `runner/run` as `unicorn-dos`; it also runs programs the emulator plugin
refuses (DOS4GW/LE programs).

## Setup

`decovery setup dosbox-lab --package <dir>` creates `<extern>/dosbox-lab-venv`, installs the SDK, this plugin and
the dosbox-lab Python package from `<dir>` (the directory with dosbox-lab's `pyproject.toml`, `python/` in its
repository), and writes `[plugins.dosbox-lab]`. The DOSBox executable is not part of the package: build it
(dosbox-lab's `build.ps1`) or point `DOSBOX_LAB_EXE` at it. Without the package or the executable, `runner/run`
answers error `-32010`.

## How a request runs

The jobs of one request are split over up to `max_parallel` DOSBox instances that run at the same time (declared
in `initialize`: one per logical core, as many as the free memory holds at 256 MB each, and no more than the
request's `options.jobs`). Larger jobs (`cost`) go first, each to the instance with the least work so far. Instance
`k` writes `NB<k>.BAT` into the current drive's folder and gets its own TMP directory `NBT<k>` (both removed
afterwards; the call is refused if either already exists), mounts the writable drives normally and read-only drives
as CD-ROM, and calls `dosbox_lab.run_batch`. Each job starts with `@ECHO DECOVERY-JOB-<i>`, switches to the current
drive's root, sets `TMP` to the instance's directory, resets the errorlevel with a 5-byte `ZERO.COM`, and runs its
lines (programs via `CALL`, so `.BAT` files return; `IF`, `FOR` and the other shell commands run as they are,
`GOTO` and labels are refused). A program with a non-zero errorlevel jumps to a shared ladder that echoes
`DECOVERY-EXIT-<code>-FAILED` and goes on with the next job; a job that completes echoes `DECOVERY-JOB-<i>-END`.
The plugin splits the captured console output at these markers into per-job `stdout` and exit code and merges the
instances' results in job order.

An instance's batch limit is `timeout_s` times the number of its jobs. A hang stops that batch: the job that was
running answers `timeout`, and the jobs after it run again in a new DOSBox session. Only when a session reaches
none of its jobs (DOSBox does not start) do they answer `failed` ("job not run"). The environment (`SET`) is shared
by the jobs of one instance, so jobs should set what they need themselves.

