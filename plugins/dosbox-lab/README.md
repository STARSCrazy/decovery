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

Needs a dosbox-lab whose `run_batch` takes the `watch` and `snapshot` arguments; with an older package
`runner/run` answers `-32010` ("dosbox-lab is too old").

## How a request runs

The jobs of one request are split over up to `max_parallel` DOSBox instances that run at the same time (declared
in `initialize`: one per logical core, as many as the free memory holds at 256 MB each, and no more than the
request's `options.jobs`). Larger jobs (`cost`) go first, each to the instance with the least work so far. Instance
`k` writes `NB<k>.BAT` into the current drive's folder and gets its own TMP directory `NBT<k>` (both removed
afterwards; the call is refused if either already exists), mounts the writable drives normally and read-only drives
as CD-ROM, and calls `dosbox_lab.run_batch`. Each job starts with `@ECHO DECOVERY-JOB-<i>`, switches to the current
drive's root, saves the variables its `SET` lines change (and `TMP`), sets `TMP` to the instance's directory, resets
the errorlevel with a 5-byte `ZERO.COM`, and runs its lines: programs via `CALL` (so `.BAT` files return) followed by
an errorlevel check; `IF`, `FOR` and the other shell commands run as they are, so a program started inside an `IF` or
`FOR` line gets no errorlevel check. `GOTO` (at the start of a line or anywhere in an `IF`/`FOR` line) and labels are
refused. A program with a non-zero errorlevel jumps to a shared ladder that echoes `DECOVERY-EXIT-<code>-FAILED`; a
job that completes echoes `DECOVERY-JOB-<i>-END`; on both paths the saved variables are restored before the next
job. The plugin splits the captured console output at these markers into per-job `stdout` and exit code and merges
the instances' results in job order. A job's result therefore does not depend on which jobs share its instance.

Each job may run `timeout_s` from its begin marker: the plugin watches the output while the session runs
(`run_batch(watch=...)`) and stops the session when the running job exceeds its limit (or the request is cancelled).
That job answers `timeout` ("no end after <timeout_s> s"); the jobs the session did not reach answer `failed` with
"job not run: ...", which decovery submits once more. A session as a whole is bounded by `timeout_s` times its jobs
plus 10 s for DOSBox to start, within the host's call budget. One DOSBox start and stop costs about 1 s here.

## Tests

`python -m unittest discover -s tests`. `tests/test_local_dosbox.py` runs only when `DOSBOX_LAB_PACKAGE` points to
the directory that holds `dosbox_lab/` and the emulator executable exists.
