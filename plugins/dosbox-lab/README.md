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

All jobs of one request run in one dosbox-lab batch: the plugin writes `NB.BAT` into the current drive's folder
(removed again afterwards), mounts the writable drives normally and read-only drives as CD-ROM, and calls
`dosbox_lab.run_batch` once. Each job starts with `@ECHO DECOVERY-JOB-<i>`, switches to the current drive's root
and runs its lines (programs via `CALL`, so `.BAT` files return). A program with a non-zero errorlevel jumps to a
shared ladder that echoes `DECOVERY-EXIT-<code>-FAILED` and goes on with the next job; a job that completes echoes
`DECOVERY-JOB-<i>-END`. The plugin splits the captured console output at these markers into per-job `stdout` and
exit code.

The batch limit is `timeout_s` times the number of jobs. A hang stops the whole batch: the job that was running
answers `timeout`, jobs after it answer `failed` ("job not run"). The environment (`SET`) is shared by the jobs of
one request, so jobs should set what they need themselves.

## Tests

`python -m unittest discover -s tests`. `tests/test_local_dosbox.py` runs only when `DOSBOX_LAB_PACKAGE` points to
the directory that holds `dosbox_lab/` and the emulator executable exists.
