"""Fake `runner` plugin for the build tests.

For a job whose last command line ends with `X.C` (any extension) it copies `X.OBJ` from the directory in
FAKE_OMF_DIR into the C mount (after a `CD D` line: `D.OBJ` into the directory D of the C mount, as `X.OBJ`) and exits 0; without that file it prints an error and exits 1. Every compiled job
appends its source name to `calls.log` and its `SET TMP=` directory (and whether it exists) to `tmp.log`, every
call appends its job count to `requests.log` (all in FAKE_OMF_DIR). The staged source of every job is copied to
`sources/<D>/<X.C>` (`sources/<X.C>` without a `CD` line) in FAKE_OMF_DIR.

With FAKE_NOT_RUN_ONCE=1 the first call with more than one job answers only its first job; the others come back
`failed` with "job not run: ..." like the dosbox-lab runner after a hang.
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "plugins", "decovery-plugin-sdk"))

from decovery_plugin import Plugin  # noqa: E402

plugin = Plugin("omf-runner", "0.0.1")
OBJECTS = os.environ["FAKE_OMF_DIR"]


def append(name, line):
    with open(os.path.join(OBJECTS, name), "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_job(job, c_root):
    cd = None
    for line in job["commands"]:
        if line.upper().startswith("SET TMP=C:\\"):
            tmp = line[len("SET TMP=C:\\"):]
            exists = os.path.isdir(os.path.join(c_root, tmp))
            append("tmp.log", f"{tmp} {'exists' if exists else 'missing'}")
        if line.upper().startswith("CD "):
            cd = line[3:].strip()
    source = job["commands"][-1].split()[-1]
    stem = source.rsplit(".", 1)[0]
    append("calls.log", f"{cd}/{source}" if cd else source)
    copy_dir = os.path.join(OBJECTS, "sources", cd or "")
    os.makedirs(copy_dir, exist_ok=True)
    staged = os.path.join(c_root, cd or "", source)
    if os.path.isfile(staged):
        shutil.copyfile(staged, os.path.join(copy_dir, source))
    # a job in a directory (a variant) is served the object named like the directory: V001.OBJ
    obj = os.path.join(OBJECTS, (cd or stem) + ".OBJ")
    if not os.path.isfile(obj):
        return {"status": "done", "exit_code": 1, "stdout": f"{source}(1): Error: no object\r\n"}
    shutil.copyfile(obj, os.path.join(c_root, cd or "", stem + ".OBJ"))
    return {"status": "done", "exit_code": 0, "stdout": ""}


@plugin.method("runner/run", capability_version=1)
def run(params, ctx):
    jobs = params["jobs"]
    append("requests.log", str(len(jobs)))
    c_root = {m["drive"]: m["path"] for m in params["mounts"]}["C"]
    marker = os.path.join(OBJECTS, "not-run.marker")
    cut = os.environ.get("FAKE_NOT_RUN_ONCE") == "1" and len(jobs) > 1 and not os.path.exists(marker)
    results = []
    for i, job in enumerate(jobs):
        if cut and i > 0:
            results.append({"status": "failed", "exit_code": None, "stdout": "",
                            "message": "job not run: an earlier job ended the batch"})
        else:
            results.append(run_job(job, c_root))
            ctx.progress(i + 1, len(jobs), f"job {i + 1} of {len(jobs)} done")
    if cut:
        open(marker, "w").close()
    return {"jobs": results}


plugin.serve()
