"""Fake `runner` plugin for the build tests.

For a job whose last command line ends with `X.C` (any extension) it copies `X.OBJ` from the directory in
FAKE_OMF_DIR into the C mount (after a `CD D` line: `D.OBJ` into the directory D of the C mount, as `X.OBJ`) and exits 0; without that file it prints an error and exits 1. Every compiled job
appends its source name to `calls.log` and its `SET TMP=` directory (and whether it exists) to `tmp.log`, every
call appends its job count to `requests.log` (all in FAKE_OMF_DIR). The staged source of every job is copied to
`sources/<D>/<X.C>` (`sources/<X.C>` without a `CD` line) in FAKE_OMF_DIR.

A job whose last command runs TLINK is a link job: its command line is appended to `link.log`, it fails when an
object of the line is missing in the C mount, else copies `REBUILD.EXE` from FAKE_OMF_DIR into the C mount (exit 0)
or, without that file, prints a linker error and exits 2.

A job whose last command runs WLINK is an LE link job: its command line goes to `link.log`, the files it links
(`NB.OBJ`, `NB.LNK`, `STUB.EXE`) are copied to `linked/` in FAKE_OMF_DIR, and `REBUILD.EXE` from FAKE_OMF_DIR is
copied into the C mount as the program `NB.LNK` names (exit 0); without it the job prints an error and exits 1.

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


def link_job(job, c_root):
    line = job["commands"][-1]
    append("link.log", line)
    objects = [t for t in line.split(",")[0].split()[1:] if "\\" not in t and not t.startswith("/")]
    missing = [o for o in objects if not os.path.isfile(os.path.join(c_root, o + ".OBJ"))]
    if missing:
        return {"status": "done", "exit_code": 2, "stdout": f"Fatal: unable to open {missing[0]}.OBJ\r\n"}
    exe = os.path.join(OBJECTS, "REBUILD.EXE")
    if not os.path.isfile(exe):
        return {"status": "done", "exit_code": 2, "stdout": "Error: Undefined symbol _main in module C0S\r\n"}
    shutil.copyfile(exe, os.path.join(c_root, "REBUILD.EXE"))
    return {"status": "done", "exit_code": 0, "stdout": "Turbo Link Version 2.0\r\n"}


def wlink_job(job, c_root):
    append("link.log", job["commands"][-1])
    kept = os.path.join(OBJECTS, "linked")
    os.makedirs(kept, exist_ok=True)
    for name in ("NB.OBJ", "NB.LNK", "STUB.EXE"):
        shutil.copyfile(os.path.join(c_root, name), os.path.join(kept, name))
    with open(os.path.join(c_root, "NB.LNK"), encoding="ascii") as f:
        output = next(line.split()[1] for line in f if line.startswith("name "))
    exe = os.path.join(OBJECTS, "REBUILD.EXE")
    if not os.path.isfile(exe):
        return {"status": "done", "exit_code": 1, "stdout": "Error! E2028: _cstart_ is an undefined reference\r\n"}
    shutil.copyfile(exe, os.path.join(c_root, output.upper()))
    return {"status": "done", "exit_code": 0, "stdout": "WATCOM Linker Version 9.5\r\n"}


def run_job(job, c_root):
    if "WLINK" in job["commands"][-1].split()[0].upper():
        return wlink_job(job, c_root)
    if "TLINK" in job["commands"][-1].split()[0].upper():
        return link_job(job, c_root)
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
