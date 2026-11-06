"""Throughput of the unicorn-dos job pool: compiles N synthetic C sources with Watcom 9.5 at 1, half and all logical
cores and prints jobs/s, busy cores and CPU utilisation per level.

    python tests/bench_pool.py <watcom-9.5 dir> [--jobs N] [--levels 1,8,16]

The Watcom directory defaults to `DECOVERY_TOOLCHAIN_WATCOM95`. Each level gets a fresh pool; "first" includes
starting the worker processes, "again" is a second request on the same pool (the steady state of a long-lived
plugin). Busy cores = CPU seconds of all jobs / wall seconds; utilisation = busy cores / workers. Not a unit test
(the file name keeps `unittest discover` away from it).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_unicorn_dos.batch import plan  # noqa: E402
from decovery_unicorn_dos.pool import JobPool, run_job  # noqa: E402

PRELUDE = ["SET WATCOM=D:\\", "SET INCLUDE=D:\\H", "SET PATH=D:\\BINW"]


def timed_job(job: dict) -> dict:
    """Worker: one job plus the CPU seconds it took in this process."""
    started = time.process_time()
    outcome = run_job(job)
    outcome["cpu_s"] = time.process_time() - started
    return outcome


def source(index: int) -> str:
    """A synthetic C file; sizes vary (4 to 40 functions) like the files of a real program."""
    count = 4 + (index * 7) % 37
    lines = ["typedef struct { int x, y, hp; char name[16]; } unit_t;", "static unit_t units[64];", ""]
    for f in range(count):
        lines += [
            f"int f{index}_{f}(int a, int b)",
            "{",
            "    int i, s = 0;",
            f"    for (i = 0; i < a; i++) {{ s += units[i & 63].hp * (b + {f}); if (s > {1000 + f}) s -= a; }}",
            f"    switch (b & 7) {{ case 0: s ^= {f}; break; case 1: s += units[b & 63].x; break;",
            "    case 2: s -= units[a & 63].y; break; default: s = s * 3 + b; }",
            "    return s;",
            "}",
            "",
        ]
    return "\r\n".join(lines) + "\r\n"


def make_jobs(build: Path, tools: Path, count: int) -> list[dict]:
    drives = {"C": build, "D": tools}
    jobs = []
    for i in range(count):
        name = f"S{i:05d}.C"
        text = source(i)
        (build / name).write_bytes(text.encode("cp437"))
        tmp = f"TMP{i:05d}"
        (build / tmp).mkdir()
        commands = PRELUDE + [f"SET TMP=C:\\{tmp}", f"WCC386 -zq -oaxt {name}"]
        jobs.append(
            {
                "drives": {k: str(v) for k, v in drives.items()},
                "read_only": ["D"],
                "current": "C",
                "timeout_s": 120.0,
                "steps": plan(commands, drives),
                "cost": len(text),
            }
        )
    return jobs


def measure(pool: JobPool, jobs: list[dict], parallel: int) -> dict:
    started = time.perf_counter()
    outcomes = pool.run(jobs, parallel=parallel)
    wall = time.perf_counter() - started
    failed = [o for o in outcomes if o["status"] != "done" or o["exit_code"] != 0]
    if failed:
        raise SystemExit(f"{len(failed)} compiles failed, first: {failed[0]}")
    cpu = sum(o["cpu_s"] for o in outcomes)
    return {"wall": wall, "jobs_s": len(jobs) / wall, "busy": cpu / wall, "util": cpu / wall / parallel}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("watcom", nargs="?", default=os.environ.get("DECOVERY_TOOLCHAIN_WATCOM95"))
    parser.add_argument("--jobs", type=int, default=64, help="number of sources (default 64)")
    parser.add_argument("--levels", help="comma-separated worker counts (default: 1, half, all cores)")
    args = parser.parse_args()
    if not args.watcom or not (Path(args.watcom) / "BINW" / "WCC386.EXE").is_file():
        raise SystemExit("pass the Watcom 9.5 directory (or set DECOVERY_TOOLCHAIN_WATCOM95)")
    cores = os.cpu_count() or 1
    levels = [int(x) for x in args.levels.split(",")] if args.levels else sorted({1, max(1, cores // 2), cores})
    print(f"{args.jobs} synthetic sources, {cores} logical cores")
    print(f"{'workers':>7} | {'first: wall s':>13} {'jobs/s':>7} | {'again: wall s':>13} {'jobs/s':>7} "
          f"{'busy cores':>10} {'util':>5}")
    for level in levels:
        with tempfile.TemporaryDirectory() as tmp:
            build = Path(tmp) / "build"
            build.mkdir()
            jobs = make_jobs(build, Path(args.watcom), args.jobs)
            pool = JobPool(workers=level, worker=timed_job)
            try:
                first = measure(pool, jobs, level)
                for path in build.glob("*.OBJ"):
                    path.unlink()
                again = measure(pool, jobs, level)
            finally:
                pool.close()
            shutil.rmtree(build, ignore_errors=True)
        print(f"{level:>7} | {first['wall']:>13.2f} {first['jobs_s']:>7.1f} | {again['wall']:>13.2f} "
              f"{again['jobs_s']:>7.1f} {again['busy']:>10.1f} {again['util']:>5.0%}")


if __name__ == "__main__":
    main()
