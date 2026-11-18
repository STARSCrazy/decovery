"""Run a command and measure how busy the machine's cores are while it runs.

Usage: python tools/measure/busy_cores.py [--interval-ms N] [--stdout FILE] -- <command...>

Samples machine-wide busy time every 250 ms with GetSystemTimes (Windows, ctypes) and prints one JSON object to
stdout: wall seconds, busy CPU seconds of the whole machine (kernel + user - idle, all cores), average and peak
busy cores, the number of logical cores, the busy share (average / logical cores) and the command's exit code. The command's own stdout goes to `--stdout`
(default: discarded) and its stderr passes through.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes


class _FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    def ticks(self) -> int:
        return (self.high << 32) | self.low


def _system_times() -> tuple[int, int]:
    """(busy, total) in 100 ns ticks summed over all logical cores."""
    idle, kernel, user = _FileTime(), _FileTime(), _FileTime()
    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        raise OSError("GetSystemTimes failed")
    total = kernel.ticks() + user.ticks()  # kernel time includes idle time
    return total - idle.ticks(), total


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--interval-ms", type=int, default=250)
    parser.add_argument("--stdout", help="file for the command's stdout")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("no command given")
    if os.name != "nt":
        parser.error("busy_cores.py needs Windows (GetSystemTimes)")

    cores = os.cpu_count() or 1
    samples: list[float] = []
    done = threading.Event()

    def sample() -> None:
        busy0, total0 = _system_times()
        while not done.wait(args.interval_ms / 1000):
            busy1, total1 = _system_times()
            if total1 > total0:
                samples.append(cores * (busy1 - busy0) / (total1 - total0))
            busy0, total0 = busy1, total1

    out = open(args.stdout, "wb") if args.stdout else subprocess.DEVNULL
    busy_start, _ = _system_times()
    started = time.perf_counter()
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    try:
        code = subprocess.call(command, stdout=out)
    finally:
        wall = time.perf_counter() - started
        busy_end, _ = _system_times()
        done.set()
        sampler.join()
        if args.stdout:
            out.close()

    cpu = (busy_end - busy_start) / 1e7
    result = {
        "exit_code": code,
        "wall_s": round(wall, 3),
        "cpu_s": round(cpu, 2),
        "busy_cores_avg": round(cpu / wall, 2) if wall > 0 else 0.0,
        "busy_cores_peak": round(max(samples), 2) if samples else 0.0,
        "logical_cores": cores,
        "busy_share": round(cpu / wall / cores, 3) if wall > 0 else 0.0,
        "samples": len(samples),
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
