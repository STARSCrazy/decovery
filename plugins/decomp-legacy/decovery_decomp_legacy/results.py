"""Where each operation leaves its result, and how it maps to `report`, `json`, `candidate` and `artifacts`.

Decomp's search steps write below `<shadow>/cache/nachbau/<step>/<function name>/` (`Dienst.nachbau_*`):
`beste.c` is a whole module file with the best version (only when it is better than the source; permutieren,
strahl, formen and plaetze delete it at their start, kette moves an old one aside), `ergebnis.txt` the report.
Only files written during this run count, so a result of an earlier run is never reported as this run's.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# operation -> folder below cache/nachbau
FOLDERS = {
    "chain": "kette",
    "permute": "permutieren",
    "beam": "strahl",
    "forms": "formen",
    "slots": "plaetze",
    "joint": "gemeinsam",
}
SEARCHES = frozenset({"chain", "permute", "beam", "forms"})
FRESH_SLACK_S = 2.0  # file time stamps are coarser than the clock on some file systems


def _fresh(path: Path, started: float) -> bool:
    try:
        return path.is_file() and path.stat().st_mtime >= started - FRESH_SLACK_S
    except OSError:
        return False


def _json_text(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def collect(operation: str, shadow: Path, name: str, stdout: str, started: float, json_path: Path | None) -> dict:
    """`{report, json, candidate, artifacts}` of a finished run. `started` is the wall-clock start (time.time())."""
    report: str = stdout
    data: Any = None
    candidate: dict | None = None
    artifacts: list[str] = []
    folder = shadow / "cache" / "nachbau" / FOLDERS[operation] / name if operation in FOLDERS else None

    if operation == "registers" and json_path is not None and json_path.is_file():
        data = _json_text(json_path.read_text(encoding="utf-8"))
        artifacts.append(str(json_path))
    elif operation == "joint":
        data = _json_text(stdout)
        if folder is not None and _fresh(folder / "ergebnis.txt", started):
            report = (folder / "ergebnis.txt").read_text(encoding="utf-8")
    elif operation == "equivalence":
        data = _json_text(stdout)
        if isinstance(data, dict) and isinstance(data.get("bericht"), str):
            report = data["bericht"]

    if folder is not None:
        for file in ("ergebnis.txt", "ergebnis.json", "stand.c", "beste.c"):
            if _fresh(folder / file, started):
                artifacts.append(str(folder / file))
        if operation == "chain" and _fresh(folder / "ergebnis.json", started):
            data = _json_text((folder / "ergebnis.json").read_text(encoding="utf-8"))
        if operation in SEARCHES and _fresh(folder / "beste.c", started):
            candidate = {"path": str(folder / "beste.c"), "kind": "module"}
    return {"report": report, "json": data, "candidate": candidate, "artifacts": artifacts}
