#!/usr/bin/env python3
"""Freeze Decomp's rebuild verdicts of a workspace as a private parity baseline (phase 4, decision 6).

Reads the function export Decomp writes (`ausgabe/funktionen/**/*.c`, header lines `@adresse` and `@nachbau`) of
the Decomp workspace in DECOVERY_DECOMP_WORKSPACE and writes
`$DECOVERY_GOLDEN_DIR/aztec/baseline-<date>.json`:

    {"date": ..., "workspace": ..., "counts": {...}, "functions": {address: verdict}, "names": {address: name}}

Verdicts are Decomp's words (`identisch`, `abweichend`, `fehler`, `nicht-versucht`). The output holds addresses of a
private target: it never goes into the repository. Standard library only. An existing baseline of the same date is
not overwritten (pass --force).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ADDRESS = re.compile(r"^\s*\*?\s*/?\*?\s*@adresse\s+(\S+)")
REBUILD = re.compile(r"^\s*\*\s*@nachbau\s+(.*)$")
NAME = re.compile(r"^\s*\*\s*@name\s+(\S+)")


def verdict_of(text: str) -> str:
    word = text.split()[0] if text.split() else ""
    if word == "nicht":
        return "nicht-versucht"
    return word


def read_function(path: Path) -> tuple[str, str, str | None] | None:
    address = verdict = name = None
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if address is None and (m := ADDRESS.match(line)):
                address = m.group(1)
            elif m := NAME.match(line):
                name = m.group(1)
            elif m := REBUILD.match(line):
                verdict = verdict_of(m.group(1))
            if line.strip().startswith("*/"):
                break
    if address is None:
        return None
    return address, verdict or "nicht-versucht", name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="overwrite a baseline of the same date")
    args = parser.parse_args()
    try:
        workspace = Path(os.environ["DECOVERY_DECOMP_WORKSPACE"])
        golden = Path(os.environ["DECOVERY_GOLDEN_DIR"])
    except KeyError as e:
        print(f"set {e.args[0]}", file=sys.stderr)
        return 2
    export = workspace / "ausgabe" / "funktionen"
    if not export.is_dir():
        print(f"no function export in {export}", file=sys.stderr)
        return 2
    functions: dict[str, str] = {}
    names: dict[str, str] = {}
    for path in sorted(export.rglob("*.c")):
        entry = read_function(path)
        if entry is None:
            print(f"warning: no @adresse in {path}", file=sys.stderr)
            continue
        functions[entry[0]] = entry[1]
        if entry[2]:
            names[entry[0]] = entry[2]
    date = datetime.date.today().isoformat()
    out = golden / "aztec" / f"baseline-{date}.json"
    if out.exists() and not args.force:
        print(f"{out} exists (frozen); pass --force to replace it", file=sys.stderr)
        return 1
    main_program = {a: v for a, v in functions.items() if not a.startswith("ovl:")}
    counts = {
        "all": dict(Counter(functions.values())),
        "main_program": dict(Counter(main_program.values())),
        "functions": len(functions),
        "main_program_functions": len(main_program),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"date": date, "workspace": str(workspace), "counts": counts,
                               "functions": functions,
                               "names": names}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{out}: {json.dumps(counts, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
