"""Where the Ghidra project lives and whether a saved one may be reused. Pure Python, no Ghidra imports.

The Ghidra project (`decovery.gpr`, `decovery.rep/`) sits in the project location next to `project.json`, which
records what it was built from. A project is reused only when `project.json` matches the requested key.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Mapping

from .export import write_atomic
from .hashing import blake3_hex

PROJECT_NAME = "decovery"
KEY_FILE = "project.json"
APPLIED_FILE = "applied.json"


def _has_dot_part(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts[1:])


def _cache_bases(env: Mapping[str, str], windows: bool) -> list[Path]:
    bases = []
    if windows and env.get("LOCALAPPDATA"):
        bases.append(Path(env["LOCALAPPDATA"]))
    if not windows and env.get("XDG_CACHE_HOME"):
        bases.append(Path(env["XDG_CACHE_HOME"]))
    # `~/.cache` has a leading dot itself, so it cannot serve; the temp dir is the last resort (as in Decomp)
    bases.append(Path(tempfile.gettempdir()))
    return [b.resolve() for b in bases]


def project_location(
    project_dir: str, env: Mapping[str, str] | None = None, windows: bool | None = None
) -> Path:
    """Absolute folder for the Ghidra project. Ghidra rejects paths with a component that starts with a dot
    (e.g. `.worktrees`); such a `project_dir` is replaced by `<cache base>/decovery/ghidra/<blake3 of the path>`,
    the cache base being `%LOCALAPPDATA%` on Windows and `$XDG_CACHE_HOME` elsewhere, else the temp dir."""
    env = os.environ if env is None else env
    windows = os.name == "nt" if windows is None else windows
    folder = Path(project_dir).resolve()
    if not _has_dot_part(folder):
        return folder
    key = str(folder).lower() if windows else str(folder)  # Windows paths are case-insensitive
    digest = blake3_hex(key.encode("utf-8"))
    bases = _cache_bases(env, windows)
    base = next((b for b in bases if not _has_dot_part(b)), bases[-1])
    return base / "decovery" / "ghidra" / digest


def project_key(program_hash: str, ghidra_version: str, calling_convention: str | None) -> dict:
    """What a saved project was built from; the calling convention is installed at import time."""
    return {
        "schema": 1,
        "program_hash": program_hash,
        "ghidra_version": ghidra_version,
        "calling_convention": calling_convention,
    }


def stored_key_matches(location: Path, key: dict) -> bool:
    try:
        stored = json.loads((location / KEY_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return stored == key


PROJECT_FILES = (
    f"{PROJECT_NAME}.gpr",
    f"{PROJECT_NAME}.rep",
    f"{PROJECT_NAME}.lock",
    f"{PROJECT_NAME}.lock~",
    KEY_FILE,
    APPLIED_FILE,
)


def reset_project(location: Path) -> None:
    """Delete a stale Ghidra project and its bookkeeping (exactly `PROJECT_FILES`); other files stay."""
    for name in PROJECT_FILES:
        entry = location / name
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        elif entry.exists() or entry.is_symlink():
            entry.unlink()


def save_key(location: Path, key: dict) -> None:
    write_atomic(location / KEY_FILE, (json.dumps(key, indent=2) + "\n").encode("utf-8"))
