"""The shadow workspace (ADR 0007, decision 2): a Decomp workspace in decovery's cache that Decomp runs on, so the
source workspace is never written.

Layout of `<shadow>`:
- `decomp.toml` copied (relative `datei = "..."` paths made absolute against the source workspace);
- `wissen/` copied file by file when the source file changed (tracked in `cache/legacy-shadow.json`); files that
  vanished from the source are removed again;
- Decomp's Ghidra project copied once, again only when the source's `meta.json` differs from the shadow's;
- `cache/laufzeit` linked (junction on Windows, symlink elsewhere) to the source's recordings;
- `nachbau/` mirrored from decovery's sources (only `SOURCE_EXTENSIONS`, by content: unchanged files keep their
  time stamps, so Decomp's caches stay valid);
- `cache/nachbau/` and everything else under `cache/` belong to Decomp runs on the shadow.

Nothing here writes below the source workspace or the sources directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .params import SOURCE_EXTENSIONS

STATE_FILE = "legacy-shadow.json"  # in <shadow>/cache
STATE_SCHEMA = 1
_GHIDRA_SKIP = ("*.lock", "*.lock~", "*.ulock")  # a running Decomp server holds these in the source project
_DATEI = re.compile(r'^(\s*datei\s*=\s*)"([^"\\]*)"(.*)$')


@dataclass
class RefreshResult:
    changed: int = 0  # files copied, written or removed (Ghidra project not counted)
    ghidra_copied: bool = False

    @property
    def refreshed(self) -> bool:
        return self.changed > 0 or self.ghidra_copied


def ghidra_project_dir(cache_dir: Path) -> Path:
    """Where Decomp keeps the Ghidra project of a workspace whose cache is `cache_dir`: `cache/ghidra`, or, when a
    path component starts with a dot (Ghidra refuses those), `%LOCALAPPDATA%/decomp/ghidra/<sha256 of the path>`.
    Mirrors `decomp.engine.ghidra.engine.GhidraEngine._projektordner`."""
    folder = (Path(cache_dir) / "ghidra").resolve()
    if not any(part.startswith(".") for part in folder.parts[1:]):
        return folder
    base = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "decomp" / "ghidra"
    return base / hashlib.sha256(str(folder).lower().encode("utf-8")).hexdigest()[:16]


def _signature(path: Path) -> list[int]:
    st = path.stat()
    return [st.st_size, st.st_mtime_ns]


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(path))


def _write_if_different(path: Path, data: bytes) -> bool:
    try:
        if path.read_bytes() == data:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".legacy-tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    return True


def _decomp_toml(source: Path) -> bytes:
    """The source's decomp.toml with relative `datei` paths made absolute (the shadow lives elsewhere)."""
    text = (source / "decomp.toml").read_text(encoding="utf-8")
    lines = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        end = line[len(body):]
        m = _DATEI.match(body)
        if m and not Path(m[2]).is_absolute():
            body = f'{m[1]}"{(source / m[2]).resolve().as_posix()}"{m[3]}'
        lines.append(body + end)
    return "".join(lines).encode("utf-8")


def _files(root: Path, extensions: frozenset[str] | None = None) -> dict[str, Path]:
    """Relative POSIX path -> file below `root`, not following links."""
    out: dict[str, Path] = {}
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not _is_link(here / d)]
        for name in filenames:
            path = here / name
            if extensions is not None and path.suffix.lower() not in extensions:
                continue
            out[path.relative_to(root).as_posix()] = path
    return out


def _remove_empty_dirs(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        here = Path(dirpath)
        if here != root and not dirnames and not filenames and not _is_link(here):
            try:
                here.rmdir()
            except OSError:
                pass


def mirror_sources(sources: Path, target: Path) -> int:
    """Make the `SOURCE_EXTENSIONS` files below `target` equal to those below `sources`; returns the files changed."""
    changed = 0
    wanted = _files(sources, SOURCE_EXTENSIONS)
    for rel, path in wanted.items():
        dest = target / rel
        try:
            same = dest.stat().st_size == path.stat().st_size and dest.read_bytes() == path.read_bytes()
        except OSError:
            same = False
        if not same:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            changed += 1
    for rel, path in _files(target, SOURCE_EXTENSIONS).items():
        if rel not in wanted:
            path.unlink()
            changed += 1
    _remove_empty_dirs(target)
    return changed


def _copy_tree_tracked(source: Path, target: Path, known: dict[str, list[int]]) -> int:
    """Copy the files of `source` whose signature differs from `known` (updated in place); remove the copies of
    files that vanished from the source. Files the shadow made itself are left alone."""
    changed = 0
    current = _files(source)
    for rel, path in current.items():
        sig = _signature(path)
        dest = target / rel
        if known.get(rel) != sig or not dest.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            known[rel] = sig
            changed += 1
    for rel in [r for r in known if r not in current]:
        (target / rel).unlink(missing_ok=True)
        del known[rel]
        changed += 1
    return changed


def _load_state(shadow: Path) -> dict:
    try:
        state = json.loads((shadow / "cache" / STATE_FILE).read_text(encoding="utf-8"))
        if state.get("schema") == STATE_SCHEMA:
            return state
    except (OSError, ValueError, AttributeError):
        pass
    return {"schema": STATE_SCHEMA}


def load_state(shadow: Path) -> dict:
    return _load_state(shadow)


def function_file(shadow: Path, function: str) -> str | None:
    """The source file Decomp built `function` (Decomp address) from, per the shadow's `wissen/nachbau.toml`."""
    try:
        data = tomllib.loads((shadow / "wissen" / "nachbau.toml").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for entry in data.get("funktion", []):
        if isinstance(entry, dict) and entry.get("adresse") == function and isinstance(entry.get("datei"), str):
            return entry["datei"]
    return None


def build_fingerprint(shadow: Path) -> str:
    """Hash of what a Decomp build of the shadow depends on: `decomp.toml` and every file under `nachbau/`."""
    digest = hashlib.sha256()
    files = [shadow / "decomp.toml"]
    root = shadow / "nachbau"
    if root.is_dir():
        files += sorted(p for p in root.rglob("*") if p.is_file())
    for path in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        digest.update(path.relative_to(shadow).as_posix().encode("utf-8") + b"\0")
        digest.update(len(data).to_bytes(8, "little") + data)
    return digest.hexdigest()


def save_state(shadow: Path, state: dict) -> None:
    _write_if_different(shadow / "cache" / STATE_FILE, json.dumps(state, indent=1, sort_keys=True).encode("utf-8"))


def ghidra_needs_copy(source: Path, shadow: Path) -> bool:
    """True when the source has a Ghidra project whose meta.json differs from the shadow's (or the shadow has none)."""
    src_meta = ghidra_project_dir(source / "cache") / "meta.json"
    if not src_meta.is_file():
        return False
    dst_meta = ghidra_project_dir(shadow / "cache") / "meta.json"
    try:
        return json.loads(src_meta.read_text(encoding="utf-8")) != json.loads(dst_meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True


def copy_ghidra(source: Path, shadow: Path) -> None:
    """Replace the shadow's Ghidra project with a copy of the source's (lock files left out)."""
    src = ghidra_project_dir(source / "cache")
    dst = ghidra_project_dir(shadow / "cache")
    if _is_link(dst):
        raise OSError(f"refusing to replace a link: {dst}")
    tmp = dst.with_name(dst.name + ".legacy-copy")
    if tmp.exists():
        shutil.rmtree(tmp)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, tmp, ignore=shutil.ignore_patterns(*_GHIDRA_SKIP))
    if dst.exists():
        shutil.rmtree(dst)
    os.replace(tmp, dst)


def make_link(link: Path, target: Path) -> bool:
    """Directory junction (Windows) or symlink `link` -> `target`; True when it was (re)created."""
    if _is_link(link):
        try:
            if Path(os.path.realpath(link)) == Path(os.path.realpath(target)):
                return False
        except OSError:
            pass
        os.unlink(link) if link.is_symlink() else os.rmdir(link)  # removes the link only, never the target
    elif link.exists():
        raise OSError(f"{link} exists and is not a link; remove it to link the recordings")
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target.resolve()), str(link))
    else:
        os.symlink(target.resolve(), link, target_is_directory=True)
    return True


def refresh(source: Path, shadow: Path, sources: Path, copy_ghidra_now: bool) -> tuple[RefreshResult, dict]:
    """Bring the shadow up to date (except names, see `names.py`). `copy_ghidra_now`: the caller decided the Ghidra
    project must be copied (`ghidra_needs_copy`) and made sure no Decomp server holds the shadow's project.
    Returns the result and the shadow state (the caller adds its own entries and saves it)."""
    result = RefreshResult()
    shadow.mkdir(parents=True, exist_ok=True)
    state = _load_state(shadow)
    if _write_if_different(shadow / "decomp.toml", _decomp_toml(source)):
        result.changed += 1
    known = state.setdefault("wissen", {})
    result.changed += _copy_tree_tracked(source / "wissen", shadow / "wissen", known)
    unpacked = source / "cache" / "entpackt.exe"
    if unpacked.is_file():
        known_cache = state.setdefault("cache_files", {})
        sig = _signature(unpacked)
        if known_cache.get("entpackt.exe") != sig:
            (shadow / "cache").mkdir(parents=True, exist_ok=True)
            shutil.copy2(unpacked, shadow / "cache" / "entpackt.exe")
            known_cache["entpackt.exe"] = sig
            result.changed += 1
    recordings = source / "cache" / "laufzeit"
    if recordings.is_dir() and make_link(shadow / "cache" / "laufzeit", recordings):
        result.changed += 1
    if copy_ghidra_now:
        copy_ghidra(source, shadow)
        result.ghidra_copied = True
    result.changed += mirror_sources(sources, shadow / "nachbau")
    return result, state
