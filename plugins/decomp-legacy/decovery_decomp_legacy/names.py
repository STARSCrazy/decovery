"""decovery's names in the shadow's knowledge (ADR 0007, decision 2).

Written through Decomp's own API (`decomp.wissen`, `decomp.nachbau.ergebnis`), so the files keep Decomp's format.
The shadow is decovery's copy, so decovery's name wins without Decomp's precedence check (`Wissen.setze` would
refuse to replace a `mensch` name with a weaker one): the symbol is replaced directly with `quelle = "import"`, the
source Decomp uses for names taken from another tool. A different address that holds one of decovery's names loses
that name, so every name stays unique. `wissen/nachbau.toml` records the name each rebuilt function had at its
last build, and Decomp looks the function up in the source by that name, so it is renamed there too.

Reading the name Decomp uses for a function's result folders (`result_name`) needs no Decomp import.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import replace
from pathlib import Path

from .params import KINDS, Symbol, default_name


def symbols_key(symbols: list[Symbol]) -> str:
    """The wanted names as a stable text."""
    return json.dumps([[s.address, s.kind, s.name] for s in symbols])


def fingerprint(symbols: list[Symbol], wissen_dir: Path) -> str:
    """Changes when the wanted names or the shadow's knowledge files change."""
    h = hashlib.sha256(json.dumps([[s.address, s.kind, s.name] for s in symbols]).encode("utf-8"))
    for name in ("symbole.toml", "nachbau.toml"):
        try:
            st = (wissen_dir / name).stat()
            h.update(f"{name}:{st.st_size}:{st.st_mtime_ns}".encode())
        except OSError:
            h.update(f"{name}:-".encode())
    return h.hexdigest()


def write_names(wissen_dir: Path, symbols: list[Symbol]) -> int:
    """Put `symbols` into the shadow's `symbole.toml` and `nachbau.toml`; returns the entries changed."""
    if not symbols:
        return 0
    from decomp import wissen as W
    from decomp.adressen import parse
    from decomp.nachbau import ergebnis as E

    wanted = {parse(s.address): s for s in symbols}  # a later entry for the same address wins
    names = {s.name for s in wanted.values()}
    w = W.laden(wissen_dir)
    changed = 0
    for adr, sym in list(w.symbole.items()):
        if adr not in wanted and sym.name in names and not sym.widerlegt:
            w.symbole[adr] = replace(sym, name=None)
            changed += 1
    for adr, s in wanted.items():
        old = w.symbole.get(adr)
        if old is None:
            w.symbole[adr] = W.Symbol(adresse=adr, art=KINDS[s.kind], name=s.name, quelle="import")
            changed += 1
        elif old.name != s.name or old.widerlegt:
            earlier = list(old.widerlegt_frueher)
            if old.widerlegt:
                earlier.append(f"{old.name or ''}: {old.widerlegt}")
            w.symbole[adr] = replace(old, name=s.name, quelle="import", widerlegt=None, widerlegt_frueher=earlier)
            changed += 1
    if changed:
        W.speichern(w, wissen_dir)
    entries = E.laden(wissen_dir)
    renamed = 0
    for adr, entry in list(entries.items()):
        s = wanted.get(adr)
        if s is not None and s.kind == "function" and entry.name != s.name:
            entries[adr] = replace(entry, name=s.name)
            renamed += 1
    if renamed:
        E.speichern(entries, wissen_dir)
    return changed + renamed


def _toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def result_name(wissen_dir: Path, address: str) -> str:
    """The name Decomp uses for the function's folders under `cache/nachbau/<step>/` (`Dienst.nachbau_*`: the name
    of its `nachbau.toml` entry, else its knowledge name, else `fun_<address>`)."""
    for entry in _toml(wissen_dir / "nachbau.toml").get("funktion", []):
        if entry.get("adresse") == address and entry.get("name"):
            return entry["name"]
    for entry in _toml(wissen_dir / "symbole.toml").get("symbol", []):
        if entry.get("adresse") == address and entry.get("name") and not entry.get("widerlegt"):
            return entry["name"]
    return default_name(address)
