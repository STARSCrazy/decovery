"""Parameters of `legacy/run`: validation, address conversion and the fixed command map (ADR 0007, decision 4)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from decovery_plugin import RpcError

INVALID_PARAMS = -32602
WORKSPACE_INVALID = -32021

# operation -> Decomp `nachbau` subcommand
COMMANDS = {
    "context": "kontext",
    "structure": "struktur",
    "registers": "vergabe",
    "slots": "plaetze",
    "joint": "gemeinsam",
    "chain": "kette",
    "permute": "permutieren",
    "beam": "strahl",
    "forms": "formen",
    "equivalence": "gleichwertig",
    "behavior": "verhalten",
}

# option -> (operations that take it, Decomp flag). `forms` has no `--minuten` and `joint` no `--datei` in Decomp,
# so they are not offered there (ADR 0007, options table).
OPTIONS: dict[str, tuple[frozenset[str], str]] = {
    "minutes": (frozenset({"chain", "permute", "beam", "slots", "equivalence"}), "--minuten"),
    "rounds": (frozenset({"chain", "permute", "beam", "forms"}), "--runden"),
    "source": (frozenset({"registers", "slots", "structure", "permute"}), "--datei"),
    "all": (frozenset({"registers"}), "--alle"),
    "run": (frozenset({"behavior"}), "--lauf"),
}

KINDS = {"function": "funktion", "global": "variable", "label": "label"}
SOURCE_EXTENSIONS = frozenset({".c", ".h", ".asm", ".s", ".inc"})

_FLAT = re.compile(r"flat:([0-9A-Fa-f]{1,8})")
_SEG = re.compile(r"seg:([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4})")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RUN_NAME = re.compile(r"[A-Za-z0-9_.-]+")


def bad(message: str) -> RpcError:
    return RpcError(INVALID_PARAMS, message)


def decomp_address(address: Any) -> str:
    """decovery address -> Decomp normal form: `flat:0001A2B0` -> `va:0001A2B0`, `seg:SSSS:OOOO` -> `rel:SSSS:OOOO`."""
    if isinstance(address, str):
        if m := _FLAT.fullmatch(address):
            return f"va:{int(m[1], 16):08X}"
        if m := _SEG.fullmatch(address):
            return f"rel:{int(m[1], 16):04X}:{int(m[2], 16):04X}"
    raise bad(f"not a decovery address (flat:XXXXXXXX or seg:SSSS:OOOO): {address!r}")


def default_name(address: str) -> str:
    """Decomp's name of a function without a knowledge name (`fun_0001A2B0`, `fun_1234_0010`)."""
    return "fun_" + address.split(":", 1)[1].replace(":", "_")


@dataclass(frozen=True)
class Symbol:
    address: str  # Decomp form
    kind: str  # decovery kind
    name: str


@dataclass
class Run:
    decomp_workspace: Path
    shadow_dir: Path
    sources_dir: Path
    symbols: list[Symbol]
    operation: str
    function: str  # Decomp form
    options: dict[str, Any] = field(default_factory=dict)
    timeout_s: float | None = None

    def command(self, json_path: Path | None) -> list[str]:
        """Arguments after `python -m decomp --bereich <shadow>`."""
        args = ["nachbau", COMMANDS[self.operation], self.function]
        if self.operation == "registers":
            assert json_path is not None
            args += ["--json", str(json_path)]
        elif self.operation in ("joint", "equivalence"):
            args.append("--json")
        for option, value in self.options.items():
            flag = OPTIONS[option][1]
            if option == "all":
                if value:
                    args.append(flag)
            elif option == "minutes":
                args += [flag, f"{value:g}" if isinstance(value, float) else str(value)]
            else:
                args += [flag, str(value)]
        return args


def _path(params: dict, key: str) -> Path:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise bad(f"'{key}' must be a non-empty path string")
    path = Path(value)
    if not path.is_absolute():
        raise bad(f"'{key}' must be an absolute path: {value}")
    return path


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _options(operation: str, raw: Any, sources_dir: Path) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise bad("'options' must be an object")
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in OPTIONS:
            raise bad(f"unknown option {key!r} (known: {', '.join(sorted(OPTIONS))})")
        if operation not in OPTIONS[key][0]:
            raise bad(f"option {key!r} does not apply to operation {operation!r}")
        if key == "minutes":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise bad("'minutes' must be a positive number")
        elif key == "rounds":
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise bad("'rounds' must be a positive integer")
        elif key == "all":
            if not isinstance(value, bool):
                raise bad("'all' must be a boolean")
        elif key == "run":
            if not isinstance(value, str) or not _RUN_NAME.fullmatch(value):
                raise bad("'run' must be a run name (letters, digits, '_', '-', '.')")
        elif key == "source":
            if not isinstance(value, str) or not value:
                raise bad("'source' must be a path")
            path = Path(value)
            if not path.is_absolute():
                path = sources_dir / path
            if not path.is_file():
                raise bad(f"'source' is not a file: {path}")
            value = str(path)
        out[key] = value
    return out


def _symbols(raw: Any) -> list[Symbol]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise bad("'symbols' must be an array")
    out = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise bad(f"'symbols[{i}]' must be an object")
        kind = entry.get("kind")
        if kind not in KINDS:
            raise bad(f"'symbols[{i}].kind' must be one of {', '.join(KINDS)}")
        name = entry.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise bad(f"'symbols[{i}].name' must be a C identifier: {name!r}")
        out.append(Symbol(decomp_address(entry.get("address")), kind, name))
    return out


def parse_run(params: Any) -> Run:
    if not isinstance(params, dict):
        raise bad("params must be an object")
    operation = params.get("operation")
    if operation not in COMMANDS:
        raise bad(f"unknown operation {operation!r} (known: {', '.join(COMMANDS)})")
    workspace = _path(params, "decomp_workspace")
    shadow = _path(params, "shadow_dir")
    sources = _path(params, "sources_dir")
    if not sources.is_dir():
        raise bad(f"'sources_dir' is not a directory: {sources}")
    function = decomp_address(params.get("function"))
    timeout = params.get("timeout_s")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0):
        raise bad("'timeout_s' must be a positive number")
    symbols = _symbols(params.get("symbols"))
    options = _options(operation, params.get("options"), sources)
    if not (workspace / "decomp.toml").is_file():
        raise RpcError(WORKSPACE_INVALID, f"not a Decomp workspace (no decomp.toml): {workspace}")
    for other, key in ((workspace, "decomp_workspace"), (sources, "sources_dir")):
        if _inside(shadow, other) or _inside(other, shadow):
            raise bad(f"'shadow_dir' must not overlap '{key}': {shadow}")
    return Run(workspace, shadow, sources, symbols, operation, function, options, timeout)
