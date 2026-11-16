"""Minimal TOML writer for arrays of tables with scalar and list values (enough for the fake's files)."""


def _wert(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_wert(x) for x in v) + "]"
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def tabellen(name, eintraege, kopf=""):
    out = [kopf] if kopf else []
    for e in eintraege:
        out.append(f"[[{name}]]")
        out += [f"{k} = {_wert(v)}" for k, v in e.items() if v is not None]
        out.append("")
    return "\n".join(out)
