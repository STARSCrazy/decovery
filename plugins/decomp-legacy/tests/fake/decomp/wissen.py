import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .adressen import parse
from .toml_schreiben import tabellen

_FELDER = ("name", "signatur", "kommentar", "quelle", "sicherheit", "widerlegt")


@dataclass
class Symbol:
    adresse: object
    art: str = "funktion"
    name: str | None = None
    quelle: str = "mensch"
    sicherheit: str = "vermutet"
    signatur: str | None = None
    kommentar: str | None = None
    widerlegt: str | None = None
    widerlegt_frueher: list = field(default_factory=list)


class Wissen:
    def __init__(self):
        self.symbole = {}


def laden(ordner):
    w = Wissen()
    p = Path(ordner) / "symbole.toml"
    if p.exists():
        for d in tomllib.loads(p.read_text(encoding="utf-8")).get("symbol", []):
            s = Symbol(parse(d["adresse"]), d.get("art", "funktion"), **{k: d.get(k) for k in _FELDER
                       if k not in ("quelle", "sicherheit")}, quelle=d.get("quelle", "mensch"),
                       sicherheit=d.get("sicherheit", "vermutet"), widerlegt_frueher=d.get("widerlegt_frueher", []))
            w.symbole[s.adresse] = s
    return w


def speichern(w, ordner):
    eintraege = []
    for s in sorted(w.symbole.values(), key=lambda s: s.adresse):
        d = {"adresse": str(s.adresse), "art": s.art}
        d.update({k: getattr(s, k) for k in _FELDER})
        if s.widerlegt_frueher:
            d["widerlegt_frueher"] = list(s.widerlegt_frueher)
        eintraege.append(d)
    (Path(ordner) / "symbole.toml").write_text(tabellen("symbol", eintraege, "# Decomp-Wissen: Symbole.\n"),
                                               encoding="utf-8")
