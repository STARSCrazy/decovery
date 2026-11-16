import tomllib
from dataclasses import dataclass
from pathlib import Path

from ..adressen import parse
from ..toml_schreiben import tabellen


@dataclass(frozen=True)
class Eintrag:
    adresse: object
    name: str
    datei: str
    ergebnis: str = "abweichend"


def laden(wissen_dir):
    p = Path(wissen_dir) / "nachbau.toml"
    if not p.exists():
        return {}
    erg = {}
    for d in tomllib.loads(p.read_text(encoding="utf-8")).get("funktion", []):
        e = Eintrag(parse(d["adresse"]), d["name"], d["datei"], d.get("ergebnis", "abweichend"))
        erg[e.adresse] = e
    return erg


def speichern(eintraege, wissen_dir):
    liste = [{"adresse": str(e.adresse), "name": e.name, "datei": e.datei, "ergebnis": e.ergebnis}
             for _, e in sorted(eintraege.items())]
    (Path(wissen_dir) / "nachbau.toml").write_text(tabellen("funktion", liste), encoding="utf-8")
