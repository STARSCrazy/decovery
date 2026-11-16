import re
from dataclasses import dataclass

_VA = re.compile(r"^va:([0-9A-Fa-f]{1,8})$")
_REL = re.compile(r"^rel:([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4})$")


class AdressFehler(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Adresse:
    raum: str
    seg: int
    wert: int

    def __str__(self):
        return f"va:{self.wert:08X}" if self.raum == "va" else f"rel:{self.seg:04X}:{self.wert:04X}"


def parse(text):
    if m := _VA.match(text.strip()):
        return Adresse("va", 0, int(m[1], 16))
    if m := _REL.match(text.strip()):
        return Adresse("rel", int(m[1], 16), int(m[2], 16))
    raise AdressFehler(text)
