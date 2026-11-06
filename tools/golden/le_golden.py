"""Export Decomp's view of an LE executable as JSON (reference data for decovery's LE loader).

Usage: PYTHONPATH=<Decomp>/src python le_golden.py <executable> <out.json>
The output is derived from the input file and must not be committed when the input is proprietary.
"""
import hashlib
import json
import sys
from pathlib import Path

# Decomp's own names (its API is German); aliased so this script's identifiers stay English.
from decomp.formate.le import lese_le as read_le_image, rohfixups as raw_fixups


def raw_fixup_json(raw) -> dict:
    """One raw fixup record under English keys (the attributes are Decomp's `RohFixup` fields)."""
    return {
        "page": raw.seite, "object": raw.objekt, "offset": raw.offset, "kind": raw.art,
        "target_object": raw.ziel_objekt, "target_offset": raw.ziel_offset,
        "short_target": raw.kurz, "length": raw.laenge,
    }


def main(exe: str, out: str) -> None:
    data = Path(exe).read_bytes()
    image = read_le_image(data)
    result = {
        "entry": image.einsprung,
        "stack": image.stapel,
        "warnings": list(image.warnungen),
        "objects": [
            {
                "number": o.nummer, "base": o.basis, "size": o.groesse, "flags": o.flags,
                "data_len": len(o.bytes), "data_sha256": hashlib.sha256(o.bytes).hexdigest(),
                "file_offset": o.datei_offset, "file_length": o.datei_laenge,
            }
            for o in image.objekte
        ],
        "fixups": [[f.adresse, f.art, f.wert] for f in image.fixups],
        "raw_fixups": [raw_fixup_json(r) for r in raw_fixups(data)],
    }
    Path(out).write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main(*sys.argv[1:3])
