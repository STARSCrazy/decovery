"""Export Decomp's view of an LE executable as JSON (reference data for decovery's LE loader).

Usage: PYTHONPATH=<Decomp>/src python le_golden.py <executable> <out.json>
The output is derived from the input file and must not be committed when the input is proprietary.
"""
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

from decomp.formate.le import lese_le, rohfixups


def main(exe: str, out: str) -> None:
    data = Path(exe).read_bytes()
    image = lese_le(data)
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
        "raw_fixups": [dataclasses.asdict(r) for r in rohfixups(data)],
    }
    Path(out).write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main(*sys.argv[1:3])
