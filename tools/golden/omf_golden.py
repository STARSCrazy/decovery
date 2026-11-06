"""Export Decomp's view of OMF object files as JSON (reference data for decovery's OMF reader).

Usage: PYTHONPATH=<Decomp>/src python omf_golden.py <out_dir> <file.obj>...
The output is derived from the inputs and must not be committed when they are proprietary.
"""
import json
import sys
from pathlib import Path

# Decomp's own name (its API is German); aliased so this script's identifiers stay English.
from decomp.signaturen.omf import lies_datei as read_omf_file


def main(out_dir: str, *files: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for f in files:
        read = read_omf_file(f)
        result = {
            "bits": read.bits,
            "unknown_records": {f"{k:02X}": v for k, v in sorted(read.unbekannt.items())},
            "functions": [
                {
                    "name": fn.name, "origin": fn.herkunft, "start": fn.start, "code": fn.bytes.hex(),
                    "gaps": sorted(fn.luecken), "references": [list(v) for v in fn.verweise],
                    "relative": sorted(fn.relativ), "addends": [list(z) for z in fn.zusaetze],
                }
                for fn in read.funktionen
            ],
        }
        (out / (Path(f).stem + ".json")).write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1], *sys.argv[2:])
