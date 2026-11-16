"""Fake Decomp CLI. `--bereich X mcp --nur-fernzugang --eltern PID` serves Decomp's server protocol (ping, beenden)
and writes cache/fernzugang.json; `--bereich X nachbau <cmd> F ...` records the call in cache/fake-calls.jsonl and
writes result files where Decomp would. Behaviour from the environment:
FAKE_DECOMP_MODE = ok (default) | fail (exit 1) | sleep (runs until killed, printing to stderr) | improve (search
steps write beste.c); FAKE_DECOMP_SERVER = fail (the server exits at start)."""

import json
import os
import secrets
import socket
import sys
import threading
import time
import tomllib
from pathlib import Path


def _lebt(pid):
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    import ctypes

    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x1000, False, pid)
    if not h:
        return False
    try:
        code = ctypes.c_ulong()
        return bool(k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259
    finally:
        k32.CloseHandle(h)


def server(bereich, eltern):
    cache = bereich / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / "fake-server-starts.txt").open("a") as f:
        f.write(f"{os.getpid()}\n")
    if os.environ.get("FAKE_DECOMP_SERVER") == "fail":
        print("Interner Fehler: Server kaputt", file=sys.stderr)
        return 3
    token = secrets.token_hex(8)
    sock = socket.create_server(("127.0.0.1", 0))
    ende = threading.Event()
    info = {"pid": os.getpid(), "port": sock.getsockname()[1], "token": token, "code": "fake",
            "kennung": os.environ.get("DECOMP_FERN_KENNUNG")}
    (cache / "fernzugang.json").write_text(json.dumps(info), encoding="utf-8")

    def bedienen(verb):
        with verb, verb.makefile("r", encoding="utf-8") as ein, verb.makefile("wb") as aus:
            anfrage = json.loads(ein.readline())
            if anfrage.get("token") != token:
                antwort = {"fehler": "Token", "art": "benutzer"}
            elif anfrage.get("befehl") == "ping":
                antwort = {"ok": "pong"}
            elif anfrage.get("befehl") == "beenden":
                antwort = {"ok": "beendet"}
                ende.set()
            else:
                antwort = {"fehler": "nicht erlaubt", "art": "benutzer"}
            aus.write((json.dumps(antwort) + "\n").encode("utf-8"))

    def annehmen():
        while True:
            try:
                verb, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=bedienen, args=(verb,), daemon=True).start()

    threading.Thread(target=annehmen, daemon=True).start()
    print(f"bereit pid={os.getpid()} port={info['port']}", flush=True)
    while not ende.wait(0.2):
        if eltern is not None and not _lebt(eltern):
            break
    sock.close()
    (cache / "fernzugang.json").unlink(missing_ok=True)
    return 0


def name_von(bereich, adresse):
    for datei, liste in (("nachbau.toml", "funktion"), ("symbole.toml", "symbol")):
        p = bereich / "wissen" / datei
        if p.exists():
            for e in tomllib.loads(p.read_text(encoding="utf-8")).get(liste, []):
                if e.get("adresse") == adresse and e.get("name") and not e.get("widerlegt"):
                    return e["name"]
    return "fun_" + adresse.split(":", 1)[1].replace(":", "_")


ORDNER = {"kette": "kette", "permutieren": "permutieren", "strahl": "strahl", "formen": "formen",
          "plaetze": "plaetze", "gemeinsam": "gemeinsam"}


def nachbau(bereich, args):
    befehl, funktion, rest = args[0], args[1], args[2:]
    cache = bereich / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    laeuft = (cache / "fernzugang.json").exists()
    with (cache / "fake-calls.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"args": args, "emu": os.environ.get("DECOMP_WATCOM_EMU"), "server": laeuft}) + "\n")
    modus = os.environ.get("FAKE_DECOMP_MODE", "ok")
    if laeuft:
        print("Hinweis: läuft über den MCP-Server, der diesen Arbeitsbereich offen hält.", file=sys.stderr)
    if modus == "fail":
        print(f"Fehler: '{funktion}' ist weder Adresse noch bekannter Name", file=sys.stderr)
        return 1
    if modus == "sleep":
        (cache / "fake-sleeping.txt").write_text(str(os.getpid()))
        i = 0
        while True:
            print(f"Runde {i}", file=sys.stderr, flush=True)
            i += 1
            time.sleep(0.3)
    name = name_von(bereich, funktion)
    bericht = f"Bericht {befehl} {name}"
    if befehl in ORDNER:
        ordner = cache / "nachbau" / ORDNER[befehl] / name
        ordner.mkdir(parents=True, exist_ok=True)
        (ordner / "ergebnis.txt").write_text(bericht + " (Datei)\n", encoding="utf-8")
        if befehl == "kette":
            (ordner / "ergebnis.json").write_text(json.dumps({"kennzahl": [3, 10]}), encoding="utf-8")
            (ordner / "stand.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
        if modus == "improve" and befehl in ("kette", "permutieren", "strahl", "formen", "plaetze"):
            (ordner / "beste.c").write_text(f"/* beste {befehl} */\n", encoding="utf-8")
    if befehl == "vergabe":
        ziel = Path(rest[rest.index("--json") + 1])
        ziel.write_text(json.dumps({name: {"zuordnung": {"count": "ESI"}}}), encoding="utf-8")
        print(f"{bericht}\n\nRegisterlauf gespeichert: {ziel}")
        return 0
    if befehl == "gemeinsam":
        print(json.dumps({"treffer": [], "funktion": name}))
        return 0
    if befehl == "gleichwertig":
        print(json.dumps({"bericht": f"{bericht} gleichwertig", "urteil": "ungeprueft"}))
        return 0
    print(bericht)
    return 0


def main(argv):
    bereich = Path(argv[argv.index("--bereich") + 1])
    rest = argv[argv.index("--bereich") + 2:]
    if rest[0] == "mcp":
        eltern = int(rest[rest.index("--eltern") + 1]) if "--eltern" in rest else None
        return server(bereich, eltern)
    if rest[0] == "nachbau":
        return nachbau(bereich, rest[1:])
    print(f"Fehler: unbekannter Befehl {rest}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
