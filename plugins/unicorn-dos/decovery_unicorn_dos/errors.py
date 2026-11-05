"""Error codes and exceptions of the unicorn-dos plugin."""

from __future__ import annotations

INVALID_PARAMS = -32602
RUNNER_UNSUPPORTED = -32020


class EmulatorError(Exception):
    """The emulation cannot go on correctly (unsupported service, CPU fault, memory fault)."""


class EmulatorTimeout(EmulatorError):
    """The program did not end within the time limit. WCC386 9.5 has real hangs (also seen in DOSBox), so this is
    not necessarily a fault of the emulation."""


class Unsupported(EmulatorError):
    """A DOS or extender service the emulation does not provide; the host adds the address."""


class DosError(Exception):
    """A DOS error code a service returns with CF set (2 file not found, 3 path not found, 5 access denied, ...)."""

    def __init__(self, code: int):
        super().__init__(f"DOS error {code}")
        self.code = code
