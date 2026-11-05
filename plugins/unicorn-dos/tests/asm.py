"""Synthetic Phar Lap programs for the tests: a 512-byte MZ stub followed by a flat P3 image loaded at 0x1000.

Instructions are written as bytes; the helpers below cover the few the tests need.
"""

import struct

LOAD = 0x1000
STACK = 0x3000


def p3_exe(code: bytes, data: dict[int, bytes] | None = None, *, level: int = 1, relocations: int = 0) -> bytes:
    """MZ stub (one 512-byte page) + P3 header + image: `code` at 0x1000, `data` as {linear address: bytes}."""
    image = bytearray(0x1000)
    image[: len(code)] = code
    for address, chunk in (data or {}).items():
        image[address - LOAD : address - LOAD + len(chunk)] = chunk
    mz = bytearray(512)
    mz[:2] = b"MZ"
    struct.pack_into("<HH", mz, 2, 0, 1)
    header = bytearray(0x200)
    header[:2] = b"P3"
    struct.pack_into("<HH", header, 2, level, 0x180)
    struct.pack_into("<I", header, 0x18, relocations)
    struct.pack_into("<II", header, 0x26, 0x200, len(image))
    struct.pack_into("<II", header, 0x5E, LOAD, STACK)
    struct.pack_into("<I", header, 0x68, LOAD)
    struct.pack_into("<I", header, 0x74, len(image))
    return bytes(mz) + bytes(header) + bytes(image)


def plain_mz() -> bytes:
    """A real-mode MZ program without a P3 image: `mov ax, 4C00h; int 21h`."""
    mz = bytearray(512)
    mz[:2] = b"MZ"
    struct.pack_into("<HHHH", mz, 2, 0x20 + 5, 1, 0, 2)  # bytes in last page, pages, relocations, header paragraphs
    mz[0x20:0x25] = b"\xb8\x00\x4c\xcd\x21"
    return bytes(mz[: 0x20 + 5])


def mov_ah(value: int) -> bytes:
    return bytes([0xB4, value])


def mov_eax(value: int) -> bytes:
    return b"\xb8" + struct.pack("<I", value)


def mov_ecx(value: int) -> bytes:
    return b"\xb9" + struct.pack("<I", value)


def mov_edx(value: int) -> bytes:
    return b"\xba" + struct.pack("<I", value)


def int21() -> bytes:
    return b"\xcd\x21"


MOV_EBX_EAX = b"\x89\xc3"
SETC_AL = b"\x0f\x92\xc0"
JMP_SELF = b"\xeb\xfe"


def exit_with(code: int) -> bytes:
    return b"\x66\xb8" + bytes([code, 0x4C]) + int21()


def exit_al() -> bytes:
    return mov_ah(0x4C) + int21()


NAME_AT = 0x1100
TEXT_AT = 0x1110


def write_file_program(name: bytes = b"OUT.TXT", text: bytes = b"OK", exit_code: int = 3) -> bytes:
    """Creates `name`, writes `text`, closes it, writes `text` to stdout and exits with `exit_code`."""
    code = (
        mov_ah(0x3C) + b"\x31\xc9" + mov_edx(NAME_AT) + int21()  # create (CX = 0)
        + MOV_EBX_EAX
        + mov_ah(0x40) + mov_ecx(len(text)) + mov_edx(TEXT_AT) + int21()  # write
        + mov_ah(0x3E) + int21()  # close
        + b"\xbb\x01\x00\x00\x00" + mov_ah(0x40) + mov_ecx(len(text)) + mov_edx(TEXT_AT) + int21()  # stdout
        + exit_with(exit_code)
    )
    return p3_exe(code, {NAME_AT: name + b"\0", TEXT_AT: text})


def counter_program() -> bytes:
    """Increments the dword at 0x1200 (0 in the image) and exits with its low byte."""
    code = b"\xa1\x00\x12\x00\x00" + b"\x40" + b"\xa3\x00\x12\x00\x00" + exit_al()
    return p3_exe(code)


def loop_program() -> bytes:
    return p3_exe(JMP_SELF)


def call_program(ah: int) -> bytes:
    """Calls INT 21h with AH = `ah`, then exits 0."""
    return p3_exe(mov_ah(ah) + int21() + exit_with(0))


def interrupt_program(number: int) -> bytes:
    return p3_exe(bytes([0xCD, number]) + exit_with(0))


def create_and_report_carry(name: bytes) -> bytes:
    """Creates `name` and exits with CF (1 = DOS error)."""
    code = mov_ah(0x3C) + b"\x31\xc9" + mov_edx(NAME_AT) + int21() + SETC_AL + exit_al()
    return p3_exe(code, {NAME_AT: name + b"\0"})
