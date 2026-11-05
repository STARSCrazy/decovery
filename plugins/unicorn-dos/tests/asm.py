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


def le_exe() -> bytes:
    """An MZ stub pointing to an LE header: no host of the plugin runs it."""
    le = bytearray(plain_mz()) + bytes(0x80)
    le[0x18] = 0x40
    le[0x3C] = 0x80
    le[0x80:0x82] = b"LE"
    return bytes(le)


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


def halt_program() -> bytes:
    """`hlt`: unicorn stops there without an exit."""
    return p3_exe(b"\xf4")


# --- real-mode MZ programs ---------------------------------------------------------------------------------------
# Image layout: code segment at paragraph 0 (0x400 bytes), data segment at paragraph 0x40 (0x200 bytes), stack
# segment at paragraph 0x60 (SP = 0x100). The host loads the image at PSP 0x0100 + 0x10, so CS = 0x0110,
# data = 0x0150, stack = 0x0170; PSP and image take 0x80 paragraphs.
LOAD_SEG = 0x0110
DATA_PARA = 0x40
DATA_SEG = LOAD_SEG + DATA_PARA
DUMP = 0x100  # dump area in the data segment: 16 bytes per call
DUMP_NAMES = ("AX", "BX", "CX", "DX", "SI", "DI", "ES", "FLAGS")


def mz_exe(
    code: bytes,
    data: bytes = b"",
    relocations: list[tuple[int, int]] = (),
    *,
    min_alloc: int = 0,
    max_alloc: int = 0xFFFF,
) -> bytes:
    """MZ program: `code` (at most 0x400 bytes), `data` (at most 0x100 bytes; the dump area follows), a 0x100-byte
    stack; `relocations` as (segment, offset) pairs relative to the load segment."""
    assert len(code) <= 0x400 and len(data) <= 0x100, (len(code), len(data))
    image = code.ljust(0x400, b"\x90") + data.ljust(0x200, b"\0") + bytes(0x100)
    table = b"".join(struct.pack("<HH", off, seg) for seg, off in relocations)
    header_paras = (0x1C + len(table) + 15) // 16
    header = bytearray(header_paras * 16)
    size = len(header) + len(image)
    header[:2] = b"MZ"
    fields = (size % 512, (size + 511) // 512, len(relocations), header_paras, min_alloc, max_alloc)
    struct.pack_into("<HHHHHH", header, 2, *fields)
    struct.pack_into("<HHHHHH", header, 0x0E, 0x60, 0x100, 0, 0, 0, 0x1C)  # SS SP checksum IP CS table
    header[0x1C : 0x1C + len(table)] = table
    return bytes(header) + image


def mov16(register: str, value: int) -> bytes:
    opcode = {"AX": 0xB8, "CX": 0xB9, "DX": 0xBA, "BX": 0xBB, "SP": 0xBC, "BP": 0xBD, "SI": 0xBE, "DI": 0xBF}
    return bytes([opcode[register]]) + struct.pack("<H", value & 0xFFFF)


SET_DS_DATA = mov16("AX", DATA_PARA) + b"\x8e\xd8"  # mov ax, DATA (relocated: code offset 1); mov ds, ax
DATA_RELOCATION = (0, 1)
PUSH_CS_POP_DS = b"\x0e\x1f"
PUSH_DS_POP_ES = b"\x1e\x07"
HLT = b"\xf4"


def mov_es_from(offset: int) -> bytes:
    """mov es, [offset] (data segment)."""
    return b"\x8e\x06" + struct.pack("<H", offset)


def exit16(code: int) -> bytes:
    return mov16("AX", 0x4C00 | code) + int21()


def dump_registers(slot: int) -> bytes:
    """Stores AX, BX, CX, DX, SI, DI, ES and FLAGS as words at DS:DUMP + 16 * slot (DS = data segment)."""
    at = DUMP + 16 * slot
    return (
        b"\xa3" + struct.pack("<H", at)
        + b"\x89\x1e" + struct.pack("<H", at + 2)
        + b"\x89\x0e" + struct.pack("<H", at + 4)
        + b"\x89\x16" + struct.pack("<H", at + 6)
        + b"\x89\x36" + struct.pack("<H", at + 8)
        + b"\x89\x3e" + struct.pack("<H", at + 10)
        + b"\x8c\x06" + struct.pack("<H", at + 12)
        + b"\x9c\x8f\x06" + struct.pack("<H", at + 14)
    )


def calls16(calls: list[tuple[bytes, int]], data: bytes = b"") -> bytes:
    """MZ program: DS = data segment, then per (setup, number): `setup`, `int number`, dump into the next slot;
    exit 0."""
    code = SET_DS_DATA
    for slot, (setup, number) in enumerate(calls):
        code += setup + bytes([0xCD, number]) + dump_registers(slot)
    return mz_exe(code + exit16(0), data, [DATA_RELOCATION])


def write_file_program16(name: bytes = b"OUT.TXT", text: bytes = b"OK", exit_code: int = 3) -> bytes:
    """Real-mode `write_file_program`: name at data:0, text at data:0x10."""
    code = (
        SET_DS_DATA
        + mov_ah(0x3C) + mov16("CX", 0) + mov16("DX", 0) + int21()  # create
        + b"\x89\xc3"  # mov bx, ax
        + mov_ah(0x40) + mov16("CX", len(text)) + mov16("DX", 0x10) + int21()  # write
        + mov_ah(0x3E) + int21()  # close
        + mov16("BX", 1) + mov_ah(0x40) + mov16("CX", len(text)) + mov16("DX", 0x10) + int21()  # stdout
        + exit16(exit_code)
    )
    data = (name + b"\0").ljust(0x10, b"\0") + text
    return mz_exe(code, data, [DATA_RELOCATION])


def loop_program16() -> bytes:
    return mz_exe(JMP_SELF)
