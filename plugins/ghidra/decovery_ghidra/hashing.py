"""BLAKE3 (hash mode, 32-byte digest) for the export file hash.

Uses the `blake3` package when it is installed; otherwise a pure-Python implementation of the reference algorithm
(the standard library has no blake3). The fallback is slow (about 1 MB/s) but only hashes the export file.
"""

from __future__ import annotations

from pathlib import Path

_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_CHUNK_START, _CHUNK_END, _PARENT, _ROOT = 1, 2, 4, 8
_CHUNK_LEN, _BLOCK_LEN = 1024, 64
_MASK = 0xFFFFFFFF


def _compress(cv: tuple, words: list[int], counter: int, block_len: int, flags: int) -> list[int]:
    s = [*cv, *_IV[:4], counter & _MASK, (counter >> 32) & _MASK, block_len, flags]
    m = list(words)
    for round_ in range(7):
        for a, b, c, d, x, y in (
            (0, 4, 8, 12, 0, 1), (1, 5, 9, 13, 2, 3), (2, 6, 10, 14, 4, 5), (3, 7, 11, 15, 6, 7),
            (0, 5, 10, 15, 8, 9), (1, 6, 11, 12, 10, 11), (2, 7, 8, 13, 12, 13), (3, 4, 9, 14, 14, 15),
        ):
            s[a] = (s[a] + s[b] + m[x]) & _MASK
            t = s[d] ^ s[a]
            s[d] = ((t >> 16) | (t << 16)) & _MASK
            s[c] = (s[c] + s[d]) & _MASK
            t = s[b] ^ s[c]
            s[b] = ((t >> 12) | (t << 20)) & _MASK
            s[a] = (s[a] + s[b] + m[y]) & _MASK
            t = s[d] ^ s[a]
            s[d] = ((t >> 8) | (t << 24)) & _MASK
            s[c] = (s[c] + s[d]) & _MASK
            t = s[b] ^ s[c]
            s[b] = ((t >> 7) | (t << 25)) & _MASK
        if round_ < 6:
            m = [m[i] for i in _PERMUTATION]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block: bytes) -> list[int]:
    block = block.ljust(_BLOCK_LEN, b"\0")
    return [int.from_bytes(block[i : i + 4], "little") for i in range(0, _BLOCK_LEN, 4)]


def _chunk_output(data: bytes, counter: int) -> tuple:
    """(cv, words, counter, block_len, flags) of a chunk's last block, the earlier blocks compressed into cv."""
    cv = _IV
    blocks = [data[i : i + _BLOCK_LEN] for i in range(0, len(data), _BLOCK_LEN)] or [b""]
    for index, block in enumerate(blocks[:-1]):
        flags = _CHUNK_START if index == 0 else 0
        cv = tuple(_compress(cv, _words(block), counter, _BLOCK_LEN, flags)[:8])
    flags = _CHUNK_END | (_CHUNK_START if len(blocks) == 1 else 0)
    return cv, _words(blocks[-1]), counter, len(blocks[-1]), flags


def _chaining_value(output: tuple) -> tuple:
    return tuple(_compress(*output)[:8])


def _parent_output(left: tuple, right: tuple) -> tuple:
    return _IV, [*left, *right], 0, _BLOCK_LEN, _PARENT


def _blake3_pure(data: bytes) -> str:
    stack: list[tuple] = []
    chunks = [data[i : i + _CHUNK_LEN] for i in range(0, len(data), _CHUNK_LEN)] or [b""]
    for counter, chunk in enumerate(chunks[:-1]):
        cv = _chaining_value(_chunk_output(chunk, counter))
        total = counter + 1
        while total & 1 == 0:  # merge completed subtrees
            cv = _chaining_value(_parent_output(stack.pop(), cv))
            total >>= 1
        stack.append(cv)
    output = _chunk_output(chunks[-1], len(chunks) - 1)
    while stack:
        output = _parent_output(stack.pop(), _chaining_value(output))
    cv, words, counter, block_len, flags = output
    state = _compress(cv, words, counter, block_len, flags | _ROOT)
    return b"".join(w.to_bytes(4, "little") for w in state[:8]).hex()


def blake3_hex(data: bytes) -> str:
    """Lowercase hex BLAKE3 digest of `data`."""
    try:
        import blake3  # type: ignore[import-not-found]
    except ImportError:
        return _blake3_pure(bytes(data))
    return blake3.blake3(data).hexdigest()


def blake3_file(path: Path) -> str:
    return blake3_hex(Path(path).read_bytes())
