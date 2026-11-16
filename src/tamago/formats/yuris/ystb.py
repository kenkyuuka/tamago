"""Encryption of YU-RIS compiled scripts (YSTB, ``ysbin/yst*.ybn``).

A YSTB file is a 32-byte plaintext header followed by sections that are each
XOR'd with the same 32-bit key, restarting at the start of every section.
Engines from version 0x1CB on (and a few earlier ones) have four sections —
commands, arguments, resources and line numbers — sized by the u32s at 0x0C,
0x10, 0x14 and 0x18; older ones have two, sized by the u32s at 0x08 and 0x0C.
The sizes always add up to the rest of the file.

The key is chosen per game.  :func:`guess_ystb_key` recovers it from a game's
scripts, using what the plaintext of the four-section layout looks like.
"""

import struct
from collections import Counter
from collections.abc import Iterable

YSTB_MAGIC = b'YSTB'
HEADER_SIZE = 0x20
DEFAULT_SCRIPT_KEY = 0x96AC6FD3

_FOUR_SECTION_VERSIONS = {0x12C, 0x198, 0x19A, 0x19C, 0x1C3}
_ARGUMENT_SIZE = 12


def is_ystb(data: bytes) -> bool:
    """Return True if *data* starts like a YSTB script."""
    return len(data) >= HEADER_SIZE and data[:4] == YSTB_MAGIC


def _section_fields(version: int) -> range:
    """Indices of the header u32s that hold the encrypted section sizes."""
    if version >= 0x1CB or version in _FOUR_SECTION_VERSIONS:
        return range(3, 7)
    return range(2, 4)


def ystb_sections(data: bytes) -> list[tuple[int, int]]:
    """Return the (offset, size) of each encrypted section of the YSTB script *data*.

    Raises ValueError if *data* is not a YSTB script or its section sizes do
    not add up to its length.
    """
    if not is_ystb(data):
        raise ValueError("not a YSTB script")
    header = struct.unpack_from('<8I', data)
    sections, offset = [], HEADER_SIZE
    for field in _section_fields(header[1]):
        sections.append((offset, header[field]))
        offset += header[field]
    if offset != len(data):
        raise ValueError(f"YSTB section sizes add up to {offset:#x} bytes, but the script has {len(data):#x}")
    return sections


def _xor(data: bytes | memoryview, key: int) -> bytes:
    """XOR *data* with *key* as repeating little-endian u32, starting at its first byte."""
    n = len(data)
    if n == 0:
        return b''
    pad = (-n) % 4
    words = int.from_bytes(bytes(data) + bytes(pad), 'little')
    mask = int.from_bytes(key.to_bytes(4, 'little') * ((n + pad) // 4), 'little')
    return (words ^ mask).to_bytes(n + pad, 'little')[:n]


def _crypt(data: bytes, key: int) -> bytes:
    if not 0 <= key <= 0xFFFFFFFF:
        raise ValueError(f"YSTB key must be a 32-bit value, got {key:#x}")
    out = bytearray(data[:HEADER_SIZE])
    view = memoryview(data)
    for offset, size in ystb_sections(data):
        out += _xor(view[offset : offset + size], key)
    return bytes(out)


def decrypt_ystb(data: bytes, key: int) -> bytes:
    """Decrypt the YSTB script *data* with *key*."""
    return _crypt(data, key)


def encrypt_ystb(data: bytes, key: int) -> bytes:
    """Encrypt the plaintext YSTB script *data* with *key* (the XOR is its own inverse)."""
    return _crypt(data, key)


def _four_sections(data: bytes) -> list[bytes] | None:
    try:
        sections = ystb_sections(data)
    except ValueError:
        return None
    if len(sections) != 4:
        return None
    return [data[offset : offset + size] for offset, size in sections]


class _Candidate:
    """A script decrypted with only bytes 1-3 of the key, ready to try each low byte.

    The low key byte only touches the low byte of each u32, so trying one is a
    single XOR per value.
    """

    def __init__(self, sections: list[bytes], high: int):
        _commands, arguments, resources, lines = sections
        lines = _xor(lines[: len(lines) & ~3], high)
        self.lines = [value for (value,) in struct.iter_unpack('<I', lines)]
        arguments = _xor(arguments[: len(arguments) - len(arguments) % _ARGUMENT_SIZE], high)
        # Only arguments of a nonzero type reference resources; the type's
        # bytes are not touched by the low key byte.
        self.references = [
            (size, offset) for _value, arg_type, size, offset in struct.iter_unpack('<HHII', arguments) if arg_type
        ]
        self.resources_size = len(resources)

    def plausible(self, low: int) -> bool:
        """Line numbers never decrease, and references stay inside the resources."""
        previous = 0
        for value in self.lines:
            line = value ^ low
            if line < previous:
                return False
            previous = line
        limit = self.resources_size
        return all((offset ^ low) + (size ^ low) <= limit for size, offset in self.references)


def guess_ystb_key(scripts: Iterable[bytes]) -> int:
    """Recover the key that the four-section YSTB *scripts* of one game were encrypted with.

    Entries that are not such scripts are ignored.  Plaintext scripts give a
    key of 0.  Bytes 1-3 of the key are what most bytes of the arguments and
    line numbers encrypt to, since most of their plaintext is 0; byte 0 is the
    value that makes the most scripts decrypt plausibly (some short scripts fit
    several, but a game's whole set fits only one).

    Raises ValueError if there are no four-section scripts.
    """
    parsed = [s for s in map(_four_sections, scripts) if s is not None]
    if not parsed:
        raise ValueError("no YSTB scripts to guess the key from")

    high = 0
    for position in (1, 2, 3):
        votes: Counter[int] = Counter()
        for sections in parsed:
            for section in (sections[1], sections[3]):
                votes.update(section[position::4])
        if votes:
            high |= votes.most_common(1)[0][0] << (8 * position)

    candidates = [_Candidate(sections, high) for sections in parsed]
    scores = [sum(c.plausible(low) for c in candidates) for low in range(256)]
    # On a tie (only possible with very few, very short scripts), prefer the
    # low byte that most argument bytes encrypt to, as for the other bytes.
    low_votes: Counter[int] = Counter()
    for sections in parsed:
        low_votes.update(sections[1][0::4])
    preferred = low_votes.most_common(1)[0][0] if low_votes else 0
    best = max(range(256), key=lambda low: (scores[low], low == preferred))
    return high | best
