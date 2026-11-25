"""Synthetic Silky's archives, built without the library so that tests check it independently."""

import struct

from tamago.tests.ai6win.samples import (
    OGG,
    QUEEN,
    QUEEN_LZSS,
    TEA_TEA_TEA,
    TEA_TEA_TEA_LZSS,
    WAV,
    ZEROS_TEA,
    ZEROS_TEA_LZSS,
    literal_lzss,
)

__all__ = [
    'ARCHIVE',
    'CONTENTS',
    'MEMBERS',
    'OGG',
    'QUEEN',
    'QUEEN_LZSS',
    'TEA_TEA_TEA',
    'WAV',
    'build_arc',
    'literal_lzss',
    'obfuscate',
]

# "The Queen of Hearts", in cp932.
QUEEN_OF_HEARTS = 'ハートの女王.BRT'.encode('cp932')


def obfuscate(name: bytes) -> bytes:
    """Subtract n, n-1, ..., 1 from the bytes of the n-byte *name*."""
    n = len(name)
    return bytes((c - (n - i)) & 0xFF for i, c in enumerate(name))


def build_arc(members: list[tuple[bytes, bytes, int]], gap: int = 0) -> bytes:
    """Build an archive from ``(raw_name, stored_bytes, unpacked_size)`` triples, in index order.

    *gap* bytes of padding are left between the index and the first member.
    """
    index_size = sum(1 + len(name) + 12 for name, _stored, _unpacked in members)
    offset = 4 + index_size + gap
    index = bytearray(struct.pack('<I', index_size))
    for name, stored, unpacked in members:
        index += bytes([len(name)]) + obfuscate(name)
        index += struct.pack('>III', len(stored), unpacked, offset)
        offset += len(stored)
    return bytes(index) + bytes(gap) + b''.join(stored for _name, stored, _unpacked in members)


# In byte order, as in the games' own archives.
MEMBERS = [
    (b'ALICE.MES', QUEEN_LZSS, len(QUEEN)),
    (b'CHESHIRE.OGG', OGG, len(OGG)),
    (b'TEA_PARTY.BIN', TEA_TEA_TEA_LZSS, len(TEA_TEA_TEA)),
    (b'WHITE_RABBIT.WAV', WAV, len(WAV)),
    (QUEEN_OF_HEARTS, ZEROS_TEA_LZSS, len(ZEROS_TEA)),
]
ARCHIVE = build_arc(MEMBERS)
CONTENTS = {
    'ALICE.MES': QUEEN,
    'CHESHIRE.OGG': OGG,
    'TEA_PARTY.BIN': TEA_TEA_TEA,
    'WHITE_RABBIT.WAV': WAV,
    'ハートの女王.BRT': ZEROS_TEA,
}
