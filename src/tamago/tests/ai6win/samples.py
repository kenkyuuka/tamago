"""Synthetic AI6WIN archives, built without the library so that tests check it independently."""

import struct

ENTRY_SIZE = 0x110
NAME_SIZE = 0x104

# Hand-checked Okumura LZSS streams (see the format notes): the first starts
# with a reference into the zero-filled initial ring, the second overlaps
# its own output.
ZEROS_TEA = b'\0\0\0\0Tea'
ZEROS_TEA_LZSS = bytes.fromhex('0e edf1 546561')
TEA_TEA_TEA = b'tea tea tea'
TEA_TEA_TEA_LZSS = bytes.fromhex('0f 74656120 eef4')
QUEEN = b'Off with her head! Off with her head!'
QUEEN_LZSS = bytes.fromhex('ff 4f66662077697468 ef 20686572 f6f0 616421 01 20 eeff')

OGG = b'OggS\0\2' + b'\0' * 20 + b'Down the rabbit-hole'
WAV = b'RIFF\x24\0\0\0WAVEfmt ' + b'\0' * 16 + b'data\0\0\0\0'


def obfuscate(name: bytes) -> bytes:
    key = len(name) + 1
    return bytes((c + key - i) & 0xFF for i, c in enumerate(name))


def build_arc(members: list[tuple[bytes, bytes, int]]) -> bytes:
    """Build an archive from ``(raw_name, stored_bytes, unpacked_size)`` triples, in index order."""
    offset = 4 + ENTRY_SIZE * len(members)
    index = bytearray(struct.pack('<I', len(members)))
    for name, stored, unpacked in members:
        index += obfuscate(name).ljust(NAME_SIZE, b'\0')
        index += struct.pack('>III', len(stored), unpacked, offset)
        offset += len(stored)
    return bytes(index) + b''.join(stored for _name, stored, _unpacked in members)


# Members in a deliberately unsorted order, as in the games' own archives.
MEMBERS = [
    (b'start.mes', QUEEN_LZSS, len(QUEEN)),
    (b'cheshire.ogg', OGG, len(OGG)),
    (b'mpeg/rabbit.mov', ZEROS_TEA_LZSS, len(ZEROS_TEA)),
    (b'backlog.area', TEA_TEA_TEA_LZSS, len(TEA_TEA_TEA)),
    (b'01.WAV', WAV, len(WAV)),
]
ARCHIVE = build_arc(MEMBERS)
CONTENTS = {
    'start.mes': QUEEN,
    'cheshire.ogg': OGG,
    'mpeg/rabbit.mov': ZEROS_TEA,
    'backlog.area': TEA_TEA_TEA,
    '01.WAV': WAV,
}
