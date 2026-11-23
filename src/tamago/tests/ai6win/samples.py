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


# -- AKB images ---------------------------------------------------------------


def literal_lzss(data: bytes) -> bytes:
    """An Okumura LZSS stream that sends every byte of *data* as a literal."""
    out = bytearray()
    for i in range(0, len(data), 8):
        chunk = data[i : i + 8]
        out.append((1 << len(chunk)) - 1)
        out += chunk
    return bytes(out)


def akb_filter(rows: list[bytes], pixel_size: int) -> bytes:
    """Delta-filter *rows* (top first) the slow, obvious way, returning them bottom first."""
    out = []
    for y, row in enumerate(rows):
        if y == 0:
            filtered = bytes(row[:pixel_size]) + bytes(
                (row[i] - row[i - pixel_size]) & 0xFF for i in range(pixel_size, len(row))
            )
        else:
            filtered = bytes((a - b) & 0xFF for a, b in zip(row, rows[y - 1], strict=True))
        out.append(filtered)
    return b''.join(reversed(out))


def build_akb(
    width: int,
    height: int,
    flags: int,
    background: bytes,
    rect: tuple[int, int, int, int],
    rows: list[bytes],
    magic: bytes = b'AKB ',
) -> bytes:
    """Build an AKB file storing *rows* (raw BGR/BGRA, top first) for *rect*."""
    pixel_size = 3 if flags & 0x40000000 else 4
    header = magic + struct.pack('<HHI', width, height, flags) + background + struct.pack('<4i', *rect)
    return header + (literal_lzss(akb_filter(rows, pixel_size)) if rows else b'')


# Alice's dress, apron, hair and the Cheshire Cat, as (R, G, B, A).
BLUE = (0x4F, 0x86, 0xC6, 0xFF)
WHITE = (0xFA, 0xFA, 0xF0, 0xFF)
GOLD = (0xF2, 0xC1, 0x4E, 0x80)
CHESHIRE = (0xB0, 0x4C, 0xA8, 0x00)

# A 3x2 picture: rows differ so that a flipped or mis-filtered decode shows.
PICTURE = [[BLUE, WHITE, GOLD], [CHESHIRE, BLUE, WHITE]]


def bgra_rows(picture) -> list[bytes]:
    return [bytes(c for r, g, b, a in row for c in (b, g, r, a)) for row in picture]


def bgr_rows(picture) -> list[bytes]:
    return [bytes(c for r, g, b, _a in row for c in (b, g, r)) for row in picture]


# 32-bit, whole canvas stored (flags 0): alpha is real even without bit 31.
AKB_RGBA = build_akb(3, 2, 0, bytes(4), (0, 0, 3, 2), bgra_rows(PICTURE))
# 24-bit, the picture placed at (1, 1) on a 5x4 canvas of opaque white.
AKB_RGB_CROPPED = build_akb(5, 4, 0xC00000FF, b'\xff\xff\xff\xff', (1, 1, 4, 3), bgr_rows(PICTURE))
# 24-bit, nothing stored: a solid black canvas.
AKB_EMPTY = build_akb(4, 3, 0xC00000FF, b'\0\0\0\xff', (0, 0, 0, 0), [])
