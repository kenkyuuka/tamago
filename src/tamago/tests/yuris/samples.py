"""Synthetic YU-RIS data for tests, built independently of the code under test."""

import struct
import zlib

ALICE = b"Alice was beginning to get very tired of sitting by her sister on the bank."
RABBIT = b"Oh dear! Oh dear! I shall be late!"
CURIOUS = b"Curiouser and curiouser!"
CHESHIRE = b"We're all mad here. I'm mad. You're mad." * 8

TABLE_A = [
    (0x03, 0x48), (0x06, 0x35), (0x09, 0x0B), (0x0C, 0x10), (0x0D, 0x13), (0x11, 0x19),
    (0x15, 0x1B), (0x1C, 0x1E), (0x20, 0x23), (0x26, 0x29), (0x2C, 0x2F), (0x2E, 0x32),
]  # fmt: skip
TABLE_D = [
    (0x03, 0x0A), (0x06, 0x35), (0x09, 0x0B), (0x0C, 0x10), (0x0D, 0x13), (0x11, 0x18),
    (0x14, 0x2E), (0x15, 0x1B), (0x1C, 0x1E), (0x20, 0x23), (0x26, 0x29), (0x2C, 0x2F),
]  # fmt: skip


def murmur2(data, seed=0):
    """Reference MurmurHash2 (32-bit), straight from Appleby's algorithm."""
    m = 0x5BD1E995
    h = (seed ^ len(data)) & 0xFFFFFFFF
    i = 0
    while len(data) - i >= 4:
        k = struct.unpack_from('<I', data, i)[0]
        k = (k * m) & 0xFFFFFFFF
        k ^= k >> 24
        k = (k * m) & 0xFFFFFFFF
        h = (h * m) & 0xFFFFFFFF
        h ^= k
        i += 4
    rest = len(data) - i
    if rest == 3:
        h ^= data[i + 2] << 16
    if rest >= 2:
        h ^= data[i + 1] << 8
    if rest >= 1:
        h ^= data[i]
        h = (h * m) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * m) & 0xFFFFFFFF
    h ^= h >> 15
    return h


def swap(table, value):
    for a, b in table:
        if value == a:
            return b
        if value == b:
            return a
    return value


def build_ypf(members, version=500, key=0xFF, table=TABLE_A, order=None):
    """Assemble a YPF archive.

    *members* is a list of ``(name, data, file_type, packed)``; packed data is
    zlib-compressed here.  Index entries are sorted by name hash like the
    engine's own archives; data is laid out in *order* (indices into *members*,
    default: as given) to mimic the packer's independent data order.
    """
    wide = version >= 478
    name_hash = murmur2 if wide else zlib.crc32
    check = murmur2 if wide else zlib.adler32
    entries = []
    for name, data, file_type, packed in members:
        raw = name.encode('cp932')
        stored = zlib.compress(data, 9) if packed else data
        entries.append([raw, data, stored, file_type, packed])
    index_size = sum(len(e[0]) + (27 if wide else 23) for e in entries)
    offset = 0x20 + index_size
    offsets = {}
    for i in order if order is not None else range(len(entries)):
        offsets[i] = offset
        offset += len(entries[i][2])

    index = b''
    for i in sorted(range(len(entries)), key=lambda i: name_hash(entries[i][0])):
        raw, data, stored, file_type, packed = entries[i]
        index += struct.pack('<IB', name_hash(raw), ~swap(table, len(raw)) & 0xFF)
        index += bytes(b ^ key for b in raw)
        index += struct.pack('<BBII', file_type, int(packed), len(data), len(stored))
        index += struct.pack('<Q' if wide else '<I', offsets[i])
        index += struct.pack('<I', check(stored))
    header = struct.pack('<4sIII16x', b'YPF\0', version, len(entries), 0x20 + len(index))
    body = b''.join(entries[i][2] for i in (order if order is not None else range(len(entries))))
    return header + index + body


def _xor(data, key):
    k = struct.pack('<I', key)
    return bytes(b ^ k[i % 4] for i, b in enumerate(data))


def ystb_plain(lines=(3, 4, 4, 7, 9, 12), version=494):
    """A plaintext YSTB with one command per line number and matching arguments."""
    n = len(lines)
    commands = b''.join(struct.pack('<BBH', 0x43 + (i % 3), 1, 0) for i in range(n))
    resources = b"'Off with her head!'" + b'Tweedledum'  # 30 bytes: not a multiple of 4
    arguments = b''.join(struct.pack('<HHII', 0, 3 if i % 2 else 1, 5, (i * 5) % 25) for i in range(n))
    line_numbers = b''.join(struct.pack('<I', v) for v in lines)
    sections = [commands, arguments, resources, line_numbers]
    header = struct.pack('<4sII4II', b'YSTB', version, n, *map(len, sections), 0)
    return header + b''.join(sections)


def ystb_encrypt(plain, key):
    """Encrypt each of the four sections separately, restarting the key for each."""
    sizes = struct.unpack_from('<4I', plain, 12)
    out, pos = plain[:32], 32
    for size in sizes:
        out += _xor(plain[pos : pos + size], key)
        pos += size
    return out


def build_ycg(width, height, bgra):
    """A zlib YCG: the rows split into two bands at height // 2."""
    assert len(bgra) == width * height * 4
    split = height // 2
    top, bottom = bgra[: split * width * 4], bgra[split * width * 4 :]
    c0, c1 = zlib.compress(top, 9), zlib.compress(bottom, 9)
    header = struct.pack('<4sIIIII', b'YCG\0', width, height, 32, 1, 2)
    header += struct.pack('<iiII', 0, split - 1, len(top), len(c0))
    header += struct.pack('<iiII', split, height - 1, len(bottom), len(c1))
    return header + c0 + c1
