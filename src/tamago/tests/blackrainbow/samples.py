"""Synthetic BlackRainbow ADVDX data for tests, built independently of the code under test."""

import struct

ALICE = b"Alice was beginning to get very tired of sitting by her sister on the bank."
RABBIT = b"Oh dear! Oh dear! I shall be late!"
CURIOUS = b"Curiouser and curiouser!"
CHESHIRE = b"We're all mad here. I'm mad. You're mad." * 8

UNUSED = 0xFFFFFFFF


def build_dat(kind, members, slots=None, game_id=0, trailer=b'', size_fields=None):
    """Assemble an ADVDX archive.

    *members* maps slot -> (raw name bytes, body).  Records are laid out in slot
    order.  *slots* is the table size (default: highest slot + 1).
    *size_fields* maps slot -> the raw 4 bytes to store in place of the size
    field, to mimic a name that overflowed into it.
    """
    count = slots if slots is not None else max(members) + 1
    base = 16 + 4 * count
    table = [UNUSED] * count
    data = b''
    for slot in sorted(members):
        raw, body = members[slot]
        assert len(raw) <= 32
        table[slot] = len(data)
        size = (size_fields or {}).get(slot, struct.pack('<I', len(body)))
        data += raw.ljust(32, b'\0') + size + body
    header = struct.pack('<4I', kind, game_id, count, base)
    return header + struct.pack(f'<{count}I', *table) + data + trailer


def lzss_literals(data):
    """Encode *data* as an LZSS stream of literals only (flag bytes of all ones)."""
    out = bytearray()
    for i in range(0, len(data), 8):
        chunk = data[i : i + 8]
        out.append((1 << len(chunk)) - 1)
        out += chunk
    return bytes(out)


def build_bmd(width, height, bgra, alpha, stream=None):
    """A _BMD image of *bgra* pixels; *stream* overrides the LZSS data (default: literals)."""
    assert len(bgra) == width * height * 4
    if stream is None:
        stream = lzss_literals(bgra)
    return struct.pack('<4sIIII', b'_BMD', len(stream), width, height, alpha) + stream


def ogg(payload):
    """Something that starts like an Ogg page, enough for content sniffing."""
    return b'OggS\0\2' + payload


# A 2x2 sprite: opaque red, half-transparent green, transparent blue, opaque white (BGRA).
SPRITE_BGRA = bytes([0, 0, 255, 255, 0, 255, 0, 128, 255, 0, 0, 0, 255, 255, 255, 255])
# A 3x1 opaque strip, alpha bytes zeroed as the engine stores it.
STRIP_BGRA = bytes([10, 20, 30, 0, 40, 50, 60, 0, 70, 80, 90, 0])
