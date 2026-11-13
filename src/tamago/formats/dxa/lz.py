"""The LZ77 variant DxLib uses to compress archive members.

A compressed stream is a 9-byte header followed by tokens::

    u32 dest_size   uncompressed size
    u32 src_size    compressed size, header included
    u8  key         escape byte, chosen as the rarest byte of the input

A byte other than *key* is a literal.  ``key key`` is a literal *key*.
``key code ...`` is a back-reference: *code* (decremented if above *key*)
holds the low 5 bits of ``length - 4``, a flag for an extension byte holding
bits 5 to 12, and the size of the following ``distance - 1`` field (1 to 3
bytes, little-endian).
"""

import struct

HEADER = struct.Struct('<IIB')

MIN_MATCH = 4
MAX_MATCH = 0x1FFF + MIN_MATCH
MAX_DISTANCE = 1 << 24

# Positions remembered per hash bucket, newest first.  Bounds compression time
# on repetitive input, like DxLib's MAX_SEARCHLISTNUM.
_MAX_CHAIN = 64


def decompress(data: bytes) -> bytes:
    """Decompress a DxLib LZ stream, raising ValueError if it is malformed."""
    if len(data) < HEADER.size:
        raise ValueError("DxLib LZ stream is shorter than its 9-byte header")
    dest_size, src_size, key = HEADER.unpack_from(data)
    if not HEADER.size <= src_size <= len(data):
        raise ValueError(f"DxLib LZ stream claims {src_size} bytes but holds {len(data)}")

    out = bytearray()
    pos = HEADER.size
    end = src_size
    try:
        while pos < end:
            b = data[pos]
            pos += 1
            if b != key:
                out.append(b)
                continue
            code = data[pos]
            pos += 1
            if code == key:
                out.append(key)
                continue
            if code > key:
                code -= 1
            length = code >> 3
            if code & 0x04:
                length |= data[pos] << 5
                pos += 1
            length += MIN_MATCH
            dist_size = code & 0x03
            if dist_size == 3:
                raise ValueError("DxLib LZ stream has an invalid distance size")
            distance = int.from_bytes(data[pos : pos + dist_size + 1], 'little') + 1
            pos += dist_size + 1
            if pos > end:
                raise IndexError
            start = len(out) - distance
            if start < 0:
                raise ValueError("DxLib LZ back-reference points before the start of the output")
            if distance >= length:
                out += out[start : start + length]
            else:
                # Overlapping copy: the match repeats the last *distance* bytes.
                pattern = bytes(out[start:])
                out += (pattern * (length // distance + 1))[:length]
    except IndexError:
        raise ValueError("DxLib LZ stream is truncated") from None

    if len(out) != dest_size:
        raise ValueError(f"DxLib LZ stream decoded to {len(out)} bytes, expected size {dest_size}")
    return bytes(out)


def _choose_key(data: bytes) -> int:
    counts = [0] * 256
    for value in set(data):
        counts[value] = data.count(value)
    return min(range(256), key=counts.__getitem__)


def _emit_match(out: bytearray, key: int, length: int, distance: int):
    stored_length = length - MIN_MATCH
    stored_distance = distance - 1
    dist_size = 0 if stored_distance < 0x100 else 1 if stored_distance < 0x10000 else 2
    code = (stored_length & 0x1F) << 3 | dist_size
    if stored_length > 0x1F:
        code |= 0x04
    out.append(key)
    out.append(code + 1 if code >= key else code)
    if stored_length > 0x1F:
        out.append(stored_length >> 5)
    out += stored_distance.to_bytes(dist_size + 1, 'little')


def compress(data: bytes) -> bytes:
    """Compress *data* into a DxLib LZ stream with a greedy hash-chain matcher."""
    key = _choose_key(data)
    out = bytearray(HEADER.size)
    size = len(data)
    chains: dict[bytes, list[int]] = {}
    pos = 0

    def remember(at: int):
        chain = chains.setdefault(data[at : at + MIN_MATCH], [])
        chain.insert(0, at)
        if len(chain) > _MAX_CHAIN:
            chain.pop()

    while pos < size:
        best_len = 0
        best_dist = 0
        if pos + MIN_MATCH <= size:
            limit = min(MAX_MATCH, size - pos)
            for candidate in chains.get(data[pos : pos + MIN_MATCH], ()):
                distance = pos - candidate
                if distance > MAX_DISTANCE:
                    break
                length = MIN_MATCH
                while length < limit and data[candidate + length] == data[pos + length]:
                    length += 1
                if length > best_len:
                    best_len, best_dist = length, distance
                    if length == limit:
                        break

        if best_len >= MIN_MATCH:
            _emit_match(out, key, best_len, best_dist)
            for at in range(pos, min(pos + best_len, size - MIN_MATCH + 1)):
                remember(at)
            pos += best_len
        else:
            b = data[pos]
            out.append(b)
            if b == key:
                out.append(b)
            if pos + MIN_MATCH <= size:
                remember(pos)
            pos += 1

    HEADER.pack_into(out, 0, size, len(out), key)
    return bytes(out)
