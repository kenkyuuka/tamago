"""LZSS compression as used by BlackRainbow's _BMD images.

This is Okumura's classic LZSS: a 4 KiB ring buffer that starts zero-filled
with its write position at 0xFEE, flag bytes read LSB first (1 = literal,
0 = reference), and two-byte references holding a 12-bit absolute ring
position and a 4-bit length (3 to 18 bytes).
"""

RING_SIZE = 0x1000
RING_MASK = RING_SIZE - 1
RING_START = 0xFEE
MIN_MATCH = 3
MAX_MATCH = 18


def decompress(data: bytes | bytearray | memoryview, size: int) -> bytes:
    """Decompress the LZSS stream *data* to *size* bytes.

    Raises ValueError if the stream ends before *size* bytes are produced.
    Anything in the stream after that point is ignored.
    """
    src = bytes(data)
    end = len(src)
    # The ring buffer's initial zeros, as if they had been output before the
    # data: every ring position then corresponds to a distance back into buf.
    buf = bytearray(RING_SIZE)
    limit = RING_SIZE + size
    i = 0
    while len(buf) < limit:
        if i >= end:
            raise ValueError(f"LZSS stream ended after {len(buf) - RING_SIZE} of {size} bytes")
        flags = src[i]
        i += 1
        for bit in range(8):
            if len(buf) >= limit:
                break
            if flags >> bit & 1:
                if i >= end:
                    raise ValueError(f"LZSS stream ended after {len(buf) - RING_SIZE} of {size} bytes")
                buf.append(src[i])
                i += 1
            else:
                if i + 1 >= end:
                    raise ValueError(f"LZSS stream ended inside a reference at offset {i}")
                lo = src[i]
                hi = src[i + 1]
                i += 2
                position = lo | (hi & 0xF0) << 4
                length = (hi & 0x0F) + MIN_MATCH
                write_pos = (RING_START + len(buf)) & RING_MASK  # (RING_START + output length) mod ring
                distance = (write_pos - position) & RING_MASK or RING_SIZE
                start = len(buf) - distance
                if distance >= length:
                    buf += buf[start : start + length]
                else:
                    # The source overlaps the bytes being written: the pattern repeats.
                    pattern = buf[start:]
                    buf += (pattern * (length // distance + 1))[:length]
    return bytes(buf[RING_SIZE:limit])


def _longest_match(data: bytes, pos: int, end: int) -> tuple[int, int]:
    """Return (distance, length) of the longest earlier match for data[pos:], or (0, 0)."""
    window = max(0, pos - RING_SIZE)
    longest = min(MAX_MATCH, end - pos)
    if longest < MIN_MATCH:
        return 0, 0
    # A match of length n is found by rfind if the source starts before pos,
    # so the search region ends at pos - 1 + n; matches may overlap pos.
    found = data.rfind(data[pos : pos + MIN_MATCH], window, pos - 1 + MIN_MATCH)
    if found < 0:
        return 0, 0
    best_len, best_at = MIN_MATCH, found
    full = data.rfind(data[pos : pos + longest], window, pos - 1 + longest)
    if full >= 0:
        return pos - full, longest
    lo, hi = MIN_MATCH + 1, longest - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        at = data.rfind(data[pos : pos + mid], window, pos - 1 + mid)
        if at >= 0:
            best_len, best_at = mid, at
            lo = mid + 1
        else:
            hi = mid - 1
    return pos - best_at, best_len


def compress(data: bytes | bytearray | memoryview) -> bytes:
    """Compress *data* into an LZSS stream that :func:`decompress` restores."""
    src = bytes(data)
    end = len(src)
    out = bytearray()
    pos = 0
    while pos < end:
        flag_at = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if pos >= end:
                break
            distance, length = _longest_match(src, pos, end)
            if length:
                position = (RING_START + pos - distance) & RING_MASK
                out.append(position & 0xFF)
                out.append((position >> 4 & 0xF0) | (length - MIN_MATCH))
                pos += length
            else:
                flags |= 1 << bit
                out.append(src[pos])
                pos += 1
        out[flag_at] = flags
    return bytes(out)
