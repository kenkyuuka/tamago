"""PRS ("YB") image decoder.

PRS is a Marble engine image format, kept by Fudegaki Soft's engine for the
images in its ``md_gra*.med`` archives.  An image is one flat BGR or BGRA pixel
buffer, compressed with an LZ77 variant and optionally delta-filtered so that
each byte is stored as the difference from the same channel of the previous
pixel.
"""

from __future__ import annotations

import sys
from array import array
from itertools import accumulate

from construct import Const, ConstructError, Int8ul, Int16ul, Int32ul, Struct
from PIL import Image

PRS_MAGIC = b'YB'

_HEADER = Struct(
    'magic' / Const(PRS_MAGIC),
    'flags' / Int8ul,
    'depth' / Int8ul,
    'packed_size' / Int32ul,
    'unknown' / Int32ul,
    'width' / Int16ul,
    'height' / Int16ul,
)
HEADER_SIZE = _HEADER.sizeof()

FLAG_DELTA = 0x80
FLAG_UNSUPPORTED = 0x40

# Long-copy lengths: n + 3, except the two largest codes.
_LONG_LENGTH = [n + 3 for n in range(256)]
_LONG_LENGTH[0xFE] = 0x400
_LONG_LENGTH[0xFF] = 0x1000

_MODES = {3: ('RGB', 'BGR'), 4: ('RGBA', 'BGRA')}


def is_prs(data: bytes) -> bool:
    """Return True if *data* starts with a PRS header."""
    return len(data) >= HEADER_SIZE and data[:2] == PRS_MAGIC and data[3] in _MODES


def _decompress(src: bytes, size: int) -> bytearray:
    """Decompress the LZ stream *src* into a buffer of *size* bytes."""
    out = bytearray(size)
    end = len(src)
    pos = dst = 0
    ctl = bit = 0
    try:
        while dst < size:
            bit >>= 1
            if not bit:
                if pos >= end:
                    break
                ctl = src[pos]
                pos += 1
                bit = 0x80
            if pos >= end:
                break
            b = src[pos]
            pos += 1
            if not ctl & bit:
                out[dst] = b
                dst += 1
                continue
            if b & 0x80:
                v = (b & 0x3F) << 8 | src[pos]
                pos += 1
                if b & 0x40:
                    length = _LONG_LENGTH[src[pos]]
                    pos += 1
                    distance = v + 1
                else:
                    length = (v & 0xF) + 3
                    distance = (v >> 4) + 1
            elif b & 3 == 3:
                length = min((b >> 2) + 9, size - dst)
                if pos + length > end:
                    break
                out[dst : dst + length] = src[pos : pos + length]
                pos += length
                dst += length
                continue
            else:
                length = (b & 3) + 2
                distance = (b >> 2) + 1
            if distance > dst:
                raise ValueError(f"PRS copy distance {distance} reaches before the start of the image")
            length = min(length, size - dst)
            start = dst - distance
            if distance >= length:
                out[dst : dst + length] = out[start : start + length]
            else:
                # Overlapping copy: repeat the last `distance` bytes.
                pattern = out[start:dst]
                out[dst : dst + length] = (pattern * (length // distance + 1))[:length]
            dst += length
    except IndexError:
        raise ValueError("PRS stream ends in the middle of a command") from None
    if dst < size:
        raise ValueError(f"PRS stream ends after {dst} of {size} pixel bytes")
    return out


# Delta decoding packs each pixel's channels into 16-bit lanes of a 64-bit word
# and sums whole pixels.  A lane starts a chunk at no more than 0xFF and gains
# at most 0xFF per pixel, so after _DELTA_CHUNK pixels it holds at most 0xFFFF
# and never carries into its neighbour.
_DELTA_CHUNK = 0x100
_LANE_LOW_BYTES = 0x00FF_00FF_00FF_00FF


def _undo_delta(buf: bytearray, depth: int) -> None:
    """Undo the delta filter: a running sum, modulo 256, of each channel."""
    count = len(buf) // depth
    wide = bytearray(8 * count)
    for channel in range(depth):
        wide[2 * channel :: 8] = buf[channel::depth]
    pixels = array('Q', wide)  # native order: lane c is byte 2c only on little-endian
    if sys.byteorder == 'big':
        pixels.byteswap()
    sums = array('Q')
    carry = 0
    for start in range(0, count, _DELTA_CHUNK):
        chunk = accumulate(pixels[start : start + _DELTA_CHUNK], initial=carry)
        next(chunk)
        sums.extend(chunk)
        carry = sums[-1] & _LANE_LOW_BYTES
    if sys.byteorder == 'big':
        sums.byteswap()
    summed = sums.tobytes()
    for channel in range(depth):
        buf[channel::depth] = summed[2 * channel :: 8]


def decode_prs(data: bytes) -> Image.Image:
    """Decode the PRS image *data* to an RGB or RGBA :class:`PIL.Image.Image`.

    Raises ValueError for data that is not a valid PRS image, and
    NotImplementedError for images with flag 0x40, whose meaning is unknown.
    """
    if data[:2] != PRS_MAGIC:
        raise ValueError("Not a PRS image: missing 'YB' signature")
    try:
        header = _HEADER.parse(data)
    except ConstructError:
        raise ValueError("PRS header is truncated") from None
    if header.depth not in _MODES:
        raise ValueError(f"Unsupported PRS pixel depth {header.depth}")
    if header.flags & FLAG_UNSUPPORTED:
        raise NotImplementedError(f"PRS flag 0x40 is not supported (flags {header.flags:#04x})")
    stream = data[HEADER_SIZE : HEADER_SIZE + header.packed_size]
    if len(stream) < header.packed_size:
        raise ValueError(f"PRS data truncated: {len(stream)} of {header.packed_size} packed bytes")

    pixels = _decompress(stream, header.width * header.height * header.depth)
    if header.flags & FLAG_DELTA:
        _undo_delta(pixels, header.depth)
    mode, raw_mode = _MODES[header.depth]
    return Image.frombytes(mode, (header.width, header.height), bytes(pixels), 'raw', raw_mode)
