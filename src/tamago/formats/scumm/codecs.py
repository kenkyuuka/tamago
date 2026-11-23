"""SCUMM bitmap codecs: strip codecs (SMAP), HE whole-image codecs (BMAP) and WIZ TRLE.

Every decoder returns palette indices as a ``bytearray`` in row-major order.
Decoders that know which pixels are transparent also return a ``bytearray``
mask (1 = transparent), or ``None`` when every pixel is opaque.

Data streams in the games sometimes end a few bits early (the last opcode is
read but never used), so reading past the end of a stream yields zero bits.
"""

from __future__ import annotations

STRIP_WIDTH = 8

_SINGLE_BYTES = [bytes([i]) for i in range(256)]

# The "new major/minor" codec's colour steps: note there is no zero step.
_HE_DELTAS = (-4, -3, -2, -1, 1, 2, 3, 4)

# Codec number families (see BMCOMP_* in ScummVM's gfx.h).
_ZIGZAG_V = range(14, 19)
_ZIGZAG_H = range(24, 29)
_ZIGZAG_VT = range(34, 39)
_ZIGZAG_HT = range(44, 49)
_MAJMIN = (*range(64, 69), *range(104, 109))
_MAJMIN_T = (*range(84, 89), *range(124, 129))
_NMAJMIN = range(134, 139)
_NMAJMIN_T = range(144, 149)
RAW = 1
TRLE_8BIT = 8
RLE_8BIT = 9
TRANSPARENT_RAW = 149
SOLID_FILL = 150


class CodecError(ValueError):
    """Bitmap data uses an unknown codec or is truncated."""


class _Bytes:
    """A byte source that yields zeros past its end."""

    __slots__ = ('data', 'end', 'pos')

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else min(end, len(data))

    def next(self) -> int:
        pos = self.pos
        self.pos = pos + 1
        return self.data[pos] if pos < self.end else 0

    def take(self, n: int) -> bytes:
        """The next *n* bytes, zero-padded past the end."""
        pos = self.pos
        self.pos = pos + n
        chunk = self.data[pos : min(pos + n, self.end)] if pos < self.end else b''
        return chunk.ljust(n, b'\0')


def decode_nmajmin(data: bytes, pos: int, count: int, bits: int) -> bytearray:
    """The "new major/minor" codec (BMAP backgrounds, strip codes 134-148): *count* pixels.

    Port of ScummVM's ``Gdi::drawStripHE``.
    """
    src = _Bytes(data, pos)
    mask = (1 << bits) - 1
    out = bytearray(count)
    color = src.next()
    acc = src.next() | (src.next() << 8) | (src.next() << 16)
    have = 24
    last = count - 1
    for i in range(count):
        out[i] = color
        if i == last:
            break
        if have < 1:
            acc |= src.next() << have
            have += 8
        have -= 1
        bit = acc & 1
        acc >>= 1
        if not bit:
            continue
        if have < 1:
            acc |= src.next() << have
            have += 8
        have -= 1
        bit = acc & 1
        acc >>= 1
        if bit:
            if have < 3:
                acc |= src.next() << have
                have += 8
            color = (color + _HE_DELTAS[acc & 7]) & 0xFF
            acc >>= 3
            have -= 3
        else:
            if have < bits:
                acc |= src.next() << have
                have += 8
            color = acc & mask
            acc >>= bits
            have -= bits
    return out


def _decode_basic(data: bytes, pos: int, height: int, bits: int, *, vertical: bool) -> bytearray:
    """The basic ("zigzag") strip codec. Port of ``drawStripBasicH``/``drawStripBasicV``."""
    src = _Bytes(data, pos)
    mask = (1 << bits) - 1
    out = bytearray(STRIP_WIDTH * height)
    color = src.next()
    acc = src.next()
    have = 8
    inc = -1
    if vertical:
        order = [y * STRIP_WIDTH + x for x in range(STRIP_WIDTH) for y in range(height)]
    else:
        order = list(range(STRIP_WIDTH * height))
    for index in order:
        if have <= 8:
            acc |= src.next() << have
            have += 8
        out[index] = color
        have -= 1
        bit = acc & 1
        acc >>= 1
        if not bit:
            continue
        have -= 1
        bit = acc & 1
        acc >>= 1
        if not bit:
            if have <= 8:
                acc |= src.next() << have
                have += 8
            color = acc & mask
            acc >>= bits
            have -= bits
            inc = -1
            continue
        have -= 1
        bit = acc & 1
        acc >>= 1
        if bit:
            inc = -inc
        color = (color + inc) & 0xFF
    return out


def decode_majmin(data: bytes, pos: int, count: int, bits: int) -> bytearray:
    """The major/minor codec (strip codes 64-128): *count* pixels. Port of ``MajMinCodec``."""
    src = _Bytes(data, pos)
    out = bytearray(count)
    color = src.next()
    acc = src.next() | (src.next() << 8)
    have = 16
    repeat = 0
    repeating = False

    def read(n: int) -> int:
        nonlocal acc, have
        if have <= 8:
            acc |= src.next() << have
            have += 8
        value = acc & ((1 << n) - 1)
        have -= n
        acc >>= n
        return value

    for i in range(count):
        out[i] = color
        if repeating:
            repeat -= 1
            if repeat == 0:
                repeating = False
            continue
        if read(1):
            if read(1):
                diff = read(3) - 4
                if diff:
                    color = (color + diff) & 0xFF
                else:
                    repeating = True
                    repeat = read(8) - 1
            else:
                color = read(bits)
    return out


def decode_3do_rle(data: bytes, pos: int, count: int) -> bytearray:
    """The 3DO byte RLE (strip codes 8 and 9): *count* pixels. Port of ``drawStrip3DO``."""
    src = _Bytes(data, pos)
    out = bytearray()
    while len(out) < count:
        b = src.next()
        n = (b >> 1) + 1
        if b & 1:
            out += bytes([src.next()]) * n
        else:
            out += src.take(n)
    del out[count:]
    return out


def decode_byle(data: bytes, pos: int, width: int, height: int, slots: int) -> bytearray:
    """Costume "BYLE" RLE (AKOS codec 1): colour slots in row-major order.

    Runs go down each column in turn; a run byte holds the slot in its high
    bits and the length in its low bits (0: the length is in the next byte).
    The split depends on the number of slots. Port of ``byleRLEDecode``.
    """
    shift, mask = {32: (3, 7), 64: (2, 3)}.get(slots, (4, 15))
    total = width * height
    end = len(data)
    runs = []
    count = 0
    while count < total:
        if pos >= end:
            raise CodecError("costume cel data is truncated")
        b = data[pos]
        pos += 1
        n = b & mask
        if not n:
            if pos >= end:
                raise CodecError("costume cel data is truncated")
            n = data[pos]
            pos += 1
        runs.append(_SINGLE_BYTES[b >> shift] * n)
        count += n
    columns = b''.join(runs)[:total]
    # Transpose from column-major to row-major.
    out = bytearray(total)
    for x in range(width):
        out[x::width] = columns[x * height : (x + 1) * height]
    return out


def decode_raw(data: bytes, pos: int, count: int) -> bytearray:
    out = bytearray(data[pos : pos + count])
    if len(out) < count:
        raise CodecError("raw bitmap data is truncated")
    return out


def mask_of(pixels: bytes | bytearray, transparent: int) -> bytearray | None:
    """A transparency mask marking the pixels equal to *transparent*, or ``None`` if there are none."""
    if not 0 <= transparent <= 255 or transparent not in pixels:
        return None
    table = bytearray(256)
    table[transparent] = 1
    return bytearray(pixels).translate(table)


def decode_strip(data: bytes, pos: int, height: int, transparent: int) -> tuple[bytearray, bytearray | None]:
    """Decode one 8-pixel-wide strip of an SMAP whose codec byte is at *pos*.

    Pixels equal to *transparent* become transparent only for codecs with a
    transparency variant; elsewhere they are ordinary colours.
    """
    if pos >= len(data):
        raise CodecError("strip offset is past the end of the image")
    code = data[pos]
    pos += 1
    bits = code % 10
    count = STRIP_WIDTH * height
    see_through = False
    if code == RAW:
        pixels = decode_raw(data, pos, count)
    elif code == TRANSPARENT_RAW:
        pixels = decode_raw(data, pos, count)
        see_through = True
    elif code in (TRLE_8BIT, RLE_8BIT):
        pixels = decode_3do_rle(data, pos, count)
        see_through = code == TRLE_8BIT
    elif code in _ZIGZAG_V or code in _ZIGZAG_VT:
        pixels = _decode_basic(data, pos, height, bits, vertical=True)
        see_through = code in _ZIGZAG_VT
    elif code in _ZIGZAG_H or code in _ZIGZAG_HT:
        pixels = _decode_basic(data, pos, height, bits, vertical=False)
        see_through = code in _ZIGZAG_HT
    elif code in _MAJMIN or code in _MAJMIN_T:
        pixels = decode_majmin(data, pos, count, bits)
        see_through = code in _MAJMIN_T
    elif code in _NMAJMIN or code in _NMAJMIN_T:
        pixels = decode_nmajmin(data, pos, count, bits)
        see_through = code in _NMAJMIN_T
    else:
        raise CodecError(f"unknown strip codec {code}")
    return pixels, mask_of(pixels, transparent) if see_through else None


def decode_smap(smap: bytes, width: int, height: int, transparent: int) -> tuple[bytearray, bytearray | None]:
    """Decode an SMAP block (*smap* is the whole block, header included) of *width* x *height* pixels.

    The body starts with one u32 offset per strip, relative to the block's tag.
    """
    if width % STRIP_WIDTH:
        raise CodecError(f"SMAP width {width} is not a multiple of {STRIP_WIDTH}")
    strips = width // STRIP_WIDTH
    if 8 + 4 * strips > len(smap):
        raise CodecError("SMAP strip table is truncated")
    pixels = bytearray(width * height)
    mask = bytearray(width * height)
    any_transparent = False
    for strip in range(strips):
        offset = int.from_bytes(smap[8 + 4 * strip : 12 + 4 * strip], 'little')
        strip_pixels, strip_mask = decode_strip(smap, offset, height, transparent)
        x0 = strip * STRIP_WIDTH
        for y in range(height):
            row = y * width + x0
            pixels[row : row + STRIP_WIDTH] = strip_pixels[y * STRIP_WIDTH : (y + 1) * STRIP_WIDTH]
            if strip_mask is not None:
                mask[row : row + STRIP_WIDTH] = strip_mask[y * STRIP_WIDTH : (y + 1) * STRIP_WIDTH]
        any_transparent = any_transparent or strip_mask is not None
    return pixels, mask if any_transparent else None


def decode_trle(data: bytes, pos: int, width: int, height: int) -> tuple[bytearray, bytearray | None]:
    """WIZ transparent RLE (WIZ codec 1, BMAP object codes 8/9). Port of ``auxDecompTRLEStream``.

    Each row is a u16 byte count and a run of opcodes; unwritten pixels are transparent.
    """
    pixels = bytearray(width * height)
    mask = bytearray(b'\1') * (width * height)
    end = len(data)
    for y in range(height):
        if pos + 2 > end:
            raise CodecError("TRLE data is truncated")
        line_size = int.from_bytes(data[pos : pos + 2], 'little')
        pos += 2
        line_end = pos + line_size
        x = 0
        row = y * width
        src = _Bytes(data, pos, line_end)
        while line_size and x < width:
            b = src.next()
            if b & 1:
                x += b >> 1
                continue
            n = min((b >> 2) + 1, width - x)
            if b & 2:
                color = src.next()
                pixels[row + x : row + x + n] = bytes([color]) * n
            else:
                pixels[row + x : row + x + n] = src.take((b >> 2) + 1)[:n]
            mask[row + x : row + x + n] = bytes(n)
            x += n
        pos = line_end
    return pixels, mask if 1 in mask else None
