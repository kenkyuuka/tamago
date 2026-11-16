"""YU-RIS YCG images.

A YCG is a 0x18-byte header (``YCG\\0``, width, height, bpp = 32, method,
band count = 2), two 16-byte band descriptors (first row, last row, unpacked
size, compressed size), then each band's compressed stream.  The pixels are
top-down BGRA; band 0 holds rows ``0 .. h//2 - 1`` and band 1 the rest, so an
image one row tall has an empty first band (last row -1), whose stream is still
a complete zlib stream.

Method 1 is zlib.  Method 2 ("YSSnp") is not documented anywhere and has not
been seen in a game; it is rejected.

YCGs are stored in YPF archives under ``.png`` names with file type 8.
"""

import io
import zlib

from construct import Const, Int32ul, Struct
from PIL import Image

YCG_MAGIC = b'YCG\0'
METHOD_ZLIB = 1
METHOD_YSSNP = 2

_HEADER = Struct(
    'magic' / Const(YCG_MAGIC),
    'width' / Int32ul,
    'height' / Int32ul,
    'bpp' / Int32ul,
    'method' / Int32ul,
    'bands' / Int32ul,
)
_BAND = Struct(
    'first_row' / Int32ul,
    'last_row' / Int32ul,
    'size' / Int32ul,
    'compressed_size' / Int32ul,
)
HEADER_SIZE = _HEADER.sizeof()
BAND_SIZE = _BAND.sizeof()
DATA_OFFSET = HEADER_SIZE + 2 * BAND_SIZE


def is_ycg(data: bytes) -> bool:
    """Return True if *data* starts with the YCG signature."""
    return data[:4] == YCG_MAGIC


def decode_ycg(data: bytes) -> Image.Image:
    """Decode the YCG image *data* to an RGBA :class:`PIL.Image.Image`.

    Raises ValueError if it is not a YCG, uses an unsupported method or depth,
    or its bands are truncated or do not hold the whole image.
    """
    if not is_ycg(data) or len(data) < DATA_OFFSET:
        raise ValueError("not a YCG image")
    header = _HEADER.parse(data)
    if header.method == METHOD_YSSNP:
        raise ValueError("YCG compression method 2 (YSSnp) is not supported")
    if header.method != METHOD_ZLIB:
        raise ValueError(f"unknown YCG compression method {header.method}")
    if header.bpp != 32:
        raise ValueError(f"unsupported YCG depth: {header.bpp} bpp")

    pixels = bytearray()
    offset = DATA_OFFSET
    for i in range(2):
        band = _BAND.parse(data[HEADER_SIZE + i * BAND_SIZE :])
        stream = data[offset : offset + band.compressed_size]
        if len(stream) != band.compressed_size:
            raise ValueError(f"YCG band {i} is truncated")
        try:
            unpacked = zlib.decompress(stream)
        except zlib.error as e:
            raise ValueError(f"YCG band {i} is corrupt: {e}") from None
        if len(unpacked) != band.size:
            raise ValueError(f"YCG band {i} unpacks to {len(unpacked)} bytes, expected {band.size}")
        pixels += unpacked
        offset += band.compressed_size

    expected = header.width * header.height * 4
    if len(pixels) != expected:
        raise ValueError(
            f"YCG bands hold {len(pixels)} bytes, but a {header.width}x{header.height} image needs size {expected}"
        )
    return Image.frombytes('RGBA', (header.width, header.height), bytes(pixels), 'raw', 'BGRA')


def encode_ycg(image: Image.Image, level: int = 9) -> bytes:
    """Encode *image* as a zlib YCG, split into two bands like the engine's own."""
    if image.mode != 'RGBA':
        image = image.convert('RGBA')
    width, height = image.size
    pixels = image.tobytes('raw', 'BGRA')
    split = height // 2
    cut = split * width * 4
    bands = [(0, split - 1, pixels[:cut]), (split, height - 1, pixels[cut:])]

    out = bytearray(_HEADER.build({'width': width, 'height': height, 'bpp': 32, 'method': METHOD_ZLIB, 'bands': 2}))
    streams = []
    for first, last, raw in bands:
        stream = zlib.compress(raw, level)
        streams.append(stream)
        # The first band of a one-row image ends at row -1.
        out += _BAND.build(
            {'first_row': first, 'last_row': last & 0xFFFFFFFF, 'size': len(raw), 'compressed_size': len(stream)}
        )
    for stream in streams:
        out += stream
    return bytes(out)


def ycg_to_png(data: bytes) -> bytes:
    """Convert the YCG image *data* to an RGBA PNG."""
    out = io.BytesIO()
    decode_ycg(data).save(out, format='PNG')
    return out.getvalue()


def png_to_ycg(data: bytes) -> bytes:
    """Convert the image file *data* (normally a PNG) to a YCG."""
    with Image.open(io.BytesIO(data)) as image:
        return encode_ycg(image)
