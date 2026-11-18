"""BlackRainbow _BMD images: LZSS-compressed 32-bit BGRA bitmaps.

A 20-byte header (``_BMD``, packed size, width, height, alpha flag) is followed
by an LZSS stream that unpacks to ``width * height * 4`` bytes of top-down
BGRA pixels.  With the alpha flag clear the image is opaque and the fourth
byte of each pixel is stored as zero.
"""

import io

from construct import Const, Int32ul, Struct
from PIL import Image

from tamago.formats.blackrainbow import lzss

BMD_MAGIC = b'_BMD'

BMDHeader = Struct(
    'magic' / Const(BMD_MAGIC),
    'packed_size' / Int32ul,
    'width' / Int32ul,
    'height' / Int32ul,
    'alpha' / Int32ul,
)
HEADER_SIZE = BMDHeader.sizeof()


def is_bmd(data: bytes) -> bool:
    """Return True if *data* starts with a _BMD header."""
    return len(data) >= HEADER_SIZE and data[:4] == BMD_MAGIC


def decode_bmd(data: bytes) -> Image.Image:
    """Decode _BMD *data* to an RGBA image, or RGB if the image is opaque."""
    if not is_bmd(data):
        raise ValueError("not a _BMD image (bad magic or truncated header)")
    header = BMDHeader.parse(data)
    stream = data[HEADER_SIZE : HEADER_SIZE + header.packed_size]
    if len(stream) != header.packed_size:
        raise ValueError(f"_BMD data is truncated: {len(stream)} of {header.packed_size} packed bytes")
    pixels = lzss.decompress(stream, header.width * header.height * 4)
    size = (header.width, header.height)
    if header.alpha:
        return Image.frombytes('RGBA', size, pixels, 'raw', 'BGRA')
    return Image.frombytes('RGB', size, pixels, 'raw', 'BGRX')


def encode_bmd(image: Image.Image) -> bytes:
    """Encode *image* as _BMD.

    An image with any pixel less than fully opaque keeps its alpha channel;
    any other image is stored as opaque, with zero alpha bytes.
    """
    rgba = image if image.mode == 'RGBA' else image.convert('RGBA')
    has_alpha = rgba.getchannel('A').getextrema() != (255, 255)
    if not has_alpha:
        # Opaque images keep a zero in the fourth byte of each pixel.
        rgba = rgba.copy()
        rgba.putalpha(0)
    pixels = rgba.tobytes('raw', 'BGRA')
    stream = lzss.compress(pixels)
    header = BMDHeader.build(
        {'packed_size': len(stream), 'width': rgba.width, 'height': rgba.height, 'alpha': int(has_alpha)}
    )
    return header + stream


def bmd_to_png(data: bytes) -> bytes:
    """Convert _BMD *data* to PNG file contents."""
    out = io.BytesIO()
    decode_bmd(data).save(out, format='PNG')
    return out.getvalue()


def png_to_bmd(data: bytes) -> bytes:
    """Convert PNG (or any image Pillow reads) file contents to _BMD."""
    with Image.open(io.BytesIO(data)) as image:
        image.load()
        return encode_bmd(image)
