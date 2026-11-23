"""AKB images, the bitmap format of elf's AI6WIN engine.

An AKB file is a 32-byte header followed by an LZSS stream (the same Okumura
LZSS as the archives).  The header gives the canvas size, two flags, a
background colour and the rectangle of the canvas whose pixels are stored;
the rest of the canvas is the background colour.  The stored pixels are BGRA,
or BGR when :data:`FLAG_RGB` is set, delta-filtered (the top row from the
pixel to its left, every other row from the row above) and then written
bottom row first.

Re-encoding with :func:`tamago.formats.ai6win.lzss.compress` reproduces the
games' files byte for byte, given the original background colour and
rectangle.  :func:`akb_to_png` keeps both in a PNG text chunk so that
:func:`png_to_akb` can put them back.

Incremental ``AKB+`` images, which are drawn over another image named in
their header, are recognised but not decoded.
"""

import io
import json

from construct import Bytes, Int16ul, Int32sl, Int32ul, Struct
from PIL import Image, ImageChops, PngImagePlugin

from tamago.formats.ai6win import lzss

MAGIC = b'AKB '
INCREMENTAL_MAGIC = b'AKB+'

FLAG_CROPPED = 0x80000000
"""Only the header's rectangle is stored; the rest of the canvas is background."""
FLAG_RGB = 0x40000000
"""Pixels are 24-bit BGR rather than 32-bit BGRA."""
RGB_LOW_BYTE = 0xFF
"""Every 24-bit image in the games has this in the flags' low byte (meaning unknown)."""

Header = Struct(
    'magic' / Bytes(4),
    'width' / Int16ul,
    'height' / Int16ul,
    'flags' / Int32ul,
    'background' / Bytes(4),  # B, G, R, A
    'left' / Int32sl,
    'top' / Int32sl,
    'right' / Int32sl,
    'bottom' / Int32sl,
)
HEADER_SIZE = Header.sizeof()

PNG_TEXT_KEY = 'tamago:akb'
"""PNG text chunk in which :func:`akb_to_png` records what the pixels don't show."""

_MAX_SIZE = 0xFFFF


def is_akb(data: bytes) -> bool:
    """Return True if *data* starts with an AKB header (plain or incremental)."""
    return len(data) >= HEADER_SIZE and data[:4] in (MAGIC, INCREMENTAL_MAGIC)


def _fill(mode: str, background: bytes) -> tuple[int, ...]:
    b, g, r, a = background
    return (r, g, b) if mode == 'RGB' else (r, g, b, a)


def _row_masks(stride: int) -> tuple[int, int]:
    return int.from_bytes(b'\x7f' * stride, 'little'), int.from_bytes(b'\x80' * stride, 'little')


def _undelta(stream: bytes, stride: int, pixel_size: int) -> bytes:
    """Reverse the delta filter on *stream* (rows bottom first), returning rows top first."""
    rows = [stream[i : i + stride] for i in range(len(stream) - stride, -1, -stride)]
    top = bytearray(rows[0])
    for i in range(pixel_size, stride):
        top[i] = (top[i] + top[i - pixel_size]) & 0xFF
    out = [bytes(top)]
    # Add each row to the one above it bytewise, all bytes at once: add the
    # low seven bits of each byte, then put back the XOR of the top bits.
    low, high = _row_masks(stride)
    above = int.from_bytes(top, 'little')
    for row in rows[1:]:
        delta = int.from_bytes(row, 'little')
        above = ((above & low) + (delta & low)) ^ ((above ^ delta) & high)
        out.append(above.to_bytes(stride, 'little'))
    return b''.join(out)


def _delta(pixels: bytes, stride: int, pixel_size: int) -> bytes:
    """Apply the delta filter to *pixels* (rows top first), returning rows bottom first."""
    top = pixels[:stride]
    first = bytearray(top)
    for i in range(pixel_size, stride):
        first[i] = (top[i] - top[i - pixel_size]) & 0xFF
    out = [bytes(first)]
    # Bytewise subtraction without borrows between bytes, as in _undelta.
    low, high = _row_masks(stride)
    above = int.from_bytes(top, 'little')
    for start in range(stride, len(pixels), stride):
        row = int.from_bytes(pixels[start : start + stride], 'little')
        diff = ((row | high) - (above & low)) ^ ((row ^ ~above) & high)
        out.append(diff.to_bytes(stride, 'little'))
        above = row
    return b''.join(reversed(out))


def read_header(data: bytes):
    """Parse and check the header of the AKB image *data*, raising ValueError if it is not one."""
    if not is_akb(data):
        raise ValueError("not an AKB image (bad magic or truncated header)")
    header = Header.parse(data)
    if not (0 <= header.left <= header.right <= header.width and 0 <= header.top <= header.bottom <= header.height):
        raise ValueError(
            f"AKB rectangle ({header.left}, {header.top})-({header.right}, {header.bottom}) "
            f"does not fit its {header.width}x{header.height} canvas"
        )
    return header


def decode_akb(data: bytes) -> Image.Image:
    """Decode AKB *data* to an RGBA image, or RGB for a 24-bit image."""
    header = read_header(data)
    if header.magic == INCREMENTAL_MAGIC:
        raise ValueError("incremental AKB+ images are drawn over another image and are not supported")
    mode, raw_mode, pixel_size = ('RGB', 'BGR', 3) if header.flags & FLAG_RGB else ('RGBA', 'BGRA', 4)
    image = Image.new(mode, (header.width, header.height), _fill(mode, header.background))
    width, height = header.right - header.left, header.bottom - header.top
    if width and height:
        stride = width * pixel_size
        stream = lzss.decompress(data[HEADER_SIZE:], stride * height)
        pixels = _undelta(stream, stride, pixel_size)
        image.paste(Image.frombytes(mode, (width, height), pixels, 'raw', raw_mode), (header.left, header.top))
    return image


def _bbox(image: Image.Image, fill: tuple[int, ...]) -> tuple[int, int, int, int] | None:
    """The bounding box of the pixels of *image* that are not *fill*, or None."""
    diff = ImageChops.difference(image, Image.new(image.mode, image.size, fill))
    # Band by band: for RGBA, getbbox() may look at alpha alone.
    boxes = [box for box in (band.getbbox() for band in diff.split()) if box]
    if not boxes:
        return None
    return (
        min(b[0] for b in boxes),
        min(b[1] for b in boxes),
        max(b[2] for b in boxes),
        max(b[3] for b in boxes),
    )


def encode_akb(
    image: Image.Image,
    background: bytes | None = None,
    rect: tuple[int, int, int, int] | None = None,
) -> bytes:
    """Encode *image* as AKB: 24-bit if it is RGB, else 32-bit.

    *background* is the header's four colour bytes (B, G, R, A), and *rect*
    the (left, top, right, bottom) rectangle of pixels to store.  By default
    the rectangle is the bounding box of the pixels that differ from the
    background, and the background is transparent black (opaque black for a
    24-bit image), or zero when the whole canvas is stored.  A given
    rectangle is enlarged if pixels outside it differ from the background.
    """
    if image.mode not in ('RGB', 'RGBA'):
        has_alpha = 'A' in image.getbands() or 'transparency' in image.info
        image = image.convert('RGBA' if has_alpha else 'RGB')
    rgb = image.mode == 'RGB'
    width, height = image.size
    if width > _MAX_SIZE or height > _MAX_SIZE:
        raise ValueError(f"AKB images can be at most {_MAX_SIZE}x{_MAX_SIZE}, not {width}x{height}")
    if background is not None and len(background) != 4:
        raise ValueError(f"AKB background must be 4 bytes, not {len(background)}")

    fill_bytes = background if background is not None else (b'\0\0\0\xff' if rgb else bytes(4))
    bbox = _bbox(image, _fill(image.mode, fill_bytes))
    if rect is None:
        rect = bbox or (0, 0, 0, 0)
    else:
        left, top, right, bottom = rect
        if not (0 <= left <= right <= width and 0 <= top <= bottom <= height):
            raise ValueError(f"AKB rectangle {rect} does not fit the {width}x{height} image")
        if bbox and not (left <= bbox[0] and top <= bbox[1] and bbox[2] <= right and bbox[3] <= bottom):
            if left == right or top == bottom:
                rect = bbox
            else:
                rect = (min(left, bbox[0]), min(top, bbox[1]), max(right, bbox[2]), max(bottom, bbox[3]))
    cropped = tuple(rect) != (0, 0, width, height)
    if background is None and not cropped:
        background = bytes(4)
    elif background is None:
        background = fill_bytes

    flags = (FLAG_RGB | RGB_LOW_BYTE if rgb else 0) | (FLAG_CROPPED if cropped else 0)
    left, top, right, bottom = rect
    header = Header.build(
        {
            'magic': MAGIC,
            'width': width,
            'height': height,
            'flags': flags,
            'background': background,
            'left': left,
            'top': top,
            'right': right,
            'bottom': bottom,
        }
    )
    if left == right or top == bottom:
        return header
    pixel_size = 3 if rgb else 4
    pixels = image.crop(rect).tobytes('raw', 'BGR' if rgb else 'BGRA')
    return header + lzss.compress(_delta(pixels, (right - left) * pixel_size, pixel_size))


def akb_to_png(data: bytes) -> bytes:
    """Convert AKB *data* to PNG file contents that :func:`png_to_akb` turns back into the same bytes."""
    header = read_header(data)
    image = decode_akb(data)
    meta = {
        'bpp': 24 if header.flags & FLAG_RGB else 32,
        'background': header.background.hex(),
        'rect': [header.left, header.top, header.right, header.bottom],
    }
    info = PngImagePlugin.PngInfo()
    info.add_text(PNG_TEXT_KEY, json.dumps(meta, separators=(',', ':')))
    out = io.BytesIO()
    image.save(out, format='PNG', pnginfo=info)
    return out.getvalue()


def _parse_meta(text: str) -> tuple[int | None, bytes | None, tuple[int, int, int, int] | None]:
    try:
        meta = json.loads(text)
        bpp = meta.get('bpp')
        background = bytes.fromhex(meta['background']) if 'background' in meta else None
        rect = tuple(int(v) for v in meta['rect']) if 'rect' in meta else None
        if bpp not in (None, 24, 32) or (rect is not None and len(rect) != 4):
            raise ValueError(text)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError(f"bad {PNG_TEXT_KEY} PNG metadata: {text!r}") from None
    return bpp, background, rect  # type: ignore[return-value]


def png_to_akb(data: bytes) -> bytes:
    """Convert PNG (or any image Pillow reads) file contents to AKB.

    The bit depth, background and rectangle recorded by :func:`akb_to_png`
    are used if present.  A 24-bit image that an editor saved with an alpha
    channel is stored as 24-bit again, provided every pixel is opaque, and a
    32-bit image saved without one stays 32-bit.
    """
    with Image.open(io.BytesIO(data)) as image:
        image.load()
        text = getattr(image, 'text', {}).get(PNG_TEXT_KEY)
        bpp, background, rect = _parse_meta(text) if text is not None else (None, None, None)
        if bpp == 24 and image.mode != 'RGB':
            rgba = image.convert('RGBA')
            if rgba.getchannel('A').getextrema() == (255, 255):
                return encode_akb(rgba.convert('RGB'), background, rect)
        if bpp == 32 and image.mode == 'RGB':
            return encode_akb(image.convert('RGBA'), background, rect)
        return encode_akb(image, background, rect)
