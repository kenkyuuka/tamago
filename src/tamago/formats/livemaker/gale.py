"""Gale image format decoder (LiveMaker engine).

Decodes Gale images to PIL Image objects.  Supports two generations:

- **Gale 103-107** (magic ``Gale<NNN>``): the classic format with a binary
  fixed header.
- **GaleX200** (magic ``GaleX200``): the newer variant whose header is a
  zlib-compressed XML document.  Per-layer pixel/alpha bytes use the same
  layout as Gale 103-107.

Compression modes 0 (zlib+blocks) and 1 (raw blocks) are supported.  The
older 100-102 layout, JPEG compression, and row/block shuffling (which
requires a per-game key) are not; attempting to decode one raises
:class:`NotImplementedError` or :class:`ValueError`.
"""

from __future__ import annotations

import io
import os
import re
import struct
import xml.etree.ElementTree as ET
import zlib

try:
    from PIL import Image
except ImportError:  # pragma: no cover - tested indirectly
    Image = None  # type: ignore[assignment,misc]

from tamago.formats.livemaker.crypto import TpRandom

GALE_MAGIC_PREFIX = b'Gale'
GALEX_MAGIC = b'GaleX200'


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


class _Layer:
    __slots__ = ('pixels', 'alpha')

    def __init__(self, pixels: bytearray, alpha: bytearray | None):
        self.pixels = pixels
        self.alpha = alpha


class _Frame:
    __slots__ = ('width', 'height', 'bpp', 'stride', 'alpha_stride', 'palette', 'layers')

    def __init__(self, width: int, height: int, bpp: int, palette: list[tuple[int, int, int]] | None):
        self.width = width
        self.height = height
        self.bpp = bpp
        self.palette = palette
        self.layers: list[_Layer] = []
        # Row stride: packed bits rounded up to whole bytes; for >=8bpp,
        # padded to a multiple of 4 bytes per BMP convention.
        stride = (width * bpp + 7) // 8
        if bpp >= 8:
            stride = (stride + 3) & ~3
        self.stride = stride
        self.alpha_stride = (width + 3) & ~3


class _Header:
    __slots__ = (
        'version',
        'width',
        'height',
        'bpp',
        'frame_count',
        'shuffled',
        'compression',
        'mask',
        'block_width',
        'block_height',
        'data_offset',
    )

    def __init__(self):
        self.version = 0
        self.width = 0
        self.height = 0
        self.bpp = 0
        self.frame_count = 0
        self.shuffled = False
        self.compression = 0
        self.mask = 0
        self.block_width = 0
        self.block_height = 0
        self.data_offset = 0


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


def _parse_header(data: bytes) -> _Header:
    if len(data) < 11 or data[:4] != GALE_MAGIC_PREFIX:
        raise ValueError("Not a Gale image (missing magic)")

    # Decode the three ASCII version digits.
    try:
        version_digits = data[4:7].decode('ascii')
        version = int(version_digits)
    except (UnicodeDecodeError, ValueError):
        raise ValueError(f"Unrecognized Gale version: {data[4:7]!r}")

    if version < 103 or version > 107:
        raise NotImplementedError(f"Gale version {version} is not supported")

    header_size = struct.unpack_from('<I', data, 7)[0]
    if header_size < 0x28 or header_size > 0x100:
        raise ValueError(f"Unreasonable Gale header size: {header_size}")
    if 11 + header_size > len(data):
        raise ValueError("Truncated Gale header")

    body = data[11 : 11 + header_size]
    inner_version = struct.unpack_from('<i', body, 0)[0]
    if inner_version != version:
        raise ValueError(f"Gale version mismatch: magic={version}, header={inner_version}")

    h = _Header()
    h.version = version
    h.width = struct.unpack_from('<I', body, 4)[0]
    h.height = struct.unpack_from('<I', body, 8)[0]
    h.bpp = struct.unpack_from('<i', body, 0xC)[0]
    h.frame_count = struct.unpack_from('<i', body, 0x10)[0]
    h.shuffled = body[0x15] != 0
    h.compression = body[0x16]
    h.mask = struct.unpack_from('<I', body, 0x18)[0]
    h.block_width = struct.unpack_from('<i', body, 0x1C)[0]
    h.block_height = struct.unpack_from('<i', body, 0x20)[0]
    h.data_offset = 11 + header_size

    if h.compression not in (0, 1, 2):
        raise ValueError(f"Unknown Gale compression mode: {h.compression}")
    if h.bpp not in (4, 8, 16, 24, 32):
        raise ValueError(f"Unsupported Gale BPP: {h.bpp}")
    if h.frame_count < 1:
        raise ValueError(f"Gale frame count must be positive (got {h.frame_count})")

    return h


# ---------------------------------------------------------------------------
# Shuffling
# ---------------------------------------------------------------------------


def _random_sequence(count: int, key: int):
    """Yield a permutation of ``range(count)`` seeded by *key*.

    Matches GARbro's ``RandomSequence``: each step picks a position within
    the remaining elements using ``prng.next_uint32() % len(remaining)``
    and removes it.
    """
    tp = TpRandom(seed=key)
    order = list(range(count))
    for _ in range(count):
        n = tp.next_uint32() % len(order)
        yield order.pop(n)


def _unshuffle_blocks(refs: list[int], count: int, key: int) -> list[int]:
    """Return a copy of *refs* with block references un-shuffled.

    The original encoder took the permutation order ``seq[i]`` produced by
    :func:`_random_sequence` and wrote the i-th source entry into slot
    ``seq[i]``.  To reverse, read slot ``seq[i]`` as the i-th source entry.
    """
    out = list(refs)
    src = 0
    for index in _random_sequence(count, key):
        out[index * 2] = refs[src]
        out[index * 2 + 1] = refs[src + 1]
        src += 2
    return out


# ---------------------------------------------------------------------------
# Block-level pixel reader
# ---------------------------------------------------------------------------


def _read_blocks(
    source: bytes,
    pos: int,
    frame: _Frame,
    is_alpha: bool,
    header: _Header,
    key: int,
    frames: list[_Frame],
) -> tuple[bytearray, int]:
    """Decode one layer's pixel or alpha plane from *source* starting at *pos*.

    Returns ``(pixels, new_pos)``.
    """
    width = frame.width
    height = frame.height
    bpp = 8 if is_alpha else frame.bpp
    stride = frame.alpha_stride if is_alpha else frame.stride

    if header.block_width <= 0 or header.block_height <= 0:
        # No block reference table; the layer is a flat stream of scanlines,
        # optionally with rows permuted by the shuffle key.
        total = stride * height
        if header.shuffled:
            pixels = bytearray(total)
            for dst_row in _random_sequence(height, key):
                start = dst_row * stride
                pixels[start : start + stride] = source[pos : pos + stride]
                pos += stride
        else:
            pixels = bytearray(source[pos : pos + total])
            pos += total
        return pixels, pos

    blocks_w = (width + header.block_width - 1) // header.block_width
    blocks_h = (height + header.block_height - 1) // header.block_height
    blocks_count = blocks_w * blocks_h

    refs_bytes = blocks_count * 8
    if pos + refs_bytes > len(source):
        raise ValueError("Truncated Gale block reference table")
    refs = list(struct.unpack_from(f'<{blocks_count * 2}i', source, pos))
    pos += refs_bytes

    if header.shuffled:
        refs = _unshuffle_blocks(refs, blocks_count, key)

    pixels = bytearray(stride * height)
    i = 0
    for y in range(0, height, header.block_height):
        bh = min(header.block_height, height - y)
        for x in range(0, width, header.block_width):
            dst = y * stride + (x * bpp + 7) // 8
            bw = min(header.block_width, width - x)
            chunk_size = (bw * bpp + 7) // 8

            frame_ref = refs[i]
            layer_ref = refs[i + 1]
            if frame_ref == -1:
                # Literal block: read `bh` rows of `chunk_size` bytes.
                if pos + bh * chunk_size > len(source):
                    raise ValueError("Truncated Gale literal block data")
                for _ in range(bh):
                    pixels[dst : dst + chunk_size] = source[pos : pos + chunk_size]
                    pos += chunk_size
                    dst += stride
            elif frame_ref == -2:
                # Self-reference: copy the rectangle at another block position
                # within this layer.
                src_x = header.block_width * (layer_ref % blocks_w)
                src_y = header.block_height * (layer_ref // blocks_w)
                src = src_y * stride + (src_x * bpp + 7) // 8
                for _ in range(bh):
                    pixels[dst : dst + chunk_size] = pixels[src : src + chunk_size]
                    src += stride
                    dst += stride
            else:
                # Cross-frame reference: copy the same-offset rectangle from
                # a previously-decoded frame/layer.
                if frame_ref >= len(frames):
                    raise ValueError(f"Gale frame reference {frame_ref} out of range")
                if layer_ref >= len(frames[frame_ref].layers):
                    raise ValueError(f"Gale layer reference {layer_ref} out of range")
                src_layer = frames[frame_ref].layers[layer_ref]
                src_plane = src_layer.alpha if is_alpha else src_layer.pixels
                if src_plane is None:
                    raise ValueError("Gale references alpha plane on a layer without alpha")
                for _ in range(bh):
                    pixels[dst : dst + chunk_size] = src_plane[dst : dst + chunk_size]
                    dst += stride
            i += 2

    return pixels, pos


def _decode_layer_payload(
    payload: bytes,
    frame: _Frame,
    is_alpha: bool,
    header: _Header,
    key: int,
    frames: list[_Frame],
) -> bytearray:
    """Apply the compression mode and return the decoded pixel/alpha plane."""
    if header.compression == 0 or (header.compression == 2 and is_alpha):
        # zlib-wrapped block stream.
        decompressed = zlib.decompress(payload)
        pixels, _ = _read_blocks(decompressed, 0, frame, is_alpha, header, key, frames)
        return pixels
    if header.compression == 2:
        # JPEG pixel plane (alpha goes through the branch above).
        return _decode_jpeg(payload, frame)
    # Compression 1: raw block stream.
    pixels, _ = _read_blocks(payload, 0, frame, is_alpha, header, key, frames)
    return pixels


def _decode_jpeg(payload: bytes, frame: _Frame) -> bytearray:
    """Decode a JPEG-compressed pixel plane.

    JPEG output sets the frame's bpp and stride to match the decoded bitmap
    (RGB24 or L8).  JPEG does not pad rows to a 4-byte boundary, so the
    adjusted stride is tight.
    """
    if Image is None:  # pragma: no cover - guarded by open_gal
        raise ImportError("Pillow is required for Gale JPEG decoding")
    jpeg = Image.open(io.BytesIO(payload))
    jpeg.load()
    if jpeg.mode == 'RGB':
        frame.bpp = 24
        frame.stride = jpeg.width * 3
        rgb = jpeg.tobytes()
        # JPEG layers are stored in RGB order on disk but our flattening
        # code expects BGR (matching the classic Gale pixel order).
        pixels = bytearray(len(rgb))
        pixels[0::3] = rgb[2::3]
        pixels[1::3] = rgb[1::3]
        pixels[2::3] = rgb[0::3]
        return pixels
    if jpeg.mode == 'L':
        frame.bpp = 8
        frame.stride = jpeg.width
        return bytearray(jpeg.tobytes())
    if jpeg.mode == 'CMYK':
        converted = jpeg.convert('RGB')
        frame.bpp = 24
        frame.stride = converted.width * 3
        data = converted.tobytes()
        pixels = bytearray(len(data))
        pixels[0::3] = data[2::3]
        pixels[1::3] = data[1::3]
        pixels[2::3] = data[0::3]
        return pixels
    raise ValueError(f"Unexpected Gale JPEG mode: {jpeg.mode}")


# ---------------------------------------------------------------------------
# Frame parser
# ---------------------------------------------------------------------------


def _read_u32(stream: io.BufferedIOBase) -> int:
    buf = stream.read(4)
    if len(buf) != 4:
        raise ValueError("Unexpected end of Gale stream while reading uint32")
    return struct.unpack('<I', buf)[0]


def _read_i32(stream: io.BufferedIOBase) -> int:
    buf = stream.read(4)
    if len(buf) != 4:
        raise ValueError("Unexpected end of Gale stream while reading int32")
    return struct.unpack('<i', buf)[0]


def _read_palette(stream: io.BufferedIOBase, bpp: int) -> list[tuple[int, int, int]]:
    """Read a (1<<bpp)-entry BGRX palette and return it as a list of RGB tuples."""
    count = 1 << bpp
    data = stream.read(count * 4)
    if len(data) != count * 4:
        raise ValueError("Truncated Gale palette")
    # BGRX in the file → store as (R, G, B) for later flattening.
    return [(data[i * 4 + 2], data[i * 4 + 1], data[i * 4]) for i in range(count)]


# ---------------------------------------------------------------------------
# GaleX200 header and frame parsing
# ---------------------------------------------------------------------------


_FRAME_ATTR_RE = re.compile(rb'<Frame [^>]+>')


def _parse_galx_header(data: bytes) -> tuple[_Header, ET.Element]:
    """Parse the GaleX200 zlib+XML header.

    Returns the common ``_Header`` view and the XML ``<Frames>`` root so
    subsequent frame/layer parsing can look up attributes by name.
    """
    if len(data) < 12:
        raise ValueError("Truncated GaleX200 header")
    header_size = struct.unpack_from('<I', data, 8)[0]
    if header_size <= 0 or 12 + header_size > len(data):
        raise ValueError(f"Unreasonable GaleX200 header size: {header_size}")

    xml_bytes = zlib.decompress(data[12 : 12 + header_size])
    # GARbro notes that GaleXml sometimes contains duplicate attributes on
    # <Frame> elements, which standard XML parsers reject.  Since frame-level
    # attributes are unused by our decoder, we strip them entirely.
    xml_bytes = _FRAME_ATTR_RE.sub(b'<Frame>', xml_bytes)
    # Gale headers are authored by the LiveMaker tooling and travel inside a
    # binary archive the caller has already chosen to read; standard library
    # XML parsing is adequate here.
    root = ET.fromstring(xml_bytes)  # noqa: S314
    if root.tag != 'Frames':
        raise ValueError(f"Unexpected GaleX200 root element: {root.tag!r}")

    attrs = root.attrib
    h = _Header()
    try:
        h.version = int(attrs['Version'])
        h.width = int(attrs['Width'])
        h.height = int(attrs['Height'])
        h.bpp = int(attrs['Bpp'])
        h.frame_count = int(attrs['Count'])
        h.shuffled = attrs.get('Randomized', '0') != '0'
        h.compression = int(attrs['CompType'])
        h.mask = int(attrs.get('BGColor', '0')) & 0xFFFFFFFF
        h.block_width = int(attrs['BlockWidth'])
        h.block_height = int(attrs['BlockHeight'])
    except KeyError as e:
        raise ValueError(f"GaleX200 header missing attribute: {e}")

    if h.compression not in (0, 1, 2):
        raise ValueError(f"Unknown GaleX200 compression mode: {h.compression}")
    if h.bpp not in (4, 8, 16, 24, 32):
        raise ValueError(f"Unsupported GaleX200 BPP: {h.bpp}")

    h.data_offset = 12 + header_size
    return h, root


def _parse_galx_palette(text: str, bpp: int) -> list[tuple[int, int, int]]:
    """Parse a GaleX200 palette: hex ``RRGGBB`` entries, back-to-back."""
    text = text.strip()
    colors = 1 << bpp
    available = len(text) // 6
    count = min(colors, available)
    palette: list[tuple[int, int, int]] = []
    for i in range(count):
        chunk = text[i * 6 : i * 6 + 6]
        r = int(chunk[0:2], 16)
        g = int(chunk[2:4], 16)
        b = int(chunk[4:6], 16)
        palette.append((r, g, b))
    # Pad with black if the XML somehow provided fewer entries than expected.
    while len(palette) < colors:
        palette.append((0, 0, 0))
    return palette


def _parse_galx_frame(
    stream: io.BufferedIOBase,
    header: _Header,
    xml_root: ET.Element,
    key: int,
    frames: list[_Frame],
) -> _Frame:
    """Decode the first frame of a GaleX200 image using the XML metadata."""
    frame_node = xml_root.find('Frame')
    if frame_node is None:
        raise ValueError("GaleX200 XML has no <Frame> element")
    layers_node = frame_node.find('Layers')
    if layers_node is None:
        raise ValueError("GaleX200 XML has no <Frame>/<Layers> element")

    attrs = layers_node.attrib
    try:
        width = int(attrs['Width'])
        height = int(attrs['Height'])
        bpp = int(attrs['Bpp'])
    except KeyError as e:
        raise ValueError(f"GaleX200 Layers missing attribute: {e}")

    palette = None
    if bpp <= 8:
        rgb = layers_node.find('RGB')
        if rgb is not None and rgb.text:
            palette = _parse_galx_palette(rgb.text, bpp)

    frame = _Frame(width, height, bpp, palette)

    for layer_node in layers_node.findall('Layer'):
        alpha_on = layer_node.attrib.get('AlphaOn', '0') != '0'
        pixel_size = _read_i32(stream)
        pixel_payload = stream.read(pixel_size)
        if len(pixel_payload) != pixel_size:
            raise ValueError("Truncated GaleX200 pixel payload")
        pixel_plane = _decode_layer_payload(pixel_payload, frame, False, header, key, frames)

        alpha_plane: bytearray | None = None
        if alpha_on:
            alpha_size = _read_i32(stream)
            alpha_payload = stream.read(alpha_size)
            if len(alpha_payload) != alpha_size:
                raise ValueError("Truncated GaleX200 alpha payload")
            alpha_plane = _decode_layer_payload(alpha_payload, frame, True, header, key, frames)
        frame.layers.append(_Layer(pixel_plane, alpha_plane))

    return frame


# ---------------------------------------------------------------------------
# Gale 103-107 frame parser
# ---------------------------------------------------------------------------


def _parse_frame(
    stream: io.BufferedIOBase,
    header: _Header,
    key: int,
    frames: list[_Frame],
) -> _Frame:
    """Parse one frame (header + palette + all its layers) from *stream*."""
    name_length = _read_u32(stream)
    stream.read(name_length)  # frame name, ignored
    _read_u32(stream)  # per-frame mask (informational)
    stream.read(9)  # reserved
    layer_count = _read_i32(stream)
    if layer_count < 1:
        raise ValueError(f"Gale layer count must be positive (got {layer_count})")

    width = _read_i32(stream)
    height = _read_i32(stream)
    bpp = _read_i32(stream)
    if bpp <= 0:
        raise ValueError(f"Invalid Gale frame bpp: {bpp}")

    palette = _read_palette(stream, bpp) if bpp <= 8 else None
    frame = _Frame(width, height, bpp, palette)

    for _ in range(layer_count):
        _read_i32(stream)  # left
        _read_i32(stream)  # top
        stream.read(1)  # visible flag
        _read_i32(stream)  # transparent colour
        _read_i32(stream)  # alpha
        stream.read(1)  # alpha_on
        layer_name_length = _read_u32(stream)
        stream.read(layer_name_length)  # layer name
        if header.version >= 107:
            stream.read(1)  # lock flag

        pixel_size = _read_i32(stream)
        pixel_payload = stream.read(pixel_size)
        if len(pixel_payload) != pixel_size:
            raise ValueError("Truncated Gale pixel payload")
        pixel_plane = _decode_layer_payload(pixel_payload, frame, False, header, key, frames)

        alpha_size = _read_i32(stream)
        alpha_plane: bytearray | None = None
        if alpha_size != 0:
            alpha_payload = stream.read(alpha_size)
            if len(alpha_payload) != alpha_size:
                raise ValueError("Truncated Gale alpha payload")
            alpha_plane = _decode_layer_payload(alpha_payload, frame, True, header, key, frames)

        frame.layers.append(_Layer(pixel_plane, alpha_plane))

    return frame


# ---------------------------------------------------------------------------
# Flattening to RGB / RGBA
# ---------------------------------------------------------------------------


def _flatten(frame: _Frame) -> Image.Image:
    """Convert the first layer of *frame* into a PIL Image."""
    layer = frame.layers[0]
    if layer.alpha is None:
        return _flatten_opaque(frame, layer)
    return _flatten_with_alpha(frame, layer)


def _flatten_opaque(frame: _Frame, layer: _Layer) -> Image.Image:
    width, height, bpp = frame.width, frame.height, frame.bpp
    stride = frame.stride
    pixels = layer.pixels
    out = bytearray(width * height * 3)
    dst = 0

    if bpp == 24:
        for y in range(height):
            src = y * stride
            for _ in range(width):
                out[dst] = pixels[src + 2]
                out[dst + 1] = pixels[src + 1]
                out[dst + 2] = pixels[src]
                dst += 3
                src += 3
    elif bpp == 32:
        for y in range(height):
            src = y * stride
            for _ in range(width):
                out[dst] = pixels[src + 2]
                out[dst + 1] = pixels[src + 1]
                out[dst + 2] = pixels[src]
                dst += 3
                src += 4
    elif bpp == 16:
        for y in range(height):
            src = y * stride
            for _ in range(width):
                pixel = pixels[src] | (pixels[src + 1] << 8)
                out[dst] = (pixel & 0xF800) * 0xFF // 0xF800
                out[dst + 1] = (pixel & 0x07E0) * 0xFF // 0x07E0
                out[dst + 2] = (pixel & 0x001F) * 0xFF // 0x001F
                dst += 3
                src += 2
    elif bpp == 8:
        palette = frame.palette or []
        for y in range(height):
            src = y * stride
            for x in range(width):
                r, g, b = palette[pixels[src + x]]
                out[dst] = r
                out[dst + 1] = g
                out[dst + 2] = b
                dst += 3
    elif bpp == 4:
        palette = frame.palette or []
        for y in range(height):
            row = y * stride
            for x in range(width):
                packed = pixels[row + x // 2]
                index = (packed & 0xF) if (x & 1) == 0 else (packed >> 4)
                r, g, b = palette[index]
                out[dst] = r
                out[dst + 1] = g
                out[dst + 2] = b
                dst += 3
    else:
        raise ValueError(f"Unsupported Gale bpp: {bpp}")

    return Image.frombytes("RGB", (width, height), bytes(out))


def _flatten_with_alpha(frame: _Frame, layer: _Layer) -> Image.Image:
    width, height, bpp = frame.width, frame.height, frame.bpp
    stride = frame.stride
    alpha_stride = frame.alpha_stride
    pixels = layer.pixels
    alpha = layer.alpha
    assert alpha is not None
    out = bytearray(width * height * 4)
    dst = 0

    if bpp == 24:
        for y in range(height):
            src = y * stride
            a = y * alpha_stride
            for x in range(width):
                out[dst] = pixels[src + 2]
                out[dst + 1] = pixels[src + 1]
                out[dst + 2] = pixels[src]
                out[dst + 3] = alpha[a + x]
                dst += 4
                src += 3
    elif bpp == 32:
        for y in range(height):
            src = y * stride
            a = y * alpha_stride
            for x in range(width):
                out[dst] = pixels[src + 2]
                out[dst + 1] = pixels[src + 1]
                out[dst + 2] = pixels[src]
                out[dst + 3] = alpha[a + x]
                dst += 4
                src += 4
    elif bpp == 16:
        for y in range(height):
            src = y * stride
            a = y * alpha_stride
            for x in range(width):
                pixel = pixels[src] | (pixels[src + 1] << 8)
                out[dst] = (pixel & 0xF800) * 0xFF // 0xF800
                out[dst + 1] = (pixel & 0x07E0) * 0xFF // 0x07E0
                out[dst + 2] = (pixel & 0x001F) * 0xFF // 0x001F
                out[dst + 3] = alpha[a + x]
                dst += 4
                src += 2
    elif bpp == 8:
        palette = frame.palette or []
        for y in range(height):
            src = y * stride
            a = y * alpha_stride
            for x in range(width):
                r, g, b = palette[pixels[src + x]]
                out[dst] = r
                out[dst + 1] = g
                out[dst + 2] = b
                out[dst + 3] = alpha[a + x]
                dst += 4
    elif bpp == 4:
        palette = frame.palette or []
        for y in range(height):
            row = y * stride
            a = y * alpha_stride
            for x in range(width):
                packed = pixels[row + x // 2]
                index = (packed & 0xF) if (x & 1) == 0 else (packed >> 4)
                r, g, b = palette[index]
                out[dst] = r
                out[dst + 1] = g
                out[dst + 2] = b
                out[dst + 3] = alpha[a + x]
                dst += 4
    else:
        raise ValueError(f"Unsupported Gale bpp: {bpp}")

    return Image.frombytes("RGBA", (width, height), bytes(out))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def open_gal(image: str | os.PathLike | io.BufferedIOBase, key: int = 0) -> Image.Image:
    """Open a Gale image and return a PIL Image.

    Args:
        image: Path to a ``.gal`` file or a file-like object opened in
            binary mode.
        key: 32-bit shuffle key for games that apply row/block scrambling.
            Unused for unshuffled images.

    Returns:
        A PIL ``Image`` in ``RGB`` mode (when the source has no alpha
        channel) or ``RGBA`` (when alpha data is present).

    Raises:
        ValueError: If *image* is not a valid Gale file.
        NotImplementedError: For formats not supported by this decoder
            (GaleX200, versions <103, JPEG-compressed layers, shuffled
            images when *key* cannot decode them).
        ImportError: If Pillow is not installed.
    """
    if Image is None:
        raise ImportError("Pillow is required for Gale image conversion. Install it with: pip install Pillow")

    if isinstance(image, (str, os.PathLike)):
        with open(image, 'rb') as f:
            data = f.read()
    else:
        data = image.read()

    # Dispatch on magic: GaleX200 uses a zlib-compressed XML header, while
    # Gale 103-107 uses a binary fixed header.
    is_galx = data[:8] == GALEX_MAGIC
    if is_galx:
        header, xml_root = _parse_galx_header(data)
    else:
        header = _parse_header(data)
        xml_root = None

    if header.shuffled and key == 0:
        raise NotImplementedError("Shuffled Gale images require a per-game 32-bit key; none provided")

    stream = io.BytesIO(data)
    stream.seek(header.data_offset)
    frames: list[_Frame] = []
    # Decode only the first frame and its layers; matches GARbro behaviour.
    # Frame 0 can reference only previously-decoded layers within itself,
    # so no further frames need to be read.
    if is_galx:
        assert xml_root is not None
        frame = _parse_galx_frame(stream, header, xml_root, key, frames)
    else:
        frame = _parse_frame(stream, header, key, frames)
    frames.append(frame)
    return _flatten(frame)
