"""Decoding and encoding the pixel data of PSB textures.

An E-mote model lists its texture atlases under ``source``: each entry has a
``texture`` dict like::

    {'type': 'RGBA8', 'width': 1024, 'height': 1024,
     'truncated_width': 988, 'truncated_height': 986, 'pixel': Resource(0)}

The atlas is ``width`` x ``height`` (powers of two); only the top-left
``truncated_width`` x ``truncated_height`` is used.  Its parts (``icon``) give
their rectangles within the atlas.

Pixel formats, as stored (rows top to bottom, no padding):

========== ==================================================================
``RGBA8``  4 bytes per pixel, in the order B, G, R, A (D3D's A8R8G8B8)
``RGBA4444`` 2 bytes per pixel, a u16 LE: B in bits 0-3, then G, R, A
``A8L8``   2 bytes per pixel: luminance, then alpha
``L8``     1 byte per pixel, luminance
``A8``     1 byte per pixel, alpha
``DXT1``   BC1 blocks
``DXT5``   BC3 blocks
``RL``     RGBA8 (B, G, R, A) compressed with a byte-oriented run length code
========== ==================================================================
"""

from __future__ import annotations

from PIL import Image

from tamago.formats.psb.values import Resource

#: Pixel formats :func:`encode` can produce.
ENCODABLE = ('RGBA8', 'RGBA4444', 'A8L8', 'L8', 'A8', 'RL')


def _rle_decode(data: bytes, size: int) -> bytes:
    """Decode ``RL``: a count byte ``n``; if bit 7 is clear, ``n + 1`` literal pixels follow,
    else one pixel repeated ``(n & 0x7F) + 3`` times."""
    out = bytearray()
    i = 0
    while len(out) < size and i < len(data):
        n = data[i]
        i += 1
        if n & 0x80:
            out += data[i : i + 4] * ((n & 0x7F) + 3)
            i += 4
        else:
            out += data[i : i + 4 * (n + 1)]
            i += 4 * (n + 1)
    if len(out) < size:
        raise ValueError('RL pixel data is truncated')
    return bytes(out[:size])


def _rle_encode(data: bytes) -> bytes:
    pixels = [data[i : i + 4] for i in range(0, len(data), 4)]
    out = bytearray()
    literal: list[bytes] = []

    def flush():
        while literal:
            run = literal[:128]
            del literal[:128]
            out.append(len(run) - 1)
            out.extend(b''.join(run))

    i = 0
    while i < len(pixels):
        j = i + 1
        while j < len(pixels) and j - i < 130 and pixels[j] == pixels[i]:
            j += 1
        if j - i >= 3:
            flush()
            out.append(0x80 | (j - i - 3))
            out.extend(pixels[i])
            i = j
        else:
            literal.append(pixels[i])
            i += 1
    flush()
    return bytes(out)


def decode(kind: str, width: int, height: int, data: bytes) -> Image.Image:
    """Decode *data*, a *width* x *height* texture of pixel format *kind*.

    Returns an ``RGBA`` image, except ``LA`` for ``A8L8``, ``L`` for ``L8``
    and an ``RGBA`` white image with the alpha for ``A8``.
    """
    size = (width, height)
    if kind == 'RGBA8':
        return Image.frombytes('RGBA', size, data, 'raw', 'BGRA')
    if kind == 'RL':
        return Image.frombytes('RGBA', size, _rle_decode(data, 4 * width * height), 'raw', 'BGRA')
    if kind == 'RGBA4444':
        # Pillow's RGBA;4B takes red from the low bits; here they're blue.
        r, g, b, a = Image.frombytes('RGBA', size, data, 'raw', 'RGBA;4B').split()
        return Image.merge('RGBA', (b, g, r, a))
    if kind == 'A8L8':
        return Image.frombytes('LA', size, data)
    if kind == 'L8':
        return Image.frombytes('L', size, data)
    if kind == 'A8':
        alpha = Image.frombytes('L', size, data)
        im = Image.new('RGBA', size, (255, 255, 255, 0))
        im.putalpha(alpha)
        return im
    if kind == 'DXT1':
        return Image.frombytes('RGBA', size, data, 'bcn', 1)
    if kind == 'DXT5':
        return Image.frombytes('RGBA', size, data, 'bcn', 3)
    raise ValueError(f'unsupported PSB texture format {kind!r}')


def encode(kind: str, image: Image.Image) -> bytes:
    """Encode *image* as pixel format *kind* (one of :data:`ENCODABLE`)."""
    if kind == 'RGBA8':
        return image.convert('RGBA').tobytes('raw', 'BGRA')
    if kind == 'RL':
        return _rle_encode(image.convert('RGBA').tobytes('raw', 'BGRA'))
    if kind == 'RGBA4444':
        raw = image.convert('RGBA').tobytes('raw', 'BGRA')
        out = bytearray(len(raw) // 2)
        for i in range(0, len(raw), 4):
            b, g, r, a = ((c + 8) // 17 for c in raw[i : i + 4])
            out[i // 2] = b | g << 4
            out[i // 2 + 1] = r | a << 4
        return bytes(out)
    if kind == 'A8L8':
        return image.convert('LA').tobytes()
    if kind == 'L8':
        return image.convert('L').tobytes()
    if kind == 'A8':
        return image.convert('RGBA').getchannel('A').tobytes()
    raise ValueError(f'cannot encode PSB texture format {kind!r}')


def texture_image(texture: dict, resources: list, *, crop: bool = True) -> Image.Image:
    """Decode a model's ``texture`` dict, its pixels taken from *resources*.

    With *crop*, the image is cut to the used area (``truncated_width`` x
    ``truncated_height``) when the texture gives one.
    """
    pixel = texture['pixel']
    if not isinstance(pixel, Resource):
        raise ValueError('the texture has no pixel resource')
    im = decode(texture['type'], int(texture['width']), int(texture['height']), resources[pixel.index])
    if crop and 'truncated_width' in texture and 'truncated_height' in texture:
        im = im.crop((0, 0, int(texture['truncated_width']), int(texture['truncated_height'])))
    return im


def iter_textures(root: dict):
    """Yield (source name, texture dict) for each texture atlas under ``root['source']``."""
    sources = root.get('source')
    if not isinstance(sources, dict):
        return
    for name, source in sources.items():
        if isinstance(source, dict) and isinstance(source.get('texture'), dict):
            yield name, source['texture']
