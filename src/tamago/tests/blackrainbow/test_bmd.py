"""Tests for _BMD image decoding and encoding."""

import io
import struct

import pytest
from PIL import Image

from tamago.formats.blackrainbow import bmd_to_png, decode_bmd, encode_bmd, is_bmd, lzss, png_to_bmd
from tamago.tests.blackrainbow.samples import SPRITE_BGRA, STRIP_BGRA, build_bmd

# The worked example: a red and a blue pixel, opaque, 8 literals.
WORKED = bytes.fromhex('5F424D44 09000000 02000000 01000000 00000000 FF 0000FF00 FF000000')


def _pixels(image):
    return [image.getpixel((x, y)) for y in range(image.height) for x in range(image.width)]


def _header(data):
    return struct.unpack_from('<4sIIII', data)


@pytest.mark.unit
class TestDecode:
    def test_is_bmd(self):
        assert is_bmd(WORKED)
        assert not is_bmd(b'\x89PNG\r\n\x1a\n')
        assert not is_bmd(b'_BM')

    def test_worked_example(self):
        image = decode_bmd(WORKED)
        assert image.mode == 'RGB'
        assert image.size == (2, 1)
        assert _pixels(image) == [(255, 0, 0), (0, 0, 255)]

    def test_alpha_image_is_rgba(self):
        image = decode_bmd(build_bmd(2, 2, SPRITE_BGRA, alpha=1))
        assert image.mode == 'RGBA'
        assert _pixels(image) == [(255, 0, 0, 255), (0, 255, 0, 128), (0, 0, 255, 0), (255, 255, 255, 255)]

    def test_rows_are_top_down(self):
        bgra = bytes([0, 0, 255, 0]) + bytes([255, 0, 0, 0])  # red row above blue row
        image = decode_bmd(build_bmd(1, 2, bgra, alpha=0))
        assert image.getpixel((0, 0)) == (255, 0, 0)
        assert image.getpixel((0, 1)) == (0, 0, 255)

    def test_opaque_image_ignores_stored_alpha(self):
        image = decode_bmd(build_bmd(3, 1, STRIP_BGRA, alpha=0))
        assert image.mode == 'RGB'
        assert _pixels(image) == [(30, 20, 10), (60, 50, 40), (90, 80, 70)]

    def test_bad_magic(self):
        with pytest.raises(ValueError, match='_BMD'):
            decode_bmd(b'_BMX' + WORKED[4:])

    def test_truncated_header(self):
        with pytest.raises(ValueError, match='_BMD'):
            decode_bmd(WORKED[:12])

    def test_short_pixel_data(self):
        with pytest.raises(ValueError):
            decode_bmd(build_bmd(2, 2, SPRITE_BGRA, alpha=1)[:-4])


@pytest.mark.unit
class TestEncode:
    def test_opaque_rgb_writes_zero_alpha(self):
        image = Image.new('RGB', (3, 2), (255, 128, 0))
        data = encode_bmd(image)
        magic, packed, width, height, alpha = _header(data)
        assert (magic, width, height, alpha) == (b'_BMD', 3, 2, 0)
        assert packed == len(data) - 20
        assert lzss.decompress(data[20:], 24) == bytes([0, 128, 255, 0]) * 6

    def test_fully_opaque_rgba_is_stored_as_opaque(self):
        image = Image.new('RGBA', (2, 2), (1, 2, 3, 255))
        assert _header(encode_bmd(image))[4] == 0
        assert decode_bmd(encode_bmd(image)).mode == 'RGB'

    def test_translucent_rgba_keeps_alpha(self):
        image = decode_bmd(build_bmd(2, 2, SPRITE_BGRA, alpha=1))
        data = encode_bmd(image)
        assert _header(data)[4] == 1
        assert decode_bmd(data).tobytes() == image.tobytes()

    @pytest.mark.parametrize('mode', ['L', 'P', 'LA'])
    def test_other_modes_are_converted(self, mode):
        image = Image.new(mode, (4, 3))
        decoded = decode_bmd(encode_bmd(image))
        assert decoded.size == (4, 3)

    def test_roundtrip_opaque(self):
        image = decode_bmd(build_bmd(3, 1, STRIP_BGRA, alpha=0))
        assert decode_bmd(encode_bmd(image)).tobytes() == image.tobytes()


@pytest.mark.unit
class TestPngConversion:
    def test_bmd_to_png(self):
        png = bmd_to_png(build_bmd(2, 2, SPRITE_BGRA, alpha=1))
        with Image.open(io.BytesIO(png)) as image:
            assert image.format == 'PNG'
            assert image.mode == 'RGBA'
            assert image.getpixel((1, 0)) == (0, 255, 0, 128)

    def test_png_to_bmd_roundtrip(self):
        original = build_bmd(3, 1, STRIP_BGRA, alpha=0)
        again = png_to_bmd(bmd_to_png(original))
        assert decode_bmd(again).tobytes() == decode_bmd(original).tobytes()
        assert _header(again)[4] == 0
