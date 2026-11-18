"""Tests for PSB texture pixel formats."""

import pytest
from PIL import Image

from tamago.formats.psb import Resource
from tamago.formats.psb import textures as t

# A 2x2 image: a white rabbit, a red queen, a blue caterpillar, a clear pool of tears.
PIXELS = [(255, 255, 255, 255), (200, 16, 46, 255), (40, 80, 200, 128), (0, 0, 0, 0)]


def pixels(im):
    return [im.getpixel((x, y)) for y in range(im.height) for x in range(im.width)]


def image():
    im = Image.new('RGBA', (2, 2))
    im.putdata(PIXELS)
    return im


@pytest.mark.unit
class TestDecode:
    def test_rgba8_is_stored_bgra(self):
        data = bytes([255, 255, 255, 255, 46, 16, 200, 255, 200, 80, 40, 128, 0, 0, 0, 0])
        assert pixels(t.decode('RGBA8', 2, 2, data)) == PIXELS

    def test_rgba4444_low_bits_are_blue(self):
        # u16 0xF00A: A=15, R=0, G=0, B=10.
        im = t.decode('RGBA4444', 1, 1, b'\x0a\xf0')
        assert im.getpixel((0, 0)) == (0, 0, 170, 255)

    def test_a8l8_is_luminance_then_alpha(self):
        im = t.decode('A8L8', 1, 1, b'\x40\x80')
        assert im.mode == 'LA' and im.getpixel((0, 0)) == (0x40, 0x80)

    def test_a8_is_white_with_alpha(self):
        assert t.decode('A8', 1, 1, b'\x7f').getpixel((0, 0)) == (255, 255, 255, 0x7F)

    def test_l8(self):
        assert t.decode('L8', 1, 1, b'\x33').getpixel((0, 0)) == 0x33

    def test_rl_runs_and_literals(self):
        # A run of 4 copies of one pixel (0x80 | 1), then 2 literal pixels (0x01).
        data = b'\x81' + bytes([1, 2, 3, 4]) + b'\x01' + bytes([5, 6, 7, 8, 9, 10, 11, 12])
        im = t.decode('RL', 3, 2, data)
        assert im.tobytes('raw', 'BGRA') == bytes([1, 2, 3, 4]) * 4 + bytes(range(5, 13))

    def test_dxt1(self):
        # One block, both colours pure red (0xF800), every index 0.
        block = b'\x00\xf8\x00\xf8' + b'\x00' * 4
        im = t.decode('DXT1', 4, 4, block)
        assert im.getpixel((3, 3)) == (255, 0, 0, 255)

    def test_unknown(self):
        with pytest.raises(ValueError):
            t.decode('ASTC', 1, 1, b'')


@pytest.mark.unit
class TestEncode:
    @pytest.mark.parametrize('kind', t.ENCODABLE)
    def test_roundtrip(self, kind):
        data = t.encode(kind, image())
        assert t.encode(kind, t.decode(kind, 2, 2, data)) == data

    def test_rgba8_is_lossless(self):
        assert pixels(t.decode('RGBA8', 2, 2, t.encode('RGBA8', image()))) == PIXELS

    def test_rl_long_run(self):
        im = Image.new('RGBA', (300, 1), (1, 2, 3, 4))
        data = t.encode('RL', im)
        assert len(data) < 30
        assert t.decode('RL', 300, 1, data).tobytes() == im.tobytes()

    def test_cannot_encode_dxt(self):
        with pytest.raises(ValueError):
            t.encode('DXT5', image())


@pytest.mark.unit
class TestTextureImage:
    def test_crops_to_truncated_size(self):
        texture = {
            'type': 'RGBA8',
            'width': 2,
            'height': 2,
            'truncated_width': 1,
            'truncated_height': 2,
            'pixel': Resource(0),
        }
        resources = [t.encode('RGBA8', image())]
        assert t.texture_image(texture, resources).size == (1, 2)
        assert t.texture_image(texture, resources, crop=False).size == (2, 2)

    def test_iter_textures(self):
        root = {'source': {'tex': {'texture': {'type': 'A8'}}, 'other': {'icon': {}}}}
        assert list(t.iter_textures(root)) == [('tex', {'type': 'A8'})]
        assert list(t.iter_textures({})) == []
