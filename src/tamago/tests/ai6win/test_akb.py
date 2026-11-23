"""Tests for AKB image decoding and encoding."""

import io
import json
import random
import struct

import pytest
from PIL import Image, PngImagePlugin

from tamago.formats.ai6win.akb import (
    FLAG_CROPPED,
    FLAG_RGB,
    HEADER_SIZE,
    PNG_TEXT_KEY,
    _delta,
    _undelta,
    akb_to_png,
    decode_akb,
    encode_akb,
    is_akb,
    png_to_akb,
    read_header,
)
from tamago.tests.ai6win.samples import (
    AKB_EMPTY,
    AKB_RGB_CROPPED,
    AKB_RGBA,
    PICTURE,
    akb_filter,
    build_akb,
)

WHITE_BG = (0xFF, 0xFF, 0xFF)


def _header(data):
    magic = data[:4]
    width, height, flags = struct.unpack_from('<HHI', data, 4)
    return magic, width, height, flags, data[12:16], struct.unpack_from('<4i', data, 16)


def _png(image, meta=None):
    info = None
    if meta is not None:
        info = PngImagePlugin.PngInfo()
        info.add_text(PNG_TEXT_KEY, json.dumps(meta))
    out = io.BytesIO()
    image.save(out, format='PNG', pnginfo=info)
    return out.getvalue()


def _picture_image(mode='RGBA'):
    image = Image.new('RGBA', (3, 2))
    image.putdata([px for row in PICTURE for px in row])
    return image.convert(mode)


@pytest.mark.unit
class TestIsAKB:
    def test_plain_and_incremental(self):
        assert is_akb(AKB_RGBA)
        assert is_akb(b'AKB+' + AKB_RGBA[4:])

    @pytest.mark.parametrize('data', [b'', AKB_RGBA[: HEADER_SIZE - 1], b'AKBX' + AKB_RGBA[4:], b'\x89PNG' * 10])
    def test_other_data(self, data):
        assert not is_akb(data)


@pytest.mark.unit
class TestDecode:
    def test_32_bit_keeps_alpha_without_flag(self):
        image = decode_akb(AKB_RGBA)
        assert image.mode == 'RGBA'
        assert image.size == (3, 2)
        assert [image.getpixel((x, y)) for y in range(2) for x in range(3)] == [px for row in PICTURE for px in row]

    def test_24_bit_cropped_on_background(self):
        image = decode_akb(AKB_RGB_CROPPED)
        assert image.mode == 'RGB'
        assert image.size == (5, 4)
        for y in range(4):
            for x in range(5):
                if 1 <= x < 4 and 1 <= y < 3:
                    expected = PICTURE[y - 1][x - 1][:3]
                else:
                    expected = WHITE_BG
                assert image.getpixel((x, y)) == expected, (x, y)

    def test_32_bit_background_is_bgra(self):
        # The background of a cropped 32-bit image keeps its alpha byte.
        data = build_akb(2, 1, FLAG_CROPPED, bytes([0x4E, 0xC1, 0xF2, 0x80]), (0, 0, 1, 1), [bytes(4)])
        assert decode_akb(data).getpixel((1, 0)) == (0xF2, 0xC1, 0x4E, 0x80)

    def test_empty_image_is_background(self):
        image = decode_akb(AKB_EMPTY)
        assert image.mode == 'RGB'
        assert image.size == (4, 3)
        assert image.getcolors() == [(12, (0, 0, 0))]

    def test_incremental_refused(self):
        with pytest.raises(ValueError, match='AKB\\+'):
            decode_akb(b'AKB+' + AKB_RGBA[4:])

    @pytest.mark.parametrize('rect', [(0, 0, 4, 2), (0, 0, 3, 3), (2, 0, 1, 2), (-1, 0, 2, 2)])
    def test_rectangle_outside_canvas(self, rect):
        data = AKB_RGBA[:16] + struct.pack('<4i', *rect) + AKB_RGBA[32:]
        with pytest.raises(ValueError, match='rectangle'):
            decode_akb(data)

    def test_truncated_stream(self):
        with pytest.raises(ValueError):
            decode_akb(AKB_RGBA[:-3])

    def test_not_akb(self):
        with pytest.raises(ValueError, match='not an AKB'):
            decode_akb(b'Down the rabbit-hole' * 3)


@pytest.mark.unit
class TestFilter:
    @pytest.mark.parametrize('pixel_size', [3, 4])
    def test_matches_obvious_implementation(self, pixel_size):
        rng = random.Random(1865)  # noqa: S311 — deterministic seed for test reproducibility
        stride = 7 * pixel_size
        rows = [bytes(rng.randrange(256) for _ in range(stride)) for _ in range(5)]
        # Rows of 0x80 and 0xFF bytes exercise the bytewise carry handling.
        rows += [b'\x80' * stride, b'\xff' * stride, bytes(stride), b'\x7f' * stride]
        pixels = b''.join(rows)
        filtered = akb_filter(rows, pixel_size)
        assert _delta(pixels, stride, pixel_size) == filtered
        assert _undelta(filtered, stride, pixel_size) == pixels

    def test_single_row(self):
        assert _undelta(_delta(b'Alice!', 6, 3), 6, 3) == b'Alice!'


@pytest.mark.unit
class TestEncode:
    def test_rgba_whole_canvas(self):
        image = _picture_image()
        data = encode_akb(image)
        assert _header(data) == (b'AKB ', 3, 2, 0, bytes(4), (0, 0, 3, 2))
        assert decode_akb(data).tobytes() == image.tobytes()

    def test_rgb_whole_canvas(self):
        image = _picture_image('RGB')
        data = encode_akb(image)
        assert _header(data) == (b'AKB ', 3, 2, FLAG_RGB | 0xFF, bytes(4), (0, 0, 3, 2))
        assert decode_akb(data).tobytes() == image.tobytes()

    def test_crops_to_pixels_that_differ_from_background(self):
        image = Image.new('RGBA', (6, 5))
        image.paste(_picture_image(), (2, 1))
        data = encode_akb(image)
        assert _header(data) == (b'AKB ', 6, 5, FLAG_CROPPED, bytes(4), (2, 1, 5, 3))
        assert decode_akb(data).tobytes() == image.tobytes()

    def test_given_background_and_rectangle(self):
        decoded = decode_akb(AKB_RGB_CROPPED)
        data = encode_akb(decoded, b'\xff\xff\xff\xff', (1, 1, 4, 3))
        assert _header(data) == _header(AKB_RGB_CROPPED)
        assert decode_akb(data).tobytes() == decoded.tobytes()

    def test_rectangle_grows_to_cover_edits(self):
        image = decode_akb(AKB_RGB_CROPPED)
        image.putpixel((4, 3), (0xB0, 0x4C, 0xA8))
        data = encode_akb(image, b'\xff\xff\xff\xff', (1, 1, 4, 3))
        assert _header(data)[5] == (1, 1, 5, 4)
        assert decode_akb(data).tobytes() == image.tobytes()

    def test_empty_rectangle_replaced_by_edits(self):
        image = decode_akb(AKB_EMPTY)
        image.putpixel((2, 1), WHITE_BG)
        data = encode_akb(image, b'\0\0\0\xff', (0, 0, 0, 0))
        assert _header(data)[5] == (2, 1, 3, 2)

    def test_empty_image_is_header_only(self):
        data = encode_akb(decode_akb(AKB_EMPTY), b'\0\0\0\xff', (0, 0, 0, 0))
        assert data == AKB_EMPTY

    def test_transparent_image_is_header_only(self):
        data = encode_akb(Image.new('RGBA', (4, 3)))
        assert data == b'AKB ' + struct.pack('<HHI', 4, 3, FLAG_CROPPED) + bytes(20)

    def test_colour_hidden_by_zero_alpha_is_kept(self):
        image = Image.new('RGBA', (2, 2))
        image.putpixel((1, 1), (0xB0, 0x4C, 0xA8, 0))
        assert _header(encode_akb(image))[5] == (1, 1, 2, 2)

    @pytest.mark.parametrize(('mode', 'expected'), [('L', 'RGB'), ('P', 'RGB'), ('LA', 'RGBA')])
    def test_other_modes_converted(self, mode, expected):
        image = _picture_image().convert(mode)
        assert decode_akb(encode_akb(image)).mode == expected

    @pytest.mark.parametrize(
        ('background', 'rect', 'match'),
        [(b'\0\0\0', None, 'background'), (None, (0, 0, 4, 2), 'rectangle'), (None, (2, 0, 1, 2), 'rectangle')],
    )
    def test_bad_arguments(self, background, rect, match):
        with pytest.raises(ValueError, match=match):
            encode_akb(_picture_image(), background, rect)

    def test_too_large(self):
        with pytest.raises(ValueError, match='at most'):
            encode_akb(Image.new('RGB', (0x10000, 1)))


@pytest.mark.unit
class TestPNG:
    @pytest.mark.parametrize(
        'akb',
        [
            encode_akb(_picture_image()),
            encode_akb(decode_akb(AKB_RGB_CROPPED), b'\xff\xff\xff\xff', (1, 1, 4, 3)),
            AKB_EMPTY,
        ],
        ids=['rgba', 'rgb-cropped', 'empty'],
    )
    def test_roundtrip_is_byte_identical(self, akb):
        assert png_to_akb(akb_to_png(akb)) == akb

    def test_metadata(self):
        with Image.open(io.BytesIO(akb_to_png(AKB_RGB_CROPPED))) as image:
            assert json.loads(image.text[PNG_TEXT_KEY]) == {
                'bpp': 24,
                'background': 'ffffffff',
                'rect': [1, 1, 4, 3],
            }

    def test_without_metadata(self):
        image = _picture_image()
        assert png_to_akb(_png(image)) == encode_akb(image)

    def test_24_bit_saved_with_opaque_alpha(self):
        rgb = decode_akb(AKB_RGB_CROPPED)
        meta = {'bpp': 24, 'background': 'ffffffff', 'rect': [1, 1, 4, 3]}
        data = png_to_akb(_png(rgb.convert('RGBA'), meta))
        assert read_header(data).flags & FLAG_RGB
        assert decode_akb(data).tobytes() == rgb.tobytes()

    def test_24_bit_given_real_transparency_becomes_32_bit(self):
        image = decode_akb(AKB_RGB_CROPPED).convert('RGBA')
        image.putpixel((0, 0), (0, 0, 0, 0))
        data = png_to_akb(_png(image, {'bpp': 24}))
        assert not read_header(data).flags & FLAG_RGB

    def test_32_bit_saved_without_alpha(self):
        data = png_to_akb(_png(_picture_image('RGB'), {'bpp': 32}))
        assert not read_header(data).flags & FLAG_RGB

    @pytest.mark.parametrize(
        'text',
        ['not json', '[1, 2]', '{"bpp": 16}', '{"background": "zz"}', '{"rect": [1, 2]}', '{"rect": 5}'],
    )
    def test_bad_metadata(self, text):
        info = PngImagePlugin.PngInfo()
        info.add_text(PNG_TEXT_KEY, text)
        out = io.BytesIO()
        _picture_image().save(out, format='PNG', pnginfo=info)
        with pytest.raises(ValueError, match=PNG_TEXT_KEY):
            png_to_akb(out.getvalue())
