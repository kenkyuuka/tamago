"""Tests for YCG image decoding and encoding."""

import io
import struct
import zlib

import pytest
from PIL import Image

from tamago.formats.yuris import decode_ycg, encode_ycg, is_ycg, png_to_ycg, ycg_to_png
from tamago.tests.yuris.samples import build_ycg

# 2x3 BGRA: distinct pixels so band order and channel order both matter.
PIXELS = (
    bytes([0, 0, 255, 255, 0, 255, 0, 255])  # row 0: red, green
    + bytes([255, 0, 0, 255, 255, 255, 255, 128])  # row 1: blue, translucent white
    + bytes([10, 20, 30, 40, 50, 60, 70, 80])  # row 2
)


@pytest.mark.unit
class TestDecode:
    def test_decodes_bands_in_order(self):
        image = decode_ycg(build_ycg(2, 3, PIXELS))
        assert image.mode == 'RGBA'
        assert image.size == (2, 3)
        assert image.getpixel((0, 0)) == (255, 0, 0, 255)
        assert image.getpixel((1, 1)) == (255, 255, 255, 128)
        assert image.getpixel((1, 2)) == (70, 60, 50, 80)

    def test_single_row_has_empty_first_band(self):
        data = build_ycg(1, 1, b'\x01\x02\x03\x04')
        assert struct.unpack_from('<I', data, 0x1C)[0] == 0xFFFFFFFF
        assert decode_ycg(data).getpixel((0, 0)) == (3, 2, 1, 4)

    def test_unsupported_method(self):
        data = bytearray(build_ycg(2, 3, PIXELS))
        data[0x10] = 2
        with pytest.raises(ValueError, match='YSSnp'):
            decode_ycg(bytes(data))

    def test_truncated(self):
        with pytest.raises(ValueError):
            decode_ycg(build_ycg(2, 3, PIXELS)[:-4])

    def test_size_mismatch(self):
        data = bytearray(build_ycg(2, 3, PIXELS))
        data[4] = 3  # width 3: bands no longer cover width * height * 4 bytes
        with pytest.raises(ValueError, match='size'):
            decode_ycg(bytes(data))

    def test_is_ycg(self):
        assert is_ycg(build_ycg(2, 3, PIXELS))
        assert not is_ycg(b'\x89PNG\r\n\x1a\n')


@pytest.mark.unit
class TestEncode:
    @pytest.mark.parametrize('height', [1, 2, 3, 7])
    def test_layout_matches_engine(self, height):
        width = 3
        image = Image.frombytes('RGBA', (width, height), bytes(range(width * height * 4)))
        data = encode_ycg(image)
        magic, w, h, bpp, method, bands = struct.unpack_from('<4sIIIII', data)
        assert (magic, w, h, bpp, method, bands) == (b'YCG\0', width, height, 32, 1, 2)
        first0, last0, size0, comp0 = struct.unpack_from('<iiII', data, 0x18)
        first1, last1, size1, comp1 = struct.unpack_from('<iiII', data, 0x28)
        split = height // 2
        assert (first0, last0, first1, last1) == (0, split - 1, split, height - 1)
        assert (size0, size1) == (split * width * 4, (height - split) * width * 4)
        assert len(data) == 0x38 + comp0 + comp1
        # Even an empty band is a complete zlib stream.
        assert zlib.decompress(data[0x38 : 0x38 + comp0]) == image.tobytes('raw', 'BGRA')[:size0]

    def test_roundtrip(self):
        original = decode_ycg(build_ycg(2, 3, PIXELS))
        assert decode_ycg(encode_ycg(original)).tobytes() == original.tobytes()

    def test_converts_other_modes_to_rgba(self):
        data = encode_ycg(Image.new('RGB', (2, 2), (1, 2, 3)))
        assert decode_ycg(data).getpixel((1, 1)) == (1, 2, 3, 255)


@pytest.mark.unit
class TestPngConversion:
    def test_ycg_to_png_and_back(self):
        ycg = build_ycg(2, 3, PIXELS)
        png = ycg_to_png(ycg)
        assert png.startswith(b'\x89PNG')
        with Image.open(io.BytesIO(png)) as image:
            assert image.mode == 'RGBA'
        assert decode_ycg(png_to_ycg(png)).tobytes() == decode_ycg(ycg).tobytes()
