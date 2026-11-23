"""Tests for the SCUMM bitmap codecs, with hand-traced bit streams."""

import pytest

from tamago.formats.scumm import codecs
from tamago.tests.scumm.samples import BACKGROUND_BMAP, BACKGROUND_PIXELS, WIZ_TRLE, BitWriter


@pytest.mark.unit
class TestNewMajMin:
    def test_literal_then_repeats(self):
        # BMAP body: codec 138, first colour 0x2A, then "1 0 <8-bit 7>" and zeros.
        assert list(codecs.decode_nmajmin(BACKGROUND_BMAP, 1, len(BACKGROUND_PIXELS), 8)) == BACKGROUND_PIXELS

    def test_small_steps(self):
        # "1 1 <3-bit 7>" adds +4; "1 1 <3-bit 0>" adds -4.
        stream = bytes([10]) + BitWriter().put(1).put(1).put(7, 3).put(1).put(1).put(0, 3).bytes(pad_to=3)
        assert list(codecs.decode_nmajmin(stream, 0, 3, 8)) == [10, 14, 10]

    def test_short_literals(self):
        # With 4-bit literals (codec 134) a literal reads only 4 bits.
        stream = bytes([1]) + BitWriter().put(1).put(0).put(0xF, 4).put(1).put(0).put(3, 4).bytes(pad_to=3)
        assert list(codecs.decode_nmajmin(stream, 0, 3, 4)) == [1, 15, 3]

    def test_colour_wraps(self):
        stream = bytes([254]) + BitWriter().put(1).put(1).put(7, 3).bytes(pad_to=3)
        assert list(codecs.decode_nmajmin(stream, 0, 2, 8)) == [254, 2]


@pytest.mark.unit
class TestMajMin:
    def test_trace(self):
        stream = bytes([10]) + (
            BitWriter()
            .put(0)  # pixel 0 (10): no change
            .put(1)
            .put(0)
            .put(0x20, 8)  # pixel 1 (10): literal 0x20
            .put(1)
            .put(1)
            .put(7, 3)  # pixel 2 (0x20): +3
            .put(1)
            .put(1)
            .put(4, 3)
            .put(3, 8)  # pixel 3 (0x23): step 0 = run; 3 more identical pixels
            .put(1)
            .put(0)
            .put(0x40, 8)  # pixel 6 (0x23, run over): literal 0x40
            .bytes(pad_to=2)
        )
        assert list(codecs.decode_majmin(stream, 0, 8, 8)) == [10, 10, 0x20, 0x23, 0x23, 0x23, 0x23, 0x40]


@pytest.mark.unit
class TestBasic:
    STREAM = bytes([50]) + (
        BitWriter()
        .put(0)  # repeat
        .put(0b011, 3)  # 1 1 0: colour += inc (-1)
        .put(0b111, 3)  # 1 1 1: inc = +1, colour += inc
        .put(0b011, 3)  # 1 1 0: colour += inc (+1)
        .put(1)
        .put(0)
        .put(60, 8)  # literal 60, inc back to -1
        .put(0b011, 3)  # colour += inc (-1)
        .put(0)
        .put(0)
        .bytes()
    )

    def test_horizontal(self):
        pixels, mask = codecs.decode_strip(bytes([28]) + self.STREAM, 0, 1, 5)
        assert list(pixels) == [50, 50, 49, 50, 51, 60, 59, 59]
        assert mask is None

    def test_vertical_fills_columns(self):
        # Codec 18: every pixel after the first is a literal, numbering the pixels in decoding order.
        bits = BitWriter()
        for value in range(1, 16):
            bits.put(1).put(0).put(value, 8)
        pixels, _mask = codecs.decode_strip(bytes([18, 0]) + bits.bytes(), 0, 2, 5)
        assert list(pixels[:8]) == [0, 2, 4, 6, 8, 10, 12, 14]
        assert list(pixels[8:]) == [1, 3, 5, 7, 9, 11, 13, 15]

    def test_transparent_variant_masks_transparent_colour(self):
        pixels, mask = codecs.decode_strip(bytes([48]) + self.STREAM, 0, 1, 50)
        assert list(pixels) == [50, 50, 49, 50, 51, 60, 59, 59]
        assert list(mask) == [1, 1, 0, 1, 0, 0, 0, 0]


@pytest.mark.unit
class TestRleAndRaw:
    def test_3do_rle(self):
        data = bytes([0b111, 9, 0b110, 1, 2, 3, 4])
        assert list(codecs.decode_3do_rle(data, 0, 8)) == [9, 9, 9, 9, 1, 2, 3, 4]

    @pytest.mark.parametrize(('code', 'masked'), [(1, False), (149, True)])
    def test_raw_strip(self, code, masked):
        pixels = [5, 1, 2, 3, 4, 5, 6, 7]
        out, mask = codecs.decode_strip(bytes([code, *pixels]), 0, 1, 5)
        assert list(out) == pixels
        assert (mask is not None and list(mask) == [1, 0, 0, 0, 0, 1, 0, 0]) if masked else mask is None

    def test_raw_truncated(self):
        with pytest.raises(codecs.CodecError):
            codecs.decode_strip(bytes([1, 0, 0]), 0, 1, 5)

    def test_unknown_codec(self):
        with pytest.raises(codecs.CodecError, match='unknown strip codec 99'):
            codecs.decode_strip(bytes([99, 0, 0, 0]), 0, 1, 5)


@pytest.mark.unit
class TestTrle:
    def test_runs_and_transparency(self):
        pixels, mask = codecs.decode_trle(WIZ_TRLE, 0, 4, 3)
        assert list(pixels) == [0, 40, 41, 0, 0, 0, 0, 0, 42, 42, 42, 42]
        assert list(mask) == [1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0]

    def test_opaque_image_has_no_mask(self):
        data = (2).to_bytes(2, 'little') + bytes([0b110, 7])
        pixels, mask = codecs.decode_trle(data, 0, 2, 1)
        assert list(pixels) == [7, 7]
        assert mask is None

    def test_truncated(self):
        with pytest.raises(codecs.CodecError):
            codecs.decode_trle(b'\x02', 0, 2, 1)


@pytest.mark.unit
class TestSmap:
    def test_strips_are_placed_side_by_side(self):
        from tamago.tests.scumm.samples import raw_strip, smap

        block = smap([raw_strip(list(range(16))), raw_strip(list(range(100, 116)))])
        pixels, mask = codecs.decode_smap(block, 16, 2, 5)
        assert list(pixels[:16]) == [*range(8), *range(100, 108)]
        assert list(pixels[16:]) == [*range(8, 16), *range(108, 116)]
        assert mask is None

    def test_width_must_be_whole_strips(self):
        with pytest.raises(codecs.CodecError):
            codecs.decode_smap(b'SMAP\0\0\0\x0c\0\0\0\0', 12, 1, 5)
