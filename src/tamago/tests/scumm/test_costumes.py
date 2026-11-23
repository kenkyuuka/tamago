"""Tests for costume (AKOS) cel extraction."""

import pytest

from tamago.formats.scumm import codecs, images, iter_blocks
from tamago.formats.scumm.images import ImageError
from tamago.tests.scumm import samples
from tamago.tests.scumm.samples import BitWriter


def _costume(data: bytes):
    akos = next(iter_blocks(data))
    return akos, images.costume_cels(akos)


def _pixels(im):
    """Pixels row by row, with every fully transparent pixel as (0, 0, 0, 0)."""
    rows = [[im.getpixel((x, y)) for x in range(im.width)] for y in range(im.height)]
    return [[p if p[3] else (0, 0, 0, 0) for p in row] for row in rows]


@pytest.mark.unit
class TestByle:
    def test_columns_and_explicit_length(self):
        pixels = codecs.decode_byle(samples.BYLE_CEL, 0, 2, 3, 16)
        assert [list(pixels[i : i + 2]) for i in range(0, 6, 2)] == samples.BYLE_SLOTS

    @pytest.mark.parametrize(('slots', 'byte', 'slot', 'length'), [(32, 0x2B, 5, 3), (64, 0x2B, 10, 3)])
    def test_slot_and_length_split(self, slots, byte, slot, length):
        assert list(codecs.decode_byle(bytes([byte]), 0, 1, length, slots)) == [slot] * length

    def test_runs_cross_columns(self):
        # One run of 4 fills both 2-pixel columns.
        assert list(codecs.decode_byle(bytes([0x34]), 0, 2, 2, 16)) == [3, 3, 3, 3]

    def test_truncated(self):
        with pytest.raises(codecs.CodecError):
            codecs.decode_byle(b'', 0, 2, 2, 16)


@pytest.mark.unit
class TestCels:
    def test_table(self):
        _akos, costume = _costume(samples.COSTUME)
        assert costume.codec == images.AKOS_BYLE_RLE
        # The empty cel 1 is left out.
        assert [cel[:3] for cel in costume.cels] == [(0, 2, 3)]

    @pytest.mark.parametrize(
        ('rgbs', 'orange', 'yellow'),
        [
            (samples.short_rgbs(), samples.ORANGE, samples.YELLOW),  # HE 71: a colour per slot
            (samples.full_rgbs(), samples.ORANGE, samples.YELLOW),  # HE 80+: RGBS[AKPL[slot]]
            (None, samples.rgb(210), samples.rgb(211)),  # no RGBS: the room palette at AKPL[slot]
        ],
    )
    def test_byle_palettes(self, rgbs, orange, yellow):
        akos, costume = _costume(samples.akos(1, [(2, 3, samples.BYLE_CEL)], rgbs=rgbs))
        im = images.cel_image(akos, costume, costume.cels[0], samples.PALETTE)
        clear = (0, 0, 0, 0)
        assert _pixels(im) == [
            [clear, (*yellow, 255)],
            [(*orange, 255), (*yellow, 255)],
            [(*orange, 255), clear],
        ]

    def test_trle_uses_palette_indices(self):
        akos, costume = _costume(samples.akos(32, [(4, 3, samples.WIZ_TRLE)], akpl=b'\0\0'))
        im = images.cel_image(akos, costume, costume.cels[0], samples.PALETTE)
        assert im.getpixel((0, 0))[3] == 0
        assert im.getpixel((1, 0)) == (*samples.rgb(40), 255)
        assert im.getpixel((3, 2)) == (*samples.rgb(42), 255)

    def test_majmin_transparent_colour_is_first_slot(self):
        # Bits per literal (8), first colour 7 (= AKPL[0], transparent), then a literal 9.
        data = bytes([8, 7]) + BitWriter().put(1).put(0).put(9, 8).bytes(pad_to=2)
        akos, costume = _costume(samples.akos(16, [(2, 1, data)], akpl=bytes([7, 0])))
        im = images.cel_image(akos, costume, costume.cels[0], samples.PALETTE)
        assert im.getpixel((0, 0))[3] == 0
        assert im.getpixel((1, 0)) == (*samples.rgb(9), 255)

    def test_unsupported_codec(self):
        akos, costume = _costume(samples.akos(5, [(2, 3, b'\0')]))
        with pytest.raises(ImageError, match='unsupported costume codec 5'):
            images.cel_image(akos, costume, costume.cels[0], samples.PALETTE)

    def test_costume_without_cels(self):
        _akos, costume = _costume(samples.akos(1, []))
        assert costume.cels == []


@pytest.mark.unit
class TestCostumeName:
    def test_first_non_empty_sequence_name(self):
        akos, _cels = _costume(samples.COSTUME)
        assert images.costume_name(akos) == 'Alice shrinks'

    def test_no_sequence_table(self):
        akos, _cels = _costume(samples.akos(1, []))
        assert images.costume_name(akos) is None
