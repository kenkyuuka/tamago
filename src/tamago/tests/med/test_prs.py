"""Tests for the PRS ("YB") image decoder."""

import struct

import pytest

from tamago.formats.med.prs import decode_prs, is_prs


def _prs(stream, width, height, *, depth=4, flags=0x03, packed_size=None, unknown=0):
    """A PRS file: 16-byte header, then *stream* as the LZ payload."""
    size = len(stream) if packed_size is None else packed_size
    return b'YB' + bytes([flags, depth]) + struct.pack('<IIHH', size, unknown, width, height) + stream


def _literals(data):
    """An LZ stream holding *data* as literals only: a zero control byte per eight bytes."""
    out = bytearray()
    for i in range(0, len(data), 8):
        out += b'\0' + data[i : i + 8]
    return bytes(out)


# Card colours from the Queen's garden, as BGRA.
WHITE_ROSE = bytes([0xF0, 0xF0, 0xF0, 0xFF])
RED_PAINT = bytes([0x20, 0x10, 0xC0, 0xFF])
HEART = bytes([0x30, 0x00, 0xD0, 0x80])
CLEAR = bytes([0x00, 0x00, 0x00, 0x00])


def _rgba(bgra):
    """Reorder BGRA pixels to RGBA."""
    out = bytearray()
    for i in range(0, len(bgra), 4):
        b, g, r, a = bgra[i : i + 4]
        out += bytes([r, g, b, a])
    return bytes(out)


def _delta(buf, depth):
    """Apply the PRS delta filter: each byte minus the byte *depth* earlier."""
    return bytes(buf[:depth]) + bytes((buf[i] - buf[i - depth]) & 0xFF for i in range(depth, len(buf)))


@pytest.mark.unit
class TestDetection:
    def test_recognises_prs(self):
        assert is_prs(_prs(_literals(WHITE_ROSE), 1, 1))

    @pytest.mark.parametrize('data', [b'', b'YB', b'YB\x83\x02' + bytes(12), b'WADY' + bytes(12), b'MD' + bytes(14)])
    def test_rejects_other_data(self, data):
        assert not is_prs(data)


@pytest.mark.unit
class TestLiterals:
    def test_bgra_pixels_become_rgba(self):
        pixels = WHITE_ROSE + RED_PAINT + HEART + CLEAR
        img = decode_prs(_prs(_literals(pixels), 2, 2))
        assert img.mode == 'RGBA'
        assert img.size == (2, 2)
        assert img.tobytes() == _rgba(pixels)

    def test_depth_3_is_rgb(self):
        pixels = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
        img = decode_prs(_prs(_literals(pixels), 2, 1, depth=3))
        assert img.mode == 'RGB'
        assert img.tobytes() == bytes([0x30, 0x20, 0x10, 0x60, 0x50, 0x40])

    def test_trailing_control_byte_is_ignored(self):
        """Some streams end with a control byte read after the image is complete."""
        pixels = WHITE_ROSE * 2
        img = decode_prs(_prs(_literals(pixels) + b'\0', 2, 1))
        assert img.tobytes() == _rgba(pixels)


@pytest.mark.unit
class TestCommands:
    def test_worked_example_overlapping_medium_copy(self):
        """Four literals, then distance 4, length 12: the pixel repeats."""
        stream = bytes([0x08]) + bytes([0xAA, 0xBB, 0xCC, 0xFF]) + bytes([0x80, 0x39])
        img = decode_prs(_prs(stream, 4, 1))
        assert img.tobytes() == _rgba(bytes([0xAA, 0xBB, 0xCC, 0xFF]) * 4)

    def test_short_copy(self):
        """0dddddLL: distance d+1, length LL+2.  Distance 4, length 4 copies one pixel."""
        stream = bytes([0x08]) + RED_PAINT + bytes([(3 << 2) | 2])
        img = decode_prs(_prs(stream, 2, 1))
        assert img.tobytes() == _rgba(RED_PAINT * 2)

    def test_short_copy_distance_one_repeats_a_byte(self):
        stream = bytes([0x40, 0x7E, 0x01])  # literal 0x7E, then distance 1 length 3
        img = decode_prs(_prs(stream, 1, 1))
        assert img.tobytes() == _rgba(bytes([0x7E] * 4))

    def test_raw_run(self):
        """0xxxxx11: copy (b >> 2) + 9 bytes straight from the stream."""
        pixels = WHITE_ROSE + RED_PAINT + HEART  # 12 bytes: a run of 9 + 3 literals
        stream = bytes([0x80, 0x03]) + pixels[:9] + pixels[9:]
        img = decode_prs(_prs(stream, 3, 1))
        assert img.tobytes() == _rgba(pixels)

    @pytest.mark.parametrize('code,length', [(0x01, 4), (0x41, 0x44), (0xFD, 0x100), (0xFE, 0x400), (0xFF, 0x1000)])
    def test_long_copy_lengths(self, code, length):
        """11hhhhhh xx nn: distance ((h << 8) | x) + 1, length from the table."""
        stream = bytes([0x08]) + HEART + bytes([0xC0, 0x03, code])
        img = decode_prs(_prs(stream, 1 + length // 4, 1))
        assert img.tobytes() == _rgba(HEART * (1 + length // 4))

    def test_long_copy_far_distance(self):
        """A distance using the high bits reaches back past 4 KiB of transparency."""
        stream = _literals(HEART + CLEAR * 7)  # 32 bytes
        stream += bytes([0xC0])  # two commands
        stream += bytes([0xC0, 0x03, 0xFF])  # distance 4, length 0x1000: more CLEAR
        stream += bytes([0xD0, 0x1F, 0x01])  # distance 0x1020 back to HEART, length 4
        img = decode_prs(_prs(stream, (32 + 0x1000 + 4) // 4, 1))
        assert img.tobytes() == _rgba(HEART + CLEAR * (7 + 0x400) + HEART)

    def test_copy_is_clipped_to_the_buffer(self):
        stream = bytes([0x08]) + HEART + bytes([0xC0, 0x03, 0xFF])  # asks for 4096 bytes
        img = decode_prs(_prs(stream, 3, 1))
        assert img.tobytes() == _rgba(HEART * 3)


@pytest.mark.unit
class TestDeltaFilter:
    def test_worked_example(self):
        stored = bytes([0x10, 0x20, 0x30, 0xFF, 0x02, 0x02, 0x02, 0x00])
        img = decode_prs(_prs(_literals(stored), 2, 1, flags=0x83))
        assert img.tobytes() == _rgba(bytes([0x10, 0x20, 0x30, 0xFF, 0x12, 0x22, 0x32, 0xFF]))

    def test_filter_continues_across_rows(self):
        """The first pixel of a row is predicted from the last pixel of the row above."""
        pixels = WHITE_ROSE + RED_PAINT + HEART + CLEAR + RED_PAINT + WHITE_ROSE
        img = decode_prs(_prs(_literals(_delta(pixels, 4)), 2, 3, flags=0x83))
        assert img.tobytes() == _rgba(pixels)

    def test_filter_wraps_modulo_256(self):
        pixels = bytes([0xFF, 0x01, 0x80, 0x00, 0x01, 0xFF, 0x00, 0x80])
        img = decode_prs(_prs(_literals(_delta(pixels, 4)), 2, 1, flags=0x83))
        assert img.tobytes() == _rgba(pixels)

    def test_depth_3_filter_uses_three_byte_stride(self):
        pixels = bytes([0x10, 0x20, 0x30, 0x11, 0x22, 0x33, 0x0F, 0x1E, 0x2D])
        img = decode_prs(_prs(_literals(_delta(pixels, 3)), 3, 1, depth=3, flags=0x80))
        assert img.tobytes() == bytes(pixels[i + 2 - 2 * (i % 3)] for i in range(len(pixels)))


@pytest.mark.unit
class TestErrors:
    def test_rejects_bad_magic(self):
        with pytest.raises(ValueError, match='PRS'):
            decode_prs(b'XB' + _prs(_literals(HEART), 1, 1)[2:])

    def test_rejects_short_header(self):
        with pytest.raises(ValueError):
            decode_prs(b'YB\x83\x04')

    def test_rejects_unknown_depth(self):
        with pytest.raises(ValueError, match='depth'):
            decode_prs(_prs(_literals(HEART), 1, 1, depth=2))

    def test_rejects_packed_size_past_end(self):
        with pytest.raises(ValueError, match='truncated'):
            decode_prs(_prs(_literals(HEART), 1, 1, packed_size=100))

    def test_rejects_stream_that_ends_early(self):
        with pytest.raises(ValueError, match='ends'):
            decode_prs(_prs(_literals(HEART), 2, 1))

    def test_rejects_copy_before_start(self):
        stream = bytes([0x40, 0x7E, (4 << 2) | 0])  # distance 5 with only one byte written
        with pytest.raises(ValueError, match='distance'):
            decode_prs(_prs(stream, 1, 1))

    def test_rejects_command_cut_short(self):
        stream = bytes([0x08]) + HEART + bytes([0xC0, 0x03])  # long copy missing its length byte
        with pytest.raises(ValueError):
            decode_prs(_prs(stream, 2, 1))

    def test_flag_0x40_is_not_supported(self):
        with pytest.raises(NotImplementedError):
            decode_prs(_prs(_literals(HEART), 1, 1, flags=0xC3))
