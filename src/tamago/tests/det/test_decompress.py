import pytest

from tamago.formats.det.detfile import decompress


@pytest.mark.unit
class TestDecompress:
    def test_literal_bytes(self):
        """Non-0xFF bytes pass through as literals."""
        data = bytes([0x41, 0x42, 0x43])
        assert decompress(data) == b'ABC'

    def test_escaped_0xff(self):
        """0xFF 0xFF produces a single literal 0xFF."""
        data = bytes([0x41, 0xFF, 0xFF, 0x42])
        assert decompress(data) == b'A\xffB'

    def test_back_reference(self):
        """0xFF followed by non-0xFF triggers a back-reference copy."""
        # Write 'ABCD', then back-reference to copy 3 bytes starting 4 back.
        # ctl byte: offset_bits = (4-1) = 3, so ctl >> 2 = 3, ctl & 3 = 0 → count=3.
        # ctl = (3 << 2) | 0 = 12
        data = bytes([0x41, 0x42, 0x43, 0x44, 0xFF, 12])
        assert decompress(data) == b'ABCDABC'

    def test_back_reference_count_variations(self):
        """Low 2 bits of control byte set copy length (3-6)."""
        # Write 'ABCDEF', back-ref 6 back, count = (ctl & 3) + 3
        for extra in range(4):
            ctl = (5 << 2) | extra  # offset back = 6
            data = bytes([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0xFF, ctl])
            result = decompress(data)
            assert result == b'ABCDEF' + b'ABCDEF'[: 3 + extra]

    def test_empty_input(self):
        assert decompress(b'') == b''

    def test_overlapping_back_reference(self):
        """Back-reference that overlaps with output being written (run-length pattern)."""
        # Write 'A', then back-ref 1 back with count=6 → 'AAAAAAA' (1 + 6)
        # ctl: offset_bits = (1-1) = 0, ctl >> 2 = 0, ctl & 3 = 3 → count=6
        ctl = (0 << 2) | 3
        data = bytes([0x41, 0xFF, ctl])
        assert decompress(data) == b'AAAAAAA'
