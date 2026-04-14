import struct

import pytest

from tamago.formats.advhd.arcfile import decompress_psp


def _pack_psp(unpacked_size: int, compressed: bytes) -> bytes:
    """Build a PSP stream: 4-byte unpacked size + LZSS data."""
    return struct.pack('<I', unpacked_size) + compressed


@pytest.mark.unit
class TestDecompressPSP:
    """Test LZSS decompression for .PSP files."""

    def test_all_literals(self):
        """Control byte 0xFF = 8 literal bytes."""
        # 8 literal bytes: A, l, i, c, e, !, \x00, \x00
        data = b'\xff' + b'Alice!!!'
        result = decompress_psp(_pack_psp(8, data))
        assert result == b'Alice!!!'

    def test_single_literal(self):
        """Single literal byte with control 0x01."""
        data = b'\x01' + b'A'
        result = decompress_psp(_pack_psp(1, data))
        assert result == b'A'

    def test_back_reference_to_zeroed_frame(self):
        """Back-reference to the zero-filled frame produces null bytes."""
        # Control byte 0x00: bit 0 = 0 → back-reference
        # Reference: hi=0x00, lo=0x02 → offset=0, length=2+2=4
        data = b'\x00' + b'\x00\x02'
        result = decompress_psp(_pack_psp(4, data))
        assert result == b'\x00\x00\x00\x00'

    def test_mixed_literal_and_reference(self):
        """Mix of literals and back-references."""
        # Control byte 0x07 = bits 1,1,1,0,0,0,0,0
        # 3 literals: A, B, C
        # Then bit 3 = 0 → back-reference
        # Frame after writing A,B,C at positions 1,2,3:
        #   frame[1]=A, frame[2]=B, frame[3]=C
        # Back-reference: hi=0x00, lo=0x10 → offset=1, length=2+0=2
        # Copies frame[1]=A, frame[2]=B
        data = b'\x07' + b'ABC' + b'\x00\x10'
        result = decompress_psp(_pack_psp(5, data))
        assert result == b'ABCAB'

    def test_empty_output(self):
        """Zero-length output should work."""
        # No compressed data needed for 0-length output,
        # but we still need valid PSP header.
        result = decompress_psp(_pack_psp(0, b''))
        assert result == b''

    def test_reference_wraps_ring_buffer(self):
        """Back-reference offset wraps around the 4096-byte ring buffer."""
        # Write 3 bytes at frame positions 1, 2, 3
        # Then reference offset 0xFFF (wraps to position 4095 which is 0x00)
        # length = 2+0 = 2, copies frame[0xFFF]=0, frame[0x000]=0
        data = b'\x07' + b'XYZ' + b'\xff\xf0'
        result = decompress_psp(_pack_psp(5, data))
        assert result == b'XYZ\x00\x00'

    def test_self_referencing_copy(self):
        """Back-reference can copy bytes that were just written (RLE-like)."""
        # Write literal 'A' at frame position 1
        # Then back-reference to offset 1 (where 'A' is), length 2+3=5
        # This copies A repeatedly: A, A, A, A, A
        data = b'\x01' + b'A' + b'\x00\x13'
        # bit 0 = 1 (literal A), bit 1 = 0 (backref)
        result = decompress_psp(_pack_psp(6, data))
        assert result == b'AAAAAA'

    def test_multiple_control_bytes(self):
        """Test that processing continues across multiple control bytes."""
        # First control byte 0xFF: 8 literals
        # Second control byte 0x01: 1 literal
        data = b'\xff' + b'ABCDEFGH' + b'\x01' + b'I'
        result = decompress_psp(_pack_psp(9, data))
        assert result == b'ABCDEFGHI'
