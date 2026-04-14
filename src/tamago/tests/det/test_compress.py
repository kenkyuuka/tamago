import pytest

from tamago.formats.det.detfile import compress, decompress


@pytest.mark.unit
class TestCompress:
    def test_empty_input(self):
        assert compress(b'') == b''

    def test_literal_bytes(self):
        """Non-0xFF bytes are emitted as literals."""
        result = compress(b'ABC')
        assert decompress(result) == b'ABC'

    def test_0xff_escaped(self):
        """Literal 0xFF is encoded as 0xFF 0xFF."""
        result = compress(bytes([0xFF]))
        assert result == bytes([0xFF, 0xFF])
        assert decompress(result) == bytes([0xFF])

    def test_repeated_data_compresses(self):
        """Repeated patterns produce back-references that are shorter."""
        data = b'ABCABC'
        result = compress(data)
        assert decompress(result) == data
        # 'ABC' repeated: 3 literal bytes + 2-byte back-ref = 5, less than 6
        assert len(result) < len(data)

    def test_long_run(self):
        """A long run of the same byte compresses well."""
        data = b'\x42' * 100
        result = compress(data)
        assert decompress(result) == data
        assert len(result) < len(data)

    def test_roundtrip_high_entropy(self):
        """High-entropy data roundtrips correctly even if it doesn't compress."""
        data = bytes(range(256))
        result = compress(data)
        assert decompress(result) == data

    def test_roundtrip_with_0xff_bytes(self):
        """Data containing many 0xFF bytes roundtrips correctly."""
        data = bytes([0xFF, 0x00, 0xFF, 0xFF, 0x01, 0xFF])
        result = compress(data)
        assert decompress(result) == data

    def test_roundtrip_overlapping_pattern(self):
        """A single byte repeated should roundtrip via overlapping back-refs."""
        data = b'AAAAAAAAAAAA'
        result = compress(data)
        assert decompress(result) == data

    def test_roundtrip_mixed_content(self):
        """Mixed compressible and incompressible data roundtrips."""
        data = b'\x00' * 50 + bytes(range(256)) + b'\x41' * 30
        result = compress(data)
        assert decompress(result) == data
