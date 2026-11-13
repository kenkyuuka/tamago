"""Tests for the DxLib LZ codec."""

import struct

import pytest

from tamago.formats.dxa.lz import compress, decompress


def _stream(dest_size, key, tokens):
    """Assemble a compressed stream from its header fields and raw token bytes."""
    return struct.pack('<IIB', dest_size, 9 + len(tokens), key) + bytes(tokens)


@pytest.mark.unit
class TestDecompress:
    def test_worked_example(self):
        # "abc", then a 9-byte copy from 3 back, overlapping itself.
        data = _stream(12, 0x00, [0x61, 0x62, 0x63, 0x00, 0x29, 0x02])
        assert decompress(data) == b'abcabcabcabc'

    def test_literals_only(self):
        assert decompress(_stream(5, 0xFF, list(b'Alice'))) == b'Alice'

    def test_doubled_key_is_a_literal_key(self):
        assert decompress(_stream(3, 0x41, [0x61, 0x41, 0x41, 0x62])) == b'aAb'

    def test_code_below_key_is_not_adjusted(self):
        # Key 0xF0: code 0x00 is below it, so it stands as is: length 4, 1-byte distance.
        data = _stream(8, 0xF0, [*b'Hare', 0xF0, 0x00, 0x03])
        assert decompress(data) == b'HareHare'

    def test_extended_length(self):
        # length - 4 = 0x25: low 5 bits 0b00101 in the code, 0x01 in the extension byte.
        code = (0x05 << 3) | 0x04 | 0x00
        data = _stream(1 + 0x29, 0x00, [0x2A, 0x00, code + 1, 0x01, 0x00])
        assert decompress(data) == b'*' * 0x2A

    def test_two_byte_distance(self):
        prefix = bytes(range(1, 256)) + b'\x01\x02\x03\x04'
        code = (0 << 3) | 0x01  # length 4, 2-byte distance
        dist = len(prefix) - 1  # copy from the very start
        data = _stream(len(prefix) + 4, 0x00, [*prefix, 0x00, code + 1, dist & 0xFF, dist >> 8])
        assert decompress(data) == prefix + b'\x01\x02\x03\x04'

    def test_three_byte_distance(self):
        prefix = b'Tweedle' + b'\x00' * 0x10000
        code = (3 << 3) | 0x02  # length 7, 3-byte distance
        dist = len(prefix) - 1
        # Key 0xFF never occurs in the prefix, so every prefix byte is a plain literal.
        tokens = [*prefix, 0xFF, code, dist & 0xFF, (dist >> 8) & 0xFF, dist >> 16]
        data = _stream(len(prefix) + 7, 0xFF, tokens)
        assert decompress(data) == prefix + b'Tweedle'

    def test_invalid_distance_size_raises(self):
        with pytest.raises(ValueError, match='distance'):
            decompress(_stream(8, 0x00, [*b'Hare', 0x00, 0x03 + 1, 0x00]))

    def test_distance_before_start_raises(self):
        with pytest.raises(ValueError, match='before the start'):
            decompress(_stream(8, 0x00, [*b'Hare', 0x00, 0x00 + 1, 0x10]))

    def test_size_mismatch_raises(self):
        with pytest.raises(ValueError, match='size'):
            decompress(_stream(6, 0xFF, list(b'Alice')))

    def test_truncated_raises(self):
        with pytest.raises(ValueError):
            decompress(_stream(12, 0x00, [0x61, 0x62, 0x63, 0x00]))

    def test_short_header_raises(self):
        with pytest.raises(ValueError, match='header'):
            decompress(b'\x01\x00\x00')

    def test_src_size_larger_than_input_raises(self):
        data = bytearray(_stream(5, 0xFF, list(b'Alice')))
        data[4] += 1
        with pytest.raises(ValueError):
            decompress(bytes(data))


@pytest.mark.unit
class TestCompress:
    @pytest.mark.parametrize(
        'data',
        [
            b'',
            b'A',
            b'abcabcabcabc',
            b"Alice was beginning to get very tired of sitting by her sister on the bank. " * 50,
            bytes(range(256)) * 40,
            b'\x00' * 20000,
            # The escape byte is chosen as the rarest value, so every value appearing
            # forces a doubled-key literal somewhere.
            bytes(range(256)) + b'Off with their heads! ' * 30,
        ],
        ids=['empty', 'one', 'abc', 'text', 'all-bytes', 'zeros', 'every-value'],
    )
    def test_roundtrip(self, data):
        packed = compress(data)
        dest_size, src_size, _key = struct.unpack_from('<IIB', packed)
        assert dest_size == len(data)
        assert src_size == len(packed)
        assert decompress(packed) == data

    def test_repetitive_data_shrinks(self):
        data = b'Curiouser and curiouser! ' * 400
        assert len(compress(data)) < len(data) // 10

    def test_long_match_is_split_at_maximum_length(self):
        data = b'Q' * 30000
        assert decompress(compress(data)) == data

    def test_key_is_rarest_byte(self):
        data = bytes(range(1, 256)) * 3  # 0x00 never appears
        assert compress(data)[8] == 0x00
