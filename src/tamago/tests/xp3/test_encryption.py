import pytest
from construct import Container

from tamago.formats.xp3.encryption import (
    FixedXorEncryption,
    HashXorEncryption,
    NullEncryption,
    PinPointEncryption,
    PoringSoftEncryption,
)
from tamago.formats.xp3.encryption.base import XP3Encryption
from tamago.formats.xp3.models import XP3Info


def _make_info(key):
    return XP3Info(file_name='test', key=key)


def _make_segment():
    return Container(flags=0, compressed=False, offset=0, original_size=0, compressed_size=0)


@pytest.mark.unit
class TestXP3EncryptionABC:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            XP3Encryption()

    def test_subclass_must_implement_decrypt(self):
        class Incomplete(XP3Encryption):
            def encrypt(self, data, info, segment):
                return data

        with pytest.raises(TypeError):
            Incomplete()

    def test_subclass_must_implement_encrypt(self):
        class Incomplete(XP3Encryption):
            def decrypt(self, data, info, segment):
                return data

        with pytest.raises(TypeError):
            Incomplete()


@pytest.mark.unit
class TestHashXorEncryption:
    def test_decrypt_known_value(self):
        enc = HashXorEncryption(shift=3)
        info = _make_info(0b11111000)  # key >> 3 = 0x1F
        seg = _make_segment()
        data = bytes([0x00, 0xFF, 0x1F, 0xA0])
        result = enc.decrypt(data, info, seg)
        assert result == bytes([b ^ 0x1F for b in data])

    def test_encrypt_known_value(self):
        enc = HashXorEncryption(shift=3)
        info = _make_info(0b11111000)
        seg = _make_segment()
        data = bytes([0x00, 0xFF, 0x1F, 0xA0])
        result = enc.encrypt(data, info, seg)
        assert result == bytes([b ^ 0x1F for b in data])

    def test_round_trip(self):
        enc = HashXorEncryption(shift=3)
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        original = b'Hello, world!'
        encrypted = enc.encrypt(original, info, seg)
        decrypted = enc.decrypt(encrypted, info, seg)
        assert decrypted == original

    def test_encrypt_decrypt_identical(self):
        enc = HashXorEncryption(shift=3)
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        data = b'test data'
        assert enc.encrypt(data, info, seg) == enc.decrypt(data, info, seg)

    def test_zero_key_byte_is_noop(self):
        enc = HashXorEncryption(shift=0)
        # key & 0xFF == 0 means no XOR applied
        info = _make_info(0x100)
        seg = _make_segment()
        data = b'unchanged'
        assert enc.decrypt(data, info, seg) is data

    def test_different_shifts_produce_different_results(self):
        info = _make_info(0xFFFFFFFF)
        seg = _make_segment()
        data = b'\x00' * 4
        results = set()
        for shift in range(8):
            enc = HashXorEncryption(shift=shift)
            results.add(enc.decrypt(data, info, seg))
        # All shifts 0-7 produce key_byte=0xFF, so result is the same
        # But with a key like 0x12345678, different shifts give different bytes
        info2 = _make_info(0x12345678)
        results2 = set()
        for shift in range(8):
            enc = HashXorEncryption(shift=shift)
            results2.add(enc.decrypt(data, info2, seg))
        assert len(results2) > 1

    def test_empty_data(self):
        enc = HashXorEncryption(shift=3)
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        assert enc.decrypt(b'', info, seg) == b''

    def test_shift_extracts_correct_byte(self):
        # key=0x00AA0000, shift=16 -> key_byte = 0xAA
        enc = HashXorEncryption(shift=16)
        info = _make_info(0x00AA0000)
        seg = _make_segment()
        data = bytes([0x00])
        assert enc.decrypt(data, info, seg) == bytes([0xAA])


@pytest.mark.unit
class TestFixedXorEncryption:
    def test_single_byte_key(self):
        enc = FixedXorEncryption(key=b'\xab')
        info = _make_info(0)
        seg = _make_segment()
        data = bytes([0x00, 0xFF, 0xAB, 0x54])
        result = enc.decrypt(data, info, seg)
        assert result == bytes([b ^ 0xAB for b in data])

    def test_multi_byte_key_cycles(self):
        enc = FixedXorEncryption(key=b'\x01\x02')
        info = _make_info(0)
        seg = _make_segment()
        data = bytes([0x10, 0x20, 0x30, 0x40])
        result = enc.decrypt(data, info, seg)
        assert result == bytes([0x10 ^ 0x01, 0x20 ^ 0x02, 0x30 ^ 0x01, 0x40 ^ 0x02])

    def test_round_trip(self):
        enc = FixedXorEncryption(key=b'\xde\xad\xbe\xef')
        info = _make_info(0)
        seg = _make_segment()
        original = b'Hello, world!'
        assert enc.decrypt(enc.encrypt(original, info, seg), info, seg) == original

    def test_encrypt_decrypt_identical(self):
        enc = FixedXorEncryption(key=b'\xab\xcd')
        info = _make_info(0)
        seg = _make_segment()
        data = b'test data'
        assert enc.encrypt(data, info, seg) == enc.decrypt(data, info, seg)

    def test_zero_key_byte_is_noop(self):
        enc = FixedXorEncryption(key=b'\x00')
        info = _make_info(0)
        seg = _make_segment()
        data = b'unchanged'
        assert enc.decrypt(data, info, seg) is data

    def test_empty_data(self):
        enc = FixedXorEncryption(key=b'\xff')
        info = _make_info(0)
        seg = _make_segment()
        assert enc.decrypt(b'', info, seg) == b''

    def test_hex_string_key(self):
        enc = FixedXorEncryption(key='ABCD')
        assert enc.key == b'\xab\xcd'

    def test_ignores_file_hash(self):
        enc = FixedXorEncryption(key=b'\xff')
        seg = _make_segment()
        data = b'\x00\x01\x02'
        # Different file hashes should produce identical results
        result1 = enc.decrypt(data, _make_info(0x00000000), seg)
        result2 = enc.decrypt(data, _make_info(0xFFFFFFFF), seg)
        assert result1 == result2

    def test_empty_key_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            FixedXorEncryption(key=b'')

    def test_invalid_key_type_rejected(self):
        with pytest.raises(ValueError):
            FixedXorEncryption(key=42)


@pytest.mark.unit
class TestPoringSoftEncryption:
    def test_decrypt_known_value(self):
        enc = PoringSoftEncryption()
        # key=0x00 -> ~(0 + 1) & 0xFF = ~1 & 0xFF = 0xFE
        info = _make_info(0x00)
        seg = _make_segment()
        data = bytes([0x00, 0xFF, 0xFE, 0xA0])
        result = enc.decrypt(data, info, seg)
        assert result == bytes([b ^ 0xFE for b in data])

    def test_encrypt_known_value(self):
        enc = PoringSoftEncryption()
        info = _make_info(0x00)
        seg = _make_segment()
        data = bytes([0x00, 0xFF, 0xFE, 0xA0])
        result = enc.encrypt(data, info, seg)
        assert result == bytes([b ^ 0xFE for b in data])

    def test_round_trip(self):
        enc = PoringSoftEncryption()
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        original = b'Hello, world!'
        encrypted = enc.encrypt(original, info, seg)
        decrypted = enc.decrypt(encrypted, info, seg)
        assert decrypted == original

    def test_encrypt_decrypt_identical(self):
        enc = PoringSoftEncryption()
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        data = b'test data'
        assert enc.encrypt(data, info, seg) == enc.decrypt(data, info, seg)

    def test_zero_key_byte_is_noop(self):
        enc = PoringSoftEncryption()
        # ~(key + 1) & 0xFF == 0 when (key + 1) & 0xFF == 0xFF, i.e. key & 0xFF == 0xFE
        info = _make_info(0xFE)
        seg = _make_segment()
        data = b'unchanged'
        assert enc.decrypt(data, info, seg) is data

    def test_empty_data(self):
        enc = PoringSoftEncryption()
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        assert enc.decrypt(b'', info, seg) == b''

    def test_key_derivation_formula(self):
        # Verify the formula: key_byte = ~(hash + 1) & 0xFF
        enc = PoringSoftEncryption()
        seg = _make_segment()
        # key=0x42 -> ~(0x42 + 1) & 0xFF = ~0x43 & 0xFF = 0xBC
        info = _make_info(0x42)
        data = bytes([0x00])
        assert enc.decrypt(data, info, seg) == bytes([0xBC])


@pytest.mark.unit
class TestNullEncryption:
    def test_decrypt_returns_data_unchanged(self):
        enc = NullEncryption()
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        data = b'Hello, world!'
        assert enc.decrypt(data, info, seg) is data

    def test_encrypt_returns_data_unchanged(self):
        enc = NullEncryption()
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        data = b'Hello, world!'
        assert enc.encrypt(data, info, seg) is data

    def test_round_trip(self):
        enc = NullEncryption()
        info = _make_info(0x12345678)
        seg = _make_segment()
        original = b'test data'
        assert enc.decrypt(enc.encrypt(original, info, seg), info, seg) is original

    def test_empty_data(self):
        enc = NullEncryption()
        info = _make_info(0)
        seg = _make_segment()
        assert enc.decrypt(b'', info, seg) == b''


@pytest.mark.unit
class TestPinPointEncryption:
    def test_decrypt_known_value(self):
        enc = PinPointEncryption()
        info = _make_info(0)
        seg = _make_segment()
        # 0xA5 = 10100101, popcount=4, rotate left by 4: 0x5A
        # 0xFF = 11111111, popcount=8, rotate left by 8 (full rotation): 0xFF
        # 0x01 = 00000001, popcount=1, rotate left by 1: 0x02
        # 0x80 = 10000000, popcount=1, rotate left by 1: 0x01
        data = bytes([0xA5, 0xFF, 0x01, 0x80])
        result = enc.decrypt(data, info, seg)
        assert result == bytes([0x5A, 0xFF, 0x02, 0x01])

    def test_encrypt_known_value(self):
        enc = PinPointEncryption()
        info = _make_info(0)
        seg = _make_segment()
        # Encrypt is the inverse: rotate right by popcount
        # 0x5A = 01011010, popcount=4, rotate right by 4: 0xA5
        # 0x02 = 00000010, popcount=1, rotate right by 1: 0x01
        # 0x01 = 00000001, popcount=1, rotate right by 1: 0x80
        data = bytes([0x5A, 0xFF, 0x02, 0x01])
        result = enc.encrypt(data, info, seg)
        assert result == bytes([0xA5, 0xFF, 0x01, 0x80])

    def test_round_trip(self):
        enc = PinPointEncryption()
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        original = b"Down the rabbit hole Alice went!"
        encrypted = enc.encrypt(original, info, seg)
        decrypted = enc.decrypt(encrypted, info, seg)
        assert decrypted == original

    def test_zero_byte_is_noop(self):
        enc = PinPointEncryption()
        info = _make_info(0)
        seg = _make_segment()
        # popcount(0) = 0, so no rotation
        assert enc.decrypt(b'\x00', info, seg) == b'\x00'

    def test_ignores_file_hash(self):
        enc = PinPointEncryption()
        seg = _make_segment()
        data = b'\xa5\x01\x80\xff'
        result1 = enc.decrypt(data, _make_info(0x00000000), seg)
        result2 = enc.decrypt(data, _make_info(0xFFFFFFFF), seg)
        assert result1 == result2

    def test_empty_data(self):
        enc = PinPointEncryption()
        info = _make_info(0)
        seg = _make_segment()
        assert enc.decrypt(b'', info, seg) == b''

    def test_all_single_bit_bytes(self):
        enc = PinPointEncryption()
        info = _make_info(0)
        seg = _make_segment()
        # Each single-bit byte has popcount=1, rotate left by 1
        for bit in range(8):
            val = 1 << bit
            expected = ((val << 1) | (val >> 7)) & 0xFF
            assert enc.decrypt(bytes([val]), info, seg) == bytes([expected])

    def test_popcount_correctness(self):
        enc = PinPointEncryption()
        # Verify popcount for known values
        assert enc._popcount(0x00) == 0
        assert enc._popcount(0x01) == 1
        assert enc._popcount(0x03) == 2
        assert enc._popcount(0x55) == 4  # 01010101
        assert enc._popcount(0xFF) == 8

    def test_full_rotation_is_identity(self):
        enc = PinPointEncryption()
        info = _make_info(0)
        seg = _make_segment()
        # 0xFF has popcount=8, rotating by 8 is a full rotation = identity
        assert enc.decrypt(bytes([0xFF]), info, seg) == bytes([0xFF])
