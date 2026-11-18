"""Tests for the PSB keystream and key recovery."""

import pytest

from tamago.formats.psb.crypt import Keystream, recover_key, xor
from tamago.tests.psb.samples import DRINK_ME, KEY, keystream


def _key_with_short_first_word():
    """A key whose first keystream word has a zero high byte (so it gives fewer than 4 bytes)."""
    seed = 0x075BCD15
    t = (seed ^ (seed << 11)) & 0xFFFFFFFF
    for key in range(0, 1 << 32, 1 << 20):
        w = t ^ key ^ ((t ^ (key >> 11)) >> 8)
        if w >> 24 == 0:
            return key
    raise AssertionError('no such key in range')


@pytest.mark.unit
class TestKeystream:
    @pytest.mark.parametrize('key', [KEY, 0x473AB96D, 0, 0xFFFFFFFF])
    def test_matches_reference(self, key):
        assert Keystream(key).take(1000) == keystream(key, 1000)

    def test_word_with_zero_high_byte_is_cut_short(self):
        key = _key_with_short_first_word()
        assert Keystream(key).take(64) == keystream(key, 64)

    def test_continues_across_calls(self):
        ks = Keystream(KEY)
        parts = ks.xor(DRINK_ME[:5]) + ks.xor(DRINK_ME[5:7]) + ks.xor(DRINK_ME[7:])
        assert parts == xor(DRINK_ME, KEY)

    def test_xor_is_its_own_inverse(self):
        assert xor(xor(DRINK_ME, KEY), KEY) == DRINK_ME

    def test_empty(self):
        assert xor(b'', KEY) == b''


@pytest.mark.unit
class TestRecoverKey:
    @pytest.mark.parametrize('key', [KEY, 0x473AB96D, 0, 0xFFFFFFFF, 0x80000001])
    def test_recovers_key_from_first_word(self, key):
        plain = (0x2C).to_bytes(4, 'little')
        assert recover_key(xor(plain, key), plain) == key

    def test_needs_four_bytes(self):
        with pytest.raises(ValueError):
            recover_key(b'abc', b'abc')
