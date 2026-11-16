"""Tests for YSTB script encryption and key recovery."""

import struct

import pytest

from tamago.formats.yuris import DEFAULT_SCRIPT_KEY, decrypt_ystb, encrypt_ystb, guess_ystb_key, is_ystb
from tamago.tests.yuris.samples import ALICE, ystb_encrypt, ystb_plain

KEYS = [DEFAULT_SCRIPT_KEY, 0x4A415E60, 0xCD49FD8C]


@pytest.mark.unit
class TestCrypt:
    @pytest.mark.parametrize('key', KEYS)
    def test_decrypt(self, key):
        plain = ystb_plain()
        assert decrypt_ystb(ystb_encrypt(plain, key), key) == plain

    @pytest.mark.parametrize('key', KEYS)
    def test_encrypt(self, key):
        plain = ystb_plain()
        assert encrypt_ystb(plain, key) == ystb_encrypt(plain, key)

    def test_key_restarts_at_each_section(self):
        """The resources section is 30 bytes, so a single running XOR would misalign the line numbers."""
        plain = ystb_plain()
        enc = encrypt_ystb(plain, 0x01020304)
        line_numbers = enc[-24:]
        assert line_numbers[:4] == bytes(a ^ b for a, b in zip(plain[-24:-20], b'\x04\x03\x02\x01', strict=True))

    def test_header_is_not_encrypted(self):
        plain = ystb_plain()
        assert encrypt_ystb(plain, 0xDEADBEEF)[:32] == plain[:32]

    def test_old_version_has_two_sections(self):
        body = ALICE[:20] + ALICE[20:31]
        plain = struct.pack('<4sIII16x', b'YSTB', 0x100, 20, 11) + body
        key = 0x11223344
        k = key.to_bytes(4, 'little')
        expected = plain[:32] + bytes(b ^ k[i % 4] for i, b in enumerate(body[:20]))
        expected += bytes(b ^ k[i % 4] for i, b in enumerate(body[20:]))
        assert encrypt_ystb(plain, key) == expected

    def test_sizes_must_match_file(self):
        bad = ystb_plain() + b'!'
        with pytest.raises(ValueError, match='section sizes'):
            decrypt_ystb(bad, DEFAULT_SCRIPT_KEY)

    def test_not_ystb(self):
        assert not is_ystb(b'YSCM' + bytes(60))
        assert is_ystb(ystb_plain())
        with pytest.raises(ValueError, match='not a YSTB'):
            decrypt_ystb(b'YSCM' + bytes(60), 0)


@pytest.mark.unit
class TestGuessKey:
    @pytest.mark.parametrize('key', KEYS)
    def test_guesses_key_from_several_scripts(self, key):
        scripts = [
            ystb_encrypt(ystb_plain(lines=tuple(range(start, start + 40, 3))), key) for start in (1, 50, 400, 1000)
        ]
        assert guess_ystb_key(scripts) == key

    def test_plaintext_gives_zero(self):
        assert guess_ystb_key([ystb_plain(lines=tuple(range(1, 80, 2)))]) == 0

    def test_ignores_non_scripts(self):
        scripts = [b'YSCM' + bytes(40), ystb_encrypt(ystb_plain(lines=tuple(range(1, 80, 2))), 0x96AC6FD3)]
        assert guess_ystb_key(scripts) == 0x96AC6FD3

    def test_no_scripts(self):
        with pytest.raises(ValueError, match='no YSTB'):
            guess_ystb_key([b'YSCM' + bytes(40)])
