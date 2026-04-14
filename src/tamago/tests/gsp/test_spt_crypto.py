import os

import pytest

from tamago.formats.gsp.spt_crypto import decrypt, encrypt, is_encrypted


def _make_spt(key0: int, body: bytes) -> bytes:
    """Build a minimal encrypted SPT with the given key byte and body."""
    return bytes([key0, 0xF0, 0x00, 0x00]) + body


@pytest.mark.unit
class TestIsEncrypted:
    def test_spt_extension(self):
        assert is_encrypted("hujii_01.spt")

    def test_dat_extension(self):
        assert is_encrypted("global.dat")

    def test_case_insensitive(self):
        assert is_encrypted("SCRIPT.SPT")
        assert is_encrypted("data.DAT")

    def test_non_encrypted_extensions(self):
        assert not is_encrypted("voice.ogg")
        assert not is_encrypted("image.bmz")
        assert not is_encrypted("scene.txt")

    def test_no_extension(self):
        assert not is_encrypted("noext")


@pytest.mark.unit
class TestDecrypt:
    def test_0xff_decrypts_to_0x00(self):
        """Encrypted 0xFF bytes should decrypt to 0x00 for all keys."""
        for key in range(0xF0, 0xF8):
            raw = _make_spt(key, b"\xff" * 16)
            dec = decrypt(raw)
            assert dec[4:] == b"\x00" * 16, f"key {key:#x}"

    def test_header_preserved(self):
        raw = _make_spt(0xF3, b"\xff" * 8)
        dec = decrypt(raw)
        assert dec[:4] == raw[:4]

    def test_non_encrypted_passthrough(self):
        data = b"OggS" + b"\x00" * 20
        assert decrypt(data) is data

    def test_empty_body(self):
        raw = bytes([0xF0, 0xF0, 0x00, 0x00])
        assert decrypt(raw) == raw


@pytest.mark.unit
class TestEncrypt:
    def test_0x00_encrypts_to_0xff(self):
        """Plaintext 0x00 bytes should encrypt to 0xFF for all keys."""
        for key in range(0xF0, 0xF8):
            plain = _make_spt(key, b"\x00" * 16)
            enc = encrypt(plain)
            assert enc[4:] == b"\xff" * 16, f"key {key:#x}"

    def test_header_preserved(self):
        plain = _make_spt(0xF5, b"\x00" * 8)
        enc = encrypt(plain)
        assert enc[:4] == plain[:4]


@pytest.mark.unit
class TestRoundtrip:
    def test_decrypt_encrypt_roundtrip(self):
        """decrypt then encrypt should restore original ciphertext."""
        for key in range(0xF0, 0xF8):
            raw = _make_spt(key, bytes(range(256)))
            dec = decrypt(raw)
            reenc = encrypt(dec)
            assert reenc == raw, f"key {key:#x}"

    def test_encrypt_decrypt_roundtrip(self):
        """encrypt then decrypt should restore original plaintext."""
        for key in range(0xF0, 0xF8):
            plain = _make_spt(key, bytes(range(256)))
            enc = encrypt(plain)
            redec = decrypt(enc)
            assert redec == plain, f"key {key:#x}"

    def test_odd_length_body(self):
        """Trailing bytes that don't fill a shuffle chunk still roundtrip."""
        raw = _make_spt(0xF2, bytes(range(13)))
        dec = decrypt(raw)
        assert encrypt(dec) == raw


@pytest.mark.nonfree
class TestNonfreeRoundtrip:
    """Verify decrypt/encrypt roundtrip on all real SPT files."""

    NONFREE_DIR = os.path.join(os.path.dirname(__file__), "nonfree")

    def test_all_spt_files(self):
        if not os.path.isdir(self.NONFREE_DIR):
            pytest.skip("nonfree/ directory not found")

        from tamago.formats.gsp.gspfile import GSPFile

        gsp_path = os.path.join(self.NONFREE_DIR, "data.gsp")
        if not os.path.isfile(gsp_path):
            pytest.skip("data.gsp not found")

        with GSPFile(gsp_path) as gsp:
            for f in gsp.files:
                if not is_encrypted(f.file_name):
                    continue
                raw = gsp.read(f)
                dec = decrypt(raw)
                reenc = encrypt(dec)
                assert reenc == raw, f"{f.file_name}: roundtrip failed"
