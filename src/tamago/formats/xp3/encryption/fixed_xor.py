"""XP3 encryption handler using a fixed repeating XOR key.

Some KiriKiri games use a fixed multi-byte key that is XORed cyclically
against the file data, independent of the file hash.

Usage:
    from tamago.formats.xp3 import XP3File
    from tamago.formats.xp3.encryption import FixedXorEncryption

    xp3 = XP3File("data.xp3", encryption=FixedXorEncryption(key=b'\\xAB\\xCD'))
    xp3.extract_all("output/")

In the encryption library TOML, specify the key as a hex string:

    [games.example]
    encryption = "fixed-xor"
    key = "ABCD"
"""

from .base import XP3Encryption


class FixedXorEncryption(XP3Encryption):
    """XP3 encryption using a fixed repeating XOR key.

    Args:
        key: The encryption key, as bytes or a hex string.
    """

    def __init__(self, key):
        if isinstance(key, str):
            key = bytes.fromhex(key)
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("key must be non-empty bytes or hex string")
        self.key = key

    def _xor(self, data):
        if len(self.key) == 1:
            k = self.key[0]
            if k == 0:
                return data
            return bytes(b ^ k for b in data)
        key = self.key
        key_len = len(key)
        return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

    def decrypt(self, data, info, segment):
        return self._xor(data)

    def encrypt(self, data, info, segment):
        return self._xor(data)
