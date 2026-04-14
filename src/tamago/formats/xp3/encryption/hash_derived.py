"""XP3 encryption handlers using keys derived from the file hash via formulas.

Usage:
    from tamago.formats.xp3 import XP3File
    from tamago.formats.xp3.encryption.hash_derived import PoringSoftEncryption

    xp3 = XP3File("data.xp3", encryption=PoringSoftEncryption())
    xp3.extract_all("output/")
"""

from .base import XP3Encryption


class PoringSoftEncryption(XP3Encryption):
    """PoringSoftCrypt: single-byte XOR with key = ~(hash + 1) & 0xFF."""

    def _xor(self, data, info):
        key_byte = (~(info.key + 1)) & 0xFF
        if key_byte == 0:
            return data
        return bytes(b ^ key_byte for b in data)

    def decrypt(self, data, info, segment):
        return self._xor(data, info)

    def encrypt(self, data, info, segment):
        return self._xor(data, info)
