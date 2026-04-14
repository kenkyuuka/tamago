"""XP3 encryption handlers using single-byte XOR derived from the file hash.

Usage:
    from tamago.formats.xp3 import XP3File
    from tamago.formats.xp3.encryption import HashXorEncryption

    xp3 = XP3File("data.xp3", encryption=HashXorEncryption(shift=3))
    xp3.extract_all("output/")
"""

from .base import XP3Encryption


class HashXorEncryption(XP3Encryption):
    """XP3 encryption using single-byte XOR derived from the adlr file hash.

    Args:
        shift: Number of bits to right-shift the hash before masking to a byte.
    """

    def __init__(self, shift):
        self.shift = shift

    def _xor(self, data, info):
        key_byte = (info.key >> self.shift) & 0xFF
        if key_byte == 0:
            return data
        return bytes(b ^ key_byte for b in data)

    def decrypt(self, data, info, segment):
        return self._xor(data, info)

    def encrypt(self, data, info, segment):
        return self._xor(data, info)
