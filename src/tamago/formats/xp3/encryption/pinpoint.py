"""XP3 encryption handler for Pin-Point games.

PinPointCrypt applies byte rotation by popcount: each byte is rotated left
(decrypt) or right (encrypt) by the number of set bits in that byte. No key
or hash involvement.

Usage:
    from tamago.formats.xp3 import XP3File
    from tamago.formats.xp3.encryption.pinpoint import PinPointEncryption

    xp3 = XP3File("data.xp3", encryption=PinPointEncryption())
    xp3.extract_all("output/")
"""

from .base import XP3Encryption


class PinPointEncryption(XP3Encryption):
    """PinPointCrypt: byte rotation by popcount.

    Decrypt rotates each byte left by popcount(byte).
    Encrypt rotates each byte right by popcount(byte).
    Rotation preserves popcount, so the count can be computed from either side.
    """

    @staticmethod
    def _popcount(x):
        """Count the number of set bits in a byte."""
        x = (x & 0x55) + ((x >> 1) & 0x55)
        x = (x & 0x33) + ((x >> 2) & 0x33)
        return (x + (x >> 4)) & 0x0F

    def decrypt(self, data, info, segment):
        if not data:
            return data
        result = bytearray(data)
        for i in range(len(result)):
            bc = self._popcount(result[i])
            if bc and bc != 8:
                result[i] = ((result[i] << bc) | (result[i] >> (8 - bc))) & 0xFF
        return bytes(result)

    def encrypt(self, data, info, segment):
        if not data:
            return data
        result = bytearray(data)
        for i in range(len(result)):
            bc = self._popcount(result[i])
            if bc and bc != 8:
                result[i] = ((result[i] >> bc) | (result[i] << (8 - bc))) & 0xFF
        return bytes(result)
