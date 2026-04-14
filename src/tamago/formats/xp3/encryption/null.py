"""Null encryption handler for games that set the encrypted flag but apply no transformation.

Usage:
    from tamago.formats.xp3 import XP3File
    from tamago.formats.xp3.encryption import NullEncryption

    xp3 = XP3File("data.xp3", encryption=NullEncryption())
    xp3.extract_all("output/")
"""

from .base import XP3Encryption


class NullEncryption(XP3Encryption):
    """No-op encryption for games that flag files as encrypted without transforming data."""

    def decrypt(self, data, info, segment):
        return data

    def encrypt(self, data, info, segment):
        return data
