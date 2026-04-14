from importlib.metadata import entry_points

from .base import XP3Encryption
from .fixed_xor import FixedXorEncryption
from .hash_derived import PoringSoftEncryption
from .hash_xor import HashXorEncryption
from .null import NullEncryption
from .pinpoint import PinPointEncryption

ENTRY_POINT_GROUP = 'tamago.formats.xp3.encryption'


def get_encryption_schemes():
    """Discover registered encryption schemes via entry points.

    Returns a dict mapping scheme names to entry points.
    """
    return {ep.name: ep for ep in entry_points(group=ENTRY_POINT_GROUP)}


__all__ = [
    'FixedXorEncryption',
    'HashXorEncryption',
    'NullEncryption',
    'PinPointEncryption',
    'PoringSoftEncryption',
    'XP3Encryption',
    'get_encryption_schemes',
]
