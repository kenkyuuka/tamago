"""MurmurHash2, which YU-RIS 478+ uses for YPF name hashes and data checksums.

The pure-Python version is the reference; a C accelerator (``_murmur_accel``)
replaces it when it was built, since archives of several gigabytes have every
stored byte hashed.
"""

import array
import sys

try:
    from tamago.formats.yuris import _murmur_accel  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - depends on the build
    _murmur_accel = None  # type: ignore[assignment]

_M = 0x5BD1E995
_MASK = 0xFFFFFFFF


def murmur2_py(data: bytes | bytearray | memoryview, seed: int = 0) -> int:
    """Return the 32-bit MurmurHash2 of *data* (Austin Appleby's original, little-endian blocks)."""
    data = memoryview(data).cast('B')
    length = len(data)
    h = (seed ^ length) & _MASK
    blocks = length & ~3
    words = array.array('I')
    assert words.itemsize == 4
    words.frombytes(data[:blocks])
    if sys.byteorder == 'big':  # pragma: no cover
        words.byteswap()
    for word in words:
        k = (word * _M) & _MASK
        k ^= k >> 24
        # (h * m) ^ (k * m): multiplying k by m again folds the block in.
        h = ((h * _M) ^ (k * _M)) & _MASK
    tail = data[blocks:]
    if len(tail) == 3:
        h ^= tail[2] << 16
    if len(tail) >= 2:
        h ^= tail[1] << 8
    if len(tail) >= 1:
        h ^= tail[0]
        h = (h * _M) & _MASK
    h ^= h >> 13
    h = (h * _M) & _MASK
    h ^= h >> 15
    return h


def murmur2(data: bytes | bytearray | memoryview, seed: int = 0) -> int:
    """Return the 32-bit MurmurHash2 of *data*."""
    if _murmur_accel is not None:
        return _murmur_accel.murmur2(data, seed)
    return murmur2_py(data, seed)
