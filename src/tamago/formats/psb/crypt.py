"""E-mote's PSB cipher: an xorshift128 keystream seeded with a per-game key.

The generator's state is four u32 words, ``{0x075BCD15, 0x159A55E5,
0x1F123BB5, key}`` (the first three are Marsaglia's xorshift128 seeds).  Every
step produces a u32 whose bytes, low byte first, are XORed into the data, but
only up to its highest non-zero byte: the cipher shifts the word right by 8
after each byte and steps again once it is zero, so a word like ``0x0000ABCD``
gives two bytes, and a zero word one.  The step differs from Marsaglia's: the
new word is ``t ^ w ^ ((t ^ (w >> 11)) >> 8)`` with ``t = x ^ (x << 11)``.

The first output depends on the key alone, and the mapping is invertible, so a
key can be recovered from the first keystream word, given known plaintext at
the start of a stream (:func:`recover_key`).
"""

_M = 0xFFFFFFFF
SEED = (0x075BCD15, 0x159A55E5, 0x1F123BB5)


class Keystream:
    """A PSB keystream; :meth:`xor` continues from where the previous call stopped."""

    def __init__(self, key: int):
        self._x, self._y, self._z = SEED
        self._w = key & _M
        self._buf = b''

    def _words(self, count: int) -> bytes:
        x, y, z, w = self._x, self._y, self._z, self._w
        out = bytearray()
        for _ in range(count):
            t = (x ^ (x << 11)) & _M
            x, y, z = y, z, w
            w = t ^ w ^ ((t ^ (w >> 11)) >> 8)
            out += w.to_bytes(4, 'little')[: max(1, (w.bit_length() + 7) // 8)]
        self._x, self._y, self._z, self._w = x, y, z, w
        return bytes(out)

    def take(self, n: int) -> bytes:
        """Return the next *n* keystream bytes."""
        while len(self._buf) < n:
            self._buf += self._words((n - len(self._buf) + 3) // 4)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def xor(self, data: bytes) -> bytes:
        """XOR *data* with the next ``len(data)`` keystream bytes (encrypts and decrypts alike)."""
        if not data:
            return b''
        stream = self.take(len(data))
        n = len(data)
        return (int.from_bytes(data, 'little') ^ int.from_bytes(stream, 'little')).to_bytes(n, 'little')


def xor(data: bytes, key: int) -> bytes:
    """XOR *data* with a fresh keystream for *key*."""
    return Keystream(key).xor(data)


def recover_key(ciphertext: bytes, plaintext: bytes) -> int:
    """Return the key whose keystream turns the first 4 bytes of *plaintext* into *ciphertext*'s.

    Both must be at least 4 bytes and start at the beginning of a stream.  This
    assumes the first keystream word has a non-zero high byte, so that it gives
    all 4 bytes; for the other keys (1 in 256) the result is wrong, and callers
    should check it.
    """
    if len(ciphertext) < 4 or len(plaintext) < 4:
        raise ValueError('recovering a key needs 4 bytes of known plaintext')
    out = int.from_bytes(ciphertext[:4], 'little') ^ int.from_bytes(plaintext[:4], 'little')
    x = SEED[0]
    t = (x ^ (x << 11)) & _M
    # out = t ^ w ^ ((t ^ (w >> 11)) >> 8); solve for u = w ^ (w >> 19).
    u = out ^ t ^ (t >> 8)
    # Invert u = w ^ (w >> 19): the top 19 bits of w are those of u, and the rest follow.
    return u ^ (u >> 19)
