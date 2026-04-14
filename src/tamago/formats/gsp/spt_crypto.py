"""Encryption and decryption for AGSD SPT script files.

SPT and DAT files stored in GSP archives are encrypted with a two-pass
symmetric cipher:

1. **Byte shuffle** — reorders bytes within fixed-size chunks (2, 4, or 8
   bytes depending on key).
2. **Bit permutation + NOT** — each byte's bits are permuted according to a
   key-selected table, then the result is XORed with 0xFF.

The first 4 bytes of the file are an unencrypted header.  Bytes 0 and 1
provide the encryption keys.  Encrypted files are identified by ``byte[1]
== 0xF0``.
"""

# fmt: off

# Bit permutation tables for decryption, indexed by key (0-7).
# Each table has 8 entries giving the shift for bits 0-7.
# Positive = left shift, negative = right shift.
_DECRYPT_TABLES: dict[int, list[int]] = {
    0: [ 2,  6, -1,  0,  1, -5, -2, -1],
    1: [ 3,  4,  0,  3, -3,  2, -6, -3],
    2: [ 7,  5,  3,  1, -1, -3, -5, -7],
    3: [ 3,  1, -1, -3,  3,  1, -1, -3],
    4: [ 6,  3, -2,  4, -3, -2, -1, -5],
    5: [ 5,  6,  4, -1, -4, -4, -2, -4],
    6: [ 7, -1,  4, -2, -2, -1, -3, -2],
    7: [ 1,  5, -2, -1,  1,  2, -2, -4],
}

# Inverse permutation tables for encryption.
_ENCRYPT_TABLES: dict[int, list[int]] = {
    0: [ 5,  1, -2,  0,  2, -1,  1, -6],
    1: [ 6,  3,  0, -3,  3, -4, -3, -2],
    2: [ 7,  5,  3,  1, -1, -3, -5, -7],
    3: [ 3,  1, -1, -3,  3,  1, -1, -3],
    4: [ 2,  3,  5,  2, -3,  1, -6, -4],
    5: [ 4,  4,  1,  4,  2, -5, -4, -6],
    6: [ 1,  2,  2,  3,  1,  2, -4, -7],
    7: [ 2, -1,  1,  4,  2, -1, -5, -2],
}

# fmt: on

# Pre-compute 256-entry lookup tables for each key to avoid per-bit loops.
_DECRYPT_LUT: dict[int, bytes] = {}
_ENCRYPT_LUT: dict[int, bytes] = {}


def _build_lut(table: list[int]) -> bytes:
    """Build a 256-byte lookup table for a bit-permutation + NOT."""
    lut = bytearray(256)
    for b in range(256):
        out = 0
        for bit in range(8):
            if not (b & (1 << bit)):
                continue
            s = table[bit]
            if s < 0:
                out |= (1 << bit) >> (-s)
            else:
                out |= (1 << bit) << s
        lut[b] = (out ^ 0xFF) & 0xFF
    return bytes(lut)


for _key in range(8):
    _DECRYPT_LUT[_key] = _build_lut(_DECRYPT_TABLES[_key])
    _ENCRYPT_LUT[_key] = _build_lut(_ENCRYPT_TABLES[_key])


def is_encrypted(name: str) -> bool:
    """Return True if *name* has an extension associated with SPT encryption."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in ("spt", "dat")


def _shuffle(body: bytearray, key: int) -> None:
    """Apply byte shuffle in-place.  All three shuffle modes are self-inverse."""
    if key == 0:
        for i in range(0, len(body) - 1, 2):
            body[i], body[i + 1] = body[i + 1], body[i]
    elif key == 1:
        for i in range(0, len(body) - 3, 4):
            body[i], body[i + 1], body[i + 2], body[i + 3] = (body[i + 2], body[i + 3], body[i], body[i + 1])
    elif key == 2:
        for i in range(0, len(body) - 7, 8):
            a, b, c, d, e, f, g, h = (
                body[i],
                body[i + 1],
                body[i + 2],
                body[i + 3],
                body[i + 4],
                body[i + 5],
                body[i + 6],
                body[i + 7],
            )
            body[i], body[i + 1], body[i + 2], body[i + 3] = g, e, f, h
            body[i + 4], body[i + 5], body[i + 6], body[i + 7] = b, c, a, d


def _apply_lut(body: bytearray, lut: bytes) -> None:
    """Apply a byte lookup table in-place."""
    for i in range(len(body)):
        body[i] = lut[body[i]]


def decrypt(data: bytes) -> bytes:
    """Decrypt an SPT/DAT file, returning the plaintext.

    The 4-byte header is preserved unchanged.  Use :func:`is_encrypted` to
    check whether a file should be decrypted based on its name.
    """
    if len(data) < 4:
        return data

    shuffle_key = data[1] ^ 0xF0
    bitperm_key = data[0] ^ 0xF0
    if bitperm_key not in _DECRYPT_LUT:
        return data

    body = bytearray(data[4:])
    _shuffle(body, shuffle_key)
    _apply_lut(body, _DECRYPT_LUT[bitperm_key])
    return data[:4] + bytes(body)


def encrypt(data: bytes) -> bytes:
    """Encrypt plaintext SPT/DAT data, returning the ciphertext.

    The 4-byte header is preserved unchanged.  The header must already
    contain valid key bytes (``byte[1] == 0xF0``, ``byte[0]`` in
    ``0xF0..0xF7``).
    """
    if len(data) < 4:
        return data

    shuffle_key = data[1] ^ 0xF0
    bitperm_key = data[0] ^ 0xF0
    if bitperm_key not in _ENCRYPT_LUT:
        return data

    body = bytearray(data[4:])
    _apply_lut(body, _ENCRYPT_LUT[bitperm_key])
    _shuffle(body, shuffle_key)
    return data[:4] + bytes(body)
