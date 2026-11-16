"""The cipher ANIM's engine applies to its scripts and images.

An enciphered file is a 4-byte marker (``00 00 00 01``), a 16-byte key, then the
data XORed with that key.  After every complete 16-byte block the key changes,
in one of eight ways chosen by the low three bits of the block's plaintext byte
at offset 14.  A final partial block is XORed with the current key and ends the
file.

Because the key schedule depends on the plaintext, decryption is strictly
sequential.  The stored key is not checked against anything, so any key
produces a file the engine accepts.
"""

MAGIC = b'\x00\x00\x00\x01'
KEY_SIZE = 16
HEADER_SIZE = len(MAGIC) + KEY_SIZE
BLOCK_SIZE = 16
# The plaintext byte of each block that selects the next key.
SELECTOR = 14


def is_encrypted(data: bytes) -> bool:
    """Return True if *data* starts with the cipher's header."""
    return len(data) >= HEADER_SIZE and data[: len(MAGIC)] == MAGIC


def stored_key(data: bytes) -> bytes:
    """Return the key stored in the header of enciphered *data*."""
    if not is_encrypted(data):
        raise ValueError("not enciphered (expected a 00 00 00 01 header)")
    return bytes(data[len(MAGIC) : HEADER_SIZE])


def _advance(k: list[int], selector: int) -> None:
    """Change key *k* in place for the next block.

    The assignments run in order, so a later one can read a byte an earlier one
    has just changed (as in cases 6 and 7).
    """
    branch = selector & 7
    if branch == 0:
        k[0] = k[0] + selector
        k[3] = k[3] + selector + 2
        k[4] = k[2] + selector + 11
        k[8] = k[6] + 7
    elif branch == 1:
        k[2] = k[9] + k[10]
        k[6] = k[7] + k[15]
        k[8] = k[8] + k[1]
        k[15] = k[5] + k[3]
    elif branch == 2:
        k[1] = k[1] + k[2]
        k[5] = k[5] + k[6]
        k[7] = k[7] + k[8]
        k[10] = k[10] + k[11]
    elif branch == 3:
        k[9] = k[2] + k[1]
        k[11] = k[6] + k[5]
        k[12] = k[8] + k[7]
        k[13] = k[11] + k[10]
    elif branch == 4:
        k[0] = k[1] + 111
        k[3] = k[4] + 71
        k[4] = k[5] + 17
        k[14] = k[15] + 64
    elif branch == 5:
        k[2] = k[2] + k[10]
        k[4] = k[5] + k[12]
        k[6] = k[8] + k[14]
        k[8] = k[11] + k[0]
    else:
        if branch == 6:
            k[9] = k[11] + k[1]
            k[11] = k[13] + k[3]
            k[13] = k[15] + k[5]
            k[15] = k[9] + k[7]
        k[1] = k[9] + k[5]
        k[2] = k[10] + k[6]
        k[3] = k[11] + k[7]
        k[4] = k[12] + k[8]
    for i in range(KEY_SIZE):
        k[i] &= 0xFF


def _xor(block: bytes, key: list[int]) -> bytes:
    n = len(block)
    return (int.from_bytes(block, 'little') ^ int.from_bytes(bytes(key[:n]), 'little')).to_bytes(n, 'little')


def decrypt(data: bytes) -> bytes:
    """Return the plaintext of enciphered *data*.  Raises ValueError if *data* is not enciphered."""
    key = list(stored_key(data))
    out = bytearray()
    for at in range(HEADER_SIZE, len(data), BLOCK_SIZE):
        block = _xor(data[at : at + BLOCK_SIZE], key)
        out += block
        if len(block) == BLOCK_SIZE:
            _advance(key, block[SELECTOR])
    return bytes(out)


def encrypt(data: bytes, key: bytes = bytes(KEY_SIZE)) -> bytes:
    """Encipher *data* with the 16-byte *key*, the inverse of :func:`decrypt`."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"the key must be {KEY_SIZE} bytes, not {len(key)}")
    k = list(key)
    out = bytearray(MAGIC + bytes(key))
    for at in range(0, len(data), BLOCK_SIZE):
        block = data[at : at + BLOCK_SIZE]
        out += _xor(block, k)
        if len(block) == BLOCK_SIZE:
            _advance(k, block[SELECTOR])
    return bytes(out)
