"""Cryptographic primitives for LiveMaker VF archives.

Two PRNGs are used by the format:

- :class:`TpRandom` — the simple multiplicative generator used to encrypt
  file names and offsets in the archive index.
- :class:`TpScramble` — a combined multiply-with-carry generator used to
  reorder chunks within scrambled file data (flags 2 and 3).
"""

import ctypes


class TpRandom:
    """PRNG used for filename encryption, offset XORing, and Gale shuffling.

    The state recurrence is ``state = (state * 5 + seed) mod 2**32``, with
    ``state`` initialized to 0.  VF archives use the fixed seed
    ``0x75D6EE39`` for filename and offset obfuscation; Gale image shuffling
    uses a per-game 32-bit key as the seed.

    The low byte of each output is used as the key byte for filename
    decryption; offsets XOR with the full 32-bit output, sign-extended to
    64 bits; Gale takes ``output % remaining`` to build a permutation.
    """

    __slots__ = ('state', 'seed')

    DEFAULT_SEED = 0x75D6EE39

    def __init__(self, seed: int = DEFAULT_SEED):
        self.seed = seed & 0xFFFFFFFF
        self.state = 0

    def reset(self) -> None:
        """Reset the PRNG state to zero."""
        self.state = 0

    def next_uint32(self) -> int:
        """Advance the state and return the new 32-bit output."""
        self.state = ((self.state << 2) + self.state + self.seed) & 0xFFFFFFFF
        return self.state

    def next_sign_extended(self) -> int:
        """Advance the state and return the output sign-extended to 64 bits.

        This is the form used when XORing file data offsets.  If the raw
        32-bit output has its high bit set, the upper 32 bits are all 1s
        rather than all 0s.
        """
        return ctypes.c_int32(self.next_uint32()).value


def crypt_name(name: bytes, rnd: TpRandom) -> bytes:
    """XOR *name* bytes with the low byte of successive PRNG outputs.

    The same operation both encrypts and decrypts names.  *rnd* is advanced
    by ``len(name)`` steps; its state carries forward so callers can encrypt
    a sequence of names with a single shared generator.
    """
    out = bytearray(name)
    for i in range(len(out)):
        out[i] ^= rnd.next_uint32() & 0xFF
    return bytes(out)


class TpScramble:
    """Combined multiply-with-carry PRNG used to scramble file data.

    Seeded with a 32-bit value; zero is silently promoted to 0xFFFFFFFF.
    The state is 5 uint32s, initialized by iterating a xorshift over the
    seed, then warmed up with 19 discarded outputs before use.
    """

    FACTOR_A = 2111111111
    FACTOR_B = 1492
    FACTOR_C = 1776
    FACTOR_D = 5115

    __slots__ = ('state',)

    def __init__(self, seed: int):
        h = seed if seed != 0 else 0xFFFFFFFF
        state = [0] * 5
        for i in range(5):
            h ^= (h << 13) & 0xFFFFFFFF
            h ^= h >> 17
            h ^= (h << 5) & 0xFFFFFFFF
            state[i] = h
        self.state = state
        for _ in range(19):
            self._next_uint32()

    def _next_uint32(self) -> int:
        s = self.state
        v = self.FACTOR_A * s[3] + self.FACTOR_B * s[2] + self.FACTOR_C * s[1] + self.FACTOR_D * s[0] + s[4]
        s[3] = s[2]
        s[2] = s[1]
        s[1] = s[0]
        s[4] = v >> 32
        s[0] = v & 0xFFFFFFFF
        return s[0]

    def next_int(self, first: int, last: int) -> int:
        """Return an integer in ``[first, last]`` inclusive."""
        r = self._next_uint32() / 0x100000000
        return first + int(r * (last - first + 1))


def scramble_sequence(count: int, seed: int) -> list[int]:
    """Return the permutation used to unscramble *count* chunks.

    Given scrambled chunks ``chunks``, the original order is recovered by
    ``[chunks[sequence[k]] for k in range(count)]``.  Equivalently, the
    scrambled layout is produced by ``scrambled[sequence[k]] = original[k]``.
    """
    tp = TpScramble(seed)
    order = list(range(count))
    seq = [0] * count
    for i in range(count - 1):
        n = tp.next_int(0, len(order) - 2)
        seq[order[n]] = i
        order.pop(n)
    seq[order[0]] = count - 1
    return seq


SCRAMBLE_SEED_MASK = 0xF8EA


def unscramble(data: bytes) -> bytes:
    """Reverse the chunk-reorder scrambling applied to file data.

    *data* begins with an 8-byte header: a little-endian int32 chunk size
    and a little-endian uint32 raw seed.  The PRNG seed is
    ``raw_seed ^ 0xF8EA``.  The remainder is divided into fixed-size chunks
    (the last may be shorter) and reassembled in original order.
    """
    if len(data) < 8:
        raise ValueError("Scrambled data must be at least 8 bytes")
    chunk_size = int.from_bytes(data[:4], 'little', signed=True)
    raw_seed = int.from_bytes(data[4:8], 'little', signed=False)
    if chunk_size <= 0:
        raise ValueError(f"Invalid scramble chunk_size {chunk_size}")
    seed = raw_seed ^ SCRAMBLE_SEED_MASK
    body = data[8:]
    body_len = len(body)
    if body_len == 0:
        return b''
    count = (body_len - 1) // chunk_size + 1
    sequence = scramble_sequence(count, seed)
    out = bytearray(body_len)
    dst = 0
    for src_idx in sequence:
        pos = src_idx * chunk_size
        length = min(chunk_size, body_len - pos)
        out[dst : dst + length] = body[pos : pos + length]
        dst += length
    return bytes(out)


def scramble(data: bytes, chunk_size: int, raw_seed: int) -> bytes:
    """Apply chunk-reorder scrambling to *data* and prepend the 8-byte header.

    The produced bytes can be passed back to :func:`unscramble` to recover
    the original content.  *raw_seed* is stored verbatim in the header; the
    PRNG seed is ``raw_seed ^ 0xF8EA``.
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be positive (got {chunk_size})")
    raw_seed &= 0xFFFFFFFF
    seed = raw_seed ^ SCRAMBLE_SEED_MASK
    body_len = len(data)
    header = int(chunk_size).to_bytes(4, 'little', signed=True) + raw_seed.to_bytes(4, 'little', signed=False)
    if body_len == 0:
        return header
    count = (body_len - 1) // chunk_size + 1
    sequence = scramble_sequence(count, seed)
    # sequence[k] is the scrambled-slot index of the k'th original chunk.
    # The generator always fixes sequence[count-1] == count-1, so the short
    # tail chunk stays in place and all other chunks are full chunk_size.
    out = bytearray(body_len)
    for k, scrambled_idx in enumerate(sequence):
        src = k * chunk_size
        dst = scrambled_idx * chunk_size
        length = min(chunk_size, body_len - src)
        out[dst : dst + length] = data[src : src + length]
    return header + bytes(out)
