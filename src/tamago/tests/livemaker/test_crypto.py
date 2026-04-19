"""Tests for LiveMaker cryptographic primitives."""

import pytest

from tamago.formats.livemaker.crypto import (
    SCRAMBLE_SEED_MASK,
    TpRandom,
    TpScramble,
    crypt_name,
    scramble,
    scramble_sequence,
    unscramble,
)


@pytest.mark.unit
class TestTpRandom:
    def test_initial_state_zero(self):
        rnd = TpRandom()
        assert rnd.state == 0

    def test_first_outputs(self):
        """Known sequence derived from ``state = (state*5 + 0x75D6EE39) mod 2^32``.

        The constant (seed) is also the first output.  The second output
        is ``6 * constant (mod 2^32)`` since ``5*x + x`` for x = constant.
        """
        rnd = TpRandom()
        assert rnd.next_uint32() == 0x75D6EE39
        assert rnd.next_uint32() == (6 * 0x75D6EE39) & 0xFFFFFFFF
        # Verify the third output via the recurrence.
        state = (6 * 0x75D6EE39) & 0xFFFFFFFF
        expected = ((state << 2) + state + 0x75D6EE39) & 0xFFFFFFFF
        assert rnd.next_uint32() == expected

    def test_reset_restores_zero(self):
        rnd = TpRandom()
        rnd.next_uint32()
        rnd.next_uint32()
        rnd.reset()
        assert rnd.state == 0
        assert rnd.next_uint32() == 0x75D6EE39

    def test_sign_extension(self):
        """``next_sign_extended`` should produce a negative Python int when bit 31 is set."""
        rnd = TpRandom()
        # Find a state where the output has bit 31 set (0x79D9B9E7 does not; 0x84... would).
        # Just iterate until we see one.
        for _ in range(1000):
            val = rnd.next_sign_extended()
            if val < 0:
                assert val & (1 << 63)  # upper bits set when masked to 64 bits
                return
        pytest.fail("No sign-extended output observed in 1000 iterations")


@pytest.mark.unit
class TestCryptName:
    def test_documented_example(self):
        """Worked example from the format documentation.

        Encrypted ``09 66 d7 8c d5 82 83 89 ff 22 cc 96`` decodes to
        ``00000001.lsb`` with a fresh PRNG at state 0.
        """
        encrypted = bytes([0x09, 0x66, 0xD7, 0x8C, 0xD5, 0x82, 0x83, 0x89, 0xFF, 0x22, 0xCC, 0x96])
        rnd = TpRandom()
        decoded = crypt_name(encrypted, rnd)
        assert decoded == b'00000001.lsb'

    def test_symmetric(self):
        """Encrypting and decrypting the same name with fresh PRNGs roundtrips."""
        name = b'alice_in_wonderland.lsb'
        rnd_enc = TpRandom()
        encrypted = crypt_name(name, rnd_enc)
        rnd_dec = TpRandom()
        decrypted = crypt_name(encrypted, rnd_dec)
        assert decrypted == name

    def test_state_carries_across_names(self):
        """A single PRNG used for two names does not re-use bytes across them."""
        rnd = TpRandom()
        name_a = b'alice'
        name_b = b'queen'
        encrypted_a = crypt_name(name_a, rnd)
        encrypted_b = crypt_name(name_b, rnd)
        # Decode with a single shared generator (matching the encoder).
        rnd2 = TpRandom()
        assert crypt_name(encrypted_a, rnd2) == name_a
        assert crypt_name(encrypted_b, rnd2) == name_b

    def test_reset_breaks_carry(self):
        """Resetting the PRNG between names breaks the chain."""
        name_a = b'rabbit'
        name_b = b'hatter'
        rnd = TpRandom()
        encrypted_a = crypt_name(name_a, rnd)
        encrypted_b = crypt_name(name_b, rnd)
        # If we reset between decoding, the second name decodes wrong.
        rnd2 = TpRandom()
        assert crypt_name(encrypted_a, rnd2) == name_a
        rnd2.reset()
        assert crypt_name(encrypted_b, rnd2) != name_b


@pytest.mark.unit
class TestTpScramble:
    def test_nonzero_seed(self):
        """Same seed reproduces the same sequence."""
        a = TpScramble(0x12345678)
        b = TpScramble(0x12345678)
        for _ in range(20):
            assert a._next_uint32() == b._next_uint32()

    def test_zero_seed_promoted(self):
        """Seed 0 is treated as 0xFFFFFFFF."""
        a = TpScramble(0)
        b = TpScramble(0xFFFFFFFF)
        for _ in range(20):
            assert a._next_uint32() == b._next_uint32()

    def test_next_int_range(self):
        tp = TpScramble(42)
        for _ in range(200):
            v = tp.next_int(5, 10)
            assert 5 <= v <= 10


@pytest.mark.unit
class TestScrambleSequence:
    def test_last_slot_fixed(self):
        """``sequence[count-1]`` is always ``count-1`` — last chunk stays in place."""
        for count in (1, 2, 5, 16, 100):
            seq = scramble_sequence(count, seed=count * 7)
            assert seq[count - 1] == count - 1

    def test_permutation(self):
        for count in (1, 2, 8, 50):
            seq = scramble_sequence(count, seed=count)
            assert sorted(seq) == list(range(count))


@pytest.mark.unit
class TestScrambleRoundtrip:
    @pytest.mark.parametrize('chunk_size', [4, 16, 64, 256])
    @pytest.mark.parametrize('seed', [0, 1, 0xDEADBEEF, 0xF8EA])
    def test_multiple_chunks(self, chunk_size, seed):
        """``unscramble(scramble(data)) == data`` for varied sizes."""
        data = bytes(range(256)) * 4  # 1024 bytes of distinguishable content
        scrambled = scramble(data, chunk_size, raw_seed=seed)
        assert unscramble(scrambled) == data

    def test_short_tail_preserved(self):
        """Data that isn't a chunk-size multiple keeps its tail intact."""
        data = b'A' * 100 + b'BCDE'
        scrambled = scramble(data, 32, raw_seed=9)
        assert unscramble(scrambled) == data

    def test_single_chunk(self):
        data = b'tea party data'
        scrambled = scramble(data, 64, raw_seed=1)
        assert unscramble(scrambled) == data

    def test_empty_data(self):
        assert unscramble(scramble(b'', 16, raw_seed=0)) == b''

    def test_header_structure(self):
        """The 8-byte header encodes chunk_size and raw_seed in LE."""
        data = b'x' * 50
        scrambled = scramble(data, 0x1000, raw_seed=0x11223344)
        assert scrambled[:4] == (0x1000).to_bytes(4, 'little', signed=True)
        assert scrambled[4:8] == (0x11223344).to_bytes(4, 'little', signed=False)

    def test_seed_mask(self):
        """PRNG seed is ``raw_seed ^ 0xF8EA``."""
        # If we scramble with raw_seed=X, unscrambling via manually using
        # seed=X^0xF8EA should produce the same result.
        data = bytes(range(100))
        chunk = 16
        raw_seed = 0x55AA
        scrambled = scramble(data, chunk, raw_seed=raw_seed)
        # Recreate unscramble manually using the expected PRNG seed.
        effective_seed = raw_seed ^ SCRAMBLE_SEED_MASK
        body = scrambled[8:]
        count = (len(body) - 1) // chunk + 1
        seq = scramble_sequence(count, effective_seed)
        out = bytearray(len(body))
        dst = 0
        for idx in seq:
            pos = idx * chunk
            length = min(chunk, len(body) - pos)
            out[dst : dst + length] = body[pos : pos + length]
            dst += length
        assert bytes(out) == data

    def test_invalid_chunk_size(self):
        with pytest.raises(ValueError):
            scramble(b'data', 0, raw_seed=0)
        with pytest.raises(ValueError):
            scramble(b'data', -1, raw_seed=0)
