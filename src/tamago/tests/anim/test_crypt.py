"""Tests for the cipher of ANIM's scripts and images."""

import pytest

from tamago.formats.anim import decrypt, encrypt, is_encrypted, stored_key

KEY = b'DRINK ME EAT ME!'

# The plaintext's full blocks select every one of the eight key changes (their
# byte 14 covers every value mod 8), and it ends in a partial block.
PLAINTEXT = (
    b"Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do: "
    b"once or twice she had peeped into the book her sister was reading, but it had no pictures or conversations "
    b"in it, whether the pleasure of making a daisy-chain would be worth the trouble of getting up and picking the "
    b"daisies, 'and what is the use of a book,' thought Alice 'without pictures or conversations?'"
)

# PLAINTEXT enciphered with KEY by an independent implementation.
CIPHERTEXT = bytes.fromhex(
    '000000014452494e4b204d4520454154204d4521053e202d2e003a245365233147242b4f2da8e9c0344f6d2245d261ed'
    '45333ccb30af958524005f23c6d528ef54282b6764e308466e45426595083255455265c90aa105e0f9005224590a6d01'
    '414e21869fe7518b5056592b50412f4e54488fc897a1d68c1144847f980e2f4245008971d0f55b0fbb45cb36d0046149'
    '4144c67375e45ced3300822b860e61554845c6615fee478a3f459965810832554552c67431f20cbe32418f2c9c066d01'
    '4255922399f50cf65044cb2b9d4131484354367195f24df13200562a7f1724535341376a9fef1ea7584e152c654d6156'
    '4845376b95f34d0c594515357d042052555226239fe78e15214b3d2b7641200144412a7089acc11021492665e50e344d'
    '440021fdd054cd0a340068a3fa044255524f36fa9c462417ee48b2b265150b4f470036e8d042081ca8183db47a080c46'
    '00542bfd7847078baa0131a4774145404e4463ef10421224f81b74a333044254534563f7fe030706f3073bbc77464255'
    '484f36fff057e867e401fdb29946154854482cedece97091ba1ceba5dc12424e520020f7f6bf658aaa09eabed6a71139'
    'b7'
)


@pytest.mark.unit
class TestKnownAnswer:
    def test_plaintext_selects_every_key_change(self):
        blocks = [PLAINTEXT[i : i + 16] for i in range(0, len(PLAINTEXT) - 15, 16)]
        assert {block[14] & 7 for block in blocks} == set(range(8))
        assert len(PLAINTEXT) % 16

    def test_decrypt(self):
        assert decrypt(CIPHERTEXT) == PLAINTEXT

    def test_encrypt(self):
        assert encrypt(PLAINTEXT, KEY) == CIPHERTEXT

    def test_stored_key(self):
        assert stored_key(CIPHERTEXT) == KEY

    def test_first_block_is_plain_xor_with_the_stored_key(self):
        assert CIPHERTEXT[20:36] == bytes(p ^ k for p, k in zip(PLAINTEXT[:16], KEY, strict=True))


@pytest.mark.unit
class TestCipher:
    @pytest.mark.parametrize('length', [0, 1, 15, 16, 17, 32, 33])
    def test_roundtrip_any_length(self, length):
        data = (PLAINTEXT * 2)[:length]
        enciphered = encrypt(data, KEY)
        assert len(enciphered) == 20 + length
        assert decrypt(enciphered) == data

    def test_default_key_is_zeros(self):
        assert stored_key(encrypt(b'Curiouser and curiouser!')) == bytes(16)

    def test_key_changes_between_blocks(self):
        # The same plaintext block twice: identical ciphertext would mean the key stayed put.
        enciphered = encrypt(b'Who are YOU? ...' * 2, KEY)
        assert enciphered[20:36] != enciphered[36:52]

    def test_wrong_key_length(self):
        with pytest.raises(ValueError, match='16 bytes'):
            encrypt(b'Off with her head!', b'QUEEN')

    def test_not_enciphered(self):
        assert not is_encrypted(b'\x89PNG\r\n\x1a\n' + bytes(16))
        assert not is_encrypted(b'\x00\x00\x00\x01short')
        with pytest.raises(ValueError, match='not enciphered'):
            decrypt(b'\x89PNG\r\n\x1a\n' + bytes(16))
