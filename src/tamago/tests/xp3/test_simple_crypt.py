import pytest

from tamago.formats.xp3 import simple_crypt

ALICE_TEXT = "Alice fell down the rabbit hole."
ALICE_UTF16 = ALICE_TEXT.encode("utf-16-le")
ALICE_BOMMED = b"\xff\xfe" + ALICE_UTF16


@pytest.mark.unit
class TestIsEncrypted:
    def test_magic_header(self):
        assert simple_crypt.is_encrypted(b"\xfe\xfe\x01")

    def test_bom_is_not_encrypted(self):
        assert not simple_crypt.is_encrypted(b"\xff\xfe")

    def test_random_bytes(self):
        assert not simple_crypt.is_encrypted(b"\x00\x00\x00")

    def test_too_short(self):
        assert not simple_crypt.is_encrypted(b"")
        assert not simple_crypt.is_encrypted(b"\xfe")


@pytest.mark.unit
class TestGetMode:
    def test_plain_returns_none(self):
        assert simple_crypt.get_mode(b"\xff\xfe") is None

    def test_mode_byte(self):
        assert simple_crypt.get_mode(b"\xfe\xfe\x01") == 1
        assert simple_crypt.get_mode(b"\xfe\xfe\x02") == 2

    def test_truncated_raises(self):
        with pytest.raises(ValueError, match="truncated"):
            simple_crypt.get_mode(b"\xfe\xfe")


@pytest.mark.unit
class TestDecodeMode1:
    def test_single_character_a(self):
        # BOM is stored unencrypted; only the text after the BOM is bit-swapped.
        data = b"\xfe\xfe\x01" + b"\xff\xfe" + _ref_swap(ALICE_BOMMED[2:4])
        expected = ALICE_BOMMED[:4]  # BOM + 'A'
        assert simple_crypt.decode(data) == expected

    def test_alice_roundtrip(self):
        encoded = simple_crypt.encode(ALICE_BOMMED)
        assert encoded.startswith(b"\xfe\xfe\x01\xff\xfe")
        assert encoded != ALICE_BOMMED
        assert simple_crypt.decode(encoded) == ALICE_BOMMED

    def test_passthrough_plain(self):
        assert simple_crypt.decode(ALICE_BOMMED) == ALICE_BOMMED

    def test_header_layout(self):
        # The first 5 bytes of any mode-1 file are FE FE 01 FF FE.
        encoded = simple_crypt.encode(b"\xff\xfe")
        assert encoded == b"\xfe\xfe\x01\xff\xfe"

    def test_empty_bom_only(self):
        assert simple_crypt.decode(b"\xff\xfe") == b"\xff\xfe"
        assert simple_crypt.decode(simple_crypt.encode(b"\xff\xfe")) == b"\xff\xfe"

    def test_rejects_missing_bom(self):
        # Valid header but no BOM after it.
        with pytest.raises(ValueError, match="BOM"):
            simple_crypt.decode(b"\xfe\xfe\x01" + b"\x00\x00\x37\x00")


@pytest.mark.unit
class TestDecodeErrors:
    def test_unsupported_mode_other(self):
        with pytest.raises(ValueError, match="unsupported mode"):
            simple_crypt.decode(b"\xfe\xfe\x99\xff\xfe")

    def test_missing_bom_after_header(self):
        with pytest.raises(ValueError, match="BOM"):
            simple_crypt.decode(b"\xfe\xfe\x01\x00\x00")

    def test_odd_payload_length(self):
        # Header + BOM + single trailing byte (odd payload)
        with pytest.raises(ValueError, match="even"):
            simple_crypt.decode(b"\xfe\xfe\x01\xff\xfe\x37")

    def test_truncated_mode2_trailer(self):
        with pytest.raises(ValueError, match="trailer"):
            simple_crypt.decode(b"\xfe\xfe\x02\xff\xfe" + b"\x00" * 5)


@pytest.mark.unit
class TestAnsiPassthrough:
    """KiriKiri falls back to ANSI/MBCS for unrecognized prefixes; so do we."""

    def test_ascii_passthrough(self):
        data = b";//===== plain ASCII =====\n"
        assert simple_crypt.decode(data) == data

    def test_shift_jis_passthrough(self):
        # Raw Shift-JIS bytes (no BOM, no FE FE magic).
        data = "アリスは白ウサギを追いかけた。".encode("shift-jis")
        assert simple_crypt.decode(data) == data

    def test_empty_passthrough(self):
        assert simple_crypt.decode(b"") == b""


@pytest.mark.unit
class TestModeBuggyXor:
    """Mode 0 is decoder-only; KiriKiri does not write it."""

    def test_decode_below_0x20_unchanged(self):
        # Characters with ch < 0x20 pass through verbatim.
        payload = b"\x01\x00\x1f\x00"  # U+0001, U+001F
        data = b"\xfe\xfe\x00\xff\xfe" + payload
        assert simple_crypt.decode(data) == b"\xff\xfe" + payload

    def test_decode_applies_xor_above_0x20(self):
        # For ch >= 0x20 the XOR is applied.
        ch = 0x0041  # 'A'
        expected_plain = ch ^ (((ch & 0xFE) << 8) ^ 1)
        cipher = bytes([ch & 0xFF, (ch >> 8) & 0xFF])
        data = b"\xfe\xfe\x00\xff\xfe" + cipher
        decoded = simple_crypt.decode(data)
        assert decoded == b"\xff\xfe" + bytes([expected_plain & 0xFF, (expected_plain >> 8) & 0xFF])

    def test_encode_rejects_mode0(self):
        with pytest.raises(ValueError, match="unsupported mode"):
            simple_crypt.encode(ALICE_BOMMED, mode=0)


@pytest.mark.unit
class TestModeCompressed:
    def test_roundtrip(self):
        encoded = simple_crypt.encode(ALICE_BOMMED, mode=2)
        assert encoded.startswith(b"\xfe\xfe\x02\xff\xfe")
        decoded = simple_crypt.decode(encoded)
        assert decoded == ALICE_BOMMED

    def test_size_trailer_matches(self):
        import struct as _s

        body = ALICE_UTF16
        encoded = simple_crypt.encode(ALICE_BOMMED, mode=2)
        compressed_size, uncompressed_size = _s.unpack("<QQ", encoded[5:21])
        assert uncompressed_size == len(body)
        assert len(encoded) == 5 + 16 + compressed_size

    def test_mismatched_size_raises(self):
        encoded = bytearray(simple_crypt.encode(ALICE_BOMMED, mode=2))
        # Corrupt the uncompressed size so the post-inflate check fails.
        encoded[13:21] = (999999).to_bytes(8, 'little')
        with pytest.raises(ValueError, match="size mismatch"):
            simple_crypt.decode(bytes(encoded))


@pytest.mark.unit
class TestEncodeErrors:
    def test_missing_bom(self):
        with pytest.raises(ValueError, match="BOM"):
            simple_crypt.encode(b"no bom here")

    def test_unsupported_mode(self):
        # Mode 0 is deprecated and buggy; encode should refuse to produce it.
        with pytest.raises(ValueError, match="unsupported mode"):
            simple_crypt.encode(ALICE_BOMMED, mode=0)
        with pytest.raises(ValueError, match="unsupported mode"):
            simple_crypt.encode(ALICE_BOMMED, mode=99)

    def test_odd_length_payload(self):
        # BOM + one extra byte = 3 bytes total (odd payload)
        with pytest.raises(ValueError, match="even"):
            simple_crypt.encode(b"\xff\xfe\xab")


@pytest.mark.unit
class TestSelfInverse:
    """Mode 1 is a bit permutation — applying encode twice should give
    back the original (with one extra header stripped)."""

    def test_double_swap_identity(self):
        for ch in ("Alice", "Cheshire", "Queen of Hearts", "白兎"):
            text = b"\xff\xfe" + ch.encode("utf-16-le")
            encoded = simple_crypt.encode(text)
            assert simple_crypt.decode(encoded) == text


def _ref_swap(payload: bytes) -> bytes:
    """Reference implementation of the bit-swap transform, for cross-checking."""
    assert len(payload) % 2 == 0
    out = bytearray()
    for i in range(0, len(payload), 2):
        w = payload[i] | (payload[i + 1] << 8)
        w = ((w & 0xAAAA) >> 1) | ((w & 0x5555) << 1)
        out += bytes([w & 0xFF, (w >> 8) & 0xFF])
    return bytes(out)
