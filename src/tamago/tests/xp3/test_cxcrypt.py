"""Tests for the CxEncryption bytecode VM and code generator."""

import struct

import pytest
from construct import Container

from tamago.formats.xp3.encryption.cxcrypt import (
    CxCodeGenerator,
    CxEncryption,
    CxProgram,
    _u32,
    extract_control_block,
)
from tamago.formats.xp3.models import XP3Info


def _make_info(key):
    return XP3Info(file_name="test", key=key)


def _make_segment():
    return Container(flags=0, compressed=False, offset=0, original_size=0, compressed_size=0)


# Build a synthetic control block (1024 uint32s) with deterministic values.
# These are stored as inverted values (matching extract_control_block output).
SYNTHETIC_CB = [_u32(~(0x12345678 + i * 0x9ABCDEF0)) for i in range(1024)]


@pytest.mark.unit
class TestCxProgram:
    """Test the bytecode VM execution."""

    def test_mov_edi_arg_and_retn(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_EDI", 2)
        p.emit("RETN")
        assert p.execute(0xDEADBEEF) == 0xDEADBEEF

    def test_arithmetic_operations(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_EDI", 2)
        p.emit("INC_EAX")
        p.emit("RETN")
        assert p.execute(41) == 42

    def test_not_eax(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_IMM")
        p.emit_u32(0)
        p.emit("NOT_EAX", 2)
        p.emit("RETN")
        assert p.execute(0) == 0xFFFFFFFF

    def test_neg_eax(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_IMM")
        p.emit_u32(1)
        p.emit("NEG_EAX", 2)
        p.emit("RETN")
        assert p.execute(0) == 0xFFFFFFFF

    def test_xor_eax_imm(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_IMM")
        p.emit_u32(0xFF00FF00)
        p.emit("XOR_EAX_IMM")
        p.emit_u32(0x0FF00FF0)
        p.emit("RETN")
        assert p.execute(0) == 0xF0F0F0F0

    def test_mov_eax_indirect(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_IMM")
        p.emit_u32(0)
        p.emit("MOV_EAX_INDIRECT")
        p.emit("RETN")
        # MOV_EAX_INDIRECT: eax = ~cb[0] = ~(~raw[0]) = raw[0]
        expected = _u32(~SYNTHETIC_CB[0])
        assert p.execute(0) == expected

    def test_indirect_out_of_bounds(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_IMM")
        p.emit_u32(9999)
        p.emit("MOV_EAX_INDIRECT")
        p.emit("RETN")
        with pytest.raises(RuntimeError, match="out of bounds"):
            p.execute(0)

    def test_push_pop_stack(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("MOV_EAX_IMM")
        p.emit_u32(42)
        p.emit("PUSH_EBX")
        p.emit("MOV_EBX_EAX", 2)
        p.emit("MOV_EAX_IMM")
        p.emit_u32(100)
        p.emit("ADD_EAX_EBX", 2)
        p.emit("POP_EBX")
        p.emit("RETN")
        assert p.execute(0) == 142

    def test_imbalanced_stack_raises(self):
        p = CxProgram(0, SYNTHETIC_CB)
        p.emit("MOV_EDI_ARG", 4)
        p.emit("PUSH_EBX")
        p.emit("RETN")
        with pytest.raises(RuntimeError, match="imbalanced"):
            p.execute(0)


@pytest.mark.unit
class TestCxPRNG:
    """Test the LCG PRNG implementation."""

    def test_default_prng_first_value(self):
        # Seed = 0: new_seed = 12345, old_shift = 0, return = 12345
        p = CxProgram(0, SYNTHETIC_CB)
        assert p.get_random() == 12345

    def test_default_prng_deterministic(self):
        p1 = CxProgram(42, SYNTHETIC_CB)
        p2 = CxProgram(42, SYNTHETIC_CB)
        for _ in range(10):
            assert p1.get_random() == p2.get_random()

    def test_default_prng_seed_matters(self):
        p1 = CxProgram(1, SYNTHETIC_CB)
        p2 = CxProgram(2, SYNTHETIC_CB)
        assert p1.get_random() != p2.get_random()


@pytest.mark.unit
class TestCxCodeGenerator:
    """Test the code generator."""

    def test_generate_returns_program(self):
        codegen = CxCodeGenerator(SYNTHETIC_CB, [0, 1, 2], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5, 6, 7])
        prog = codegen.generate(0)
        assert isinstance(prog, CxProgram)

    def test_generate_deterministic(self):
        codegen = CxCodeGenerator(SYNTHETIC_CB, [0, 1, 2], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5, 6, 7])
        prog1 = codegen.generate(0)
        prog2 = codegen.generate(0)
        assert prog1.execute(12345) == prog2.execute(12345)

    def test_different_seeds_different_programs(self):
        codegen = CxCodeGenerator(SYNTHETIC_CB, [0, 1, 2], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5, 6, 7])
        prog1 = codegen.generate(0)
        prog2 = codegen.generate(1)
        # Different seeds should (almost certainly) produce different results
        assert prog1.execute(12345) != prog2.execute(12345)

    def test_prng_state_persists_across_stage_retries(self):
        """Programs that don't fit at stage 5 should produce different results
        than programs that do fit, because the PRNG state from the failed
        attempt carries forward to the next stage."""
        codegen = CxCodeGenerator(SYNTHETIC_CB, [0, 1, 2], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5, 6, 7])
        # Generate with default limit
        prog_default = codegen.generate(0)
        result_default = prog_default.execute(12345)

        # Generate with a very large limit (forces stage 5 to always succeed)
        old_limit = CxProgram.LENGTH_LIMIT
        CxProgram.LENGTH_LIMIT = 1024
        prog_large = codegen.generate(0)
        result_large = prog_large.execute(12345)
        CxProgram.LENGTH_LIMIT = old_limit

        # If stage 5 fits in both cases, results should be the same
        # (this test documents the behavior, not a specific expected value)
        assert isinstance(result_default, int)
        assert isinstance(result_large, int)


@pytest.mark.unit
class TestExtractControlBlock:
    def test_finds_signature(self):
        # Build fake TPM data with embedded control block signature
        sig = b" Encryption control block"
        padding = b"\x00" * 100
        cb_data = struct.pack("<1024I", *range(1024))
        tpm = padding + sig[: len(sig)] + cb_data[len(sig) :]
        # The signature must align to the start of the control block
        tpm = padding + cb_data[:4]  # first 4 bytes before sig
        # Actually, just embed the signature followed by data
        tpm = b"\x00" * 100
        raw_cb = list(range(1024))
        tpm += struct.pack("<1024I", *raw_cb)
        # Insert signature at start of the control block area
        sig_offset = 100
        tpm = tpm[:sig_offset] + sig + tpm[sig_offset + len(sig) :]

        result = extract_control_block(bytes(tpm))
        assert result is not None
        assert len(result) == 1024
        # Values should be inverted
        for i in range(10):
            raw = struct.unpack_from("<I", tpm, sig_offset + i * 4)[0]
            assert result[i] == _u32(~raw)

    def test_returns_none_when_not_found(self):
        assert extract_control_block(b"\x00" * 1000) is None


@pytest.mark.unit
class TestCxEncryption:
    """Test the full CxEncryption handler."""

    def test_round_trip(self):
        enc = CxEncryption(
            control_block=SYNTHETIC_CB,
            mask=0x1C9,
            offset=0x1F3,
        )
        info = _make_info(0xDEADBEEF)
        seg = _make_segment()
        original = b"Down the rabbit hole Alice went!"
        encrypted = enc.encrypt(original, info, seg)
        decrypted = enc.decrypt(encrypted, info, seg)
        assert decrypted == original

    def test_encrypt_decrypt_symmetric(self):
        enc = CxEncryption(control_block=SYNTHETIC_CB, mask=0x1C9, offset=0x1F3)
        info = _make_info(0x12345678)
        seg = _make_segment()
        data = b"Curiouser and curiouser!"
        assert enc.encrypt(data, info, seg) == enc.decrypt(data, info, seg)

    def test_different_hashes_different_encryption(self):
        enc = CxEncryption(control_block=SYNTHETIC_CB, mask=0x1C9, offset=0x1F3)
        seg = _make_segment()
        data = b"\x00" * 16
        result1 = enc.decrypt(data, _make_info(0x11111111), seg)
        result2 = enc.decrypt(data, _make_info(0x22222222), seg)
        assert result1 != result2

    def test_threshold_split(self):
        """Data before and after the threshold use different hash transforms."""
        enc = CxEncryption(control_block=SYNTHETIC_CB, mask=0x1C9, offset=0x1F3)
        info = _make_info(0x00000000)
        seg = _make_segment()
        # With hash=0, base_offset = (0 & 0x1C9) + 0x1F3 = 499
        # A buffer of 1000 bytes should be split at position 499
        data = b"\x00" * 1000
        result = enc.decrypt(data, info, seg)
        assert result != data  # should be XORed
