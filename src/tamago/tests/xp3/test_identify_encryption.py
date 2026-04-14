"""Tests for scripts/identify_encryption.py."""

import os
import sys
import tempfile
import zlib

import pytest

# Add scripts to path so we can import identify_encryption
sys.path.insert(0, str(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'scripts')))

from identify_encryption import (
    DetectionCandidate,
    VerificationResult,
    check_unencrypted,
    discover_game,
    generate_library_entry,
    verify_candidate,
)

from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.encryption.hash_xor import HashXorEncryption

SAMPLES = os.path.join(os.path.dirname(__file__), 'samples')


def _make_xp3_with_files(tmpdir, filename, file_contents, encryption=None):
    """Helper: create an XP3 archive from a dict of {arcname: bytes}."""
    xp3_path = os.path.join(tmpdir, filename)
    with XP3File(xp3_path, 'x', encryption=encryption) as xp3:
        for arcname, data in file_contents.items():
            filepath = os.path.join(tmpdir, arcname)
            with open(filepath, 'wb') as f:
                f.write(data)
            xp3.write(filepath, arcname=arcname)
            os.unlink(filepath)
    return xp3_path


@pytest.mark.unit
class TestDiscoverGame:
    def test_finds_xp3_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_xp3_with_files(tmpdir, 'data.xp3', {'test.txt': b'hello'})
            _make_xp3_with_files(tmpdir, 'voice.xp3', {'voice.txt': b'world'})

            xp3_files, enc_tpms, util_tpms = discover_game(tmpdir)
            basenames = [os.path.basename(f) for f in xp3_files]
            assert 'data.xp3' in basenames
            assert 'voice.xp3' in basenames

    def test_separates_tpm_types(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_xp3_with_files(tmpdir, 'data.xp3', {'test.txt': b'hello'})

            # Create encryption TPM
            with open(os.path.join(tmpdir, 'crypt.tpm'), 'wb') as f:
                f.write(b'encryption plugin')

            # Create utility TPM
            with open(os.path.join(tmpdir, 'extrans.tpm'), 'wb') as f:
                f.write(b'utility plugin')

            xp3_files, enc_tpms, util_tpms = discover_game(tmpdir)
            enc_names = [os.path.basename(f) for f in enc_tpms]
            util_names = [os.path.basename(f) for f in util_tpms]
            assert 'crypt.tpm' in enc_names
            assert 'extrans.tpm' in util_names
            assert 'crypt.tpm' not in util_names

    def test_skips_invalid_xp3(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with .xp3 extension but invalid magic
            with open(os.path.join(tmpdir, 'bad.xp3'), 'wb') as f:
                f.write(b'not an xp3 file')

            xp3_files, enc_tpms, util_tpms = discover_game(tmpdir)
            assert len(xp3_files) == 0

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            xp3_files, enc_tpms, util_tpms = discover_game(tmpdir)
            assert xp3_files == []
            assert enc_tpms == []
            assert util_tpms == []


@pytest.mark.unit
class TestCheckUnencrypted:
    def test_true_when_no_encrypted_flags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            xp3_path = _make_xp3_with_files(tmpdir, 'data.xp3', {'test.txt': b'hello'})
            assert check_unencrypted([xp3_path]) is True

    def test_false_when_encrypted_flags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            enc = HashXorEncryption(shift=3)
            xp3_path = _make_xp3_with_files(
                tmpdir,
                'data.xp3',
                {'test.txt': b'hello'},
                encryption=enc,
            )
            assert check_unencrypted([xp3_path]) is False


@pytest.mark.unit
class TestVerifyCandidate:
    def test_success_case(self):
        """Verify that correct encryption is confirmed against files with known magic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            enc = HashXorEncryption(shift=3)

            # Create a minimal PNG header (magic + IHDR)
            png_magic = b'\x89PNG\r\n\x1a\n'
            ihdr_data = b'\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00'
            ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF
            png_header = png_magic + b'\x00\x00\x00\x0d' + b'IHDR' + ihdr_data + ihdr_crc.to_bytes(4, 'big')
            png_data = png_header + b'\x00' * 100

            # Create several PNG files for enough verification targets
            # Each must have unique content (different adler32) to avoid XP3 dedup
            files = {}
            for i in range(5):
                files[f'image{i}.png'] = png_data + bytes([i]) * 50

            xp3_path = _make_xp3_with_files(tmpdir, 'data.xp3', files, encryption=enc)

            candidate = DetectionCandidate(
                encryption=enc,
                method="probe",
                scheme_name="hash-xor",
                params={"shift": 3},
            )

            result = verify_candidate(candidate, [xp3_path])
            assert result.total_checked >= 3
            assert result.failures == 0
            assert result.confirmed

    def test_failure_case(self):
        """Verify that wrong encryption fails verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            enc_write = HashXorEncryption(shift=3)
            enc_wrong = HashXorEncryption(shift=7)

            png_magic = b'\x89PNG\r\n\x1a\n'
            ihdr_data = b'\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00'
            ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF
            png_header = png_magic + b'\x00\x00\x00\x0d' + b'IHDR' + ihdr_data + ihdr_crc.to_bytes(4, 'big')
            png_data = png_header + b'\x00' * 100

            files = {f'image{i}.png': png_data + bytes([i]) * 50 for i in range(5)}
            xp3_path = _make_xp3_with_files(tmpdir, 'data.xp3', files, encryption=enc_write)

            candidate = DetectionCandidate(
                encryption=enc_wrong,
                method="probe",
                scheme_name="hash-xor",
                params={"shift": 7},
            )

            result = verify_candidate(candidate, [xp3_path])
            assert result.failures > 0
            assert not result.confirmed

    def test_not_confirmed_with_too_few_files(self):
        """Verification requires at least 3 files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            enc = HashXorEncryption(shift=3)
            png_magic = b'\x89PNG\r\n\x1a\n'
            ihdr_data = b'\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00'
            ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF
            png_header = png_magic + b'\x00\x00\x00\x0d' + b'IHDR' + ihdr_data + ihdr_crc.to_bytes(4, 'big')
            png_data = png_header + b'\x00' * 100

            # Only 1 PNG file
            xp3_path = _make_xp3_with_files(tmpdir, 'data.xp3', {'image.png': png_data}, encryption=enc)

            candidate = DetectionCandidate(
                encryption=enc,
                method="probe",
                scheme_name="hash-xor",
                params={"shift": 3},
            )

            result = verify_candidate(candidate, [xp3_path])
            assert result.successes > 0
            assert result.failures == 0
            assert not result.confirmed  # fewer than 3


@pytest.mark.unit
class TestGenerateLibraryEntry:
    def test_correct_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            enc = HashXorEncryption(shift=3)
            xp3_path = _make_xp3_with_files(tmpdir, 'data.xp3', {'test.txt': b'hello'}, encryption=enc)

            # Create a TPM
            tpm_path = os.path.join(tmpdir, 'crypt.tpm')
            with open(tpm_path, 'wb') as f:
                f.write(b'fake tpm')

            candidate = DetectionCandidate(
                encryption=enc,
                method="probe",
                scheme_name="hash-xor",
                params={"shift": 3},
            )

            entry_key, toml_text = generate_library_entry(tmpdir, candidate, [xp3_path], [tpm_path])

            assert f'[games.{entry_key}]' in toml_text
            assert 'encryption = "hash-xor"' in toml_text
            assert "shift = 3" in toml_text
            assert "tpm_hashes = [" in toml_text
            assert "xp3_hashes = [" in toml_text
            # Should contain actual hash values
            assert '", # data.xp3' in toml_text
            assert '", # crypt.tpm' in toml_text

    def test_excludes_patch_xp3(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            enc = HashXorEncryption(shift=0)
            _make_xp3_with_files(tmpdir, 'data.xp3', {'test.txt': b'hello'}, encryption=enc)
            _make_xp3_with_files(tmpdir, 'patch2.xp3', {'fix.txt': b'fix'}, encryption=enc)

            candidate = DetectionCandidate(
                encryption=enc,
                method="probe",
                scheme_name="hash-xor",
                params={"shift": 0},
            )

            xp3_files = [
                os.path.join(tmpdir, 'data.xp3'),
                os.path.join(tmpdir, 'patch2.xp3'),
            ]

            entry_key, toml_text = generate_library_entry(tmpdir, candidate, xp3_files, [])
            assert 'data.xp3' in toml_text
            assert 'patch2.xp3' not in toml_text


@pytest.mark.unit
class TestVerificationResultConfirmed:
    def test_confirmed_property(self):
        cand = DetectionCandidate(encryption=None, method="probe", scheme_name="test", params={})
        vr = VerificationResult(candidate=cand, total_checked=5, successes=5, failures=0)
        assert vr.confirmed

    def test_not_confirmed_with_failures(self):
        cand = DetectionCandidate(encryption=None, method="probe", scheme_name="test", params={})
        vr = VerificationResult(candidate=cand, total_checked=5, successes=3, failures=2)
        assert not vr.confirmed

    def test_not_confirmed_too_few(self):
        cand = DetectionCandidate(encryption=None, method="probe", scheme_name="test", params={})
        vr = VerificationResult(candidate=cand, total_checked=2, successes=2, failures=0)
        assert not vr.confirmed
