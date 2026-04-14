import hashlib
import os
import tempfile

import pytest
from construct import Container

from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.detect import (
    auto_detect,
    build_tpm_index,
    build_xp3_index,
    detect_by_probe,
    detect_by_tpm,
    detect_by_xp3_hash,
    hash_xp3_structure,
    instantiate_encryption,
    load_library,
    try_decrypt_segment,
)
from tamago.formats.xp3.encryption import HashXorEncryption
from tamago.formats.xp3.models import XP3Info

SAMPLES = os.path.join(os.path.dirname(__file__), 'samples')


@pytest.mark.unit
class TestLoadLibrary:
    def test_loads_with_expected_structure(self):
        lib = load_library()
        entry = lib['games']['hash-xor-3']
        assert 'encryption' in entry
        assert 'tpm_hashes' in entry
        assert 'xp3_hashes' in entry


@pytest.mark.unit
class TestInstantiateEncryption:
    def test_with_params(self):
        enc = instantiate_encryption({'encryption': 'hash-xor', 'shift': 5})
        assert isinstance(enc, HashXorEncryption)
        assert enc.shift == 5

    def test_unknown_scheme(self):
        assert instantiate_encryption({'encryption': 'nonexistent'}) is None

    def test_bad_params(self):
        assert instantiate_encryption({'encryption': 'hash-xor', 'bogus': 1}) is None

    def test_reserved_keys_not_passed_as_kwargs(self):
        enc = instantiate_encryption(
            {
                'encryption': 'hash-xor',
                'shift': 3,
                'title': 'Test Game',
                'tpm_hashes': [],
                'xp3_hashes': [],
            }
        )
        assert isinstance(enc, HashXorEncryption)
        assert enc.shift == 3


@pytest.mark.unit
class TestBuildIndexes:
    def test_build_tpm_index(self):
        lib = {'games': {'g1': {'tpm_hashes': ['aaa', 'bbb'], 'xp3_hashes': []}}}
        index = build_tpm_index(lib)
        assert 'aaa' in index
        assert 'bbb' in index
        assert index['aaa'] == ('g1', lib['games']['g1'])

    def test_build_tpm_index_empty(self):
        assert build_tpm_index({'games': {}}) == {}
        assert build_tpm_index({}) == {}

    def test_build_xp3_index(self):
        lib = {'games': {'g1': {'tpm_hashes': [], 'xp3_hashes': ['ccc']}}}
        index = build_xp3_index(lib)
        assert 'ccc' in index

    def test_build_xp3_index_empty(self):
        assert build_xp3_index({'games': {}}) == {}


@pytest.mark.unit
class TestTryDecryptSegment:
    def test_successful_decrypt(self):
        enc = HashXorEncryption(shift=3)
        info = XP3Info(file_name='test', key=0xDEADBEEF)
        seg = Container(flags=0, compressed=False, offset=0, original_size=5, compressed_size=5)

        plaintext = b'hello'
        encrypted = enc.encrypt(plaintext, info, seg)
        result = try_decrypt_segment(enc, encrypted, info, seg)
        assert result == plaintext

    def test_returns_none_on_failure(self):
        enc = HashXorEncryption(shift=3)
        info = XP3Info(file_name='test', key=0xDEADBEEF)
        seg = Container(flags=1, compressed=True, offset=0, original_size=5, compressed_size=5)

        result = try_decrypt_segment(enc, b'not zlib', info, seg)
        assert result is None


@pytest.mark.unit
class TestHashXp3Structure:
    def test_deterministic(self):
        path = os.path.join(SAMPLES, 'single_compressed.xp3')
        assert hash_xp3_structure(path) == hash_xp3_structure(path)

    def test_different_for_different_files(self):
        h1 = hash_xp3_structure(os.path.join(SAMPLES, 'single_compressed.xp3'))
        h2 = hash_xp3_structure(os.path.join(SAMPLES, 'multi_compressed.xp3'))
        assert h1 != h2

    def test_raises_on_non_xp3(self):
        with tempfile.NamedTemporaryFile(suffix='.xp3') as f:
            f.write(b'not an xp3 file')
            f.flush()
            with pytest.raises(ValueError, match="Not an XP3"):
                hash_xp3_structure(f.name)


@pytest.mark.integration
class TestDetectByTpm:
    def test_no_tpm_returns_none(self):
        assert detect_by_tpm(os.path.join(SAMPLES, 'single_compressed.xp3')) is None

    def test_matching_tpm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_tpm = os.path.join(tmpdir, 'game.tpm')
            with open(fake_tpm, 'wb') as f:
                f.write(b'fake tpm content')
            tpm_hash = hashlib.sha256(b'fake tpm content').hexdigest()

            xp3_path = os.path.join(tmpdir, 'data.xp3')
            txt = os.path.join(tmpdir, 'test.txt')
            with open(txt, 'wb') as f:
                f.write(b'test')
            with XP3File(xp3_path, 'x') as xp3:
                xp3.write(txt)

            fake_lib = {
                'games': {
                    'test-game': {
                        'title': 'Test',
                        'encryption': 'hash-xor',
                        'shift': 3,
                        'tpm_hashes': [tpm_hash],
                        'xp3_hashes': [],
                    }
                }
            }
            game_key, enc = detect_by_tpm(xp3_path, library=fake_lib)
            assert game_key == 'test-game'
            assert enc.shift == 3


@pytest.mark.integration
class TestDetectByXp3Hash:
    def test_no_match_returns_none(self):
        assert detect_by_xp3_hash(os.path.join(SAMPLES, 'single_compressed.xp3')) is None

    def test_matching_hash(self):
        xp3_path = os.path.join(SAMPLES, 'single_compressed.xp3')
        fake_lib = {
            'games': {
                'test-game': {
                    'title': 'Test',
                    'encryption': 'hash-xor',
                    'shift': 7,
                    'tpm_hashes': [],
                    'xp3_hashes': [hash_xp3_structure(xp3_path)],
                }
            }
        }
        game_key, enc = detect_by_xp3_hash(xp3_path, library=fake_lib)
        assert game_key == 'test-game'
        assert enc.shift == 7


@pytest.mark.integration
class TestDetectByProbe:
    def test_finds_shift_3(self):
        enc, params = detect_by_probe(os.path.join(SAMPLES, 'encrypted_with_png.xp3'))
        assert isinstance(enc, HashXorEncryption)

    def test_finds_custom_shift(self):
        enc, params = detect_by_probe(os.path.join(SAMPLES, 'encrypted_shift5_with_png.xp3'))
        assert enc.shift == 5

    def test_no_magic_files_returns_none(self):
        assert detect_by_probe(os.path.join(SAMPLES, 'single_encrypted_compressed.xp3')) is None

    def test_unencrypted_returns_none(self):
        assert detect_by_probe(os.path.join(SAMPLES, 'single_compressed.xp3')) is None

    def test_ignores_unencrypted_candidates(self):
        """Probe should not match NullEncryption on an unencrypted file when encrypted files exist."""
        # Minimal valid 1x1 white PNG
        png_data = (
            b'\x89PNG\r\n\x1a\n'  # PNG signature
            b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
            b'\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N'
            b'\x00\x00\x00\x00IEND\xaeB`\x82'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create source files
            png_path = os.path.join(tmpdir, 'alice.png')
            txt_path = os.path.join(tmpdir, 'rabbit.txt')
            with open(png_path, 'wb') as f:
                f.write(png_data)
            with open(txt_path, 'wb') as f:
                f.write(b'Down the rabbit hole!')

            # Build archive with a mix: encrypted text + unencrypted PNG
            xp3_path = os.path.join(tmpdir, 'data.xp3')
            enc = HashXorEncryption(shift=3)
            with XP3File(xp3_path, 'x', encryption=enc) as xp3:
                xp3.write(txt_path)  # encrypted, flags=ENCRYPTED
                # Temporarily disable encryption for the PNG
                xp3.encryption = None
                xp3.write(png_path)  # unencrypted, flags=0
                xp3.encryption = enc

            # Verify the archive has the expected structure
            with XP3File(xp3_path) as xp3:
                flags = {f.file_name: f.encrypted for f in xp3.files}
                assert flags['rabbit.txt'] is True
                assert flags['alice.png'] is False

            # Probe should NOT match: the only magic-signature file is unencrypted
            result = detect_by_probe(xp3_path)
            assert result is None

    def test_prefers_encrypted_candidate(self):
        """When both encrypted and unencrypted magic files exist, probe uses the encrypted one."""
        import struct
        import zlib as _zlib

        def _make_png(pixel_rgb):
            """Create a minimal 1x1 PNG with the given RGB pixel."""
            ihdr = b'\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00'
            ihdr_crc = struct.pack('>I', _zlib.crc32(b'IHDR' + ihdr) & 0xFFFFFFFF)
            raw_row = b'\x00' + bytes(pixel_rgb)
            idat_payload = _zlib.compress(raw_row)
            idat_crc = struct.pack('>I', _zlib.crc32(b'IDAT' + idat_payload) & 0xFFFFFFFF)
            iend_crc = struct.pack('>I', _zlib.crc32(b'IEND') & 0xFFFFFFFF)
            return (
                b'\x89PNG\r\n\x1a\n'
                + struct.pack('>I', len(ihdr))
                + b'IHDR'
                + ihdr
                + ihdr_crc
                + struct.pack('>I', len(idat_payload))
                + b'IDAT'
                + idat_payload
                + idat_crc
                + b'\x00\x00\x00\x00IEND'
                + iend_crc
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            enc_png = os.path.join(tmpdir, 'queen.png')
            plain_png = os.path.join(tmpdir, 'alice.png')
            with open(enc_png, 'wb') as f:
                f.write(_make_png((255, 0, 0)))  # red pixel
            with open(plain_png, 'wb') as f:
                f.write(_make_png((0, 0, 255)))  # blue pixel

            xp3_path = os.path.join(tmpdir, 'data.xp3')
            enc = HashXorEncryption(shift=3)
            with XP3File(xp3_path, 'x', encryption=enc) as xp3:
                xp3.write(enc_png)  # encrypted PNG, flags=ENCRYPTED
                xp3.encryption = None
                xp3.write(plain_png)  # unencrypted PNG, flags=0
                xp3.encryption = enc

            # Probe should find hash-xor shift=3 via the encrypted PNG
            result = detect_by_probe(xp3_path)
            assert result is not None
            detected_enc, params = result
            assert isinstance(detected_enc, HashXorEncryption)
            assert detected_enc.shift == 3


@pytest.mark.integration
class TestAutoDetect:
    def test_unencrypted_returns_none(self):
        assert auto_detect(os.path.join(SAMPLES, 'single_compressed.xp3')) is None

    def test_detected_encryption_extracts_correctly(self):
        xp3_path = os.path.join(SAMPLES, 'encrypted_with_png.xp3')
        enc = auto_detect(xp3_path)
        assert isinstance(enc, HashXorEncryption)
        with XP3File(xp3_path, encryption=enc) as xp3:
            with tempfile.TemporaryDirectory() as tmpdir:
                for member in xp3.files:
                    outpath = os.path.join(tmpdir, member.file_name)
                    xp3.extract(member, outpath)
                    assert os.path.getsize(outpath) == member.original_size
