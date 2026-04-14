import os
import struct
import tempfile

import pytest

from tamago.formats.gsp.gspfile import ENTRY_SIZE, FILENAME_SIZE, HEADER_SIZE, GSPFile
from tamago.formats.gsp.spt_crypto import decrypt, encrypt


def _build_archive(files: list[tuple[str, bytes]]) -> bytes:
    """Build a synthetic GSP archive from a list of (name, data) pairs."""
    count = len(files)
    data_offset = HEADER_SIZE + count * ENTRY_SIZE

    buf = struct.pack('<I', count)

    offset = data_offset
    for name, data in files:
        name_bytes = name.encode('ascii')
        padded = name_bytes + b'\x00' * (FILENAME_SIZE - len(name_bytes))
        buf += struct.pack('<II', offset, len(data))
        buf += padded
        offset += len(data)

    for _name, data in files:
        buf += data

    return buf


@pytest.mark.unit
class TestGSPFileRead:
    """Test reading GSP archives with synthetic data."""

    def test_read_single_file(self):
        content = b'Down the rabbit hole!'
        archive = _build_archive([('alice.txt', content)])

        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with GSPFile(tmp_path) as gsp:
                assert len(gsp.files) == 1
                assert gsp.files[0].file_name == 'alice.txt'
                assert gsp.files[0].size == len(content)
                assert gsp.read('alice.txt') == content
        finally:
            os.unlink(tmp_path)

    def test_read_multiple_files(self):
        files = [
            ('cheshire.ogg', b'\x00' * 100),
            ('hatter.ogg', b'\xff' * 200),
            ('dormouse.ogg', b'A very merry unbirthday'),
        ]
        archive = _build_archive(files)

        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with GSPFile(tmp_path) as gsp:
                assert len(gsp.files) == 3
                for i, (name, data) in enumerate(files):
                    assert gsp.files[i].file_name == name
                    assert gsp.read(name) == data
        finally:
            os.unlink(tmp_path)

    def test_read_by_info_object(self):
        content = b'Curiouser and curiouser!'
        archive = _build_archive([('wonder.dat', content)])

        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with GSPFile(tmp_path) as gsp:
                assert gsp.read(gsp.files[0]) == content
        finally:
            os.unlink(tmp_path)

    def test_read_missing_member_raises(self):
        archive = _build_archive([('alice.txt', b'data')])

        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with GSPFile(tmp_path) as gsp:
                with pytest.raises(KeyError, match='nonexistent'):
                    gsp.read('nonexistent')
        finally:
            os.unlink(tmp_path)

    def test_read_closed_archive_raises(self):
        archive = _build_archive([('alice.txt', b'data')])

        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            gsp = GSPFile(tmp_path)
            gsp.close()
            with pytest.raises(ValueError, match='closed'):
                gsp.read('alice.txt')
        finally:
            os.unlink(tmp_path)

    def test_empty_archive(self):
        archive = _build_archive([])

        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with GSPFile(tmp_path) as gsp:
                assert len(gsp.files) == 0
        finally:
            os.unlink(tmp_path)

    def test_truncated_header_raises(self):
        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(b'\x01\x00')
            tmp_path = tmp.name

        try:
            with pytest.raises(ValueError, match='too small'):
                GSPFile(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_truncated_index_raises(self):
        # Header says 1 entry but file ends before the entry.
        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(struct.pack('<I', 1))
            tmp.write(b'\x00' * 10)
            tmp_path = tmp.name

        try:
            with pytest.raises(ValueError, match='Truncated'):
                GSPFile(tmp_path)
        finally:
            os.unlink(tmp_path)


@pytest.mark.unit
class TestGSPFileExtract:
    """Test extracting files from GSP archives."""

    def test_extract_all(self):
        files = [
            ('alice.txt', b'Down the rabbit hole!'),
            ('queen.txt', b'Off with her head!'),
        ]
        archive = _build_archive(files)

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, 'test.gsp')
            with open(archive_path, 'wb') as f:
                f.write(archive)

            out_dir = os.path.join(tmpdir, 'out')
            os.makedirs(out_dir)

            with GSPFile(archive_path) as gsp:
                gsp.extract_all(out_dir)

            for name, data in files:
                with open(os.path.join(out_dir, name), 'rb') as f:
                    assert f.read() == data

    def test_extract_with_glob(self):
        files = [
            ('voice01.ogg', b'\x00' * 10),
            ('music01.wav', b'\x00' * 20),
            ('voice02.ogg', b'\x00' * 30),
        ]
        archive = _build_archive(files)

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, 'test.gsp')
            with open(archive_path, 'wb') as f:
                f.write(archive)

            out_dir = os.path.join(tmpdir, 'out')
            os.makedirs(out_dir)

            with GSPFile(archive_path) as gsp:
                gsp.extract_all(out_dir, glob='*.ogg')

            assert os.path.exists(os.path.join(out_dir, 'voice01.ogg'))
            assert os.path.exists(os.path.join(out_dir, 'voice02.ogg'))
            assert not os.path.exists(os.path.join(out_dir, 'music01.wav'))


@pytest.mark.unit
class TestGSPFileCreate:
    """Test creating GSP archives."""

    def test_create_and_read_back(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create source files.
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, 'alice.txt'), 'wb') as f:
                f.write(b'Down the rabbit hole!')
            with open(os.path.join(src_dir, 'queen.txt'), 'wb') as f:
                f.write(b'Off with her head!')

            # Create archive.
            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write_all(src_dir)

            # Read it back.
            with GSPFile(archive_path) as gsp:
                assert len(gsp.files) == 2
                assert gsp.read('alice.txt') == b'Down the rabbit hole!'
                assert gsp.read('queen.txt') == b'Off with her head!'

    def test_roundtrip(self):
        """Create archive, extract, recreate, verify identical."""
        files = [
            ('cheshire.dat', b'We are all mad here'),
            ('caterpillar.dat', b'Who are you?'),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create original archive.
            archive1 = os.path.join(tmpdir, 'orig.gsp')
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            for name, data in files:
                with open(os.path.join(src_dir, name), 'wb') as f:
                    f.write(data)

            with GSPFile(archive1, mode='w') as gsp:
                gsp.write_all(src_dir)

            # Extract.
            ext_dir = os.path.join(tmpdir, 'extracted')
            os.makedirs(ext_dir)
            with GSPFile(archive1) as gsp:
                gsp.extract_all(ext_dir)

            # Recreate from extracted files.
            archive2 = os.path.join(tmpdir, 'rebuilt.gsp')
            with GSPFile(archive2, mode='w') as gsp:
                gsp.write_all(ext_dir)

            # Verify byte-identical archives.
            with open(archive1, 'rb') as f:
                data1 = f.read()
            with open(archive2, 'rb') as f:
                data2 = f.read()
            assert data1 == data2

    def test_write_with_explicit_arcname(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'input.txt')
            with open(src, 'wb') as f:
                f.write(b'Tweedledee and Tweedledum')

            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write(src, arcname='custom_name.txt')

            with GSPFile(archive_path) as gsp:
                assert gsp.files[0].file_name == 'custom_name.txt'
                assert gsp.read('custom_name.txt') == b'Tweedledee and Tweedledum'

    def test_filename_too_long_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'x.txt')
            with open(src, 'wb') as f:
                f.write(b'data')

            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                with pytest.raises(ValueError, match='too long'):
                    gsp.write(src, arcname='a' * 57)

    def test_write_on_read_mode_raises(self):
        archive = _build_archive([('x.txt', b'data')])
        with tempfile.NamedTemporaryFile(suffix='.gsp', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with GSPFile(tmp_path) as gsp:
                with pytest.raises(ValueError, match="mode='w'"):
                    gsp.write('/dev/null', arcname='x.txt')
        finally:
            os.unlink(tmp_path)

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match='Invalid mode'):
            GSPFile('/dev/null', mode='x')


@pytest.mark.unit
class TestGSPFileEncryptOnWrite:
    """Test that .spt and .dat files are encrypted when creating archives."""

    # Valid SPT header: bitperm_key=2 (0xF2^0xF0=2), shuffle_key=0 (0xF0^0xF0=0)
    HEADER = b'\xf2\xf0\x00\x00'

    def _make_plaintext(self, body: bytes) -> bytes:
        """Build a plaintext SPT file with a valid encryption header."""
        return self.HEADER + body

    def test_spt_encrypted_on_write(self):
        """An .spt file written to an archive should be stored encrypted."""
        plaintext = self._make_plaintext(b'Off with her head!')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write plaintext .spt to disk.
            src = os.path.join(tmpdir, 'queen.spt')
            with open(src, 'wb') as f:
                f.write(plaintext)

            # Create archive.
            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write(src)

            # Read raw bytes from archive (bypass decryption).
            with GSPFile(archive_path) as gsp:
                raw = gsp.read('queen.spt', decrypt=False)
            assert raw != plaintext, 'file should be encrypted in archive'
            assert raw == encrypt(plaintext), 'file should match encrypt() output'

    def test_dat_encrypted_on_write(self):
        """A .dat file written to an archive should be stored encrypted."""
        plaintext = self._make_plaintext(b'Curiouser and curiouser!')

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'alice.dat')
            with open(src, 'wb') as f:
                f.write(plaintext)

            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write(src)

            with GSPFile(archive_path) as gsp:
                raw = gsp.read('alice.dat', decrypt=False)
            assert raw == encrypt(plaintext)

    def test_read_decrypts_after_encrypted_write(self):
        """Reading with decrypt=True should recover the original plaintext."""
        plaintext = self._make_plaintext(b'We are all mad here')

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'cheshire.spt')
            with open(src, 'wb') as f:
                f.write(plaintext)

            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write(src)

            with GSPFile(archive_path) as gsp:
                assert gsp.read('cheshire.spt') == plaintext

    def test_non_encrypted_extensions_unchanged(self):
        """Files without .spt/.dat extensions should not be encrypted."""
        content = b'\xf2\xf0\x00\x00some data that looks like it has a header'

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'hatter.ogg')
            with open(src, 'wb') as f:
                f.write(content)

            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write(src)

            with GSPFile(archive_path) as gsp:
                assert gsp.read('hatter.ogg', decrypt=False) == content

    def test_encrypt_false_skips_encryption(self):
        """Setting encrypt=False should store the file as-is."""
        plaintext = self._make_plaintext(b'Drink me!')

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'potion.spt')
            with open(src, 'wb') as f:
                f.write(plaintext)

            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write(src, encrypt=False)

            with GSPFile(archive_path) as gsp:
                raw = gsp.read('potion.spt', decrypt=False)
            assert raw == plaintext

    def test_roundtrip_extract_recreate(self):
        """Extract (decrypts) then recreate (encrypts) should preserve content."""
        plaintext = self._make_plaintext(b'Tweedledee and Tweedledum')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create source .spt file and build first archive.
            src = os.path.join(tmpdir, 'twins.spt')
            with open(src, 'wb') as f:
                f.write(plaintext)

            archive1 = os.path.join(tmpdir, 'orig.gsp')
            with GSPFile(archive1, mode='w') as gsp:
                gsp.write(src)

            # Extract (decrypts .spt).
            ext_dir = os.path.join(tmpdir, 'extracted')
            os.makedirs(ext_dir)
            with GSPFile(archive1) as gsp:
                gsp.extract_all(ext_dir)

            # Verify extracted file is plaintext.
            with open(os.path.join(ext_dir, 'twins.spt'), 'rb') as f:
                assert f.read() == plaintext

            # Recreate archive from extracted files (encrypts .spt).
            archive2 = os.path.join(tmpdir, 'rebuilt.gsp')
            with GSPFile(archive2, mode='w') as gsp:
                gsp.write_all(ext_dir)

            # Both archives should be byte-identical.
            with open(archive1, 'rb') as f:
                data1 = f.read()
            with open(archive2, 'rb') as f:
                data2 = f.read()
            assert data1 == data2

    def test_write_all_encrypts(self):
        """write_all should also encrypt matching files."""
        plaintext = self._make_plaintext(b'A very merry unbirthday')

        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, 'party.spt'), 'wb') as f:
                f.write(plaintext)
            with open(os.path.join(src_dir, 'music.ogg'), 'wb') as f:
                f.write(b'not encrypted')

            archive_path = os.path.join(tmpdir, 'test.gsp')
            with GSPFile(archive_path, mode='w') as gsp:
                gsp.write_all(src_dir)

            with GSPFile(archive_path) as gsp:
                # .spt was encrypted then decrypted back to plaintext
                assert gsp.read('party.spt') == plaintext
                # .spt raw data differs from plaintext
                assert gsp.read('party.spt', decrypt=False) == encrypt(plaintext)
                # .ogg unchanged
                assert gsp.read('music.ogg') == b'not encrypted'


@pytest.mark.nonfree
class TestGSPFileNonfree:
    """Tests using real game data from nonfree/ samples."""

    NONFREE_DIR = os.path.join(os.path.dirname(__file__), 'nonfree')

    def test_read_nonfree_samples(self):
        """Open each .gsp file in nonfree/ and verify basic integrity."""
        if not os.path.isdir(self.NONFREE_DIR):
            pytest.skip('nonfree/ directory not found')

        samples = [f for f in os.listdir(self.NONFREE_DIR) if f.endswith('.gsp')]
        if not samples:
            pytest.skip('no .gsp samples in nonfree/')

        for sample in samples:
            path = os.path.join(self.NONFREE_DIR, sample)
            with GSPFile(path) as gsp:
                assert len(gsp.files) > 0, f'{sample}: no files in archive'
                # Verify we can read every member.
                for f in gsp.files:
                    data = gsp.read(f)
                    assert len(data) == f.size, f'{sample}/{f.file_name}: size mismatch'

    def test_roundtrip_nonfree_samples(self):
        """Extract and recreate each nonfree sample, verify content is preserved.

        Files are re-added in the original archive order.  The rebuilt archive
        should contain identical file contents, though the raw archive bytes may
        differ if the original has unreferenced trailing data.
        """
        if not os.path.isdir(self.NONFREE_DIR):
            pytest.skip('nonfree/ directory not found')

        samples = [f for f in os.listdir(self.NONFREE_DIR) if f.endswith('.gsp')]
        if not samples:
            pytest.skip('no .gsp samples in nonfree/')

        for sample in samples:
            path = os.path.join(self.NONFREE_DIR, sample)
            with tempfile.TemporaryDirectory() as tmpdir:
                # Extract, preserving the original file list.
                ext_dir = os.path.join(tmpdir, 'extracted')
                os.makedirs(ext_dir)
                with GSPFile(path) as orig_gsp:
                    original_names = [f.file_name for f in orig_gsp.files]
                    original_data = {f.file_name: orig_gsp.read(f) for f in orig_gsp.files}
                    orig_gsp.extract_all(ext_dir)

                # Recreate in original order.
                rebuilt = os.path.join(tmpdir, 'rebuilt.gsp')
                with GSPFile(rebuilt, mode='w') as gsp:
                    for name in original_names:
                        gsp.write(os.path.join(ext_dir, name), arcname=name)

                # Read back and compare file contents.
                with GSPFile(rebuilt) as rebuilt_gsp:
                    assert len(rebuilt_gsp.files) == len(original_names), f'{sample}: file count mismatch'
                    for i, f in enumerate(rebuilt_gsp.files):
                        assert f.file_name == original_names[i], f'{sample}: name mismatch at {i}'
                        assert (
                            rebuilt_gsp.read(f) == original_data[f.file_name]
                        ), f'{sample}/{f.file_name}: content mismatch'
