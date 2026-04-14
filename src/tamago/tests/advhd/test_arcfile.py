import os
import struct
import tempfile

import pytest

from tamago.formats.advhd.arcfile import ARCFile, ARCInfo, decrypt_script, encrypt_script, is_script_file


def _build_archive(files: list[tuple[str, bytes]], encrypt_scripts: bool = True) -> bytes:
    """Build a synthetic ARC archive from a list of (name, data) pairs.

    If *encrypt_scripts* is True, .ws2/.json file data is rotated left by 2
    (matching the on-disk storage format).
    """
    count = len(files)

    # Build index entries to calculate index_size.
    index_parts: list[bytes] = []
    for name, _data in files:
        name_encoded = name.encode('utf-16-le') + b'\x00\x00'
        entry = struct.pack('<II', 0, 0) + name_encoded  # placeholder size/offset
        index_parts.append(entry)

    index_size = sum(len(p) for p in index_parts)

    # Rebuild with correct size/offset values.
    buf = struct.pack('<II', count, index_size)
    offset = 0
    for name, data in files:
        name_encoded = name.encode('utf-16-le') + b'\x00\x00'
        stored = encrypt_script(data) if (encrypt_scripts and is_script_file(name)) else data
        buf += struct.pack('<II', len(stored), offset) + name_encoded
        offset += len(stored)

    # Append file data.
    for name, data in files:
        stored = encrypt_script(data) if (encrypt_scripts and is_script_file(name)) else data
        buf += stored

    return buf


@pytest.mark.unit
class TestScriptCrypto:
    """Test the script encryption/decryption byte rotation."""

    def test_decrypt_known_value(self):
        # 0x58 rotated right by 2 = 0x16
        assert decrypt_script(b'\x58') == b'\x16'

    def test_encrypt_known_value(self):
        # 0x16 rotated left by 2 = 0x58
        assert encrypt_script(b'\x16') == b'\x58'

    def test_roundtrip(self):
        data = bytes(range(256))
        assert decrypt_script(encrypt_script(data)) == data

    def test_encrypt_decrypt_roundtrip(self):
        data = b'Down the rabbit hole!'
        assert decrypt_script(encrypt_script(data)) == data

    def test_empty(self):
        assert decrypt_script(b'') == b''
        assert encrypt_script(b'') == b''


@pytest.mark.unit
class TestIsScriptFile:
    """Test script file detection."""

    def test_ws2_detected(self):
        assert is_script_file('scene01.ws2') is True

    def test_json_detected(self):
        assert is_script_file('config.json') is True

    def test_case_insensitive(self):
        assert is_script_file('SCENE.WS2') is True
        assert is_script_file('Config.JSON') is True

    def test_non_script(self):
        assert is_script_file('bgm01.ogg') is False
        assert is_script_file('image.png') is False


@pytest.mark.unit
class TestARCFileRead:
    """Test reading ARC archives with synthetic data."""

    def test_read_single_file(self):
        content = b'Down the rabbit hole!'
        archive = _build_archive([('alice.ogg', content)])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                assert len(arc.files) == 1
                assert arc.files[0].file_name == 'alice.ogg'
                assert arc.files[0].size == len(content)
                assert arc.read('alice.ogg') == content
        finally:
            os.unlink(tmp_path)

    def test_read_multiple_files(self):
        files = [
            ('cheshire.ogg', b'\x00' * 100),
            ('hatter.ogg', b'\xff' * 200),
            ('dormouse.ogg', b'A very merry unbirthday'),
        ]
        archive = _build_archive(files)

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                assert len(arc.files) == 3
                for i, (name, data) in enumerate(files):
                    assert arc.files[i].file_name == name
                    assert arc.read(name) == data
        finally:
            os.unlink(tmp_path)

    def test_read_script_decrypted(self):
        """Script files (.ws2) should be decrypted automatically on read."""
        plaintext = b'This is a script file'
        archive = _build_archive([('scene01.ws2', plaintext)])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                assert arc.read('scene01.ws2') == plaintext
        finally:
            os.unlink(tmp_path)

    def test_read_script_raw(self):
        """Reading with decrypt=False should return the encrypted bytes."""
        plaintext = b'This is a script file'
        archive = _build_archive([('scene01.ws2', plaintext)])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                raw = arc.read('scene01.ws2', decrypt=False)
                assert raw == encrypt_script(plaintext)
                assert raw != plaintext
        finally:
            os.unlink(tmp_path)

    def test_read_by_info_object(self):
        content = b'Curiouser and curiouser!'
        archive = _build_archive([('wonder.ogg', content)])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                assert arc.read(arc.files[0]) == content
        finally:
            os.unlink(tmp_path)

    def test_read_missing_member_raises(self):
        archive = _build_archive([('alice.ogg', b'data')])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                with pytest.raises(KeyError, match='nonexistent'):
                    arc.read('nonexistent')
        finally:
            os.unlink(tmp_path)

    def test_read_closed_archive_raises(self):
        archive = _build_archive([('alice.ogg', b'data')])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            arc = ARCFile(tmp_path)
            arc.close()
            with pytest.raises(ValueError, match='closed'):
                arc.read('alice.ogg')
        finally:
            os.unlink(tmp_path)

    def test_empty_archive(self):
        archive = _build_archive([])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                assert len(arc.files) == 0
        finally:
            os.unlink(tmp_path)

    def test_truncated_header_raises(self):
        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(b'\x01\x00')
            tmp_path = tmp.name

        try:
            with pytest.raises(ValueError, match='too small'):
                ARCFile(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_unicode_filenames(self):
        """Archive should handle non-ASCII UTF-16LE filenames."""
        content = b'tea party data'
        archive = _build_archive([('\u30c6\u30b9\u30c8.ogg', content)])

        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                assert arc.files[0].file_name == '\u30c6\u30b9\u30c8.ogg'
                assert arc.read('\u30c6\u30b9\u30c8.ogg') == content
        finally:
            os.unlink(tmp_path)

    def test_model_archive_no_decrypt(self):
        """Archives with 'Model' in the filename should not decrypt scripts."""
        plaintext = b'This is a script'
        encrypted = encrypt_script(plaintext)
        # Build archive where script data is stored encrypted (as on disk)
        archive = _build_archive([('scene.ws2', plaintext)])

        with tempfile.NamedTemporaryFile(suffix='.arc', prefix='Model_', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                # Model archives treat scripts as plain files — read returns raw bytes
                data = arc.read('scene.ws2')
                assert data == encrypted
        finally:
            os.unlink(tmp_path)


@pytest.mark.unit
class TestARCFileExtract:
    """Test extracting files from ARC archives."""

    def test_extract_all(self):
        files = [
            ('alice.ogg', b'Down the rabbit hole!'),
            ('queen.ogg', b'Off with her head!'),
        ]
        archive = _build_archive(files)

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, 'test.arc')
            with open(archive_path, 'wb') as f:
                f.write(archive)

            out_dir = os.path.join(tmpdir, 'out')
            os.makedirs(out_dir)

            with ARCFile(archive_path) as arc:
                arc.extract_all(out_dir)

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
            archive_path = os.path.join(tmpdir, 'test.arc')
            with open(archive_path, 'wb') as f:
                f.write(archive)

            out_dir = os.path.join(tmpdir, 'out')
            os.makedirs(out_dir)

            with ARCFile(archive_path) as arc:
                arc.extract_all(out_dir, glob='*.ogg')

            assert os.path.exists(os.path.join(out_dir, 'voice01.ogg'))
            assert os.path.exists(os.path.join(out_dir, 'voice02.ogg'))
            assert not os.path.exists(os.path.join(out_dir, 'music01.wav'))

    def test_extract_script_decrypted(self):
        """Extracted .ws2 files should contain decrypted plaintext."""
        plaintext = b'Script content here'
        archive = _build_archive([('scene.ws2', plaintext)])

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, 'test.arc')
            with open(archive_path, 'wb') as f:
                f.write(archive)

            out_dir = os.path.join(tmpdir, 'out')
            os.makedirs(out_dir)

            with ARCFile(archive_path) as arc:
                arc.extract_all(out_dir)

            with open(os.path.join(out_dir, 'scene.ws2'), 'rb') as f:
                assert f.read() == plaintext


@pytest.mark.unit
class TestARCFileCreate:
    """Test creating ARC archives."""

    def test_create_and_read_back(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, 'alice.ogg'), 'wb') as f:
                f.write(b'Down the rabbit hole!')
            with open(os.path.join(src_dir, 'queen.ogg'), 'wb') as f:
                f.write(b'Off with her head!')

            archive_path = os.path.join(tmpdir, 'test.arc')
            with ARCFile(archive_path, mode='w') as arc:
                arc.write_all(src_dir)

            with ARCFile(archive_path) as arc:
                assert len(arc.files) == 2
                assert arc.read('alice.ogg') == b'Down the rabbit hole!'
                assert arc.read('queen.ogg') == b'Off with her head!'

    def test_roundtrip(self):
        """Create archive, extract, recreate, verify identical."""
        files = [
            ('cheshire.ogg', b'We are all mad here'),
            ('caterpillar.ogg', b'Who are you?'),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            archive1 = os.path.join(tmpdir, 'orig.arc')
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            for name, data in files:
                with open(os.path.join(src_dir, name), 'wb') as f:
                    f.write(data)

            with ARCFile(archive1, mode='w') as arc:
                arc.write_all(src_dir)

            ext_dir = os.path.join(tmpdir, 'extracted')
            os.makedirs(ext_dir)
            with ARCFile(archive1) as arc:
                arc.extract_all(ext_dir)

            archive2 = os.path.join(tmpdir, 'rebuilt.arc')
            with ARCFile(archive2, mode='w') as arc:
                arc.write_all(ext_dir)

            with open(archive1, 'rb') as f:
                data1 = f.read()
            with open(archive2, 'rb') as f:
                data2 = f.read()
            assert data1 == data2

    def test_roundtrip_with_scripts(self):
        """Scripts should survive extract (decrypt) → create (encrypt) cycle."""
        plaintext = b'This is script content \xff\x00\x80'

        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, 'scene.ws2'), 'wb') as f:
                f.write(plaintext)
            with open(os.path.join(src_dir, 'bgm.ogg'), 'wb') as f:
                f.write(b'audio data')

            archive1 = os.path.join(tmpdir, 'orig.arc')
            with ARCFile(archive1, mode='w') as arc:
                arc.write_all(src_dir)

            ext_dir = os.path.join(tmpdir, 'extracted')
            os.makedirs(ext_dir)
            with ARCFile(archive1) as arc:
                arc.extract_all(ext_dir)

            # Verify extracted script is plaintext
            with open(os.path.join(ext_dir, 'scene.ws2'), 'rb') as f:
                assert f.read() == plaintext

            archive2 = os.path.join(tmpdir, 'rebuilt.arc')
            with ARCFile(archive2, mode='w') as arc:
                arc.write_all(ext_dir)

            # Archives should be byte-identical
            with open(archive1, 'rb') as f:
                data1 = f.read()
            with open(archive2, 'rb') as f:
                data2 = f.read()
            assert data1 == data2

    def test_write_with_explicit_arcname(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'input.ogg')
            with open(src, 'wb') as f:
                f.write(b'Tweedledee and Tweedledum')

            archive_path = os.path.join(tmpdir, 'test.arc')
            with ARCFile(archive_path, mode='w') as arc:
                arc.write(src, arcname='custom_name.ogg')

            with ARCFile(archive_path) as arc:
                assert arc.files[0].file_name == 'custom_name.ogg'
                assert arc.read('custom_name.ogg') == b'Tweedledee and Tweedledum'

    def test_write_on_read_mode_raises(self):
        archive = _build_archive([('x.ogg', b'data')])
        with tempfile.NamedTemporaryFile(suffix='.arc', delete=False) as tmp:
            tmp.write(archive)
            tmp_path = tmp.name

        try:
            with ARCFile(tmp_path) as arc:
                with pytest.raises(ValueError, match="mode='w'"):
                    arc.write('/dev/null', arcname='x.ogg')
        finally:
            os.unlink(tmp_path)

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match='Invalid mode'):
            ARCFile('/dev/null', mode='x')

    def test_script_encrypted_on_write(self):
        """A .ws2 file written to an archive should be stored encrypted."""
        plaintext = b'Off with her head!'

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'queen.ws2')
            with open(src, 'wb') as f:
                f.write(plaintext)

            archive_path = os.path.join(tmpdir, 'test.arc')
            with ARCFile(archive_path, mode='w') as arc:
                arc.write(src)

            with ARCFile(archive_path) as arc:
                raw = arc.read('queen.ws2', decrypt=False)
            assert raw != plaintext, 'script should be encrypted in archive'
            assert raw == encrypt_script(plaintext)

    def test_json_encrypted_on_write(self):
        """A .json file written to an archive should be stored encrypted."""
        plaintext = b'{"key": "value"}'

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'config.json')
            with open(src, 'wb') as f:
                f.write(plaintext)

            archive_path = os.path.join(tmpdir, 'test.arc')
            with ARCFile(archive_path, mode='w') as arc:
                arc.write(src)

            with ARCFile(archive_path) as arc:
                raw = arc.read('config.json', decrypt=False)
            assert raw == encrypt_script(plaintext)

    def test_encrypt_false_skips_encryption(self):
        """Setting encrypt=False should store script files as-is."""
        plaintext = b'Drink me!'

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'potion.ws2')
            with open(src, 'wb') as f:
                f.write(plaintext)

            archive_path = os.path.join(tmpdir, 'test.arc')
            with ARCFile(archive_path, mode='w') as arc:
                arc.write(src, encrypt=False)

            with ARCFile(archive_path) as arc:
                raw = arc.read('potion.ws2', decrypt=False)
            assert raw == plaintext


@pytest.mark.unit
class TestARCInfo:
    """Test the ARCInfo data class."""

    def test_repr(self):
        info = ARCInfo()
        info.file_name = 'alice.ogg'
        info.offset = 0x100
        info.size = 0x200
        r = repr(info)
        assert 'alice.ogg' in r
        assert '256' in r or '0x100' in r

    def test_defaults(self):
        info = ARCInfo()
        assert info.file_name == ''
        assert info.offset == 0
        assert info.size == 0


NONFREE_DIR = os.path.join(os.path.dirname(__file__), 'nonfree')


@pytest.mark.nonfree
class TestARCFileNonfree:
    """Tests using real game data from nonfree/ samples."""

    def _find_arcs(self):
        arcs = []
        if not os.path.isdir(NONFREE_DIR):
            return arcs
        for dirpath, _dirnames, filenames in os.walk(NONFREE_DIR):
            for name in filenames:
                if name.endswith('.arc'):
                    arcs.append(os.path.join(dirpath, name))
        return arcs

    def test_read_all_archives(self):
        """Open each .arc file in nonfree/ and verify basic integrity."""
        arcs = self._find_arcs()
        if not arcs:
            pytest.skip('no .arc samples in nonfree/')

        for arc_path in arcs:
            with ARCFile(arc_path) as arc:
                assert len(arc.files) > 0, f'{arc_path}: no files'
                for f in arc.files:
                    data = arc.read(f)
                    assert len(data) == f.size, f'{arc_path}/{f.file_name}: size mismatch'

    def test_roundtrip_nonfree_samples(self):
        """Extract and recreate each nonfree sample, verify content is preserved."""
        arcs = self._find_arcs()
        if not arcs:
            pytest.skip('no .arc samples in nonfree/')

        for arc_path in arcs:
            with tempfile.TemporaryDirectory() as tmpdir:
                ext_dir = os.path.join(tmpdir, 'extracted')
                os.makedirs(ext_dir)
                with ARCFile(arc_path) as orig:
                    original_names = [f.file_name for f in orig.files]
                    original_data = {f.file_name: orig.read(f) for f in orig.files}
                    orig.extract_all(ext_dir)

                rebuilt_path = os.path.join(tmpdir, 'rebuilt.arc')
                with ARCFile(rebuilt_path, mode='w') as arc:
                    for name in original_names:
                        filepath = os.path.join(ext_dir, name)
                        arc.write(filepath, arcname=name)

                with ARCFile(rebuilt_path) as rebuilt:
                    assert len(rebuilt.files) == len(original_names), (
                        f'{arc_path}: file count mismatch'
                    )
                    for i, f in enumerate(rebuilt.files):
                        assert f.file_name == original_names[i], (
                            f'{arc_path}: name mismatch at {i}'
                        )
                        assert rebuilt.read(f) == original_data[f.file_name], (
                            f'{arc_path}/{f.file_name}: content mismatch'
                        )
