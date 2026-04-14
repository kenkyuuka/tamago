import os
import struct
import tempfile

import pytest

from tamago.formats.det.detfile import DETFile


@pytest.mark.unit
class TestDETFileIndex:
    """Test DETFile opening with synthetic archive files."""

    def _write_archive(self, tmpdir, names, entries, entry_size=0x10, det_size=1024):
        """Create synthetic .det, .nme, and .atm/.at2 files."""
        det_path = os.path.join(tmpdir, 'test.det')
        nme_path = os.path.join(tmpdir, 'test.nme')

        suffix = '.atm' if entry_size == 0x10 else '.at2'
        idx_path = os.path.join(tmpdir, 'test' + suffix)

        # Write .det — just zero-filled to the required size.
        with open(det_path, 'wb') as f:
            f.write(b'\x00' * det_size)

        # Write .nme — null-terminated strings.
        with open(nme_path, 'wb') as f:
            f.write(names)

        # Write index.
        with open(idx_path, 'wb') as f:
            for entry in entries:
                if entry_size == 0x10:
                    f.write(struct.pack('<iII', entry[0], entry[1], entry[2]))
                    f.write(b'\x00' * 4)  # padding
                else:
                    f.write(struct.pack('<iII', entry[0], entry[1], entry[2]))
                    f.write(b'\x00' * 4)  # padding
                    f.write(struct.pack('<I', entry[3]))
            f.write(b'\x00' * 4)  # trailer

        return det_path

    def test_open_atm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Two files: "a.txt" at nme offset 0, "b.txt" at nme offset 6
            names = b'a.txt\x00b.txt\x00'
            entries = [
                (0, 0, 10),  # name_offset=0, data_offset=0, packed_size=10
                (6, 10, 20),  # name_offset=6, data_offset=10, packed_size=20
            ]
            det_path = self._write_archive(tmpdir, names, entries, det_size=1024)
            with DETFile(det_path) as det:
                assert len(det.files) == 2
                assert det.files[0].file_name == 'a.txt'
                assert det.files[0].offset == 0
                assert det.files[0].packed_size == 10
                assert det.files[1].file_name == 'b.txt'

    def test_open_at2(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            names = b'file.bmp\x00'
            entries = [
                (0, 0, 50, 100),  # name_offset, data_offset, packed_size, unpacked_size
            ]
            det_path = self._write_archive(tmpdir, names, entries, entry_size=0x14, det_size=1024)
            with DETFile(det_path) as det:
                assert len(det.files) == 1
                assert det.files[0].file_name == 'file.bmp'
                assert det.files[0].unpacked_size == 100

    def test_missing_nme_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            det_path = os.path.join(tmpdir, 'test.det')
            with open(det_path, 'wb') as f:
                f.write(b'\x00' * 100)
            with pytest.raises(FileNotFoundError, match='Name file not found'):
                DETFile(det_path)

    def test_missing_index_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            det_path = os.path.join(tmpdir, 'test.det')
            nme_path = os.path.join(tmpdir, 'test.nme')
            with open(det_path, 'wb') as f:
                f.write(b'\x00' * 100)
            with open(nme_path, 'wb') as f:
                f.write(b'name\x00')
            with pytest.raises(FileNotFoundError, match='Index file not found'):
                DETFile(det_path)


@pytest.mark.unit
class TestDETFileCreate:
    """Test DETFile archive creation."""

    def test_create_and_read_at2(self):
        """Create an archive with at2 index and read it back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write source files.
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            content_a = b'Hello, world!'
            content_b = b'\x00' * 50 + b'\x41' * 20
            with open(os.path.join(src_dir, 'a.txt'), 'wb') as f:
                f.write(content_a)
            with open(os.path.join(src_dir, 'b.bin'), 'wb') as f:
                f.write(content_b)

            # Create archive.
            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write(os.path.join(src_dir, 'a.txt'))
                det.write(os.path.join(src_dir, 'b.bin'))

            # Verify companion files exist.
            assert os.path.exists(os.path.join(tmpdir, 'test.nme'))
            assert os.path.exists(os.path.join(tmpdir, 'test.at2'))

            # Read back and verify.
            with DETFile(det_path) as det:
                assert len(det.files) == 2
                assert det.files[0].file_name == 'a.txt'
                assert det.files[1].file_name == 'b.bin'
                assert det.read('a.txt') == content_a
                assert det.read('b.bin') == content_b
                assert det.files[0].unpacked_size == len(content_a)
                assert det.files[1].unpacked_size == len(content_b)

    def test_create_and_read_atm(self):
        """Create an archive with atm index and read it back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            content = b'Test data for atm format'
            with open(os.path.join(src_dir, 'file.dat'), 'wb') as f:
                f.write(content)

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='atm') as det:
                det.write(os.path.join(src_dir, 'file.dat'))

            assert os.path.exists(os.path.join(tmpdir, 'test.atm'))
            assert not os.path.exists(os.path.join(tmpdir, 'test.at2'))

            with DETFile(det_path) as det:
                assert len(det.files) == 1
                assert det.files[0].file_name == 'file.dat'
                assert det.read('file.dat') == content

    def test_write_all(self):
        """write_all adds all files from a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            for name in ('x.txt', 'y.txt', 'z.bin'):
                with open(os.path.join(src_dir, name), 'wb') as f:
                    f.write(name.encode())

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write_all(src_dir)

            with DETFile(det_path) as det:
                names = sorted(f.file_name for f in det.files)
                assert names == ['x.txt', 'y.txt', 'z.bin']
                assert det.read('x.txt') == b'x.txt'

    def test_write_all_with_glob(self):
        """write_all respects glob filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            os.makedirs(src_dir)
            for name in ('a.txt', 'b.txt', 'c.bin'):
                with open(os.path.join(src_dir, name), 'wb') as f:
                    f.write(name.encode())

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write_all(src_dir, glob='*.txt')

            with DETFile(det_path) as det:
                names = sorted(f.file_name for f in det.files)
                assert names == ['a.txt', 'b.txt']

    def test_arcname_slash_conversion(self):
        """Forward slashes in arcname are converted to backslashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, 'file.txt')
            with open(src, 'wb') as f:
                f.write(b'data')

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write(src, arcname='subdir/file.txt')

            with DETFile(det_path) as det:
                assert det.files[0].file_name == 'subdir\\file.txt'
                assert det.read('subdir\\file.txt') == b'data'

    def test_write_all_recursive(self):
        """write_all recurses into subdirectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            sub_dir = os.path.join(src_dir, 'sub')
            os.makedirs(sub_dir)
            with open(os.path.join(src_dir, 'top.txt'), 'wb') as f:
                f.write(b'top')
            with open(os.path.join(sub_dir, 'nested.txt'), 'wb') as f:
                f.write(b'nested')

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write_all(src_dir)

            with DETFile(det_path) as det:
                names = sorted(f.file_name for f in det.files)
                assert names == ['sub\\nested.txt', 'top.txt']
                assert det.read('sub\\nested.txt') == b'nested'

    def test_write_requires_write_mode(self):
        """write() raises ValueError when archive is opened for reading."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a valid archive with one file.
            src = os.path.join(tmpdir, 'file.txt')
            with open(src, 'wb') as f:
                f.write(b'data')

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write(src)

            with DETFile(det_path) as det:
                with pytest.raises(ValueError, match=r"write.*requires mode='w'"):
                    det.write(src)

    def test_invalid_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            det_path = os.path.join(tmpdir, 'test.det')
            with pytest.raises(ValueError, match='Invalid mode'):
                DETFile(det_path, mode='x')

    def test_invalid_index_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            det_path = os.path.join(tmpdir, 'test.det')
            with pytest.raises(ValueError, match='Invalid index_format'):
                DETFile(det_path, mode='w', index_format='bad')


@pytest.mark.integration
class TestDETFileRoundTrip:
    """Create archives, extract them, and verify byte-for-byte fidelity."""

    @staticmethod
    def _populate(directory, file_map):
        """Write *file_map* (name -> bytes) into *directory*, creating subdirs."""
        for name, content in file_map.items():
            path = os.path.join(directory, *name.split('/'))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(content)

    @pytest.mark.parametrize('index_format', ['at2', 'atm'])
    def test_roundtrip_single_file(self, index_format):
        """A single file survives create → extract unchanged."""
        content = b'The quick brown fox jumps over the lazy dog.'
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            out_dir = os.path.join(tmpdir, 'out')
            self._populate(src_dir, {'greeting.txt': content})

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format=index_format) as det:
                det.write_all(src_dir)
            with DETFile(det_path) as det:
                det.extract_all(out_dir)

            with open(os.path.join(out_dir, 'greeting.txt'), 'rb') as f:
                assert f.read() == content

    @pytest.mark.parametrize('index_format', ['at2', 'atm'])
    def test_roundtrip_many_files(self, index_format):
        """Multiple files with varied content survive a roundtrip."""
        files = {
            'readme.txt': b'hello',
            'empty.dat': b'',
            'binary.bin': bytes(range(256)),
            'repeated.dat': b'\xab' * 500,
            'ff_heavy.bin': b'\xff' * 200,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            out_dir = os.path.join(tmpdir, 'out')
            self._populate(src_dir, files)

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format=index_format) as det:
                det.write_all(src_dir)
            with DETFile(det_path) as det:
                det.extract_all(out_dir)

            for name, expected in files.items():
                with open(os.path.join(out_dir, name), 'rb') as f:
                    assert f.read() == expected, f'{name} content mismatch'

    @pytest.mark.parametrize('index_format', ['at2', 'atm'])
    def test_roundtrip_nested_directories(self, index_format):
        """Subdirectory structure is preserved through create → extract."""
        files = {
            'top.txt': b'top-level',
            'sub/nested.txt': b'one level deep',
            'sub/deep/leaf.txt': b'two levels deep',
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            out_dir = os.path.join(tmpdir, 'out')
            self._populate(src_dir, files)

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format=index_format) as det:
                det.write_all(src_dir)
            with DETFile(det_path) as det:
                det.extract_all(out_dir)

            for name, expected in files.items():
                # extract_all splits on '/' so backslash arcnames map back to subdirs
                extracted = os.path.join(out_dir, *name.split('/'))
                with open(extracted, 'rb') as f:
                    assert f.read() == expected, f'{name} content mismatch'

    @pytest.mark.parametrize('index_format', ['at2', 'atm'])
    def test_roundtrip_large_compressible(self, index_format):
        """A large file with repeating patterns roundtrips correctly."""
        # 4 KiB of repeating 16-byte pattern — fits within the 64-byte
        # back-reference window, so the compressor can exploit it.
        pattern = bytes(range(16))
        content = pattern * 256
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            out_dir = os.path.join(tmpdir, 'out')
            self._populate(src_dir, {'big.dat': content})

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format=index_format, compressed=True) as det:
                det.write_all(src_dir)

            # Verify the packed size is smaller than the original.
            with DETFile(det_path) as det:
                assert det.files[0].packed_size < len(content)
                det.extract_all(out_dir)

            with open(os.path.join(out_dir, 'big.dat'), 'rb') as f:
                assert f.read() == content

    @pytest.mark.parametrize('index_format', ['at2', 'atm'])
    def test_roundtrip_high_entropy(self, index_format):
        """High-entropy data roundtrips even when compression expands it."""
        import random

        rng = random.Random(42)  # noqa: S311 — deterministic seed for test reproducibility
        content = bytes(rng.getrandbits(8) for _ in range(4096))
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            out_dir = os.path.join(tmpdir, 'out')
            self._populate(src_dir, {'noise.bin': content})

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format=index_format) as det:
                det.write_all(src_dir)
            with DETFile(det_path) as det:
                det.extract_all(out_dir)

            with open(os.path.join(out_dir, 'noise.bin'), 'rb') as f:
                assert f.read() == content

    def test_roundtrip_extract_with_glob(self):
        """Glob filtering during extract only extracts matched files."""
        files = {
            'track01.ogg': b'audio1',
            'track02.ogg': b'audio2',
            'cover.bmp': b'image',
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            out_dir = os.path.join(tmpdir, 'out')
            self._populate(src_dir, files)

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write_all(src_dir)
            with DETFile(det_path) as det:
                det.extract_all(out_dir, glob='*.ogg')

            assert os.path.exists(os.path.join(out_dir, 'track01.ogg'))
            assert os.path.exists(os.path.join(out_dir, 'track02.ogg'))
            assert not os.path.exists(os.path.join(out_dir, 'cover.bmp'))

    def test_roundtrip_read_api(self):
        """DETFile.read() returns the exact original bytes for each member."""
        files = {
            'a.dat': b'\x00' * 100,
            'b.dat': b'\xff' * 100,
            'c.dat': bytes(range(200)),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            self._populate(src_dir, files)

            det_path = os.path.join(tmpdir, 'test.det')
            with DETFile(det_path, mode='w', index_format='at2') as det:
                det.write_all(src_dir)
            with DETFile(det_path) as det:
                for name, expected in files.items():
                    assert det.read(name) == expected, f'{name} read mismatch'

    @pytest.mark.parametrize('index_format', ['at2', 'atm'])
    def test_roundtrip_archive_to_archive(self, index_format):
        """Archive → extract → recreate → extract and compare both extractions."""
        files = {
            'text.txt': b'Some text content here.',
            'binary.bin': bytes(range(64)) * 4,
            'sub/nested.dat': b'\x00\xff' * 50,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, 'src')
            self._populate(src_dir, files)

            # files → archive1
            arc1 = os.path.join(tmpdir, 'arc1.det')
            with DETFile(arc1, mode='w', index_format=index_format) as det:
                det.write_all(src_dir)

            # archive1 → extracted1
            ext1 = os.path.join(tmpdir, 'ext1')
            with DETFile(arc1) as det:
                det.extract_all(ext1)

            # extracted1 → archive2
            arc2 = os.path.join(tmpdir, 'arc2.det')
            with DETFile(arc2, mode='w', index_format=index_format) as det:
                det.write_all(ext1)

            # archive2 → extracted2
            ext2 = os.path.join(tmpdir, 'ext2')
            with DETFile(arc2) as det:
                det.extract_all(ext2)

            # Both extractions must produce identical file contents.
            for name, expected in files.items():
                parts = name.split('/')
                path1 = os.path.join(ext1, *parts)
                path2 = os.path.join(ext2, *parts)
                with open(path1, 'rb') as f:
                    got1 = f.read()
                with open(path2, 'rb') as f:
                    got2 = f.read()
                assert got1 == expected, f'{name} first extraction mismatch'
                assert got2 == expected, f'{name} second extraction mismatch'

    @pytest.mark.parametrize('index_format', ['at2', 'atm'])
    def test_roundtrip_synthetic_archive_extract(self, index_format):
        """Synthetic archive (hand-built .det/.nme/.atm) → extract → recreate → read."""
        # Build a synthetic archive from raw compressed data, then extract it,
        # recreate from the extracted files, and verify read() matches.
        from tamago.formats.det.detfile import compress

        original = {
            'alpha.txt': b'AAAAAABBBBBB',
            'beta.bin': bytes([0xFF, 0x00, 0x7F, 0x80]) * 10,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            det_path = os.path.join(tmpdir, 'synth.det')
            nme_data = bytearray()
            name_offsets = []
            packed_blobs = []
            data_offset = 0

            for name, content in original.items():
                name_offsets.append(len(nme_data))
                nme_data.extend(name.encode('shift_jis'))
                nme_data.append(0)
                packed = compress(content)
                packed_blobs.append((data_offset, packed, len(content)))
                data_offset += len(packed)

            # Write .det
            with open(det_path, 'wb') as f:
                for _, packed, _ in packed_blobs:
                    f.write(packed)
                f.write(b'\x00\x00\x00\x00')

            # Write .nme
            nme_data.extend(b'\x00\x00\x00\x00')
            nme_path = os.path.join(tmpdir, 'synth.nme')
            with open(nme_path, 'wb') as f:
                f.write(nme_data)

            # Write index
            use_at2 = index_format == 'at2'
            suffix = '.at2' if use_at2 else '.atm'
            idx_path = os.path.join(tmpdir, 'synth' + suffix)
            with open(idx_path, 'wb') as f:
                for i, (doff, packed, unpacked_size) in enumerate(packed_blobs):
                    f.write(struct.pack('<iII', name_offsets[i], doff, len(packed)))
                    f.write(b'\x00\x00\x00\x00')
                    if use_at2:
                        f.write(struct.pack('<I', unpacked_size))
                f.write(b'\x00\x00\x00\x00')  # trailer

            # Read synthetic archive and verify contents.
            with DETFile(det_path) as det:
                for name, expected in original.items():
                    assert det.read(name) == expected, f'{name} synthetic read mismatch'

            # Extract, recreate, and verify again.
            ext_dir = os.path.join(tmpdir, 'ext')
            with DETFile(det_path) as det:
                det.extract_all(ext_dir)

            arc2 = os.path.join(tmpdir, 'rebuilt.det')
            with DETFile(arc2, mode='w', index_format=index_format) as det:
                det.write_all(ext_dir)

            with DETFile(arc2) as det:
                for name, expected in original.items():
                    assert det.read(name) == expected, f'{name} rebuilt read mismatch'
