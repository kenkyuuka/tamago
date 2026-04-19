"""Tests for LiveMaker VFFile reader and writer."""

import datetime
import os
import pathlib
import struct
import tempfile

import pytest

from tamago.formats.livemaker.vffile import (
    EXE_TRAILER_TAG,
    FLAG_COMPRESSED,
    FLAG_SCRAMBLED,
    FLAG_SCRAMBLED_COMPRESSED,
    FLAG_STORED,
    VFFile,
    VFInfo,
)


@pytest.mark.unit
class TestVFInfo:
    def test_defaults(self):
        info = VFInfo()
        assert info.file_name == ''
        assert info.offset == 0
        assert info.packed_size == 0
        assert info.flags == FLAG_STORED
        assert info.compressed is False
        assert info.scrambled is False

    def test_repr_contains_name(self):
        info = VFInfo()
        info.file_name = 'alice.lsb'
        assert 'alice.lsb' in repr(info)


@pytest.mark.unit
class TestVFFileRoundtripStandalone:
    def _write_src(self, base: pathlib.Path, files: dict[str, bytes]):
        for name, data in files.items():
            path = base / name.replace('\\', os.sep)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def test_basic_roundtrip(self):
        files = {
            'alice.lsb': b'Down the rabbit hole!\n' * 10,
            'queen.txt': b'Off with her head!\n',
            'wonderland\\cheshire.ogg': b'\x00OggS' + b'mock ogg data ' * 20,
        }
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            self._write_src(src, files)

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src)

            with VFFile(arc_path) as arc:
                assert len(arc.files) == len(files)
                stored = {f.file_name: arc.read(f) for f in arc.files}

            for name, data in files.items():
                key = name.replace('/', '\\')
                assert stored[key] == data, f"mismatch for {key}"

    def test_default_compression_by_extension(self):
        """``.lsb`` and ``.txt`` compress by default; ``.ogg`` stores raw."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            (src / 'a.lsb').write_bytes(b'A' * 500)
            (src / 'b.ogg').write_bytes(b'B' * 500)

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src)

            with VFFile(arc_path) as arc:
                by_name = {f.file_name: f for f in arc.files}
                assert by_name['a.lsb'].flags == FLAG_COMPRESSED
                assert by_name['b.ogg'].flags == FLAG_STORED
                # Compressed entry should be smaller than unpacked, stored entry equal.
                assert by_name['a.lsb'].packed_size < 500
                assert by_name['b.ogg'].packed_size == 500

    def test_explicit_compress_override(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            (src / 'a.ogg').write_bytes(b'X' * 500)

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src, compress=True)

            with VFFile(arc_path) as arc:
                assert arc.files[0].flags == FLAG_COMPRESSED
                assert arc.read(arc.files[0]) == b'X' * 500

    def test_scramble_stored(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            content = b'Curiouser and curiouser!' * 50
            (src / 'rabbit.bin').write_bytes(content)

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src, scramble=True)

            with VFFile(arc_path) as arc:
                assert arc.files[0].flags == FLAG_SCRAMBLED
                assert arc.read(arc.files[0]) == content

    def test_scramble_compressed(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            content = b'We are all mad here.\n' * 50
            (src / 'cheshire.lsb').write_bytes(content)

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src, scramble=True)

            with VFFile(arc_path) as arc:
                assert arc.files[0].flags == FLAG_SCRAMBLED_COMPRESSED
                assert arc.read(arc.files[0]) == content

    def test_binary_identical_roundtrip(self):
        """Extract then recreate should produce the same file byte-for-byte."""
        files = {
            'alice.lsb': b'Down the rabbit hole!\n' * 10,
            'queen.txt': b'Off with her head!\n',
            'sub\\hatter.lpb': b'\xff\x00\xaa' * 30,
        }
        ts = datetime.datetime(2024, 6, 15, 12, 0, 0)  # noqa: DTZ001

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            for name, data in files.items():
                path = src / name.replace('\\', '/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            first = tmp / 'first.dat'
            with VFFile(first, mode='w') as arc:
                for name, _data in files.items():
                    path = src / name.replace('\\', '/')
                    arc.write(path, arcname=name, timestamp=ts)

            ext_dir = tmp / 'ext'
            ext_dir.mkdir()
            with VFFile(first) as arc:
                arc.extract_all(ext_dir)

            second = tmp / 'second.dat'
            with VFFile(second, mode='w') as arc:
                for name in files:
                    disk_name = name.replace('\\', '/')
                    arc.write(ext_dir / disk_name, arcname=name, timestamp=ts)

            assert first.read_bytes() == second.read_bytes()


@pytest.mark.unit
class TestVFFileExtractAll:
    def test_backslash_separator_creates_dirs(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            (src / 'a' / 'b').mkdir(parents=True)
            (src / 'a' / 'b' / 'tea.txt').write_bytes(b'Have some tea.')

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src)

            out_dir = tmp / 'out'
            out_dir.mkdir()
            with VFFile(arc_path) as arc:
                # name stored as 'a\\b\\tea.txt'
                assert arc.files[0].file_name == r'a\b\tea.txt'
                arc.extract_all(out_dir)

            assert (out_dir / 'a' / 'b' / 'tea.txt').read_bytes() == b'Have some tea.'

    def test_glob_filter(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            (src / 'voice01.ogg').write_bytes(b'\x01' * 10)
            (src / 'voice02.ogg').write_bytes(b'\x02' * 10)
            (src / 'music.wav').write_bytes(b'\x03' * 10)

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src)

            out_dir = tmp / 'out'
            out_dir.mkdir()
            with VFFile(arc_path) as arc:
                arc.extract_all(out_dir, glob='*.ogg')

            assert (out_dir / 'voice01.ogg').exists()
            assert (out_dir / 'voice02.ogg').exists()
            assert not (out_dir / 'music.wav').exists()


@pytest.mark.unit
class TestVFFileExeEmbedded:
    """Exercise the exe-embedded configuration with a fake MZ prefix."""

    def test_reads_past_exe_stub(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            # Build a bare archive first.
            src = tmp / 'src'
            src.mkdir()
            (src / 'alice.lsb').write_bytes(b'Drink me!\n' * 5)
            bare = tmp / 'bare.dat'
            with VFFile(bare, mode='w') as arc:
                arc.write_all(src)

            vf_bytes = bare.read_bytes()

            # Fake an exe: 256 bytes of stub (starts with MZ), then archive,
            # then 6-byte trailer.
            stub = b'MZ' + b'\x00' * 254
            base_offset = len(stub)
            exe_bytes = stub + vf_bytes + struct.pack('<I', base_offset) + EXE_TRAILER_TAG

            exe_path = tmp / 'game.exe'
            exe_path.write_bytes(exe_bytes)

            with VFFile(exe_path) as arc:
                assert len(arc.files) == 1
                assert arc.files[0].file_name == 'alice.lsb'
                assert arc.read(arc.files[0]) == b'Drink me!\n' * 5


@pytest.mark.unit
class TestVFFileErrors:
    def test_invalid_mode(self, tmp_path):
        with pytest.raises(ValueError, match='Invalid mode'):
            VFFile(tmp_path / 'does-not-matter', mode='x')

    def test_read_missing_member(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            (src / 'alice.lsb').write_bytes(b'hello')

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src)

            with VFFile(arc_path) as arc:
                with pytest.raises(KeyError, match='nonexistent'):
                    arc.read('nonexistent')

    def test_write_on_read_mode(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            (src / 'a.lsb').write_bytes(b'x')
            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src)

            with VFFile(arc_path) as arc:
                with pytest.raises(ValueError, match="mode='w'"):
                    arc.write('/dev/null', arcname='x.lsb')

    def test_not_a_vf_archive(self):
        with tempfile.NamedTemporaryFile(suffix='.dat', delete=False) as f:
            f.write(b'not a vf archive at all')
            path = f.name
        try:
            with pytest.raises(ValueError):
                VFFile(path)
        finally:
            os.unlink(path)

    def test_unsupported_version(self):
        """A VF archive claiming version 999 should be rejected."""
        with tempfile.NamedTemporaryFile(suffix='.dat', delete=False) as f:
            f.write(b'vf' + struct.pack('<I', 999) + struct.pack('<I', 0))
            path = f.name
        try:
            with pytest.raises(ValueError, match='version'):
                VFFile(path)
        finally:
            os.unlink(path)


@pytest.mark.unit
class TestVFFileJapaneseNames:
    def test_shift_jis_roundtrip(self):
        """Names containing non-ASCII Shift-JIS characters roundtrip."""
        name = '\u30a2\u30ea\u30b9.lsb'  # "alice" in katakana
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            src = tmp / 'src'
            src.mkdir()
            (src / name).write_bytes(b'Drink me!')

            arc_path = tmp / 'test.dat'
            with VFFile(arc_path, mode='w') as arc:
                arc.write_all(src)

            with VFFile(arc_path) as arc:
                assert arc.files[0].file_name == name
                assert arc.read(arc.files[0]) == b'Drink me!'
