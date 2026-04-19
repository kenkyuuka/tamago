"""Roundtrip tests for real LiveMaker VF archives in nonfree/.

These tests verify that the library can open, fully read, and recreate
real-world VF archives (embedded, standalone, or multi-part).  The
nonfree directory is gitignored — populate it manually with ``.exe``,
``.dat``, or ``.dat``+``.ext``(+``.001``, ...) archives to enable these
tests.  If no samples are present the tests skip cleanly.
"""

import os
import pathlib
import tempfile

import pytest

from tamago.formats.livemaker.vffile import VFFile

NONFREE = pathlib.Path(__file__).parent / 'nonfree'

_ARCHIVE_SUFFIXES = ('.exe', '.dat')


def _collect_archives() -> list[pathlib.Path]:
    """Return candidate archive paths (main file only — companions implied)."""
    if not NONFREE.is_dir():
        return []
    results: list[pathlib.Path] = []
    for root, _dirs, files in os.walk(NONFREE):
        for name in sorted(files):
            p = pathlib.Path(root) / name
            if p.suffix.lower() in _ARCHIVE_SUFFIXES:
                results.append(p)
    return sorted(results)


_archives = _collect_archives()
_skip_no_samples = pytest.mark.skipif(not _archives, reason='no nonfree LiveMaker samples available')


@pytest.mark.nonfree
@pytest.mark.integration
@_skip_no_samples
@pytest.mark.parametrize('path', _archives, ids=lambda p: str(p.relative_to(NONFREE)))
class TestNonfreeLiveMakerSamples:
    def test_opens_and_lists_files(self, path):
        """Archive opens without error and contains at least one entry."""
        try:
            arc = VFFile(path)
        except ValueError:
            pytest.skip(f'{path.name} is not a LiveMaker archive')
        with arc:
            assert len(arc.files) > 0, f'{path} has no file entries'
            for f in arc.files:
                assert f.file_name, f'empty file_name in {path}'

    def test_read_all_entries(self, path):
        """Every entry in the archive can be read and decompressed/unscrambled."""
        try:
            arc = VFFile(path)
        except ValueError:
            pytest.skip(f'{path.name} is not a LiveMaker archive')
        with arc:
            for f in arc.files:
                data = arc.read(f)
                # At minimum, something comes back.  (Empty entries are valid.)
                assert isinstance(data, bytes)

    def test_roundtrip(self, path):
        """Extract and recreate the archive, verify every entry's content.

        We compare decoded content rather than raw archive bytes, since
        re-encoding with default zlib settings does not necessarily produce
        byte-identical compressed payloads.  What matters is that a reader
        sees the same files with the same contents.
        """
        try:
            orig = VFFile(path)
        except ValueError:
            pytest.skip(f'{path.name} is not a LiveMaker archive')
        with orig:
            original_names = [f.file_name for f in orig.files]
            original_data = {f.file_name: orig.read(f) for f in orig.files}
            original_meta = {f.file_name: (f.compressed, f.scrambled, f.timestamp) for f in orig.files}

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            ext_dir = tmp / 'extracted'
            ext_dir.mkdir()
            with VFFile(path) as arc:
                arc.extract_all(ext_dir)

            rebuilt = tmp / 'rebuilt.dat'
            with VFFile(rebuilt, mode='w') as out:
                for name in original_names:
                    disk_path = ext_dir / pathlib.Path(name.replace('\\', os.sep))
                    compress, scramble, ts = original_meta[name]
                    out.write(
                        disk_path,
                        arcname=name,
                        compress=compress,
                        scramble=scramble,
                        timestamp=ts,
                    )

            with VFFile(rebuilt) as arc:
                assert len(arc.files) == len(original_names)
                for info in arc.files:
                    assert info.file_name in original_data
                    assert (
                        arc.read(info) == original_data[info.file_name]
                    ), f'{path}:{info.file_name} content mismatch after roundtrip'
