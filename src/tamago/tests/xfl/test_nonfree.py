"""Roundtrip tests for real XFL game archives in nonfree/.

The nonfree directory is gitignored — populate it manually with .xfl files
(in any subdirectory layout) to enable these tests.
"""

import os

import pytest

from tamago.formats.xfl.xflfile import XFLFile

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect_xfl_files():
    """Collect .xfl files from nonfree/, including subdirectories."""
    if not os.path.isdir(NONFREE):
        return []
    results = []
    for root, _dirs, files in os.walk(NONFREE):
        for f in files:
            if f.lower().endswith('.xfl'):
                results.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(results)


xfl_files = _collect_xfl_files()
skip_no_samples = pytest.mark.skipif(not xfl_files, reason="no nonfree XFL samples available")


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', xfl_files)
class TestNonfreeXFLSamples:
    def test_read_every_member(self, relpath):
        """Every member (including nested ones) can be read at its declared size."""
        path = os.path.join(NONFREE, relpath)
        with XFLFile(path) as xfl:
            assert xfl.files or xfl.archives, f"{relpath} has no members"
            for member in xfl.files:
                assert len(xfl.read(member)) == member.size, f"{relpath}:{member.file_name}"

    def test_roundtrip(self, relpath, tmp_path):
        """Extract, recreate, and verify contents and exact archive bytes."""
        path = os.path.join(NONFREE, relpath)
        out = tmp_path / 'extracted'
        with XFLFile(path) as xfl:
            names = [f.file_name for f in xfl.files]
            xfl.extract_all(out)

        rebuilt = tmp_path / 'rebuilt.xfl'
        with XFLFile(rebuilt, mode='w') as xfl:
            xfl.write_all(out)

        with XFLFile(path) as orig, XFLFile(rebuilt) as new:
            assert [f.file_name for f in new.files] == names
            for a, b in zip(orig.files, new.files, strict=True):
                assert orig.read(a) == new.read(b), f"{relpath}:{a.file_name} content mismatch"

        with open(path, 'rb') as f_orig, open(rebuilt, 'rb') as f_new:
            while True:
                a = f_orig.read(1 << 20)
                b = f_new.read(1 << 20)
                assert a == b, f"{relpath}: rebuilt archive differs from original"
                if not a:
                    break
