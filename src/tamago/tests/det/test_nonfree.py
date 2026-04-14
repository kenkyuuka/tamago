"""Smoke tests for real DET game archives in nonfree/.

These tests verify that the library can open and read real-world DET files.
The nonfree directory is gitignored — populate it manually with .det
files to enable these tests.
"""

import os
import tempfile

import pytest

from tamago.formats.det.detfile import DETFile

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect_det_files():
    """Collect .det files from nonfree/, including subdirectories."""
    if not os.path.isdir(NONFREE):
        return []
    results = []
    for root, _dirs, files in os.walk(NONFREE):
        for f in sorted(files):
            if f.lower().endswith('.det'):
                results.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(results)


det_files = _collect_det_files()
skip_no_samples = pytest.mark.skipif(not det_files, reason="no nonfree DET samples available")


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', det_files)
class TestNonfreeDETSamples:
    """Basic reading tests for real DET archives."""

    def test_opens_and_lists_files(self, relpath):
        """Archive opens without error and has at least one file entry."""
        path = os.path.join(NONFREE, relpath)
        with DETFile(path) as det:
            assert len(det.files) > 0, f"{relpath} has no file entries"

    def test_file_entries_have_names(self, relpath):
        """Every file entry has a non-empty name."""
        path = os.path.join(NONFREE, relpath)
        with DETFile(path) as det:
            for member in det.files:
                assert member.file_name, f"empty file_name in {relpath}"

    def test_read_first_file(self, relpath):
        """The first file in the archive can be read without error."""
        path = os.path.join(NONFREE, relpath)
        with DETFile(path) as det:
            member = det.files[0]
            data = det.read(member.file_name)
            assert (
                len(data) == member.unpacked_size
            ), f"{relpath}:{member.file_name} read {len(data)} bytes, expected {member.unpacked_size}"

    def test_extract_all(self, relpath):
        """All files can be extracted without error."""
        path = os.path.join(NONFREE, relpath)
        with DETFile(path) as det:
            with tempfile.TemporaryDirectory() as tmpdir:
                det.extract_all(tmpdir)
