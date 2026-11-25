"""Smoke tests for real DET game archives in nonfree/.

These tests verify that the library can open and read real-world DET files.
The nonfree directory is gitignored — populate it manually with .det
files to enable these tests.
"""

import os

import pytest

from tamago.formats.det.detfile import DETFile
from tamago.formats.member_paths import member_path

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
def test_extracts_every_member(relpath, tmp_path):
    """The archive lists named members, and every one extracts at its stated size."""
    with DETFile(os.path.join(NONFREE, relpath)) as det:
        assert det.files, f"{relpath} has no file entries"
        for member in det.files:
            assert member.file_name, f"empty file_name in {relpath}"
        det.extract_all(tmp_path)
        for member in det.files:
            assert os.path.getsize(member_path(tmp_path, member.file_name)) == member.unpacked_size, member.file_name
