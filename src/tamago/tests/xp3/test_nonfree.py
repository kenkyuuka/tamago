"""Smoke tests for real XP3 game archives in nonfree/.

These tests verify that the library can open and read real-world XP3 files,
including encryption auto-detection. The nonfree directory is gitignored —
populate it manually with .xp3 files to enable these tests.

For best results, place entire game directories (or symlinks) as
subdirectories of nonfree/, so TPM-based detection works:

    nonfree/
        some-game/
            data.xp3
            patch.xp3
            something.tpm
        standalone.xp3
"""

import os
import tempfile

import pytest

from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.detect import auto_detect

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect_xp3_files():
    """Collect .xp3 files from nonfree/, including subdirectories."""
    if not os.path.isdir(NONFREE):
        return []
    results = []
    for root, _dirs, files in os.walk(NONFREE):
        for f in sorted(files):
            if f.lower().endswith('.xp3'):
                results.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(results)


xp3_files = _collect_xp3_files()
skip_no_samples = pytest.mark.skipif(not xp3_files, reason="no nonfree XP3 samples available")

# 255 bytes is the common filesystem filename limit (ext4, btrfs, etc.)
_MAX_FILENAME_BYTES = 255


def _find_extractable_member(xp3):
    """Return the first member whose basename fits in a filesystem filename, or None."""
    for member in xp3.files:
        if len(os.path.basename(member.file_name).encode("utf-8")) <= _MAX_FILENAME_BYTES:
            return member
    return None


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', xp3_files)
class TestNonfreeXP3Samples:
    """Basic reading and extraction tests for real XP3 archives."""

    def test_opens_and_lists_files(self, relpath):
        """Archive opens without error and has at least one file entry."""
        path = os.path.join(NONFREE, relpath)
        with XP3File(path) as xp3:
            assert len(xp3.files) > 0, f"{relpath} has no file entries"

    def test_file_entries_have_names(self, relpath):
        """Every file entry has a non-empty name."""
        path = os.path.join(NONFREE, relpath)
        with XP3File(path) as xp3:
            for member in xp3.files:
                assert member.file_name, f"empty file_name in {relpath}"

    def test_extract_first_file(self, relpath):
        """The first extractable file extracts to the correct size (no encryption)."""
        path = os.path.join(NONFREE, relpath)
        with XP3File(path) as xp3:
            member = _find_extractable_member(xp3)
            if member is None:
                pytest.skip("no member with a filename short enough to extract")
            with tempfile.TemporaryDirectory() as tmpdir:
                outpath = os.path.join(tmpdir, os.path.basename(member.file_name))
                xp3.extract(member, outpath)
                size = os.path.getsize(outpath)
                assert (
                    size == member.original_size
                ), f"{relpath}:{member.file_name} extracted {size} bytes, expected {member.original_size}"

    def test_auto_detect_and_extract(self, relpath):
        """Auto-detect encryption, then extract the first extractable file and verify size."""
        path = os.path.join(NONFREE, relpath)
        encryption = auto_detect(path)
        with XP3File(path, encryption=encryption) as xp3:
            member = _find_extractable_member(xp3)
            if member is None:
                pytest.skip("no member with a filename short enough to extract")
            with tempfile.TemporaryDirectory() as tmpdir:
                outpath = os.path.join(tmpdir, os.path.basename(member.file_name))
                xp3.extract(member, outpath)
                size = os.path.getsize(outpath)
                assert (
                    size == member.original_size
                ), f"{relpath}:{member.file_name} extracted {size} bytes, expected {member.original_size}"
