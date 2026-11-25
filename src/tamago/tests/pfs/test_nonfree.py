"""Roundtrip tests for real Artemis PFS archives in nonfree/.

The nonfree directory is gitignored: populate it manually with ``.pfs``
archives (and patch archives such as ``root.pfs.000``) from Artemis games to
enable these tests.  They skip when no samples are present.
"""

import filecmp
import hashlib
import os
import re

import pytest

from tamago.cli import detect_format
from tamago.formats.pfs import PFSFile

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')
_ARCHIVE_NAME = re.compile(r'\.pfs(\.\d+)?$', re.IGNORECASE)


def _collect():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            if _ARCHIVE_NAME.search(f):
                found.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(found)


archives = _collect()


def _contents(arc):
    return [(info.raw_name, hashlib.sha256(arc.read(info)).digest()) for info in arc.files]


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not archives, reason="no nonfree PFS samples available")
@pytest.mark.parametrize('relpath', archives)
class TestNonfreeArchives:
    def test_detected(self, relpath):
        assert detect_format(os.path.join(NONFREE, relpath)) == 'pfs'

    def test_reads_every_member(self, relpath):
        with PFSFile(os.path.join(NONFREE, relpath)) as arc:
            assert arc.files
            for info in arc.files:
                assert len(arc.read(info)) == info.size, info.file_name

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.pfs'

        with PFSFile(source) as arc:
            original = _contents(arc)
            arc.extract_all(extracted)

        with PFSFile(rebuilt, mode='w') as arc:
            arc.write_all(extracted)

        with PFSFile(rebuilt) as arc:
            assert _contents(arc) == original
        # The manifest keeps the original data order, so the index (and the
        # pf8 key, its hash) come out the same, and so does every byte.
        assert filecmp.cmp(source, rebuilt, shallow=False)
