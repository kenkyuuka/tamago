"""Roundtrip tests for real AI6WIN archives in nonfree/.

The nonfree directory is gitignored: populate it manually with ``.arc``
archives from AI6WIN games (elf, Silky's) to enable these tests.  They skip
when no samples are present.
"""

import filecmp
import hashlib
import os

import pytest

from tamago.cli import detect_format
from tamago.formats.ai6win import ARCFile

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            if f.lower().endswith('.arc'):
                found.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(found)


archives = _collect()


def _contents(arc):
    return [(info.raw_name, hashlib.sha256(arc.read(info)).digest()) for info in arc.files]


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not archives, reason="no nonfree AI6WIN samples available")
@pytest.mark.parametrize('relpath', archives)
class TestNonfreeArchives:
    def test_detected(self, relpath):
        assert detect_format(os.path.join(NONFREE, relpath)) == 'ai6win'

    def test_reads_every_member(self, relpath):
        with ARCFile(os.path.join(NONFREE, relpath)) as arc:
            assert arc.files
            for info in arc.files:
                assert len(arc.read(info)) == info.unpacked_size, info.file_name

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.arc'

        with ARCFile(source) as arc:
            original = _contents(arc)
            arc.extract_all(extracted)

        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(extracted)

        with ARCFile(rebuilt) as arc:
            assert _contents(arc) == original
        # The games' packer used Okumura's LZSS encoder, which tamago
        # reproduces, so rebuilding from the manifest is byte-identical.
        assert filecmp.cmp(source, rebuilt, shallow=False)
