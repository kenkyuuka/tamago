"""Roundtrip tests for real Black Cyc packs in nonfree/.

The nonfree directory is gitignored: populate it manually with the ``dwq/``
(``.gtb``/``.gpk``) and ``cdvaw/`` (``.vtb``/``.vpk``) folders of Black Cyc,
Cyc No-nos or CYCLET games to enable these tests.  They skip when no samples
are present.
"""

import filecmp
import hashlib
import os

import pytest

from tamago.cli import detect_format
from tamago.formats.blackcyc import PackFile

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            if f.lower().endswith(('.gtb', '.vtb')):
                found.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(found)


packs = _collect()


def _contents(pack):
    return [(info.raw_name, hashlib.sha256(pack.read(info)).digest()) for info in pack.files]


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not packs, reason="no nonfree Black Cyc samples available")
@pytest.mark.parametrize('relpath', packs)
class TestNonfreePacks:
    def test_detected(self, relpath):
        index = os.path.join(NONFREE, relpath)
        assert detect_format(index) == 'blackcyc'
        with PackFile(index) as pack:
            assert detect_format(pack.data_path) == 'blackcyc'

    def test_reads_every_member(self, relpath):
        with PackFile(os.path.join(NONFREE, relpath)) as pack:
            assert pack.files
            for info in pack.files:
                assert len(pack.read(info)) == info.size, info.file_name

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt' / os.path.basename(relpath)
        rebuilt.parent.mkdir()

        with PackFile(source) as pack:
            original = _contents(pack)
            source_data = pack.data_path
            pack.extract_all(extracted)

        with PackFile(rebuilt, mode='w') as pack:
            pack.write_all(extracted)

        with PackFile(rebuilt) as pack:
            assert _contents(pack) == original
            rebuilt_data = pack.data_path
        # The packs are sorted the way the games' packer sorts them, so both
        # files of the pair come out identical.
        assert filecmp.cmp(source, rebuilt, shallow=False)
        assert filecmp.cmp(source_data, rebuilt_data, shallow=False)
