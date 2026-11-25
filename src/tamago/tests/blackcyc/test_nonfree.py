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
from tamago.formats.blackcyc.packfile import pack_paths
from tamago.tests.nonfree_sampling import select_members, split_by_size

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


def _data_size(relpath):
    return os.path.getsize(pack_paths(os.path.join(NONFREE, relpath))[2])


# The image and voice packs have different indexes, so each kind is rebuilt
# whole at least once; the large event-image and voice packs are sampled.
whole, sampled = split_by_size(packs, _data_size, variant=lambda relpath: os.path.splitext(relpath)[1].lower())


def _contents(pack):
    result = []
    for info in pack.files:
        data = pack.read(info)
        assert len(data) == info.size, info.file_name
        result.append((info.raw_name, hashlib.sha256(data).digest()))
    return result


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


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not whole, reason="no nonfree Black Cyc samples available")
@pytest.mark.parametrize('relpath', whole)
def test_extract_and_recreate_roundtrip(relpath, tmp_path):
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


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not sampled, reason="no large nonfree Black Cyc samples available")
@pytest.mark.parametrize('relpath', sampled)
def test_reads_sampled_members(relpath):
    with PackFile(os.path.join(NONFREE, relpath)) as pack:
        assert pack.files
        for info in select_members(pack.files):
            assert len(pack.read(info)) == info.size, info.file_name
