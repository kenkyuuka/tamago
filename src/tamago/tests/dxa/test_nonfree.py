"""Roundtrip tests for real DxLib DXA archives in nonfree/.

The nonfree directory is gitignored: populate it manually with DXA archives,
whatever their extension (``.dxa``, ``.dat``, ``.med``...), to enable these
tests.  They skip when no samples are present.
"""

import hashlib
import os

import pytest

from tamago.formats.dxa import DXAFile, is_dxa

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect_samples():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        found.extend(os.path.relpath(os.path.join(root, f), NONFREE) for f in files if is_dxa(os.path.join(root, f)))
    return sorted(found)


samples = _collect_samples()
skip_no_samples = pytest.mark.skipif(not samples, reason="no nonfree DXA samples available")


def _digest(data):
    return hashlib.sha256(data).digest()


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', samples)
class TestNonfreeDXASamples:
    def test_reads_every_member(self, relpath):
        with DXAFile(os.path.join(NONFREE, relpath)) as dxa:
            assert dxa.files, f"{relpath} has no members"
            for info in dxa.files:
                assert len(dxa.read(info)) == info.size, info.file_name

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.dxa'

        with DXAFile(source) as dxa:
            original = {info.file_name: _digest(dxa.read(info)) for info in dxa.files}
            password, version = dxa.password, dxa.version
            dxa.extract_all(extracted)

        with DXAFile(rebuilt, mode='w', password=password) as dxa:
            dxa.write_all(extracted)

        with DXAFile(rebuilt) as dxa:
            assert dxa.password == password
            assert {info.file_name: _digest(dxa.read(info)) for info in dxa.files} == original
        # Same key and version, so the encrypted signature matches too.
        if version == 4:
            with open(source, 'rb') as a, open(rebuilt, 'rb') as b:
                assert a.read(4) == b.read(4)
