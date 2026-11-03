"""Roundtrip tests for real RPA game archives in nonfree/.

The nonfree directory is gitignored: populate it manually with .rpa files to
enable these tests. They skip when no samples are present.
"""

import hashlib
import os

import pytest

from tamago.formats.rpa import RPAFile

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect_samples():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        found.extend(os.path.relpath(os.path.join(root, f), NONFREE) for f in files if f.lower().endswith('.rpa'))
    return sorted(found)


samples = _collect_samples()
skip_no_samples = pytest.mark.skipif(not samples, reason="no nonfree RPA samples available")


def _digest(data):
    return hashlib.sha256(data).digest()


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', samples)
class TestNonfreeRPASamples:
    def test_reads_every_member(self, relpath):
        with RPAFile(os.path.join(NONFREE, relpath)) as rpa:
            assert rpa.files, f"{relpath} has no members"
            for member in rpa.files:
                assert len(rpa.read(member)) == member.size, member.file_name

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.rpa'

        with RPAFile(source) as rpa:
            original = {member.file_name: _digest(rpa.read(member)) for member in rpa.files}
            rpa.extract_all(extracted)

        with RPAFile(rebuilt, mode='w') as rpa:
            rpa.write_all(extracted)

        with RPAFile(rebuilt) as rpa:
            assert {member.file_name: _digest(rpa.read(member)) for member in rpa.files} == original
