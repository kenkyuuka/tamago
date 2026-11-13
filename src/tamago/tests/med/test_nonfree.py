"""Roundtrip tests for real MD archives in nonfree/.

The nonfree directory is gitignored: populate it manually with MD ``.med``
files (``md_scr.med``, ``md_gra.med``, ``md_bgm.med``...) to enable these tests.
They skip when no samples are present.
"""

import hashlib
import os

import pytest

from tamago.formats.med import MEDFile, is_med_header

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect_samples():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            path = os.path.join(root, f)
            with open(path, 'rb') as fp:
                if is_med_header(fp.read(16)):
                    found.append(os.path.relpath(path, NONFREE))
    return sorted(found)


samples = _collect_samples()
skip_no_samples = pytest.mark.skipif(not samples, reason="no nonfree MD samples available")


def _digest(data):
    return hashlib.sha256(data).digest()


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', samples)
class TestNonfreeMEDSamples:
    def test_reads_every_member(self, relpath):
        with MEDFile(os.path.join(NONFREE, relpath)) as med:
            assert med.files, f"{relpath} has no members"
            if med.is_script_archive:
                assert med.keyword, f"{relpath}: script keyword not recovered"
            for info in med.files:
                assert len(med.read(info)) == info.size, info.file_name

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.med'

        with MEDFile(source) as med:
            original = {info.file_name: _digest(med.read(info)) for info in med.files}
            keyword, signature = med.keyword, med.signature
            med.extract_all(extracted)

        with MEDFile(rebuilt, mode='w', keyword=keyword) as med:
            med.write_all(extracted)

        with MEDFile(rebuilt, keyword=keyword) as med:
            assert med.signature[3] == signature[3]
            assert {info.file_name: _digest(med.read(info)) for info in med.files} == original

    def test_rebuild_in_original_order_matches_stored_bytes(self, relpath, tmp_path):
        """Rebuilt in the original order, every member's stored bytes and counter match exactly."""
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.med'

        with MEDFile(source) as med:
            keyword, signature = med.keyword, med.signature
            names = [info.file_name for info in med.files]
            med.extract_all(extracted)
        with MEDFile(source, decrypt=False) as med:
            stored = [(info.counter, _digest(med.read(info))) for info in med.files]

        with MEDFile(rebuilt, mode='w', keyword=keyword, signature=signature) as med:
            for name in names:
                med.write(extracted / name, arcname=name)

        with MEDFile(rebuilt, decrypt=False) as med:
            assert [info.file_name for info in med.files] == names
            assert [(info.counter, _digest(med.read(info))) for info in med.files] == stored
