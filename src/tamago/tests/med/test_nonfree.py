"""Roundtrip tests for real MD archives in nonfree/.

The nonfree directory is gitignored: populate it manually with MD ``.med``
files (``md_scr.med``, ``md_gra.med``, ``md_bgm.med``...) to enable these tests.
They skip when no samples are present.
"""

import hashlib
import os
import struct

import pytest

from tamago.formats.med import MEDFile, is_med_header
from tamago.formats.med.prs import decode_prs, is_prs
from tamago.formats.med.wady import decode_wady, is_wady

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


def _media_samples():
    """Samples that are image or audio archives, by the type digit in their header."""
    found = []
    for relpath in samples:
        with open(os.path.join(NONFREE, relpath), 'rb') as fp:
            if fp.read(4)[3:4] != b'0':
                found.append(relpath)
    return found


media_samples = _media_samples()

# Members decoded per archive, spread evenly: a full image archive takes minutes.
PRS_SAMPLE = 16
WADY_SAMPLE = 2


def _spread(items, count):
    if len(items) <= count:
        return items
    step = len(items) / count
    return [items[int(i * step)] for i in range(count)]


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not media_samples, reason="no nonfree MD image or audio samples available")
@pytest.mark.parametrize('relpath', media_samples)
def test_decodes_media_members(relpath):
    """PRS images and WADY audio decode to the size and format their headers give."""
    with MEDFile(os.path.join(NONFREE, relpath)) as med:
        members = [(info, med.read(info)) for info in med.files]
    images = [(info, data) for info, data in members if is_prs(data)]
    tracks = [(info, data) for info, data in members if is_wady(data)]
    assert images or tracks, f'{relpath} holds neither PRS images nor WADY audio'

    for info, data in _spread(images, PRS_SAMPLE):
        width, height = struct.unpack_from('<HH', data, 12)
        img = decode_prs(data)
        assert img.size == (width, height), info.file_name
        assert img.mode == {3: 'RGB', 4: 'RGBA'}[data[3]], info.file_name

    for info, data in _spread(tracks, WADY_SAMPLE):
        channels, rate, sample_count = struct.unpack_from('<HII', data, 6)
        audio = decode_wady(data)
        assert (audio.channels, audio.sample_rate) == (channels, rate), info.file_name
        assert len(audio.pcm) == 2 * sample_count, info.file_name
