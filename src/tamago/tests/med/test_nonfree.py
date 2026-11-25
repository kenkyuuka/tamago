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
from tamago.tests.nonfree_sampling import select_members, split_by_size, spread

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


def _digest(data):
    return hashlib.sha256(data).digest()


def _kind(relpath):
    """The archive's type digit, from its header (``0`` for scripts)."""
    with open(os.path.join(NONFREE, relpath), 'rb') as fp:
        return fp.read(4)[3:4]


# The smallest archive of each type is rebuilt whole; larger ones are sampled.
whole, sampled = split_by_size(samples, lambda relpath: os.path.getsize(os.path.join(NONFREE, relpath)), _kind)


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not whole, reason="no nonfree MD samples available")
@pytest.mark.parametrize('relpath', whole)
def test_extract_and_recreate_roundtrip(relpath, tmp_path):
    """Rebuilt with the archive's keyword, its contents survive; rebuilt in its order, so do its stored bytes."""
    source = os.path.join(NONFREE, relpath)
    extracted = tmp_path / 'extracted'

    with MEDFile(source) as med:
        assert med.files, f"{relpath} has no members"
        if med.is_script_archive:
            assert med.keyword, f"{relpath}: script keyword not recovered"
        original = {}
        for info in med.files:
            data = med.read(info)
            assert len(data) == info.size, info.file_name
            original[info.file_name] = _digest(data)
        keyword, signature = med.keyword, med.signature
        names = [info.file_name for info in med.files]
        med.extract_all(extracted)
    with MEDFile(source, decrypt=False) as med:
        stored = [(info.counter, _digest(med.read(info))) for info in med.files]

    rebuilt = tmp_path / 'rebuilt.med'
    with MEDFile(rebuilt, mode='w', keyword=keyword) as med:
        med.write_all(extracted)
    with MEDFile(rebuilt, keyword=keyword) as med:
        assert med.signature[3] == signature[3]
        assert {info.file_name: _digest(med.read(info)) for info in med.files} == original

    in_order = tmp_path / 'in_order.med'
    with MEDFile(in_order, mode='w', keyword=keyword, signature=signature) as med:
        for name in names:
            med.write(extracted / name, arcname=name)
    with MEDFile(in_order, decrypt=False) as med:
        assert [info.file_name for info in med.files] == names
        assert [(info.counter, _digest(med.read(info))) for info in med.files] == stored


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not sampled, reason="no large nonfree MD samples available")
@pytest.mark.parametrize('relpath', sampled)
def test_reads_sampled_members(relpath):
    with MEDFile(os.path.join(NONFREE, relpath)) as med:
        assert med.files, f"{relpath} has no members"
        for info in select_members(med.files):
            assert len(med.read(info)) == info.size, info.file_name


media_samples = [relpath for relpath in samples if _kind(relpath) != b'0']

# Members decoded per archive, spread evenly: a full image archive takes minutes.
PRS_SAMPLE = 16
WADY_SAMPLE = 2


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

    for info, data in spread(images, PRS_SAMPLE):
        width, height = struct.unpack_from('<HH', data, 12)
        img = decode_prs(data)
        assert img.size == (width, height), info.file_name
        assert img.mode == {3: 'RGB', 4: 'RGBA'}[data[3]], info.file_name

    for info, data in spread(tracks, WADY_SAMPLE):
        channels, rate, sample_count = struct.unpack_from('<HII', data, 6)
        audio = decode_wady(data)
        assert (audio.channels, audio.sample_rate) == (channels, rate), info.file_name
        assert len(audio.pcm) == 2 * sample_count, info.file_name
