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
from tamago.formats.ai6win.akb import (
    FLAG_RGB,
    INCREMENTAL_MAGIC,
    akb_to_png,
    decode_akb,
    png_to_akb,
    read_header,
)
from tamago.tests.nonfree_sampling import select_members, split_by_size

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
# Only the small archives (scripts and data) are rebuilt whole: they hold the
# compressed scripts that pin the LZSS encoder, and the media archives differ
# only in size (apart from Movie.arc, whose compressed members are sampled).
whole, sampled = split_by_size(archives, lambda relpath: os.path.getsize(os.path.join(NONFREE, relpath)))


def _contents(arc):
    result = []
    for info in arc.files:
        data = arc.read(info)
        assert len(data) == info.unpacked_size, info.file_name
        result.append((info.raw_name, hashlib.sha256(data).digest()))
    return result


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not archives, reason="no nonfree AI6WIN samples available")
@pytest.mark.parametrize('relpath', archives)
class TestNonfreeArchives:
    def test_detected(self, relpath):
        assert detect_format(os.path.join(NONFREE, relpath)) == 'ai6win'


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not whole, reason="no nonfree AI6WIN samples available")
@pytest.mark.parametrize('relpath', whole)
def test_extract_and_recreate_roundtrip(relpath, tmp_path):
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


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not sampled, reason="no large nonfree samples available")
@pytest.mark.parametrize('relpath', sampled)
def test_reads_sampled_members(relpath):
    with ARCFile(os.path.join(NONFREE, relpath)) as arc:
        assert arc.files
        for info in select_members(arc.files):
            assert len(arc.read(info)) == info.unpacked_size, info.file_name


SAMPLED_IMAGES = 12
"""How many of each archive's images (the smallest stored) the image tests use: decoding every one takes minutes."""


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not archives, reason="no nonfree AI6WIN samples available")
@pytest.mark.parametrize('relpath', archives)
def test_images_decode_and_roundtrip(relpath):
    """Decode a sample of the archive's AKB images, and re-encode the cheapest of each bit depth.

    Picking by stored size reads nothing but the index; the smallest images
    include the empty ones and both bit depths.  Re-encoding is slow in pure
    Python, so only the image with the fewest pixels in each group is
    checked to come back byte for byte.
    """
    with ARCFile(os.path.join(NONFREE, relpath)) as arc:
        infos = sorted((i for i in arc.files if i.file_name.lower().endswith('.akb')), key=lambda i: i.size)
        if not infos:
            pytest.skip("no AKB images in this archive")
        cheapest: dict = {}
        for info in infos[:SAMPLED_IMAGES]:
            data = arc.read(info)
            header = read_header(data)
            if header.magic == INCREMENTAL_MAGIC:
                continue
            assert decode_akb(data).size == (header.width, header.height), info.file_name
            pixels = (header.right - header.left) * (header.bottom - header.top)
            group = (bool(header.flags & FLAG_RGB), pixels == 0)
            if group not in cheapest or pixels < cheapest[group][0]:
                cheapest[group] = (pixels, info.file_name, data)
    for _pixels, name, data in cheapest.values():
        assert png_to_akb(akb_to_png(data)) == data, name
