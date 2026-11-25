"""Roundtrip tests for real Silky's archives in nonfree/.

The nonfree directory is gitignored: populate it manually with ``.arc``
archives from Silky's games (e.g. Silky's Sakura's ``Script.arc``,
``data.arc``, ``layer.arc``) to enable these tests.  They skip when no samples
are present.
"""

import filecmp
import hashlib
import os

import pytest

from tamago.cli import detect_format
from tamago.formats.ai6win.akb import FLAG_RGB, INCREMENTAL_MAGIC, akb_to_png, decode_akb, png_to_akb, read_header
from tamago.formats.silky import ARCFile

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
@pytest.mark.skipif(not archives, reason="no nonfree Silky's samples available")
@pytest.mark.parametrize('relpath', archives)
class TestNonfreeArchives:
    def test_detected(self, relpath):
        assert detect_format(os.path.join(NONFREE, relpath)) == 'silky'

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
        # reproduces, so an unmodified archive rebuilds byte for byte.
        assert filecmp.cmp(source, rebuilt, shallow=False)


SAMPLED_IMAGES = 12
"""How many of each archive's images (the smallest stored) the image tests use: decoding every one takes minutes."""


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not archives, reason="no nonfree Silky's samples available")
@pytest.mark.parametrize('relpath', archives)
def test_images_convert_and_roundtrip(relpath, tmp_path):
    """Convert a sample of the archive's AKB images to PNG and back.

    The smallest images (picked from the index alone) include both bit
    depths and empty ones.  Each group's image with the fewest pixels must
    re-encode byte for byte; the others must decode at their stated size.
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
        assert arc.extract(infos[0], tmp_path / infos[0].file_name, convert_akb=True).endswith('.png')
    for _pixels, name, data in cheapest.values():
        assert png_to_akb(akb_to_png(data)) == data, name
