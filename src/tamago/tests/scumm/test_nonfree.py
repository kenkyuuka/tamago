"""Extraction tests for real Humongous SCUMM games in nonfree/.

The nonfree directory is gitignored: populate it manually with game folders
(``NAME.he0``, ``NAME.he1`` or ``NAME.(A)``, ``NAME.he2``, ``NAME.he4``) to enable
these tests. They skip when no samples are present.

SCUMM support is extraction only, so instead of a roundtrip these check that
every member of every file can be produced: every sound converts to WAV and
every image to PNG, and without conversion every member is a whole block.
"""

import io
import logging
import os
import struct

import pytest
from PIL import Image

from tamago.formats.scumm import KIND_ROOMS, HEFile, is_he_file

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _walk():
    if not os.path.isdir(NONFREE):
        return
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            yield os.path.join(root, f)


files = sorted(os.path.relpath(path, NONFREE) for path in _walk() if is_he_file(path))


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not files, reason="no nonfree SCUMM samples available")
@pytest.mark.parametrize('relpath', files)
class TestNonfreeFiles:
    def test_converts_every_member(self, relpath, caplog):
        he = HEFile(os.path.join(NONFREE, relpath))
        members = he.members()
        assert members, f"{relpath} has no members"
        with caplog.at_level(logging.WARNING, logger='tamago.formats.scumm'):
            for member in members:
                produced = he.produce(member)
                assert produced is not None, f"{member.file_name} was skipped"
                name, data = produced
                assert name == member.file_name, f"{member.file_name} was not converted"
                if name.endswith('.wav'):
                    assert data[:4] == b'RIFF' and data[8:12] == b'WAVE', name
                elif name.endswith('.png'):
                    with Image.open(io.BytesIO(data)) as im:
                        im.load()
                        assert im.width > 0 and im.height > 0, name
        assert not caplog.records, [r.getMessage() for r in caplog.records]

    def test_raw_members_are_whole_blocks(self, relpath):
        he = HEFile(os.path.join(NONFREE, relpath))
        for member in he.members(convert=False):
            data = member.produce()
            tag, size = struct.unpack('>4sI', data[:8])
            assert size == len(data), member.file_name
            assert tag.decode('ascii').lower().strip() in member.file_name, member.file_name

    def test_resources_are_named_from_the_index(self, relpath):
        he = HEFile(os.path.join(NONFREE, relpath))
        if he.kind != KIND_ROOMS or he.index is None:
            pytest.skip("not a room file with an index")
        names = he.namelist(convert=False)
        positional = [n for n in names if n.split('/')[-1].split('-')[0] in ('scrp', 'soun', 'digi', 'akos', 'awiz')]
        # A few orphan blocks that no directory lists are expected (Freddi Fish 4 has three sounds).
        assert len(positional) <= max(5, len(names) // 500), positional[:10]
