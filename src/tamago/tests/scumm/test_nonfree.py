"""Extraction tests for real Humongous SCUMM games in nonfree/.

The nonfree directory is gitignored: populate it manually with game folders
(``NAME.he0``, ``NAME.he1`` or ``NAME.(A)``, ``NAME.he2``, ``NAME.he4``) to enable
these tests. They skip when no samples are present.

SCUMM support is extraction only, so instead of a roundtrip these check that
every member of every file can be produced: sounds convert to WAV and images
to PNG, and without conversion every member is a whole block.  Conversion is
checked on a sample of each kind of member (costume cels, object images,
sounds...), as a game has tens of thousands of costume cels.
"""

import io
import logging
import os
import re
import struct
from collections import defaultdict

import pytest
from PIL import Image

from tamago.formats.scumm import KIND_ROOMS, HEFile, is_he_file
from tamago.tests.nonfree_sampling import spread

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _walk():
    if not os.path.isdir(NONFREE):
        return
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            yield os.path.join(root, f)


files = sorted(os.path.relpath(path, NONFREE) for path in _walk() if is_he_file(path))

CONVERTED_PER_KIND = 64


def _kind(name):
    """A member's kind: the leading word of each part of its name, and its extension.

    ``room-001/costume-0012-body/cel-003.png`` is ``('room', 'costume', 'cel', '.png')``.
    """
    parts = name.split('/')
    return (*(re.match('[a-z]*', part).group() for part in parts), os.path.splitext(name)[1])


def _sample(members):
    """Up to CONVERTED_PER_KIND members of each kind, spread through the file."""
    kinds = defaultdict(list)
    for member in members:
        kinds[_kind(member.file_name)].append(member)
    return [member for kind in kinds.values() for member in spread(kind, CONVERTED_PER_KIND)]


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not files, reason="no nonfree SCUMM samples available")
@pytest.mark.parametrize('relpath', files)
class TestNonfreeFiles:
    def test_converts_sampled_members(self, relpath, caplog):
        he = HEFile(os.path.join(NONFREE, relpath))
        members = he.members()
        assert members, f"{relpath} has no members"
        with caplog.at_level(logging.WARNING, logger='tamago.formats.scumm'):
            for member in _sample(members):
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
