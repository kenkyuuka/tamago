"""Every format's extract_all must keep files inside the output directory."""

import pytest

from tamago.formats.advhd.arcfile import ARCFile
from tamago.formats.det.detfile import DETFile
from tamago.formats.gsp.gspfile import GSPFile
from tamago.formats.livemaker.vffile import VFFile
from tamago.formats.rpa.rpafile import RPAFile
from tamago.formats.xp3 import XP3File

FORMATS = [
    pytest.param(ARCFile, 'test.arc', id='arc'),
    pytest.param(DETFile, 'test.det', id='det'),
    pytest.param(GSPFile, 'test.gsp', id='gsp'),
    pytest.param(RPAFile, 'test.rpa', id='rpa'),
    pytest.param(VFFile, 'test.dat', id='vf'),
    pytest.param(XP3File, 'test.xp3', id='xp3'),
]

CREATE_KWARGS = {
    DETFile: {'mode': 'w', 'index_format': 'at2'},
    XP3File: {'mode': 'x'},
}


def _build(tmp_path, cls, filename, members):
    """Write an archive holding *members*, a dict of stored name to contents."""
    src = tmp_path / 'src'
    src.mkdir()
    archive = tmp_path / filename
    with cls(archive, **CREATE_KWARGS.get(cls, {'mode': 'w'})) as arc:
        for index, (name, data) in enumerate(members.items()):
            source = src / f'{index}.bin'
            source.write_bytes(data)
            arc.write(source, arcname=name)
    return archive


@pytest.mark.integration
@pytest.mark.parametrize(('cls', 'filename'), FORMATS)
class TestExtractContainment:
    @pytest.mark.parametrize(
        'name',
        ['../escape.txt', 'hall/../../escape.txt', '..\\escape.txt', '/etc/escape.txt', 'C:\\escape.txt'],
    )
    def test_unsafe_name_refused_before_writing(self, tmp_path, cls, filename, name):
        archive = _build(tmp_path, cls, filename, {'alice.txt': b'Curiouser', name: b'and curiouser'})
        out = tmp_path / 'deep' / 'out'
        with cls(archive) as arc, pytest.raises(ValueError, match='unsafe'):
            arc.extract_all(out)
        assert not out.exists()
        assert not (tmp_path / 'deep' / 'escape.txt').exists()

    def test_contained_dotdot_name_extracts(self, tmp_path, cls, filename):
        archive = _build(tmp_path, cls, filename, {'alice.txt.warning/../alice.txt': b'Curiouser'})
        out = tmp_path / 'out'
        with cls(archive) as arc:
            arc.extract_all(out)
        assert (out / 'alice.txt').read_bytes() == b'Curiouser'
        assert not (out / 'alice.txt.warning').exists()

    def test_unsafe_name_outside_glob_does_not_block(self, tmp_path, cls, filename):
        archive = _build(tmp_path, cls, filename, {'alice.txt': b'Curiouser', '../escape.bin': b'and curiouser'})
        out = tmp_path / 'out'
        with cls(archive) as arc:
            arc.extract_all(out, glob='*.txt')
        assert (out / 'alice.txt').read_bytes() == b'Curiouser'
        assert not (tmp_path / 'escape.bin').exists()

    def test_backslash_is_a_separator(self, tmp_path, cls, filename):
        archive = _build(tmp_path, cls, filename, {'hall\\door.txt': b'Drink me'})
        out = tmp_path / 'out'
        with cls(archive) as arc:
            arc.extract_all(out)
        assert (out / 'hall' / 'door.txt').read_bytes() == b'Drink me'
