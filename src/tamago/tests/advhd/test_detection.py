"""AdvHD .arc archives are recognised by their index, not by the extension alone."""

import struct
import sys

import pytest

from tamago.cli import detect_format, main
from tamago.formats.advhd.arcfile import ARCFile, is_advhd_arc


def _advhd_archive(tmp_path, name='Bgm.arc'):
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'alice.ogg').write_bytes(b'OggS Down the rabbit-hole')
    (src / 'hatter.ws2').write_bytes(b'Why is a raven like a writing-desk?')
    path = tmp_path / name
    with ARCFile(path, mode='w') as arc:
        arc.write_all(src)
    return path


# Files from other engines that share the .arc extension (see issue #28).
_OTHER_ARCS = {
    # Older AdvHD (v1): an extension type table and ASCII names.
    'advhd-v1': struct.pack('<I', 1) + b'OGG\0' + struct.pack('<II', 1, 0x10) + b'alice\0\0\0' + bytes(32),
    # elf AI6WIN: a count, then fixed-width obfuscated names.
    'ai6win': struct.pack('<I', 0xDA) + bytes([0x6B, 0x75, 0x71, 0x6A, 0x6B]) + bytes(0x300),
    # Silky's: an index size, then length-prefixed names.
    'silky': struct.pack('<I', 0x1427) + bytes([9]) + b'alice.ogg' + bytes(0x200),
    'link6': b'LINK6\0\0\0' + bytes(0x200),
    'empty': b'',
    'zeros': bytes(64),
}


@pytest.mark.unit
class TestIsAdvhdArc:
    def test_recognises_written_archive(self, tmp_path):
        assert is_advhd_arc(_advhd_archive(tmp_path))

    @pytest.mark.parametrize('data', _OTHER_ARCS.values(), ids=_OTHER_ARCS.keys())
    def test_rejects_other_engines(self, tmp_path, data):
        path = tmp_path / 'other.arc'
        path.write_bytes(data)
        assert not is_advhd_arc(path)

    def test_rejects_member_past_end_of_file(self, tmp_path):
        path = _advhd_archive(tmp_path)
        path.write_bytes(path.read_bytes()[:-1])
        assert not is_advhd_arc(path)

    def test_rejects_index_size_mismatch(self, tmp_path):
        path = _advhd_archive(tmp_path)
        data = bytearray(path.read_bytes())
        struct.pack_into('<I', data, 4, struct.unpack_from('<I', data, 4)[0] + 2)
        path.write_bytes(data)
        assert not is_advhd_arc(path)

    def test_missing_file(self, tmp_path):
        assert not is_advhd_arc(tmp_path / 'missing.arc')


@pytest.mark.unit
class TestDetectFormat:
    def test_detects_advhd(self, tmp_path):
        assert detect_format(_advhd_archive(tmp_path)) == 'advhd'

    def test_detects_upper_case_extension(self, tmp_path):
        assert detect_format(_advhd_archive(tmp_path, 'Bgm.ARC')) == 'advhd'

    @pytest.mark.parametrize('data', _OTHER_ARCS.values(), ids=_OTHER_ARCS.keys())
    def test_other_arc_files_are_unknown(self, tmp_path, data):
        path = tmp_path / 'other.arc'
        path.write_bytes(data)
        assert detect_format(path) is None


@pytest.mark.integration
def test_extract_of_unknown_arc_reports_format(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'other.arc'
    path.write_bytes(_OTHER_ARCS['silky'])
    monkeypatch.setattr(sys, 'argv', ['tamago', 'extract', str(path), str(tmp_path / 'out')])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert 'cannot detect format' in capsys.readouterr().err
