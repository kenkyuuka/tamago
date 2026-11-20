"""Tests for Black Cyc detection and the CLI handler."""

import sys

import pytest

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.blackcyc.handler import BlackCycHandler
from tamago.tests.blackcyc.samples import GPK, GPK_CONTENTS, GTB, VPK, VPK_CONTENTS, VTB, write_pair


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['blackcyc'].load() is BlackCycHandler

    @pytest.mark.parametrize('which', [0, 1], ids=['index', 'data'])
    def test_detects_image_pack(self, tmp_path, which):
        paths = write_pair(tmp_path, 'bg0', GTB, GPK, '.gtb', '.gpk')
        assert detect_format(paths[which]) == 'blackcyc'

    @pytest.mark.parametrize('which', [0, 1], ids=['index', 'data'])
    def test_detects_voice_pack(self, tmp_path, which):
        paths = write_pair(tmp_path, 'AA', VTB, VPK, '.VTB', '.VPK')
        assert detect_format(paths[which]) == 'blackcyc'

    def test_data_file_alone_is_unknown(self, tmp_path):
        path = tmp_path / 'bg0.gpk'
        path.write_bytes(GPK)
        assert detect_format(path) is None


@pytest.mark.integration
class TestCommands:
    def test_top_level_extract_and_create(self, tmp_path, monkeypatch):
        _index, data = write_pair(tmp_path, 'bg0', GTB, GPK, '.gtb', '.gpk')
        out = tmp_path / 'out'
        _run(monkeypatch, 'extract', data, out)
        assert {p.name: p.read_bytes() for p in out.iterdir()} == GPK_CONTENTS
        (tmp_path / 'again').mkdir()
        _run(monkeypatch, 'create', '--format', 'blackcyc', out, tmp_path / 'again' / 'bg0.gpk')
        assert (tmp_path / 'again' / 'bg0.gtb').read_bytes() == GTB
        assert (tmp_path / 'again' / 'bg0.gpk').read_bytes() == GPK

    def test_format_subcommands(self, tmp_path, monkeypatch):
        index, _data = write_pair(tmp_path, 'aa', VTB, VPK, '.vtb', '.vpk')
        out = tmp_path / 'out'
        _run(monkeypatch, 'blackcyc', 'extract', index, out)
        assert {p.name: p.read_bytes() for p in out.iterdir()} == VPK_CONTENTS
        (tmp_path / 'again').mkdir()
        _run(monkeypatch, 'blackcyc', 'create', out, tmp_path / 'again' / 'aa.vtb')
        assert (tmp_path / 'again' / 'aa.vtb').read_bytes() == VTB
        assert (tmp_path / 'again' / 'aa.vpk').read_bytes() == VPK

    def test_glob(self, tmp_path, monkeypatch):
        index, _data = write_pair(tmp_path, 'bg0', GTB, GPK, '.gtb', '.gpk')
        out = tmp_path / 'out'
        _run(monkeypatch, 'extract', '--glob', 'tea*', index, out)
        assert sorted(p.name for p in out.iterdir()) == ['tea_party.dwq', 'teacup.dwq']

    def test_malformed_pack_reports_error(self, tmp_path, monkeypatch, capsys):
        index, _data = write_pair(tmp_path, 'bg0', GTB, GPK[:4], '.gtb', '.gpk')
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, 'blackcyc', 'extract', index, tmp_path / 'out')
        assert exc.value.code == 1
        assert 'outside' in capsys.readouterr().err

    def test_create_reports_bad_member(self, tmp_path, monkeypatch, capsys):
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'drink_me.txt').write_bytes(b'')
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, 'blackcyc', 'create', src, tmp_path / 'bg0.gpk')
        assert exc.value.code == 1
        assert 'drink_me.txt' in capsys.readouterr().err
