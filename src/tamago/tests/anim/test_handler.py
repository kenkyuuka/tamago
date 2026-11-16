"""Tests for ANIM detection and the CLI handler."""

import argparse
import sys

import pytest

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.anim.handler import AnimHandler
from tamago.tests.anim.samples import LIP_SYNC, build_pck, eog, vorbis_ogg

OGG = vorbis_ogg(channels=2, granules=(0, 44100))
MEMBERS = [('b090001g.eog', eog(OGG, 44100 * 4)), ('w000001a.csv', LIP_SYNC)]


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['anim'].load() is AnimHandler

    @pytest.mark.parametrize('name', ['alice_wave.pck', 'psbpack.dat'])
    def test_detects_by_structure(self, tmp_path, name):
        path = tmp_path / name
        path.write_bytes(build_pck(MEMBERS))
        assert detect_format(path) == 'anim'


@pytest.mark.integration
class TestPacks:
    def test_extract_unwraps_then_create_rewraps(self, tmp_path):
        archive = tmp_path / 'alice_wave.pck'
        archive.write_bytes(build_pck(MEMBERS))
        out = tmp_path / 'out'
        AnimHandler().cmd_extract(argparse.Namespace(input=archive, output=out, glob=None))
        assert (out / 'b090001g.ogg').read_bytes() == OGG
        rebuilt = tmp_path / 'rebuilt.pck'
        AnimHandler().cmd_create(argparse.Namespace(input=out, output=rebuilt, glob=None))
        assert rebuilt.read_bytes() == archive.read_bytes()

    def test_cli_no_convert_and_no_wrap(self, tmp_path, monkeypatch):
        archive = tmp_path / 'alice_wave.pck'
        archive.write_bytes(build_pck(MEMBERS))
        out = tmp_path / 'out'
        _run(monkeypatch, 'anim', 'extract', archive, out, '--no-convert-eog')
        assert (out / 'b090001g.eog').read_bytes() == MEMBERS[0][1]
        rebuilt = tmp_path / 'rebuilt.pck'
        _run(monkeypatch, 'create', '--format', 'anim', out, rebuilt, '--no-wrap-ogg')
        assert rebuilt.read_bytes() == archive.read_bytes()

    def test_top_level_extract_detects(self, tmp_path, monkeypatch):
        archive = tmp_path / 'psbpack.dat'
        archive.write_bytes(build_pck(MEMBERS))
        _run(monkeypatch, 'extract', archive, tmp_path / 'out')
        assert (tmp_path / 'out' / 'b090001g.ogg').read_bytes() == OGG

    def test_extract_not_a_pack_exits(self, tmp_path, capsys):
        archive = tmp_path / 'tarts.pck'
        archive.write_bytes(b'\xff' * 32)
        with pytest.raises(SystemExit):
            AnimHandler().cmd_extract(argparse.Namespace(input=archive, output=tmp_path / 'out', glob=None))
        assert 'not an ANIM pack' in capsys.readouterr().err
