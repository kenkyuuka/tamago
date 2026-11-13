"""Tests for DXA detection and the CLI handler."""

import argparse

import pytest

from tamago.cli import detect_format, get_format_handlers
from tamago.formats.dxa import DXAFile, derive_key
from tamago.formats.dxa.handler import DXAHandler
from tamago.tests.dxa.test_dxafile import ALICE, HATTER, PLAIN_KEY, _build


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['dxa'].load() is DXAHandler

    @pytest.mark.parametrize('name', ['md_cv.med', 'voice.dxa', 'data.bin'])
    def test_detects_default_key_with_any_extension(self, tmp_path, name):
        path = tmp_path / name
        path.write_bytes(_build({'alice.txt': ALICE}))
        assert detect_format(path) == 'dxa'

    def test_detects_password_archive(self, tmp_path):
        path = tmp_path / 'data.dat'
        path.write_bytes(_build({'alice.txt': ALICE}, key=derive_key('Wonderland')))
        assert detect_format(path) == 'dxa'

    def test_detects_unencrypted(self, tmp_path):
        path = tmp_path / 'data.dat'
        path.write_bytes(_build({'alice.txt': ALICE}, key=PLAIN_KEY))
        assert detect_format(path) == 'dxa'


@pytest.mark.integration
class TestHandler:
    def test_extract(self, tmp_path):
        archive = tmp_path / 'md_se.med'
        archive.write_bytes(_build({'tea_party': {'hatter.txt': HATTER}}))
        out = tmp_path / 'out'
        DXAHandler().cmd_extract(argparse.Namespace(input=archive, output=out, glob=None))
        assert (out / 'tea_party' / 'hatter.txt').read_bytes() == HATTER

    def test_extract_reports_recovered_password(self, tmp_path, capsys):
        archive = tmp_path / 'data.dat'
        archive.write_bytes(_build({'alice.txt': ALICE}, key=derive_key('Wonderland')))
        DXAHandler().cmd_extract(argparse.Namespace(input=archive, output=tmp_path / 'out', glob=None))
        assert "'Wonderland'" in capsys.readouterr().err

    def test_extract_invalid_archive_exits(self, tmp_path, capsys):
        archive = tmp_path / 'tea.dxa'
        archive.write_bytes(b'Twinkle, twinkle, little bat!')
        with pytest.raises(SystemExit):
            DXAHandler().cmd_extract(argparse.Namespace(input=archive, output=tmp_path / 'out', glob=None))
        assert 'Error' in capsys.readouterr().err

    def test_create_with_password_and_compression(self, tmp_path):
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'queen.txt').write_bytes(b'Off with their heads! ' * 50)
        out = tmp_path / 'out.dxa'
        args = argparse.Namespace(input=src, output=out, glob=None, compress=True, password='Wonderland')
        DXAHandler().cmd_create(args)
        with DXAFile(out, password='Wonderland') as dxa:
            assert dxa.files[0].packed_size is not None
            assert dxa.read('queen.txt') == b'Off with their heads! ' * 50

    def test_top_level_create_args(self, tmp_path):
        # The top-level `tamago create` passes only common flags.
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'alice.txt').write_bytes(ALICE)
        out = tmp_path / 'out.dxa'
        DXAHandler().cmd_create(argparse.Namespace(input=src, output=out, glob=None, compress=None))
        with DXAFile(out) as dxa:
            assert dxa.password == ''
            assert dxa.read('alice.txt') == ALICE
