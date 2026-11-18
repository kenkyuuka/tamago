"""Tests for BlackRainbow detection and the CLI handler."""

import sys

import pytest
from PIL import Image

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.blackrainbow import MANIFEST_NAME, DATFile, decode_bmd, is_bmd
from tamago.formats.blackrainbow.handler import BlackRainbowHandler
from tamago.tests.blackrainbow.samples import ALICE, SPRITE_BGRA, STRIP_BGRA, build_bmd, build_dat, ogg

SPRITE = build_bmd(2, 2, SPRITE_BGRA, alpha=1)
STRIP = build_bmd(3, 1, STRIP_BGRA, alpha=0)
ARCHIVE = build_dat(2, {0: (b'cheshire.bmd', SPRITE), 2: (b'', STRIP)}, slots=4)


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['blackrainbow'].load() is BlackRainbowHandler

    @pytest.mark.parametrize('name', ['bg.dat', 'm01_01.pak'])
    def test_detects_by_structure(self, tmp_path, name):
        path = tmp_path / name
        path.write_bytes(ARCHIVE)
        assert detect_format(path) == 'blackrainbow'

    def test_ignores_other_dat_files(self, tmp_path):
        path = tmp_path / 'config.dat'
        path.write_bytes(bytes(16) + ALICE)
        assert detect_format(path) is None


@pytest.mark.integration
class TestArchives:
    def test_top_level_extract_and_create(self, tmp_path, monkeypatch):
        archive = tmp_path / 'image.dat'
        archive.write_bytes(ARCHIVE)
        _run(monkeypatch, 'extract', archive, tmp_path / 'out')
        assert (tmp_path / 'out' / 'cheshire.bmd').read_bytes() == SPRITE
        assert (tmp_path / 'out' / MANIFEST_NAME).is_file()
        _run(monkeypatch, 'create', '--format', 'blackrainbow', tmp_path / 'out', tmp_path / 'again.dat')
        assert (tmp_path / 'again.dat').read_bytes() == ARCHIVE

    def test_extract_convert_bmd(self, tmp_path, monkeypatch):
        archive = tmp_path / 'image.dat'
        archive.write_bytes(ARCHIVE)
        _run(monkeypatch, 'blackrainbow', 'extract', '--convert-bmd', archive, tmp_path / 'out')
        with Image.open(tmp_path / 'out' / '002.png') as image:
            assert image.mode == 'RGB'
        _run(monkeypatch, 'blackrainbow', 'create', tmp_path / 'out', tmp_path / 'again.dat')
        with DATFile(tmp_path / 'again.dat') as dat:
            assert [i.slot for i in dat.files] == [0, 2]
            assert decode_bmd(dat.read(dat.files[1])).tobytes() == decode_bmd(STRIP).tobytes()

    def test_create_with_parameters(self, tmp_path, monkeypatch):
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'init.spt').write_bytes(ALICE)
        out = tmp_path / 'sj_spt.dat'
        _run(monkeypatch, 'blackrainbow', 'create', '--kind', 'script', '--game-id', '15432', '--slots', '3', src, out)
        assert out.read_bytes() == build_dat(5, {0: (b'init.spt', ALICE)}, slots=3, game_id=0x15432)

    def test_top_level_create_with_parameters(self, tmp_path, monkeypatch):
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'se.ogg').write_bytes(ogg(ALICE))
        out = tmp_path / 'se.dat'
        _run(monkeypatch, 'create', '--format', 'blackrainbow', '--slots', '2', src, out)
        assert out.read_bytes() == build_dat(4, {0: (b'se.ogg', ogg(ALICE))}, slots=2)

    @pytest.mark.parametrize('value', ['xyz', '123456789'])
    def test_bad_game_id(self, tmp_path, monkeypatch, value):
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'blackrainbow', 'create', '--game-id', value, tmp_path, tmp_path / 'x.dat')

    def test_create_error_exits(self, tmp_path, monkeypatch, capsys):
        src = tmp_path / 'src'
        src.mkdir()
        (src / ('x' * 40 + '.bmd')).write_bytes(SPRITE)
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, 'blackrainbow', 'create', src, tmp_path / 'x.dat')
        assert e.value.code == 1
        assert 'Error' in capsys.readouterr().err

    def test_extract_not_an_archive_exits(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / 'image.dat'
        path.write_bytes(ALICE)
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, 'blackrainbow', 'extract', path, tmp_path / 'out')
        assert e.value.code == 1
        assert 'ADVDX' in capsys.readouterr().err


@pytest.mark.integration
class TestImageCommands:
    def test_decode_and_encode_directory(self, tmp_path, monkeypatch):
        src = tmp_path / 'bmd'
        src.mkdir()
        (src / 'sprite.bmd').write_bytes(SPRITE)
        (src / 'notes.txt').write_bytes(ALICE)
        _run(monkeypatch, 'blackrainbow', 'decode-bmd', src, tmp_path / 'png')
        assert (tmp_path / 'png' / 'notes.txt').read_bytes() == ALICE
        with Image.open(tmp_path / 'png' / 'sprite.png') as image:
            assert image.format == 'PNG'

        _run(monkeypatch, 'blackrainbow', 'encode-bmd', tmp_path / 'png', tmp_path / 'again')
        again = (tmp_path / 'again' / 'sprite.bmd').read_bytes()
        assert is_bmd(again)
        assert decode_bmd(again).tobytes() == decode_bmd(SPRITE).tobytes()
        assert (tmp_path / 'again' / 'notes.txt').read_bytes() == ALICE

    def test_single_files(self, tmp_path, monkeypatch):
        (tmp_path / 'strip.bmd').write_bytes(STRIP)
        _run(monkeypatch, 'blackrainbow', 'decode-bmd', tmp_path / 'strip.bmd', tmp_path / 'strip.png')
        _run(monkeypatch, 'blackrainbow', 'encode-bmd', tmp_path / 'strip.png', tmp_path / 'again.bmd')
        assert decode_bmd((tmp_path / 'again.bmd').read_bytes()).tobytes() == decode_bmd(STRIP).tobytes()

    def test_decode_single_non_bmd_exits(self, tmp_path, monkeypatch, capsys):
        (tmp_path / 'a.bmd').write_bytes(ALICE)
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'blackrainbow', 'decode-bmd', tmp_path / 'a.bmd', tmp_path / 'a.png')
        assert 'not a _BMD image' in capsys.readouterr().err
