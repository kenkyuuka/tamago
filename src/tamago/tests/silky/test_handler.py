"""Tests for Silky's archive detection and the CLI handler."""

import sys

import pytest

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.ai6win.akb import decode_akb, encode_akb
from tamago.formats.silky import MANIFEST_NAME, ARCFile
from tamago.formats.silky.handler import SilkyHandler
from tamago.tests.ai6win.samples import AKB_RGBA
from tamago.tests.ai6win.samples import ARCHIVE as AI6WIN_ARCHIVE
from tamago.tests.silky.samples import ARCHIVE, CONTENTS, build_arc


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['silky'].load() is SilkyHandler

    @pytest.mark.parametrize('name', ['Script.arc', 'VOICE.ARC'])
    def test_detects_arc(self, tmp_path, name):
        path = tmp_path / name
        path.write_bytes(ARCHIVE)
        assert detect_format(path) == 'silky'

    def test_requires_arc_extension(self, tmp_path):
        path = tmp_path / 'Script.dat'
        path.write_bytes(ARCHIVE)
        assert detect_format(path) is None

    def test_ai6win_archive_still_ai6win(self, tmp_path):
        path = tmp_path / 'mes.arc'
        path.write_bytes(AI6WIN_ARCHIVE)
        assert detect_format(path) == 'ai6win'

    def test_identify(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / 'Script.arc'
        path.write_bytes(ARCHIVE)
        _run(monkeypatch, 'identify', path)
        assert capsys.readouterr().out == f"{path}: silky\n"


@pytest.mark.integration
class TestCommands:
    def test_top_level_extract_and_create(self, tmp_path, monkeypatch):
        archive = tmp_path / 'Script.arc'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'extract', archive, out)
        for name, data in CONTENTS.items():
            assert (out / name).read_bytes() == data
        assert (out / MANIFEST_NAME).is_file()
        _run(monkeypatch, 'create', '--format', 'silky', out, tmp_path / 'again.arc')
        assert (tmp_path / 'again.arc').read_bytes() == ARCHIVE

    @pytest.mark.parametrize(('flag', 'expected'), [('--compress', True), ('--no-compress', False)])
    def test_create_compress_flags(self, tmp_path, monkeypatch, flag, expected):
        archive = tmp_path / 'Script.arc'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'silky', 'extract', archive, out)
        _run(monkeypatch, 'silky', 'create', flag, out, tmp_path / 'again.arc')
        with ARCFile(tmp_path / 'again.arc') as arc:
            assert all(info.compressed == expected for info in arc.files)
            assert {name: arc.read(name) for name in arc.namelist()} == CONTENTS

    def test_extract_glob(self, tmp_path, monkeypatch):
        archive = tmp_path / 'Script.arc'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'silky', 'extract', '--glob', '*.MES', archive, out)
        assert sorted(p.name for p in out.iterdir()) == ['ALICE.MES', MANIFEST_NAME]

    def test_extract_not_an_archive(self, tmp_path, monkeypatch, capsys):
        archive = tmp_path / 'Script.arc'
        archive.write_bytes(b'LINK6\0\0\0' + bytes(64))
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, 'silky', 'extract', archive, tmp_path / 'out')
        assert exc.value.code == 1
        assert 'Error' in capsys.readouterr().err

    def test_create_with_bad_manifest(self, tmp_path, monkeypatch, capsys):
        src = tmp_path / 'src'
        src.mkdir()
        (src / MANIFEST_NAME).write_text('{"format": "ai6win", "members": []}')
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, 'silky', 'create', src, tmp_path / 'new.arc')
        assert exc.value.code == 1
        assert 'manifest' in capsys.readouterr().err


@pytest.mark.integration
class TestAKBCommands:
    def test_extract_convert_and_create(self, tmp_path, monkeypatch):
        akb = encode_akb(decode_akb(AKB_RGBA))
        archive = tmp_path / 'layer.arc'
        archive.write_bytes(build_arc([(b'ALICE.AKB', akb, len(akb))]))
        out = tmp_path / 'out'
        _run(monkeypatch, 'silky', 'extract', '--convert-akb', archive, out)
        assert sorted(p.name for p in out.iterdir()) == ['ALICE.png', MANIFEST_NAME]
        _run(monkeypatch, 'create', '--format', 'silky', out, tmp_path / 'again.arc')
        assert (tmp_path / 'again.arc').read_bytes() == archive.read_bytes()
