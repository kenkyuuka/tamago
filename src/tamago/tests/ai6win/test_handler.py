"""Tests for AI6WIN detection and the CLI handler."""

import sys

import pytest

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.ai6win import MANIFEST_NAME, ARCFile
from tamago.formats.ai6win.handler import AI6WINHandler
from tamago.tests.ai6win.samples import ARCHIVE, CONTENTS


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['ai6win'].load() is AI6WINHandler

    @pytest.mark.parametrize('name', ['mes.arc', 'Voice.ARC'])
    def test_detects_arc(self, tmp_path, name):
        path = tmp_path / name
        path.write_bytes(ARCHIVE)
        assert detect_format(path) == 'ai6win'

    def test_requires_arc_extension(self, tmp_path):
        path = tmp_path / 'mes.dat'
        path.write_bytes(ARCHIVE)
        assert detect_format(path) is None


@pytest.mark.integration
class TestCommands:
    def test_top_level_extract_and_create(self, tmp_path, monkeypatch):
        archive = tmp_path / 'mes.arc'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'extract', archive, out)
        for name, data in CONTENTS.items():
            assert (out / name).read_bytes() == data
        assert (out / MANIFEST_NAME).is_file()
        _run(monkeypatch, 'create', '--format', 'ai6win', out, tmp_path / 'again.arc')
        assert (tmp_path / 'again.arc').read_bytes() == ARCHIVE

    @pytest.mark.parametrize(('flag', 'expected'), [('--compress', True), ('--no-compress', False)])
    def test_create_compress_flags(self, tmp_path, monkeypatch, flag, expected):
        archive = tmp_path / 'mes.arc'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'ai6win', 'extract', archive, out)
        _run(monkeypatch, 'ai6win', 'create', flag, out, tmp_path / 'again.arc')
        with ARCFile(tmp_path / 'again.arc') as arc:
            assert all(info.compressed == expected for info in arc.files)
            assert {name: arc.read(name) for name in arc.namelist()} == CONTENTS

    def test_glob(self, tmp_path, monkeypatch):
        archive = tmp_path / 'mes.arc'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'extract', '--glob', '*.mes', archive, out)
        assert sorted(p.name for p in out.iterdir()) == [MANIFEST_NAME, 'start.mes']

    def test_malformed_archive_reports_error(self, tmp_path, monkeypatch, capsys):
        archive = tmp_path / 'mes.arc'
        archive.write_bytes(ARCHIVE[:-1])
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, 'ai6win', 'extract', archive, tmp_path / 'out')
        assert exc.value.code == 1
        assert 'outside' in capsys.readouterr().err
