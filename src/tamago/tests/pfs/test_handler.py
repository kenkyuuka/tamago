"""Tests for PFS archive detection and the CLI handler."""

import sys

import pytest

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.pfs import MANIFEST_NAME, PFSFile
from tamago.formats.pfs.handler import PFSHandler
from tamago.tests.pfs.samples import CONTENTS, DATA_ORDER, EXAMPLE, MEMBERS, build_pfs

ARCHIVE = build_pfs(MEMBERS, 8, DATA_ORDER)


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['pfs'].load() is PFSHandler

    @pytest.mark.parametrize('version', [2, 6, 8])
    @pytest.mark.parametrize('name', ['root.pfs', 'root.pfs.000', 'Wonderland.pfs'])
    def test_detects_pfs(self, tmp_path, name, version):
        path = tmp_path / name
        path.write_bytes(build_pfs(MEMBERS, version))
        assert detect_format(path) == 'pfs'

    def test_rejects_text_starting_with_pf(self, tmp_path):
        path = tmp_path / 'notes.txt'
        path.write_bytes(b'pf8 was the Mock Turtle\'s favourite song')
        assert detect_format(path) is None

    def test_identify(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / 'root.pfs'
        path.write_bytes(ARCHIVE)
        _run(monkeypatch, 'identify', path)
        assert capsys.readouterr().out == f"{path}: pfs\n"


@pytest.mark.integration
class TestCommands:
    def test_top_level_extract_and_create(self, tmp_path, monkeypatch):
        archive = tmp_path / 'root.pfs'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'extract', archive, out)
        for name, data in CONTENTS.items():
            assert (out / name.replace('\\', '/')).read_bytes() == data
        assert (out / MANIFEST_NAME).is_file()
        _run(monkeypatch, 'create', '--format', 'pfs', out, tmp_path / 'again.pfs')
        assert (tmp_path / 'again.pfs').read_bytes() == ARCHIVE

    def test_extract_glob(self, tmp_path, monkeypatch):
        archive = tmp_path / 'root.pfs'
        archive.write_bytes(ARCHIVE)
        out = tmp_path / 'out'
        _run(monkeypatch, 'pfs', 'extract', '--glob', 'tea\\*', archive, out)
        assert sorted(p.name for p in out.rglob('*') if p.is_file()) == [MANIFEST_NAME, 'hatter.txt']

    @pytest.mark.parametrize('command', [['pfs', 'create'], ['create', '--format', 'pfs']])
    def test_create_version_and_encoding(self, tmp_path, monkeypatch, command):
        src = tmp_path / 'src'
        (src / 'tea').mkdir(parents=True)
        (src / 'tea' / 'hatter.txt').write_bytes(b'Have some wine.\n')
        out = tmp_path / 'root.pfs'
        _run(monkeypatch, *command, '--version', '2', '--encoding', 'utf-8', src, out)
        with PFSFile(out) as arc:
            assert arc.version == 2
            assert arc.read('tea\\hatter.txt') == b'Have some wine.\n'

    def test_create_defaults_to_version_8(self, tmp_path, monkeypatch):
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'alice.txt').write_bytes(b'Curiouser and curiouser!\n')
        out = tmp_path / 'root.pfs'
        _run(monkeypatch, 'pfs', 'create', src, out)
        assert out.read_bytes()[:3] == b'pf8'

    def test_create_refuses_compress(self, tmp_path, monkeypatch, capsys):
        src = tmp_path / 'src'
        src.mkdir()
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, 'pfs', 'create', '--compress', src, tmp_path / 'root.pfs')
        assert exc.value.code == 1
        assert 'uncompressed' in capsys.readouterr().err

    def test_extract_bad_archive(self, tmp_path, monkeypatch, capsys):
        archive = tmp_path / 'root.pfs'
        archive.write_bytes(EXAMPLE[:0x0B] + b'\xff\xff\x00\x00' + EXAMPLE[0x0F:])
        with pytest.raises(SystemExit) as exc:
            PFSHandler().cmd_extract(type('Args', (), {'input': archive, 'output': tmp_path / 'out'})())
        assert exc.value.code == 1
        assert 'Error:' in capsys.readouterr().err
