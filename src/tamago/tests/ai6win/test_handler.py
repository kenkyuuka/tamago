"""Tests for AI6WIN detection and the CLI handler."""

import sys

import pytest
from PIL import Image

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.ai6win import MANIFEST_NAME, ARCFile
from tamago.formats.ai6win.akb import akb_to_png, decode_akb, encode_akb
from tamago.formats.ai6win.handler import AI6WINHandler
from tamago.tests.ai6win.samples import AKB_EMPTY, AKB_RGB_CROPPED, AKB_RGBA, ARCHIVE, CONTENTS, build_arc


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


@pytest.mark.integration
class TestAKBCommands:
    def test_extract_convert_and_create(self, tmp_path, monkeypatch):
        akb = encode_akb(decode_akb(AKB_RGBA))
        archive = tmp_path / 'Layer.arc'
        archive.write_bytes(build_arc([(b'alice.akb', akb, len(akb))]))
        out = tmp_path / 'out'
        _run(monkeypatch, 'ai6win', 'extract', '--convert-akb', archive, out)
        assert sorted(p.name for p in out.iterdir()) == [MANIFEST_NAME, 'alice.png']
        _run(monkeypatch, 'ai6win', 'create', out, tmp_path / 'again.arc')
        assert (tmp_path / 'again.arc').read_bytes() == archive.read_bytes()

    def test_decode_and_encode_file(self, tmp_path, monkeypatch):
        akb = encode_akb(decode_akb(AKB_RGB_CROPPED), b'\xff\xff\xff\xff', (1, 1, 4, 3))
        (tmp_path / 'alice.akb').write_bytes(akb)
        _run(monkeypatch, 'ai6win', 'decode-akb', tmp_path / 'alice.akb', tmp_path / 'alice.png')
        with Image.open(tmp_path / 'alice.png') as image:
            assert image.size == (5, 4)
        _run(monkeypatch, 'ai6win', 'encode-akb', tmp_path / 'alice.png', tmp_path / 'again.akb')
        assert (tmp_path / 'again.akb').read_bytes() == akb

    def test_decode_directory(self, tmp_path, monkeypatch):
        src = tmp_path / 'src'
        (src / 'ev').mkdir(parents=True)
        (src / 'ev' / 'alice.akb').write_bytes(AKB_RGBA)
        (src / 'kuro.AKB').write_bytes(AKB_EMPTY)
        (src / 'tea_party.akb').write_bytes(b'AKB+' + AKB_RGBA[4:])
        (src / 'start.mes').write_bytes(b'Curiouser and curiouser!')
        _run(monkeypatch, 'ai6win', 'decode-akb', src, tmp_path / 'png')
        files = sorted(p.relative_to(tmp_path / 'png').as_posix() for p in (tmp_path / 'png').rglob('*.*'))
        assert files == ['ev/alice.png', 'kuro.png', 'start.mes', 'tea_party.akb']

    def test_encode_directory(self, tmp_path, monkeypatch):
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'alice.png').write_bytes(akb_to_png(AKB_RGBA))
        (src / 'start.mes').write_bytes(b'Curiouser and curiouser!')
        _run(monkeypatch, 'ai6win', 'encode-akb', src, tmp_path / 'akb')
        assert decode_akb((tmp_path / 'akb' / 'alice.akb').read_bytes()).tobytes() == decode_akb(AKB_RGBA).tobytes()
        assert (tmp_path / 'akb' / 'start.mes').is_file()

    @pytest.mark.parametrize(('command', 'data'), [('decode-akb', b'AKB+' + AKB_RGBA[4:]), ('encode-akb', AKB_RGBA)])
    def test_wrong_input_file(self, tmp_path, monkeypatch, capsys, command, data):
        (tmp_path / 'in').write_bytes(data)
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, 'ai6win', command, tmp_path / 'in', tmp_path / 'out')
        assert exc.value.code == 1
        assert 'is not a' in capsys.readouterr().err

    def test_corrupt_image_reports_error(self, tmp_path, monkeypatch, capsys):
        (tmp_path / 'in.akb').write_bytes(AKB_RGBA[:-3])
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'ai6win', 'decode-akb', tmp_path / 'in.akb', tmp_path / 'out.png')
        assert 'in.akb' in capsys.readouterr().err
