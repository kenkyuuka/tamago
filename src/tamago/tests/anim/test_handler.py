"""Tests for ANIM detection and the CLI handler."""

import argparse
import sys

import pytest

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.anim import decrypt, encrypt, stored_key
from tamago.formats.anim.handler import AnimHandler
from tamago.tests.anim.samples import DRINK_ME, EAT_ME, LIP_SYNC, build_pck, eog, vorbis_ogg

OGG = vorbis_ogg(channels=2, granules=(0, 44100))
MEMBERS = [('b090001g.eog', eog(OGG, 44100 * 4)), ('w000001a.csv', LIP_SYNC)]
KEY = bytes.fromhex('0123456789abcdef0123456789abcdef')
PNG = b'\x89PNG\r\n\x1a\n' + DRINK_ME


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

    def test_enciphered_file_is_not_an_archive(self, tmp_path):
        path = tmp_path / 'alice_sce.dat'
        path.write_bytes(encrypt(DRINK_ME))
        assert detect_format(path) is None


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


@pytest.mark.integration
class TestCipherCommands:
    def test_decrypt_file(self, tmp_path, monkeypatch):
        source = tmp_path / 'BG010.gax'
        source.write_bytes(encrypt(PNG, KEY))
        _run(monkeypatch, 'anim', 'decrypt', source, tmp_path / 'BG010.png')
        assert (tmp_path / 'BG010.png').read_bytes() == PNG

    def test_encrypt_file_with_key(self, tmp_path, monkeypatch):
        source = tmp_path / 'alice_sce.dat'
        source.write_bytes(EAT_ME)
        _run(monkeypatch, 'anim', 'encrypt', source, tmp_path / 'out.dat', '--key', KEY.hex())
        assert (tmp_path / 'out.dat').read_bytes() == encrypt(EAT_ME, KEY)

    def test_encrypt_default_key(self, tmp_path, monkeypatch):
        source = tmp_path / 'alice_sce.dat'
        source.write_bytes(EAT_ME)
        _run(monkeypatch, 'anim', 'encrypt', source, tmp_path / 'out.dat')
        assert stored_key((tmp_path / 'out.dat').read_bytes()) == bytes(16)

    def test_bad_key(self, tmp_path, monkeypatch, capsys):
        source = tmp_path / 'alice_sce.dat'
        source.write_bytes(EAT_ME)
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'anim', 'encrypt', source, tmp_path / 'out.dat', '--key', 'abcd')
        assert '32 hex digits' in capsys.readouterr().err

    def test_decrypt_plain_file_exits(self, tmp_path, monkeypatch, capsys):
        source = tmp_path / 'BG010.png'
        source.write_bytes(PNG)
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'anim', 'decrypt', source, tmp_path / 'out.png')
        assert 'not enciphered' in capsys.readouterr().err

    def test_encrypt_enciphered_file_exits(self, tmp_path, monkeypatch, capsys):
        source = tmp_path / 'BG010.gax'
        source.write_bytes(encrypt(PNG))
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'anim', 'encrypt', source, tmp_path / 'out.gax')
        assert 'already enciphered' in capsys.readouterr().err

    def test_directory_roundtrip(self, tmp_path, monkeypatch):
        game = tmp_path / 'game'
        (game / 'cg').mkdir(parents=True)
        (game / 'cg' / 'BG010.gax').write_bytes(encrypt(PNG, KEY))
        (game / 'cg' / 'pSaveThumb.png').write_bytes(PNG)
        (game / 'alice_sce.dat').write_bytes(encrypt(EAT_ME, KEY))

        plain = tmp_path / 'plain'
        _run(monkeypatch, 'anim', 'decrypt', game, plain)
        assert sorted(str(p.relative_to(plain)) for p in plain.rglob('*') if p.is_file()) == [
            'alice_sce.dat',
            'cg/BG010.gax',
        ]
        assert (plain / 'cg' / 'BG010.gax').read_bytes() == PNG

        again = tmp_path / 'again'
        _run(monkeypatch, 'anim', 'encrypt', plain, again, '--key', KEY.hex())
        assert (again / 'cg' / 'BG010.gax').read_bytes() == (game / 'cg' / 'BG010.gax').read_bytes()
        assert decrypt((again / 'alice_sce.dat').read_bytes()) == EAT_ME
