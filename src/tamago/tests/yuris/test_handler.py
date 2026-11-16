"""Tests for YU-RIS detection and the CLI handler."""

import sys

import pytest
from PIL import Image

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.yuris import YPFFile, decode_ycg, is_ycg
from tamago.formats.yuris.handler import YurisHandler
from tamago.formats.yuris.ypf import archive_params
from tamago.tests.yuris.samples import ALICE, CHESHIRE, TABLE_D, build_ycg, build_ypf, ystb_encrypt, ystb_plain

YCG = build_ycg(2, 2, bytes(range(16)))
MEMBERS = [
    ('ysbin\\yst00000.ybn', CHESHIRE, 0, True),
    ('cgsys\\cheshire.png', YCG, 8, False),
]
KEY = 0x4A415E60


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


def _scripts(root, key):
    """A ysbin directory: encrypted scripts plus a plain YSCM table."""
    root.mkdir(parents=True)
    plains = {}
    for i, start in enumerate((1, 60, 300)):
        plain = ystb_plain(lines=tuple(range(start, start + 40, 3)))
        plains[f'yst{i:05d}.ybn'] = plain
        (root / f'yst{i:05d}.ybn').write_bytes(ystb_encrypt(plain, key))
    (root / 'yscom.ybn').write_bytes(b'YSCM' + ALICE)
    return plains


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['yuris'].load() is YurisHandler

    def test_detects_by_magic(self, tmp_path):
        path = tmp_path / 'data.dat'
        path.write_bytes(build_ypf(MEMBERS))
        assert detect_format(path) == 'yuris'


@pytest.mark.integration
class TestArchives:
    def test_top_level_extract(self, tmp_path, monkeypatch):
        archive = tmp_path / 'cgsys.ypf'
        archive.write_bytes(build_ypf(MEMBERS))
        _run(monkeypatch, 'extract', archive, tmp_path / 'out')
        assert (tmp_path / 'out' / 'cgsys' / 'cheshire.png').read_bytes() == YCG

    def test_extract_convert_ycg(self, tmp_path, monkeypatch):
        archive = tmp_path / 'cgsys.ypf'
        archive.write_bytes(build_ypf(MEMBERS))
        _run(monkeypatch, 'yuris', 'extract', archive, tmp_path / 'out', '--convert-ycg')
        with Image.open(tmp_path / 'out' / 'cgsys' / 'cheshire.png') as image:
            assert image.format == 'PNG'

    def test_create_like_copies_parameters(self, tmp_path, monkeypatch):
        original = tmp_path / 'original.ypf'
        original.write_bytes(build_ypf(MEMBERS, version=479, key=0xC9, table=TABLE_D))
        _run(monkeypatch, 'yuris', 'extract', original, tmp_path / 'out')
        rebuilt = tmp_path / 'rebuilt.ypf'
        _run(monkeypatch, 'yuris', 'create', tmp_path / 'out', rebuilt, '--like', original)
        assert archive_params(rebuilt) == {'version': 479, 'key': 0xC9, 'length_table': 'd'}
        with YPFFile(rebuilt) as ypf:
            for name, data, file_type, _packed in MEMBERS:
                assert ypf.read(name) == data
                assert ypf.getinfo(name).file_type == file_type

    def test_create_explicit_parameters_override_like(self, tmp_path, monkeypatch):
        original = tmp_path / 'original.ypf'
        original.write_bytes(build_ypf(MEMBERS, version=479, key=0xC9, table=TABLE_D))
        _run(monkeypatch, 'yuris', 'extract', original, tmp_path / 'out')
        rebuilt = tmp_path / 'rebuilt.ypf'
        _run(
            monkeypatch,
            'create',
            '--format',
            'yuris',
            tmp_path / 'out',
            rebuilt,
            '--like',
            original,
            '--version',
            '0x1F4',
            '--name-key',
            'ff',
            '--length-table',
            'a',
        )
        assert archive_params(rebuilt) == {'version': 500, 'key': 0xFF, 'length_table': 'a'}

    def test_create_encode_ycg(self, tmp_path, monkeypatch):
        src = tmp_path / 'src' / 'cg'
        src.mkdir(parents=True)
        Image.new('RGBA', (2, 2), (1, 2, 3, 4)).save(src / 'alice.png')
        out = tmp_path / 'cg.ypf'
        _run(monkeypatch, 'yuris', 'create', tmp_path / 'src', out, '--encode-ycg')
        with YPFFile(out) as ypf:
            assert is_ycg(ypf.read('cg\\alice.png'))

    def test_like_with_unknown_table_needs_explicit_table(self, tmp_path, monkeypatch, capsys):
        original = tmp_path / 'original.ypf'
        original.write_bytes(build_ypf(MEMBERS, table=[(0x12, 0x40)]))
        (tmp_path / 'src').mkdir()
        (tmp_path / 'src' / 'a.ybn').write_bytes(ALICE)
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'yuris', 'create', tmp_path / 'src', tmp_path / 'x.ypf', '--like', original)
        assert '--length-table' in capsys.readouterr().err

    def test_extract_not_a_ypf_exits(self, tmp_path, monkeypatch, capsys):
        archive = tmp_path / 'tarts.ypf'
        archive.write_bytes(b'\xff' * 64)
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'yuris', 'extract', archive, tmp_path / 'out')
        assert 'not a YPF archive' in capsys.readouterr().err


@pytest.mark.integration
class TestScriptCommands:
    def test_decrypt_directory_guesses_key(self, tmp_path, monkeypatch, capsys):
        plains = _scripts(tmp_path / 'ysbin', KEY)
        _run(monkeypatch, 'yuris', 'decrypt', tmp_path / 'ysbin', tmp_path / 'plain')
        for name, plain in plains.items():
            assert (tmp_path / 'plain' / name).read_bytes() == plain
        # Tables other than scripts are copied unchanged so the directory can be repacked.
        assert (tmp_path / 'plain' / 'yscom.ybn').read_bytes() == b'YSCM' + ALICE
        assert '4a415e60' in capsys.readouterr().err.lower()

    def test_decrypt_with_key_and_encrypt_back(self, tmp_path, monkeypatch):
        _scripts(tmp_path / 'ysbin', KEY)
        _run(monkeypatch, 'yuris', 'decrypt', tmp_path / 'ysbin', tmp_path / 'plain', '--key', '4a415e60')
        _run(monkeypatch, 'yuris', 'encrypt', tmp_path / 'plain', tmp_path / 'again', '--key', '0x4A415E60')
        for path in (tmp_path / 'ysbin').iterdir():
            assert (tmp_path / 'again' / path.name).read_bytes() == path.read_bytes()

    def test_encrypt_single_file_default_key(self, tmp_path, monkeypatch):
        plain = ystb_plain()
        (tmp_path / 'a.ybn').write_bytes(plain)
        _run(monkeypatch, 'yuris', 'encrypt', tmp_path / 'a.ybn', tmp_path / 'b.ybn')
        assert (tmp_path / 'b.ybn').read_bytes() == ystb_encrypt(plain, 0x96AC6FD3)

    def test_decrypt_single_non_script_exits(self, tmp_path, monkeypatch, capsys):
        (tmp_path / 'yscom.ybn').write_bytes(b'YSCM' + ALICE)
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'yuris', 'decrypt', tmp_path / 'yscom.ybn', tmp_path / 'out.ybn')
        assert 'not a YSTB' in capsys.readouterr().err

    def test_bad_key(self, tmp_path, monkeypatch):
        (tmp_path / 'a.ybn').write_bytes(ystb_plain())
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'yuris', 'encrypt', tmp_path / 'a.ybn', tmp_path / 'b.ybn', '--key', 'rabbit')


@pytest.mark.integration
class TestImageCommands:
    def test_decode_and_encode_directory(self, tmp_path, monkeypatch):
        src = tmp_path / 'cgsys'
        src.mkdir()
        (src / 'cheshire.png').write_bytes(YCG)
        (src / 'readme.txt').write_bytes(ALICE)
        _run(monkeypatch, 'yuris', 'decode-ycg', src, tmp_path / 'png')
        with Image.open(tmp_path / 'png' / 'cheshire.png') as image:
            assert image.format == 'PNG'
        assert (tmp_path / 'png' / 'readme.txt').read_bytes() == ALICE
        _run(monkeypatch, 'yuris', 'encode-ycg', tmp_path / 'png', tmp_path / 'ycg')
        again = (tmp_path / 'ycg' / 'cheshire.png').read_bytes()
        assert decode_ycg(again).tobytes() == decode_ycg(YCG).tobytes()

    def test_decode_single_non_ycg_exits(self, tmp_path, monkeypatch, capsys):
        (tmp_path / 'a.png').write_bytes(ALICE)
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'yuris', 'decode-ycg', tmp_path / 'a.png', tmp_path / 'b.png')
        assert 'not a YCG' in capsys.readouterr().err
