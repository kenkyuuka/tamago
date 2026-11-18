"""Tests for PSB detection and the CLI handler."""

import json
import sys

import pytest
from PIL import Image

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.psb import PSB, Float32, Resource, read
from tamago.formats.psb import textures as t
from tamago.formats.psb.handler import PSBHandler
from tamago.formats.psb.psbfile import write
from tamago.tests.psb.samples import KEY, encrypt_header, tiny_psb


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


def model():
    """A PSB with one 2x2 RGBA8 atlas, used 1x2, header-encrypted."""
    im = Image.new('RGBA', (2, 2), (255, 255, 255, 255))
    texture = {
        'type': 'RGBA8',
        'width': 2,
        'height': 2,
        'truncated_width': 1,
        'truncated_height': 2,
        'pixel': Resource(0),
    }
    root = {
        'id': 'motion',
        'source': {'rabbit#hole': {'texture': texture, 'type': 0}},
        'version': Float32(3.0299999713897705),
    }
    return write(PSB(root=root, resources=[t.encode('RGBA8', im)], version=4, flags=1, key=KEY))


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['psb'].load() is PSBHandler

    def test_detects_by_magic(self, tmp_path):
        path = tmp_path / 'Malice100.psb'
        path.write_bytes(tiny_psb()[0])
        assert detect_format(path) == 'psb'


@pytest.mark.integration
class TestCli:
    def test_extract_and_create_roundtrip(self, monkeypatch, tmp_path):
        src = tmp_path / 'model.psb'
        src.write_bytes(model())
        _run(monkeypatch, 'extract', src, tmp_path / 'out')
        doc = json.loads((tmp_path / 'out' / 'psb.json').read_text(encoding='utf-8'))
        assert doc['key'] == f'{KEY:#010x}' and doc['version'] == 4 and doc['flags'] == 1
        assert doc['root']['source']['rabbit#hole']['texture']['pixel'] == {'$resource': 0}
        assert (tmp_path / 'out' / 'resources' / '0.bin').exists()
        with Image.open(tmp_path / 'out' / 'textures' / 'rabbit_hole.png') as im:
            assert im.size == (1, 2)

        _run(monkeypatch, 'create', '--format', 'psb', tmp_path / 'out', tmp_path / 'back.psb')
        assert (tmp_path / 'back.psb').read_bytes() == src.read_bytes()

    def test_extract_without_textures(self, monkeypatch, tmp_path):
        src = tmp_path / 'model.psb'
        src.write_bytes(model())
        _run(monkeypatch, 'psb', 'extract', '--no-textures', src, tmp_path / 'out')
        assert not (tmp_path / 'out' / 'textures').exists()

    def test_create_unencrypted(self, monkeypatch, tmp_path):
        src = tmp_path / 'model.psb'
        src.write_bytes(model())
        _run(monkeypatch, 'psb', 'extract', src, tmp_path / 'out')
        _run(monkeypatch, 'psb', 'create', '--no-encrypt', tmp_path / 'out', tmp_path / 'plain.psb')
        psb = read((tmp_path / 'plain.psb').read_bytes())
        assert psb.key is None and psb.flags == 0
        assert psb.root == read(src.read_bytes()).root

    def test_create_with_another_key(self, monkeypatch, tmp_path):
        src = tmp_path / 'model.psb'
        src.write_bytes(model())
        _run(monkeypatch, 'psb', 'extract', src, tmp_path / 'out')
        _run(monkeypatch, 'psb', 'create', '--key', '0x12345678', tmp_path / 'out', tmp_path / 'other.psb')
        assert read((tmp_path / 'other.psb').read_bytes()).key == 0x12345678

    def test_decrypt(self, monkeypatch, tmp_path):
        plain = tiny_psb(3)[0]
        (tmp_path / 'enc.psb').write_bytes(encrypt_header(plain))
        _run(monkeypatch, 'psb', 'decrypt', tmp_path / 'enc.psb', tmp_path / 'dec.psb')
        assert (tmp_path / 'dec.psb').read_bytes() == plain

    def test_info(self, monkeypatch, tmp_path, capsys):
        src = tmp_path / 'model.psb'
        src.write_bytes(model())
        _run(monkeypatch, 'psb', 'info', src)
        out = capsys.readouterr().out
        assert f'key {KEY:#010x}' in out
        assert 'texture rabbit#hole: RGBA8 2x2 (used 1x2)' in out
        assert 'version:   3.03' in out

    def test_unreadable_file(self, monkeypatch, tmp_path, capsys):
        bad = tmp_path / 'bad.psb'
        bad.write_bytes(b'PSB\0' + bytes(60))
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, 'psb', 'extract', bad, tmp_path / 'out')
        assert e.value.code == 1
        assert 'Error' in capsys.readouterr().err
