"""Roundtrip tests for real E-mote PSB files in nonfree/.

The nonfree directory is gitignored: populate it manually with ``*.psb``
files, or with packs holding them (ANIM's ``psbpack.dat``), to enable these
tests.  They skip when no samples are present.

Every loose PSB, and a sample of those in each pack, is read (decrypting it),
its textures decoded, its tree taken through JSON and back, and it is written
again, which must reproduce the original bytes exactly, encryption included.
``tamago psb extract`` and ``create`` are checked the same way on loose files.
"""

import json
import os
import sys

import pytest

from tamago.cli import main
from tamago.formats.anim import PCKFile, is_pck
from tamago.formats.psb import is_psb, read
from tamago.formats.psb import textures as t
from tamago.formats.psb.jsontree import from_json, to_json
from tamago.formats.psb.psbfile import write
from tamago.tests.nonfree_sampling import select_members

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _walk():
    if not os.path.isdir(NONFREE):
        return
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            yield os.path.join(root, f)


def _is_psb_file(path):
    with open(path, 'rb') as f:
        return is_psb(f.read(4))


loose = sorted(os.path.relpath(p, NONFREE) for p in _walk() if _is_psb_file(p))
packs = sorted(os.path.relpath(p, NONFREE) for p in _walk() if not _is_psb_file(p) and is_pck(p))


def _check(name, data):
    psb = read(data)
    assert isinstance(psb.root, dict), name
    for source, texture in t.iter_textures(psb.root):
        im = t.texture_image(texture, psb.resources)
        assert im.size[0] > 0, f'{name}: {source}'
    assert from_json(json.loads(json.dumps(to_json(psb.root), ensure_ascii=False))) == psb.root, name
    assert write(psb) == data, f'{name} is not reproduced exactly'


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not loose, reason="no nonfree PSB samples available")
@pytest.mark.parametrize('relpath', loose)
class TestNonfreeFiles:
    def test_roundtrip(self, relpath):
        with open(os.path.join(NONFREE, relpath), 'rb') as f:
            _check(relpath, f.read())

    def test_cli_extract_and_create(self, relpath, tmp_path, monkeypatch):
        src = os.path.join(NONFREE, relpath)
        monkeypatch.setattr(sys, 'argv', ['tamago', 'extract', src, str(tmp_path / 'out')])
        main()
        monkeypatch.setattr(
            sys, 'argv', ['tamago', 'create', '--format', 'psb', str(tmp_path / 'out'), str(tmp_path / 'back.psb')]
        )
        main()
        with open(src, 'rb') as f:
            assert (tmp_path / 'back.psb').read_bytes() == f.read()


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not packs, reason="no nonfree packs of PSB files available")
@pytest.mark.parametrize('relpath', packs)
class TestNonfreePacks:
    def test_sampled_members_roundtrip(self, relpath):
        checked = 0
        with PCKFile(os.path.join(NONFREE, relpath)) as pck:
            for info in select_members(pck.files):
                data = pck.read(info)
                if is_psb(data):
                    _check(f'{relpath}:{info.file_name}', data)
                    checked += 1
        if not checked:
            pytest.skip(f'{relpath} holds no PSB files')
