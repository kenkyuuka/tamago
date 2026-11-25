"""Roundtrip tests for real BlackRainbow ADVDX archives in nonfree/.

The nonfree directory is gitignored: populate it manually with ``.dat`` and
``.pak`` archives from ADVDX games to enable these tests.  They skip when no
samples are present.
"""

import hashlib
import os

import pytest

from tamago.formats.blackrainbow import DATFile, decode_bmd, encode_bmd, is_advdx_dat, is_bmd

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            if f.lower().endswith(('.dat', '.pak')):
                found.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(found)


archives = _collect()


def _contents(dat):
    result = {}
    for info in dat.files:
        data = dat.read(info)
        assert len(data) == info.size, info.file_name
        result[info.slot] = (info.raw_name, hashlib.sha256(data).digest())
    return result


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not archives, reason="no nonfree ADVDX samples available")
@pytest.mark.parametrize('relpath', archives)
class TestNonfreeArchives:
    def test_detected(self, relpath):
        assert is_advdx_dat(os.path.join(NONFREE, relpath))

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.dat'

        with DATFile(source) as dat:
            assert dat.files
            original = _contents(dat)
            params = (dat.kind, dat.game_id, dat.slot_count, dat.trailer)
            # A name that overflowed its field leaves a bad size field, which a
            # rebuild repairs; everything else must come back byte for byte.
            intact = all(info.stored_size == info.size for info in dat.files)
            dat.extract_all(extracted)

        with DATFile(rebuilt, mode='w') as dat:
            dat.write_all(extracted)

        with DATFile(rebuilt) as dat:
            assert (dat.kind, dat.game_id, dat.slot_count, dat.trailer) == params
            assert _contents(dat) == original
        if intact:
            with open(source, 'rb') as f:
                assert rebuilt.read_bytes() == f.read()

    def test_bmd_images_roundtrip(self, relpath):
        with DATFile(os.path.join(NONFREE, relpath)) as dat:
            if dat.kind != 2:
                pytest.skip("not an image archive")
            for info in dat.files:
                data = dat.read(info)
                assert is_bmd(data), info.file_name
                image = decode_bmd(data)
                assert decode_bmd(encode_bmd(image)).tobytes() == image.tobytes(), info.file_name
