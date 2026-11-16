"""Roundtrip tests for real YU-RIS archives in nonfree/.

The nonfree directory is gitignored: populate it manually with ``*.ypf``
archives to enable these tests.  They skip when no samples are present.
"""

import hashlib
import os

import pytest

from tamago.formats.yuris import (
    YPFFile,
    decode_ycg,
    decrypt_ystb,
    encode_ycg,
    encrypt_ystb,
    guess_ystb_key,
    is_ycg,
    is_ystb,
)
from tamago.formats.yuris.ypf import archive_params

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect():
    if not os.path.isdir(NONFREE):
        return []
    found = []
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            if f.lower().endswith('.ypf'):
                found.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(found)


archives = _collect()


def _contents(ypf):
    return {info.file_name: (info.file_type, hashlib.sha256(ypf.read(info)).digest()) for info in ypf.files}


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not archives, reason="no nonfree YPF samples available")
@pytest.mark.parametrize('relpath', archives)
class TestNonfreeArchives:
    def test_reads_every_member(self, relpath):
        with YPFFile(os.path.join(NONFREE, relpath)) as ypf:
            for info in ypf.files:
                assert len(ypf.read(info)) == info.size, info.file_name
            assert ypf.testzip() is None

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.ypf'
        params = archive_params(source)
        assert params['length_table'] is not None, "length table not recognised"

        with YPFFile(source) as ypf:
            original = _contents(ypf)
            ypf.extract_all(extracted)

        # An archive with no members has no names to learn the key from.
        known = {name: value for name, value in params.items() if value is not None}
        with YPFFile(rebuilt, mode='w', **known) as ypf:
            ypf.write_all(extracted)

        assert archive_params(rebuilt) == params
        with YPFFile(rebuilt) as ypf:
            assert _contents(ypf) == original
            assert ypf.testzip() is None

    def test_scripts_decrypt_and_reencrypt(self, relpath):
        with YPFFile(os.path.join(NONFREE, relpath)) as ypf:
            scripts = [data for data in (ypf.read(i) for i in ypf.files if i.file_type == 0) if is_ystb(data)]
        if not scripts:
            pytest.skip("no YSTB scripts in this archive")
        key = guess_ystb_key(scripts)
        for data in scripts:
            assert encrypt_ystb(decrypt_ystb(data, key), key) == data

    def test_ycg_images_roundtrip(self, relpath):
        with YPFFile(os.path.join(NONFREE, relpath)) as ypf:
            images = [i for i in ypf.files if i.file_type == 8]
            if not images:
                pytest.skip("no YCG images in this archive")
            for info in images:
                data = ypf.read(info)
                assert is_ycg(data), info.file_name
                image = decode_ycg(data)
                assert decode_ycg(encode_ycg(image)).tobytes() == image.tobytes(), info.file_name
