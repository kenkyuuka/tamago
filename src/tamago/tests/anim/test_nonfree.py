"""Roundtrip tests for real ANIM game files in nonfree/.

The nonfree directory is gitignored: populate it manually with packs
(``*_wave.pck``, ``psbpack.dat``) and enciphered files (``*_sce.dat``,
``*_define.dat``, ``cg/*.gax``) to enable these tests.  They skip when no
samples are present.
"""

import hashlib
import os

import pytest

from tamago.formats.anim import PCKFile, decrypt, encrypt, is_encrypted, is_eog, is_pck, stored_key, unwrap_eog

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _walk():
    if not os.path.isdir(NONFREE):
        return
    for root, _dirs, files in os.walk(NONFREE, followlinks=True):
        for f in files:
            yield os.path.join(root, f)


def _collect(predicate):
    return sorted(os.path.relpath(path, NONFREE) for path in _walk() if predicate(path))


def _enciphered(path):
    with open(path, 'rb') as f:
        return is_encrypted(f.read(20))


packs = _collect(is_pck)
enciphered = _collect(_enciphered)


def _digest(data):
    return hashlib.sha256(data).digest()


def _contents(pck):
    """Each member's contents, with EOG audio unwrapped (its PCM size field is not kept by conversion)."""
    result = {}
    for info in pck.files:
        data = pck.read(info)
        result[info.file_name] = _digest(unwrap_eog(data) if is_eog(data) else data)
    return result


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not packs, reason="no nonfree ANIM pack samples available")
@pytest.mark.parametrize('relpath', packs)
class TestNonfreePacks:
    def test_reads_every_member(self, relpath):
        with PCKFile(os.path.join(NONFREE, relpath)) as pck:
            assert pck.files, f"{relpath} has no members"
            for info in pck.files:
                assert len(pck.read(info)) == info.size, info.file_name

    def test_extract_and_recreate_roundtrip(self, relpath, tmp_path):
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.pck'

        with PCKFile(source) as pck:
            original = _contents(pck)
            pck.extract_all(extracted, convert_eog=True)

        with PCKFile(rebuilt, mode='w') as pck:
            pck.write_all(extracted, wrap_ogg=True)

        with PCKFile(rebuilt) as pck:
            assert _contents(pck) == original

    def test_recreate_as_stored_is_byte_identical(self, relpath, tmp_path):
        """Without conversion, the rebuilt pack (index, name order and data) matches the original exactly."""
        source = os.path.join(NONFREE, relpath)
        extracted = tmp_path / 'extracted'
        rebuilt = tmp_path / 'rebuilt.pck'

        with PCKFile(source) as pck:
            pck.extract_all(extracted)
        with PCKFile(rebuilt, mode='w') as pck:
            pck.write_all(extracted)

        with open(source, 'rb') as a, open(rebuilt, 'rb') as b:
            while True:
                chunk = a.read(1 << 20)
                assert chunk == b.read(1 << 20)
                if not chunk:
                    break


@pytest.mark.nonfree
@pytest.mark.integration
@pytest.mark.skipif(not enciphered, reason="no nonfree ANIM enciphered samples available")
@pytest.mark.parametrize('relpath', enciphered)
def test_decrypt_and_reencrypt_roundtrip(relpath):
    with open(os.path.join(NONFREE, relpath), 'rb') as f:
        data = f.read()
    plain = decrypt(data)
    if relpath.lower().endswith('.gax'):
        assert plain.startswith(b'\x89PNG\r\n\x1a\n'), relpath
    assert encrypt(plain, stored_key(data)) == data
