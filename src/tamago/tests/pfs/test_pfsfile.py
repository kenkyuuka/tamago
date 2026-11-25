"""Tests for reading and writing Artemis PFS archives."""

import hashlib
import json
import struct

import pytest

from tamago.formats import pfs
from tamago.formats.pfs import MANIFEST_NAME, PFSFile, is_pfs
from tamago.tests.pfs.samples import (
    ALICE,
    CONTENTS,
    DATA_ORDER,
    EXAMPLE,
    EXAMPLE_MEMBERS,
    HATTER,
    MEMBERS,
    QUEEN,
    QUEEN_NAME,
    build_pfs,
    xor,
)

VERSIONS = [2, 6, 8]


def _write(tmp_path, data, name='root.pfs'):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _contents(path):
    with PFSFile(path) as arc:
        return {info.file_name: arc.read(info) for info in arc.files}


def _populate(root, files):
    for name, data in files.items():
        path = root / name.replace('\\', '/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


@pytest.mark.integration
class TestRead:
    @pytest.mark.parametrize('version', VERSIONS)
    def test_reads_members(self, tmp_path, version):
        path = _write(tmp_path, build_pfs(MEMBERS, version, DATA_ORDER))
        with PFSFile(path) as arc:
            assert arc.version == version
            assert arc.namelist() == list(CONTENTS)
            for name, data in CONTENTS.items():
                assert arc.read(name) == data

    def test_worked_example(self, tmp_path):
        path = _write(tmp_path, EXAMPLE)
        with PFSFile(path) as arc:
            assert arc.key == bytes.fromhex('0d81e1fc67f3818509292262aa9c7de4f032dec8')
            assert [(i.file_name, i.offset, i.size) for i in arc.files] == [
                ('alice.txt', 0x62, len(ALICE)),
                ('tea\\hatter.txt', 0x77, len(HATTER)),
            ]
            assert arc.read('alice.txt') == ALICE
            assert arc.read('tea\\hatter.txt') == HATTER

    def test_key_is_sha1_of_index(self, tmp_path):
        data = build_pfs(MEMBERS, 8, DATA_ORDER)
        (index_size,) = struct.unpack_from('<I', data, 3)
        with PFSFile(_write(tmp_path, data)) as arc:
            assert arc.key == hashlib.sha1(data[7 : 7 + index_size], usedforsecurity=False).digest()

    @pytest.mark.parametrize('version', [2, 6])
    def test_unencrypted_versions_have_no_key(self, tmp_path, version):
        with PFSFile(_write(tmp_path, build_pfs(MEMBERS, version))) as arc:
            assert arc.key is None

    def test_read_by_info_and_getinfo(self, tmp_path):
        with PFSFile(_write(tmp_path, build_pfs(MEMBERS, 8, DATA_ORDER))) as arc:
            info = arc.getinfo(QUEEN_NAME)
            assert info.raw_name == QUEEN_NAME.encode('cp932')
            assert arc.read(info) == QUEEN
            with pytest.raises(KeyError):
                arc.getinfo('dormouse.txt')

    def test_streams_members_in_chunks(self, tmp_path, monkeypatch):
        # A chunk size that is not a multiple of the key length must not
        # throw the key out of step.
        monkeypatch.setattr(pfs.pfsfile, 'CHUNK_SIZE', 7)
        path = _write(tmp_path, build_pfs(MEMBERS, 8, DATA_ORDER))
        with PFSFile(path) as arc:
            arc.extract(QUEEN_NAME, tmp_path / 'queen.txt')
            assert arc.read(QUEEN_NAME) == QUEEN
        assert (tmp_path / 'queen.txt').read_bytes() == QUEEN

    def test_utf8_names(self, tmp_path):
        name = 'ハートの女王.txt'
        path = _write(tmp_path, build_pfs([(name.encode('utf-8'), QUEEN)]))
        with PFSFile(path) as arc:
            assert arc.encoding == 'utf-8'
            assert arc.namelist() == [name]

    def test_cp932_names(self, tmp_path):
        with PFSFile(_write(tmp_path, build_pfs(MEMBERS))) as arc:
            assert arc.encoding == 'cp932'

    def test_ascii_names_count_as_cp932(self, tmp_path):
        with PFSFile(_write(tmp_path, build_pfs(EXAMPLE_MEMBERS))) as arc:
            assert arc.encoding == 'cp932'

    def test_empty_archive(self, tmp_path):
        with PFSFile(_write(tmp_path, build_pfs([]))) as arc:
            assert arc.files == []

    @pytest.mark.parametrize(
        'data, message',
        [
            (b'pf8', 'too small'),
            (b'pf9' + EXAMPLE[3:], 'version'),
            (b'PF8' + EXAMPLE[3:], 'not a PFS'),
            (EXAMPLE[:3] + struct.pack('<I', 0x1000) + EXAMPLE[7:], 'does not fit'),
            (EXAMPLE[:0x0B] + struct.pack('<I', 0x100) + EXAMPLE[0x0F:], 'runs past'),
            (EXAMPLE[:0x1C] + struct.pack('<I', 0x1000) + EXAMPLE[0x20:], 'outside'),
        ],
    )
    def test_rejects_bad_archives(self, tmp_path, data, message):
        with pytest.raises(ValueError, match=message):
            PFSFile(_write(tmp_path, data))

    def test_rejects_undecodable_name(self, tmp_path):
        path = _write(tmp_path, build_pfs([(b'\x81', ALICE)]))
        with pytest.raises(ValueError, match='cannot be decoded'):
            PFSFile(path)


@pytest.mark.integration
class TestIsPfs:
    @pytest.mark.parametrize('version', VERSIONS)
    def test_accepts_archives(self, tmp_path, version):
        assert is_pfs(_write(tmp_path, build_pfs(MEMBERS, version)))

    def test_accepts_patch_archive_name(self, tmp_path):
        assert is_pfs(_write(tmp_path, EXAMPLE, 'root.pfs.001'))

    @pytest.mark.parametrize('data', [b'', b'pf8', b'pf8\xff\xff\xff\xff', b'pfs' + EXAMPLE[3:], b'pf89 is a file'])
    def test_rejects_others(self, tmp_path, data):
        assert not is_pfs(_write(tmp_path, data))

    def test_missing_file(self, tmp_path):
        assert not is_pfs(tmp_path / 'missing.pfs')


@pytest.mark.integration
class TestExtract:
    def test_extract_all(self, tmp_path):
        path = _write(tmp_path, build_pfs(MEMBERS, 8, DATA_ORDER))
        out = tmp_path / 'out'
        with PFSFile(path) as arc:
            arc.extract_all(out)
        for name, data in CONTENTS.items():
            assert (out / name.replace('\\', '/')).read_bytes() == data
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert manifest == {
            'format': 'pfs',
            'version': 8,
            'encoding': 'cp932',
            # In data order, not index order.
            'members': [
                {'name': 'alice.txt'},
                {'name': QUEEN_NAME},
                {'name': 'Cheshire.png'},
                {'name': 'tea\\hatter.txt'},
            ],
        }

    def test_glob(self, tmp_path):
        path = _write(tmp_path, build_pfs(MEMBERS, 8, DATA_ORDER))
        out = tmp_path / 'out'
        with PFSFile(path) as arc:
            arc.extract_all(out, glob='*.txt')
        assert sorted(p.name for p in out.rglob('*') if p.is_file()) == [
            MANIFEST_NAME,
            'alice.txt',
            'court.txt',
            'hatter.txt',
        ]
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert [m['name'] for m in manifest['members']] == ['alice.txt', QUEEN_NAME, 'tea\\hatter.txt']

    def test_refuses_unsafe_names(self, tmp_path):
        path = _write(tmp_path, build_pfs([(b'..\\..\\caterpillar.txt', ALICE)]))
        with PFSFile(path) as arc, pytest.raises(ValueError, match='unsafe'):
            arc.extract_all(tmp_path / 'out')
        assert not (tmp_path / 'out').exists()

    def test_refuses_member_named_like_manifest(self, tmp_path):
        path = _write(tmp_path, build_pfs([(MANIFEST_NAME.encode(), ALICE)]))
        with PFSFile(path) as arc, pytest.raises(ValueError, match='manifest'):
            arc.extract_all(tmp_path / 'out')

    def test_name_hex_for_names_cp932_cannot_reproduce(self, tmp_path):
        # 0x8790 (the NEC row-13 "≒") decodes to a character that cp932
        # encodes as 0x81E0.
        raw = b'\x87\x90.txt'
        path = _write(tmp_path, build_pfs([(raw, ALICE)]))
        out = tmp_path / 'out'
        with PFSFile(path) as arc:
            arc.extract_all(out)
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert manifest['members'][0]['name_hex'] == raw.hex()
        rebuilt = tmp_path / 'again.pfs'
        with PFSFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == path.read_bytes()


@pytest.mark.integration
class TestCreate:
    @pytest.mark.parametrize('version', VERSIONS)
    def test_roundtrip_is_byte_identical(self, tmp_path, version):
        original = _write(tmp_path, build_pfs(MEMBERS, version, DATA_ORDER))
        out = tmp_path / 'out'
        with PFSFile(original) as arc:
            arc.extract_all(out)
        rebuilt = tmp_path / 'again.pfs'
        with PFSFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == original.read_bytes()

    def test_worked_example(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {n.decode(): d for n, d in EXAMPLE_MEMBERS})
        path = tmp_path / 'root.pfs'
        with PFSFile(path, mode='w') as arc:
            arc.write_all(src)
        assert path.read_bytes() == EXAMPLE

    @pytest.mark.parametrize('version', VERSIONS)
    def test_without_manifest_sorts_by_name_bytes(self, tmp_path, version):
        src = tmp_path / 'src'
        _populate(src, CONTENTS)
        path = tmp_path / 'root.pfs'
        with PFSFile(path, mode='w', version=version) as arc:
            arc.write_all(src)
        assert path.read_bytes() == build_pfs(MEMBERS, version)

    def test_default_version_is_8(self, tmp_path):
        path = tmp_path / 'root.pfs'
        with PFSFile(path, mode='w') as arc:
            assert arc.version == 8
        assert path.read_bytes()[:3] == b'pf8'

    def test_new_files_follow_listed_ones(self, tmp_path):
        original = _write(tmp_path, build_pfs(MEMBERS, 8, DATA_ORDER))
        out = tmp_path / 'out'
        with PFSFile(original) as arc:
            arc.extract_all(out)
        (out / 'tea' / 'dormouse.txt').write_bytes(b'Twinkle, twinkle, little bat!\n')
        (out / 'Cheshire.png').write_bytes(b'only the grin')
        rebuilt = tmp_path / 'again.pfs'
        with PFSFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        with PFSFile(rebuilt) as arc:
            # The index stays sorted; the data keeps its order, with the new file last.
            assert arc.namelist() == ['Cheshire.png', 'alice.txt', 'tea\\dormouse.txt', 'tea\\hatter.txt', QUEEN_NAME]
            by_offset = [i.file_name for i in sorted(arc.files, key=lambda i: i.offset)]
            assert by_offset == ['alice.txt', QUEEN_NAME, 'Cheshire.png', 'tea\\hatter.txt', 'tea\\dormouse.txt']
            assert arc.read('Cheshire.png') == b'only the grin'

    def test_manifest_sets_version_and_encoding(self, tmp_path):
        name = 'ハートの女王.txt'
        original = _write(tmp_path, build_pfs([(name.encode('utf-8'), QUEEN)], version=6))
        out = tmp_path / 'out'
        with PFSFile(original) as arc:
            arc.extract_all(out)
        rebuilt = tmp_path / 'again.pfs'
        with PFSFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == original.read_bytes()

    def test_explicit_version_overrides_manifest(self, tmp_path):
        original = _write(tmp_path, build_pfs(MEMBERS, 8, DATA_ORDER))
        out = tmp_path / 'out'
        with PFSFile(original) as arc:
            arc.extract_all(out)
        rebuilt = tmp_path / 'again.pfs'
        with PFSFile(rebuilt, mode='w', version=2) as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == build_pfs(MEMBERS, 2, DATA_ORDER)

    def test_missing_listed_file(self, tmp_path):
        original = _write(tmp_path, build_pfs(MEMBERS, 8, DATA_ORDER))
        out = tmp_path / 'out'
        with PFSFile(original) as arc:
            arc.extract_all(out)
        (out / 'alice.txt').unlink()
        with pytest.raises(ValueError, match='missing'), PFSFile(tmp_path / 'again.pfs', mode='w') as arc:
            arc.write_all(out)

    def test_invalid_manifest(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'alice.txt': ALICE, MANIFEST_NAME: b'{"format": "silky", "members": []}'})
        with pytest.raises(ValueError, match='Invalid PFS manifest'), PFSFile(tmp_path / 'a.pfs', mode='w') as arc:
            arc.write_all(src)

    def test_write_glob(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, CONTENTS)
        path = tmp_path / 'root.pfs'
        with PFSFile(path, mode='w') as arc:
            arc.write_all(src, glob='tea\\*')
        assert _contents(path) == {'tea\\hatter.txt': HATTER}

    def test_skips_output_inside_source(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'alice.txt': ALICE})
        with PFSFile(src / 'root.pfs', mode='w') as arc:
            arc.write_all(src)
        assert _contents(src / 'root.pfs') == {'alice.txt': ALICE}

    def test_write_single_files(self, tmp_path):
        (tmp_path / 'alice.txt').write_bytes(ALICE)
        path = tmp_path / 'root.pfs'
        with PFSFile(path, mode='w') as arc:
            arc.write(tmp_path / 'alice.txt')
            arc.write(tmp_path / 'alice.txt', arcname='tea/hatter.txt')
        assert _contents(path) == {'alice.txt': ALICE, 'tea\\hatter.txt': ALICE}

    def test_streams_members_in_chunks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pfs.pfsfile, 'CHUNK_SIZE', 7)
        src = tmp_path / 'src'
        _populate(src, CONTENTS)
        path = tmp_path / 'root.pfs'
        with PFSFile(path, mode='w') as arc:
            arc.write_all(src)
        assert path.read_bytes() == build_pfs(MEMBERS)

    def test_rejects_duplicate_names(self, tmp_path):
        (tmp_path / 'alice.txt').write_bytes(ALICE)
        with PFSFile(tmp_path / 'root.pfs', mode='w') as arc:
            arc.write(tmp_path / 'alice.txt')
            with pytest.raises(ValueError, match='more than once'):
                arc.write(tmp_path / 'alice.txt')

    @pytest.mark.parametrize('arcname', ['', 'tea\0party.txt'])
    def test_rejects_bad_names(self, tmp_path, arcname):
        (tmp_path / 'alice.txt').write_bytes(ALICE)
        with PFSFile(tmp_path / 'root.pfs', mode='w') as arc, pytest.raises(ValueError):
            arc.write(tmp_path / 'alice.txt', arcname=arcname)

    def test_rejects_unencodable_name(self, tmp_path):
        (tmp_path / 'alice.txt').write_bytes(ALICE)
        with PFSFile(tmp_path / 'root.pfs', mode='w') as arc, pytest.raises(ValueError, match='cp932'):
            arc.write(tmp_path / 'alice.txt', arcname='🐇.txt')

    def test_utf8_encoding(self, tmp_path):
        (tmp_path / 'alice.txt').write_bytes(ALICE)
        path = tmp_path / 'root.pfs'
        with PFSFile(path, mode='w', encoding='utf-8') as arc:
            arc.write(tmp_path / 'alice.txt', arcname='🐇.txt')
        with PFSFile(path) as arc:
            assert arc.files[0].raw_name == '🐇.txt'.encode()

    @pytest.mark.parametrize('kwargs', [{'version': 7}, {'encoding': 'latin-1'}, {'mode': 'a'}])
    def test_rejects_bad_options(self, tmp_path, kwargs):
        with pytest.raises(ValueError):
            PFSFile(tmp_path / 'root.pfs', **{'mode': 'w', **kwargs})

    def test_no_partial_archive_after_error(self, tmp_path):
        (tmp_path / 'alice.txt').write_bytes(ALICE)
        path = tmp_path / 'root.pfs'
        with pytest.raises(RuntimeError), PFSFile(path, mode='w') as arc:
            arc.write(tmp_path / 'alice.txt')
            raise RuntimeError
        assert path.read_bytes() == b''

    def test_read_requires_read_mode(self, tmp_path):
        with PFSFile(tmp_path / 'root.pfs', mode='w') as arc, pytest.raises(ValueError, match="mode='r'"):
            arc.read('alice.txt')


@pytest.mark.unit
def test_xor_matches_reference():
    key = hashlib.sha1(b'Curiouser and curiouser!', usedforsecurity=False).digest()
    data = bytes(range(256)) * 3
    for start in (0, 1, 19, 20, 33):
        assert pfs.pfsfile.xor_key(data, key, start) == xor(data, key[start % 20 :] + key[: start % 20])
