"""Tests for the DxLib DXA archive reader and writer."""

import os
import struct

import pytest

from tamago.formats.dxa import DXAFile, derive_key, is_dxa, password_from_key
from tamago.formats.dxa.lz import compress

DEFAULT_KEY = bytes.fromhex('55AA2055550655AA55D57C66')
PLAIN_KEY = bytes(12)

ALICE = b'Alice was beginning to get very tired of sitting by her sister on the bank.'
HATTER = b'Why is a raven like a writing-desk?'
QUEEN = b'Off with their heads! ' * 40


def _xor(data, pos, key):
    return bytes(b ^ key[(pos + i) % 12] for i, b in enumerate(data))


CODECS = {932: 'cp932', 65001: 'utf-8'}


def _name_record(name, codec='cp932'):
    raw = name.encode(codec)
    upper = ''.join(c.upper() if c.isascii() else c for c in name).encode(codec)
    units = (len(raw) + 4) // 4 if raw else 0
    return struct.pack('<HH', units, sum(upper) & 0xFFFF) + upper.ljust(units * 4, b'\0') + raw.ljust(units * 4, b'\0')


def _build(tree, *, version=4, key=DEFAULT_KEY, packed=(), codepage=932, times=(0, 0, 0)):
    """Assemble a DXA archive by hand, independently of the writer under test.

    *tree* maps names to bytes (files) or nested dicts (directories).  Files whose
    names are in *packed* are stored LZ-compressed.
    """
    header_size = 0x1C if version >= 4 else 0x18
    record_size = 0x2C if version >= 2 else 0x28
    data = bytearray()
    names = bytearray(_name_record(''))
    records = []  # file table records, filled in place
    dirs = []  # directory table records

    def add_name(name):
        offset = len(names)
        names.extend(_name_record(name, CODECS[codepage]))
        return offset

    def add_record(name_offset, attr, address, size, packed_size):
        records.append([name_offset, attr, address, size, packed_size])
        return len(records) - 1

    def place_dir(tree, own_record, parent_dir):
        dir_index = len(dirs)
        dirs.append(None)
        first = len(records)
        children = []
        for name, value in tree.items():
            if isinstance(value, dict):
                children.append((add_record(add_name(name), 0x10, 0, 0, 0xFFFFFFFF), value))
            else:
                stored = compress(value) if name in packed else value
                address = len(data)
                data.extend(stored)
                add_record(add_name(name), 0x20, address, len(value), len(stored) if name in packed else 0xFFFFFFFF)
        dirs[dir_index] = [own_record * record_size, parent_dir, len(tree), first * record_size]
        for record_index, subtree in children:
            records[record_index][2] = len(dirs) * 16
            place_dir(subtree, record_index, dir_index * 16)

    add_record(0, 0x10, 0, 0, 0xFFFFFFFF)
    place_dir(tree, 0, 0xFFFFFFFF)

    file_table = bytearray()
    for name_offset, attr, address, size, packed_size in records:
        file_table += struct.pack('<II3QII', name_offset, attr, *times, address, size)
        if version >= 2:
            file_table += struct.pack('<I', packed_size)
    dir_table = b''.join(struct.pack('<4I', *d) for d in dirs)
    index = bytes(names) + bytes(file_table) + dir_table

    index_offset = header_size + len(data)
    header = struct.pack(
        '<2sHIIIII', b'DX', version, len(index), header_size, index_offset, len(names), len(names) + len(file_table)
    )
    if version >= 4:
        header += struct.pack('<I', codepage)
    assert len(header) == header_size
    plain = header + bytes(data) + index
    return _xor(plain, 0, key)


def _write(tmp_path, tree, name='test.dxa', **kwargs):
    path = tmp_path / name
    path.write_bytes(_build(tree, **kwargs))
    return path


def _contents(path, **kwargs):
    with DXAFile(path, **kwargs) as dxa:
        return {info.file_name: dxa.read(info) for info in dxa.files}


@pytest.mark.unit
class TestKeys:
    def test_default_key(self):
        assert derive_key('') == DEFAULT_KEY

    def test_password_is_repeated_to_twelve_bytes(self):
        assert derive_key('Alice') == derive_key('AliceAliceAl')

    def test_long_password_is_truncated(self):
        assert derive_key('CheshireCatGrins') == derive_key('CheshireCatG')

    @pytest.mark.parametrize(
        ('password', 'key'),
        [
            ('hug_001', '97 57 ed 0a cf 9c ce f2 ab 18 23 fc'),
            ('FbavPKCS7', 'b9 26 eb 98 af e7 bc 95 b9 39 f0 ad'),
            ('jirotsuke', '95 96 f8 09 8b df 8a 92 2b 15 40 be'),
        ],
    )
    def test_known_password_keys(self, password, key):
        # Passwords from crass's key list; the keys appear in arc_unpacker's known-key list.
        assert derive_key(password) == bytes.fromhex(key)

    @pytest.mark.parametrize('password', ['', 'Alice', 'hug_001', 'Jabberwocky!', 'ウサギ'])
    def test_password_from_key_inverts(self, password):
        assert password_from_key(derive_key(password)) == password

    def test_non_text_key_has_no_password(self):
        assert password_from_key(bytes(12)) is None


@pytest.mark.unit
class TestRead:
    def test_flat_default_key(self, tmp_path):
        path = _write(tmp_path, {'alice.txt': ALICE, 'hatter.txt': HATTER})
        with DXAFile(path) as dxa:
            assert dxa.version == 4
            assert dxa.key == DEFAULT_KEY
            assert dxa.password == ''
            assert [i.file_name for i in dxa.files] == ['alice.txt', 'hatter.txt']
            assert dxa.read('hatter.txt') == HATTER

    def test_nested_directories(self, tmp_path):
        tree = {
            'rabbit_hole.txt': ALICE,
            'tea_party': {'hatter.txt': HATTER, 'dormouse': {'treacle.txt': b'Twinkle, twinkle'}},
            'zz_garden': {'queen.txt': QUEEN},
        }
        assert _contents(_write(tmp_path, tree)) == {
            'rabbit_hole.txt': ALICE,
            'tea_party/hatter.txt': HATTER,
            'tea_party/dormouse/treacle.txt': b'Twinkle, twinkle',
            'zz_garden/queen.txt': QUEEN,
        }

    def test_compressed_member(self, tmp_path):
        path = _write(tmp_path, {'queen.txt': QUEEN, 'alice.txt': ALICE}, packed={'queen.txt'})
        with DXAFile(path) as dxa:
            queen = dxa.files[0]
            assert queen.packed_size is not None and queen.packed_size < len(QUEEN)
            assert queen.size == len(QUEEN)
            assert dxa.read(queen) == QUEEN
            assert dxa.files[1].packed_size is None

    @pytest.mark.parametrize('version', [1, 2, 3])
    def test_older_versions(self, tmp_path, version):
        packed = {'queen.txt'} if version >= 2 else set()
        path = _write(tmp_path, {'queen.txt': QUEEN, 'den': {'alice.txt': ALICE}}, version=version, packed=packed)
        with DXAFile(path) as dxa:
            assert dxa.version == version
            assert {i.file_name: dxa.read(i) for i in dxa.files} == {'queen.txt': QUEEN, 'den/alice.txt': ALICE}

    def test_unencrypted(self, tmp_path):
        path = _write(tmp_path, {'alice.txt': ALICE}, key=PLAIN_KEY)
        assert path.read_bytes()[:2] == b'DX'
        with DXAFile(path) as dxa:
            assert dxa.key == PLAIN_KEY
            assert dxa.read('alice.txt') == ALICE

    def test_password_given(self, tmp_path):
        path = _write(tmp_path, {'alice.txt': ALICE}, key=derive_key('Wonderland'))
        with DXAFile(path, password='Wonderland') as dxa:
            assert dxa.read('alice.txt') == ALICE

    @pytest.mark.parametrize('version', [1, 2, 3, 4])
    def test_unknown_password_is_recovered(self, tmp_path, version):
        path = _write(
            tmp_path, {'alice.txt': ALICE, 'den': {'hatter.txt': HATTER}}, version=version, key=derive_key('Wonderland')
        )
        with DXAFile(path) as dxa:
            assert dxa.version == version
            assert dxa.key == derive_key('Wonderland')
            assert dxa.password == 'Wonderland'
            assert dxa.read('den/hatter.txt') == HATTER

    def test_wrong_password_raises(self, tmp_path):
        path = _write(tmp_path, {'alice.txt': ALICE}, key=derive_key('Wonderland'))
        with pytest.raises(ValueError, match='password'):
            DXAFile(path, password='Looking-Glass')

    def test_shift_jis_names(self, tmp_path):
        tree = {'不思議の国': {'アリス.txt': ALICE}}
        assert _contents(_write(tmp_path, tree)) == {'不思議の国/アリス.txt': ALICE}

    def test_utf8_codepage(self, tmp_path):
        path = _write(tmp_path, {'アリス.txt': ALICE}, codepage=65001)
        assert _contents(path) == {'アリス.txt': ALICE}

    def test_timestamps(self, tmp_path):
        # 2015-07-04 12:00:00 UTC as a FILETIME.
        filetime = 130804848000000000
        path = _write(tmp_path, {'alice.txt': ALICE}, times=(filetime, filetime, filetime))
        with DXAFile(path) as dxa:
            assert dxa.files[0].write_time == filetime

    def test_extract_all(self, tmp_path):
        path = _write(tmp_path, {'rabbit_hole.txt': ALICE, 'tea_party': {'hatter.txt': HATTER}})
        out = tmp_path / 'out'
        with DXAFile(path) as dxa:
            dxa.extract_all(out)
        assert (out / 'rabbit_hole.txt').read_bytes() == ALICE
        assert (out / 'tea_party' / 'hatter.txt').read_bytes() == HATTER

    def test_extract_all_glob(self, tmp_path):
        path = _write(tmp_path, {'alice.txt': ALICE, 'queen.bin': QUEEN})
        out = tmp_path / 'out'
        with DXAFile(path) as dxa:
            dxa.extract_all(out, glob='*.txt')
        assert sorted(os.listdir(out)) == ['alice.txt']

    def test_missing_member_raises(self, tmp_path):
        with DXAFile(_write(tmp_path, {'alice.txt': ALICE})) as dxa, pytest.raises(KeyError):
            dxa.read('cheshire.txt')


@pytest.mark.unit
class TestReadCorrupt:
    def _patch_index(self, tmp_path, tree, patch):
        plain = bytearray(_xor(_build(tree), 0, DEFAULT_KEY))
        _sig, _ver, index_size, _data, index_offset, file_table, dir_table, _cp = struct.unpack_from('<2sH6I', plain)
        patch(plain, index_offset, file_table, dir_table)
        path = tmp_path / 'bad.dxa'
        path.write_bytes(_xor(bytes(plain), 0, DEFAULT_KEY))
        return path

    def test_directory_loop_raises(self, tmp_path):
        def loop(plain, index_offset, file_table, _dir_table):
            # Point the sub-directory's record back at the root directory.
            struct.pack_into('<I', plain, index_offset + file_table + 0x2C + 0x20, 0)

        path = self._patch_index(tmp_path, {'den': {'alice.txt': ALICE}}, loop)
        with pytest.raises(ValueError, match='loop'):
            DXAFile(path)

    def test_member_past_end_raises(self, tmp_path):
        def grow(plain, index_offset, file_table, _dir_table):
            struct.pack_into('<I', plain, index_offset + file_table + 0x2C + 0x24, 0x7FFFFFFF)

        path = self._patch_index(tmp_path, {'alice.txt': ALICE}, grow)
        with pytest.raises(ValueError, match='past the end'):
            DXAFile(path)

    def test_child_count_past_table_raises(self, tmp_path):
        def many(plain, index_offset, _file_table, dir_table):
            struct.pack_into('<I', plain, index_offset + dir_table + 8, 100000)

        path = self._patch_index(tmp_path, {'alice.txt': ALICE}, many)
        with pytest.raises(ValueError):
            DXAFile(path)

    def test_not_an_archive_raises(self, tmp_path):
        path = tmp_path / 'tea.txt'
        path.write_bytes(b'Twinkle, twinkle, little bat! How I wonder what you are!')
        with pytest.raises(ValueError):
            DXAFile(path)

    def test_too_short_raises(self, tmp_path):
        path = tmp_path / 'tiny.dxa'
        path.write_bytes(b'DX')
        with pytest.raises(ValueError):
            DXAFile(path)


@pytest.mark.unit
class TestDetect:
    @pytest.mark.parametrize(
        'key', [DEFAULT_KEY, PLAIN_KEY, derive_key('Wonderland')], ids=['default', 'plain', 'password']
    )
    def test_detects(self, tmp_path, key):
        assert is_dxa(_write(tmp_path, {'alice.txt': ALICE}, key=key))

    def test_rejects_other_data(self, tmp_path):
        path = tmp_path / 'tea.txt'
        path.write_bytes(b'Twinkle, twinkle, little bat! How I wonder what you are!' * 4)
        assert not is_dxa(path)

    def test_rejects_missing_file(self, tmp_path):
        assert not is_dxa(tmp_path / 'nowhere.dxa')


def _make_source(tmp_path, files):
    src = tmp_path / 'src'
    for name, data in files.items():
        p = src / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return src


WRITE_FILES = {
    'rabbit_hole.txt': ALICE,
    'tea_party/hatter.txt': HATTER,
    'tea_party/dormouse/treacle.txt': b'Twinkle, twinkle',
    'croquet/queen.txt': QUEEN,
    'empty.txt': b'',
}


@pytest.mark.unit
class TestWrite:
    def test_roundtrip(self, tmp_path):
        src = _make_source(tmp_path, WRITE_FILES)
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w') as dxa:
            dxa.write_all(src)
        assert _contents(out) == WRITE_FILES

    def test_layout(self, tmp_path):
        src = _make_source(tmp_path, {'alice.txt': ALICE})
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w') as dxa:
            dxa.write_all(src)
        plain = _xor(out.read_bytes(), 0, DEFAULT_KEY)
        sig, version, index_size, data_start, index_offset, file_table, dir_table, codepage = struct.unpack_from(
            '<2sH6I', plain
        )
        assert (sig, version, data_start, codepage) == (b'DX', 4, 0x1C, 932)
        assert index_offset + index_size == len(plain)
        assert plain[0x1C : 0x1C + len(ALICE)] == ALICE
        index = plain[index_offset:]
        # Root name record, then 'alice.txt'.
        assert index[:4] == b'\0\0\0\0'
        assert index[4:].startswith(_name_record('alice.txt'))
        # Root record, then the file.
        root = struct.unpack_from('<II3QIII', index, file_table)
        assert root == (0, 0x10, 0, 0, 0, 0, 0, 0xFFFFFFFF)
        assert struct.unpack_from('<4I', index, dir_table) == (0, 0xFFFFFFFF, 1, 0x2C)

    def test_name_records_uppercase_ascii_only(self, tmp_path):
        # The cp932 trail byte of 'ヂ' is 0x61 ('a') and must survive uppercasing.
        name = 'ヂa.txt'
        assert name.encode('cp932')[1] == 0x61
        src = _make_source(tmp_path, {name: ALICE})
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w') as dxa:
            dxa.write_all(src)
        index = _xor(out.read_bytes(), 0, DEFAULT_KEY)[0x1C + len(ALICE) :]
        units, parity = struct.unpack_from('<HH', index, 4)
        upper = index[8 : 8 + units * 4].rstrip(b'\0')
        assert upper == b'\x83\x61A.TXT'
        assert parity == sum(upper)
        assert _contents(out) == {name: ALICE}

    def test_password(self, tmp_path):
        src = _make_source(tmp_path, {'alice.txt': ALICE})
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w', password='Wonderland') as dxa:
            dxa.write_all(src)
        assert _xor(out.read_bytes()[:2], 0, derive_key('Wonderland')) == b'DX'
        assert _contents(out, password='Wonderland') == {'alice.txt': ALICE}

    def test_compress_only_when_smaller(self, tmp_path):
        noise = os.urandom(4096)
        src = _make_source(tmp_path, {'queen.txt': QUEEN, 'noise.bin': noise})
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w', compress=True) as dxa:
            dxa.write_all(src)
        with DXAFile(out) as dxa:
            by_name = {i.file_name: i for i in dxa.files}
            assert by_name['queen.txt'].packed_size is not None
            assert by_name['noise.bin'].packed_size is None
            assert dxa.read('queen.txt') == QUEEN
            assert dxa.read('noise.bin') == noise

    def test_uncompressed_by_default(self, tmp_path):
        src = _make_source(tmp_path, {'queen.txt': QUEEN})
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w') as dxa:
            dxa.write_all(src)
        with DXAFile(out) as dxa:
            assert dxa.files[0].packed_size is None

    def test_timestamps_come_from_source(self, tmp_path):
        src = _make_source(tmp_path, {'alice.txt': ALICE})
        os.utime(src / 'alice.txt', (1436011200, 1436011200))  # 2015-07-04 12:00:00 UTC
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w') as dxa:
            dxa.write_all(src)
        with DXAFile(out) as dxa:
            assert dxa.files[0].write_time == 130804848000000000
            assert dxa.files[0].access_time == 130804848000000000

    def test_glob(self, tmp_path):
        src = _make_source(tmp_path, WRITE_FILES)
        out = tmp_path / 'out.dxa'
        with DXAFile(out, mode='w') as dxa:
            dxa.write_all(src, glob='tea_party/*')
        assert sorted(_contents(out)) == ['tea_party/dormouse/treacle.txt', 'tea_party/hatter.txt']

    def test_duplicate_name_raises(self, tmp_path):
        src = _make_source(tmp_path, {'alice.txt': ALICE})
        with DXAFile(tmp_path / 'out.dxa', mode='w') as dxa:
            dxa.write(src / 'alice.txt')
            with pytest.raises(ValueError, match='Duplicate'):
                dxa.write(src / 'alice.txt', arcname='ALICE.TXT')

    def test_file_and_directory_clash_raises(self, tmp_path):
        src = _make_source(tmp_path, {'alice.txt': ALICE})
        with DXAFile(tmp_path / 'out.dxa', mode='w') as dxa:
            dxa.write(src / 'alice.txt', arcname='den')
            with pytest.raises(ValueError, match='den'):
                dxa.write(src / 'alice.txt', arcname='den/alice.txt')

    def test_unencodable_name_raises(self, tmp_path):
        src = _make_source(tmp_path, {'alice.txt': ALICE})
        with DXAFile(tmp_path / 'out.dxa', mode='w') as dxa, pytest.raises(ValueError, match='cp932'):
            dxa.write(src / 'alice.txt', arcname='🐇.txt')

    def test_does_not_pack_itself(self, tmp_path):
        src = _make_source(tmp_path, {'alice.txt': ALICE})
        out = src / 'out.dxa'
        with DXAFile(out, mode='w') as dxa:
            dxa.write_all(src)
        assert _contents(out) == {'alice.txt': ALICE}

    def test_invalid_mode(self, tmp_path):
        with pytest.raises(ValueError, match='mode'):
            DXAFile(tmp_path / 'out.dxa', mode='a')
