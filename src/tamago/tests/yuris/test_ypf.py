"""Tests for reading and writing YPF archives."""

import struct
import zlib

import pytest

from tamago.formats.yuris import YPFFile, is_ycg
from tamago.formats.yuris.ypf import LENGTH_TABLES, archive_params
from tamago.tests.yuris.samples import (
    ALICE,
    CHESHIRE,
    CURIOUS,
    RABBIT,
    TABLE_A,
    TABLE_D,
    build_ycg,
    build_ypf,
    murmur2,
    swap,
)

YCG = build_ycg(2, 2, bytes(range(16)))
MEMBERS = [
    ('ysbin\\yst00000.ybn', CHESHIRE, 0, True),
    ('bg\\rabbit.png', b'\x89PNG\r\n\x1a\n' + RABBIT, 2, False),
    ('se\\tea_party.ogg', b'OggS' + ALICE, 6, False),
    ('cgsys\\cheshire.png', YCG, 8, False),
    ('voice\\アリス_001.ogg', b'OggS' + CURIOUS, 6, True),
]


def _write(tmp_path, data, name='alice.ypf'):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _populate(root, members=MEMBERS):
    for name, data, _type, _packed in members:
        path = root.joinpath(*name.split('\\'))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def _index(path):
    """Parse an archive's index with the reference rules (version, then entries)."""
    data = path.read_bytes()
    _magic, version, count, index_end = struct.unpack_from('<4sIII', data)
    wide = version >= 478
    entries, pos = [], 0x20
    for _ in range(count):
        name_hash, enc_len = struct.unpack_from('<IB', data, pos)
        raw = data[pos + 5 : pos + 5 + 255]
        entries.append((name_hash, enc_len, raw, pos))
        # Length is recovered by matching the hash, so this needs no table.
        for length in range(1, 256):
            key = raw[length - 4] ^ 0x2E if length >= 4 else 0xFF
            name = bytes(b ^ key for b in raw[:length])
            if (murmur2 if wide else zlib.crc32)(name) == name_hash:
                break
        tail = data[pos + 5 + length :]
        file_type, packed, usize, psize = struct.unpack_from('<BBII', tail)
        offset, check = struct.unpack_from('<QI' if wide else '<II', tail, 10)
        entries[-1] = {
            'hash': name_hash,
            'enc_len': enc_len,
            'name': name,
            'key': key,
            'type': file_type,
            'packed': packed,
            'usize': usize,
            'psize': psize,
            'offset': offset,
            'check': check,
        }
        pos += 5 + length + (22 if wide else 18)
    assert pos == index_end
    return version, entries, data


@pytest.mark.integration
class TestRead:
    @pytest.mark.parametrize('version', [461, 476, 477, 478, 494, 500])
    def test_reads_members_across_versions(self, tmp_path, version):
        path = _write(tmp_path, build_ypf(MEMBERS, version=version, order=[3, 0, 4, 2, 1]))
        with YPFFile(path) as ypf:
            assert ypf.version == version
            assert ypf.key == 0xFF
            assert sorted(info.file_name for info in ypf.files) == sorted(m[0] for m in MEMBERS)
            for name, data, file_type, packed in MEMBERS:
                info = ypf.getinfo(name)
                assert (info.file_type, info.packed, info.size) == (file_type, packed, len(data))
                assert ypf.read(name) == data

    def test_custom_key_and_length_table(self, tmp_path):
        """CLOCKUP-style archives: key 0xC9 and table D, which encodes these lengths differently from A."""
        members = [
            ('cg\\tea.png', ALICE, 2, False),  # 10 = 0x0A
            ('cg\\knave_tart.png', RABBIT, 2, False),  # 17 = 0x11
            ('cg\\mock_turtle_1.png', CURIOUS, 2, False),  # 20 = 0x14
            ('cg\\caterpillar_smoke.png', CHESHIRE, 2, False),  # 24 = 0x18
            ('cg\\queen_of_hearts_12.png', ALICE, 2, False),  # 25 = 0x19
        ]
        path = _write(tmp_path, build_ypf(members, key=0xC9, table=TABLE_D))
        with YPFFile(path) as ypf:
            assert ypf.key == 0xC9
            assert ypf.length_table == 'd'
            for name, data, *_ in members:
                assert ypf.read(name) == data

    def test_unknown_length_table_still_reads(self, tmp_path):
        odd = [(0x0D, 0x40)]  # a table no game is known to use
        path = _write(tmp_path, build_ypf(MEMBERS, table=odd))
        with YPFFile(path) as ypf:
            assert ypf.length_table is None
            assert ypf.read('bg\\rabbit.png').endswith(RABBIT)

    def test_short_names_with_no_extension(self, tmp_path):
        members = [('a', ALICE, 0, False), ('bg\\rabbit.png', RABBIT, 2, False)]
        path = _write(tmp_path, build_ypf(members, key=0x34))
        with YPFFile(path) as ypf:
            assert ypf.read('a') == ALICE
            assert ypf.key == 0x34

    def test_empty_archive(self, tmp_path):
        path = _write(tmp_path, build_ypf([]))
        assert path.stat().st_size == 0x20
        with YPFFile(path) as ypf:
            assert ypf.files == []
            ypf.extract_all(tmp_path / 'out')
        assert (tmp_path / 'out').is_dir()

    def test_testzip_reports_bad_checksum(self, tmp_path):
        data = bytearray(build_ypf(MEMBERS[:2], version=500))
        data[-1] ^= 0x01  # last stored byte belongs to the second member written
        path = _write(tmp_path, bytes(data))
        with YPFFile(path) as ypf:
            assert ypf.testzip() == MEMBERS[1][0]

    def test_testzip_clean(self, tmp_path):
        for version in (461, 500):
            path = _write(tmp_path, build_ypf(MEMBERS, version=version), f'v{version}.ypf')
            with YPFFile(path) as ypf:
                assert ypf.testzip() is None

    def test_not_a_ypf(self, tmp_path):
        path = _write(tmp_path, b'Down the Rabbit-Hole' * 4)
        with pytest.raises(ValueError, match='not a YPF archive'):
            YPFFile(path)

    def test_corrupt_index(self, tmp_path):
        data = bytearray(build_ypf(MEMBERS))
        data[0x20:0x24] = b'\0\0\0\0'  # first name hash no longer matches any length
        path = _write(tmp_path, bytes(data))
        with pytest.raises(ValueError, match='index'):
            YPFFile(path)

    def test_extract_all_with_glob(self, tmp_path):
        path = _write(tmp_path, build_ypf(MEMBERS))
        out = tmp_path / 'out'
        with YPFFile(path) as ypf:
            ypf.extract_all(out, glob='se\\*')
        assert [p.name for p in out.rglob('*') if p.is_file()] == ['tea_party.ogg']
        assert (out / 'se' / 'tea_party.ogg').read_bytes() == b'OggS' + ALICE

    def test_extract_refuses_unsafe_names(self, tmp_path):
        path = _write(tmp_path, build_ypf([('..\\..\\mad_tea.ybn', ALICE, 0, False)]))
        with YPFFile(path) as ypf, pytest.raises(ValueError, match='unsafe'):
            ypf.extract_all(tmp_path / 'out')

    def test_extract_converts_ycg(self, tmp_path):
        from PIL import Image

        path = _write(tmp_path, build_ypf(MEMBERS))
        out = tmp_path / 'out'
        with YPFFile(path) as ypf:
            ypf.extract_all(out, convert_ycg=True)
        with Image.open(out / 'cgsys' / 'cheshire.png') as image:
            assert image.format == 'PNG'
            assert image.size == (2, 2)
        # Real PNGs are left untouched.
        assert (out / 'bg' / 'rabbit.png').read_bytes() == MEMBERS[1][1]


@pytest.mark.integration
class TestArchiveParams:
    def test_params_from_archive(self, tmp_path):
        path = _write(tmp_path, build_ypf(MEMBERS, version=479, key=0xC9, table=TABLE_D))
        params = archive_params(path)
        assert params == {'version': 479, 'key': 0xC9, 'length_table': 'd'}

    def test_params_ambiguous_table_prefers_standard(self, tmp_path):
        # Names of length 13 and 18 are encoded identically by tables A and D.
        members = [('bg\\rabbit.png', RABBIT, 2, False), ('ysbin\\yst00000.ybn', ALICE, 0, True)]
        path = _write(tmp_path, build_ypf(members, table=TABLE_A))
        assert archive_params(path)['length_table'] == 'a'

    def test_params_ambiguous_table_with_key_c9_prefers_d(self, tmp_path):
        members = [('bg\\rabbit.png', RABBIT, 2, False), ('ysbin\\yst00000.ybn', ALICE, 0, True)]
        path = _write(tmp_path, build_ypf(members, key=0xC9, table=TABLE_D))
        assert archive_params(path)['length_table'] == 'd'


@pytest.mark.integration
class TestWrite:
    @pytest.mark.parametrize('version', [461, 477, 478, 500])
    def test_roundtrip_and_engine_invariants(self, tmp_path, version):
        src = _populate(tmp_path / 'src')
        out = tmp_path / 'out.ypf'
        with YPFFile(out, mode='w', version=version) as ypf:
            ypf.write_all(src)
        got_version, entries, data = _index(out)
        assert got_version == version
        hashes = [e['hash'] for e in entries]
        assert hashes == sorted(hashes), "the engine expects the index sorted by name hash"
        check = murmur2 if version >= 478 else zlib.adler32
        expected = {name: (blob, file_type) for name, blob, file_type, _ in MEMBERS}
        for e in entries:
            name = e['name'].decode('cp932')
            stored = data[e['offset'] : e['offset'] + e['psize']]
            assert e['check'] == check(stored)
            assert e['key'] == 0xFF
            assert e['enc_len'] == ~swap(TABLE_A, len(e['name'])) & 0xFF
            content = zlib.decompress(stored) if e['packed'] else stored
            assert (content, e['type']) == expected[name]
            assert e['usize'] == len(content)

    def test_names_use_backslashes(self, tmp_path):
        src = _populate(tmp_path / 'src')
        out = tmp_path / 'out.ypf'
        with YPFFile(out, mode='w') as ypf:
            ypf.write_all(src)
        with YPFFile(out) as ypf:
            assert 'voice\\アリス_001.ogg' in ypf.namelist()

    def test_key_and_table_are_applied(self, tmp_path):
        src = _populate(tmp_path / 'src', [('cg\\knave_tart.png', CURIOUS, 2, False)])
        out = tmp_path / 'out.ypf'
        with YPFFile(out, mode='w', key=0xC9, length_table='d') as ypf:
            ypf.write_all(src)
        _v, (entry,), _d = _index(out)
        assert entry['key'] == 0xC9
        assert entry['enc_len'] == ~0x18 & 0xFF  # 17 = 0x11 <-> 0x18 in table D

    def test_default_compression_by_version(self, tmp_path):
        src = _populate(tmp_path / 'src')
        packed = {}
        for version in (477, 500):
            out = tmp_path / f'{version}.ypf'
            with YPFFile(out, mode='w', version=version) as ypf:
                ypf.write_all(src)
            packed[version] = {e['name'].decode('cp932') for e in _index(out)[1] if e['packed']}
        # Only members that shrink are compressed; v478+ restricts that to scripts.
        assert packed[500] == {'ysbin\\yst00000.ybn'}
        assert 'ysbin\\yst00000.ybn' in packed[477]
        assert 'bg\\rabbit.png' not in packed[477]  # too short to shrink

    def test_compress_flags(self, tmp_path):
        src = _populate(tmp_path / 'src', [('se\\mad.ogg', CHESHIRE, 6, False)])
        for compress, expected in ((True, 1), (False, 0)):
            out = tmp_path / f'{compress}.ypf'
            with YPFFile(out, mode='w', version=500, compress=compress) as ypf:
                ypf.write_all(src)
            assert _index(out)[1][0]['packed'] == expected

    def test_ycg_content_gets_type_8(self, tmp_path):
        src = _populate(tmp_path / 'src', [('cgsys\\cheshire.png', YCG, 8, False)])
        out = tmp_path / 'out.ypf'
        with YPFFile(out, mode='w') as ypf:
            ypf.write_all(src)
        assert _index(out)[1][0]['type'] == 8

    def test_encode_ycg_converts_real_pngs(self, tmp_path):
        from PIL import Image

        src = tmp_path / 'src'
        (src / 'cg').mkdir(parents=True)
        Image.new('RGBA', (3, 2), (255, 128, 0, 200)).save(src / 'cg' / 'alice.png')
        (src / 'cg' / 'notes.txt').write_bytes(ALICE)
        out = tmp_path / 'out.ypf'
        with YPFFile(out, mode='w', encode_ycg=True) as ypf:
            ypf.write_all(src)
        with YPFFile(out) as ypf:
            assert ypf.getinfo('cg\\alice.png').file_type == 8
            assert is_ycg(ypf.read('cg\\alice.png'))
            assert ypf.read('cg\\notes.txt') == ALICE

    @pytest.mark.parametrize('version', [0, -1, 2**32])
    def test_bad_version(self, tmp_path, version):
        with pytest.raises(ValueError, match='version'):
            YPFFile(tmp_path / 'x.ypf', mode='w', version=version)

    def test_bad_table_and_key(self, tmp_path):
        with pytest.raises(ValueError, match='length table'):
            YPFFile(tmp_path / 'x.ypf', mode='w', length_table='z')
        with pytest.raises(ValueError, match='key'):
            YPFFile(tmp_path / 'x.ypf', mode='w', key=256)

    def test_rejects_duplicate_names(self, tmp_path):
        (tmp_path / 'alice.ybn').write_bytes(ALICE)
        with YPFFile(tmp_path / 'x.ypf', mode='w') as ypf:
            ypf.write(tmp_path / 'alice.ybn', 'ysbin\\alice.ybn')
            with pytest.raises(ValueError, match='Duplicate'):
                ypf.write(tmp_path / 'alice.ybn', 'ysbin/alice.ybn')

    def test_rejects_unencodable_and_long_names(self, tmp_path):
        (tmp_path / 'alice.ybn').write_bytes(ALICE)
        with YPFFile(tmp_path / 'x.ypf', mode='w') as ypf:
            with pytest.raises(ValueError, match='cp932'):
                ypf.write(tmp_path / 'alice.ybn', 'ysbin\\🐇.ybn')
            with pytest.raises(ValueError, match='255'):
                ypf.write(tmp_path / 'alice.ybn', 'a' * 256)

    def test_glob_and_skips_output_inside_source(self, tmp_path):
        src = _populate(tmp_path / 'src')
        out = src / 'pac.ypf'
        with YPFFile(out, mode='w') as ypf:
            ypf.write_all(src, glob='se/*')
        with YPFFile(out) as ypf:
            assert ypf.namelist() == ['se\\tea_party.ogg']

    def test_length_tables_are_involutions(self):
        for name, pairs in LENGTH_TABLES.items():
            values = [v for pair in pairs for v in pair]
            assert len(values) == len(set(values)), name
