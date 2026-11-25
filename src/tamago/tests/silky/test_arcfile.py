"""Tests for reading and writing Silky's .arc archives."""

import json
import struct

import pytest

from tamago.formats.silky import MANIFEST_NAME, ARCFile, decode_name, encode_name, is_silky_arc
from tamago.tests.ai6win.samples import ARCHIVE as AI6WIN_ARCHIVE
from tamago.tests.silky.samples import (
    ARCHIVE,
    CONTENTS,
    MEMBERS,
    OGG,
    QUEEN,
    QUEEN_LZSS,
    TEA_TEA_TEA,
    WAV,
    build_arc,
    literal_lzss,
    obfuscate,
)


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / 'Script.arc'
    path.write_bytes(ARCHIVE)
    return path


def _populate(root, files):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _extracted(archive, tmp_path):
    out = tmp_path / 'out'
    with ARCFile(archive) as arc:
        arc.extract_all(out)
    return out


@pytest.mark.unit
class TestNames:
    def test_worked_example(self):
        stored = bytes.fromhex('3b 42 38 3f 42 48 44 2a 4a 43 52')
        assert decode_name(stored) == b'FLAGINI.MES'
        assert encode_name(b'FLAGINI.MES') == stored

    def test_alice(self):
        assert encode_name(b'alice.mes') == bytes.fromhex('58 64 62 5d 60 2a 6a 63 72')

    def test_matches_independent_obfuscation(self):
        for name, _stored, _unpacked in MEMBERS:
            assert encode_name(name) == obfuscate(name)
            assert decode_name(obfuscate(name)) == name

    def test_longest_name_wraps_key(self):
        # The first byte's key is 255; 'a' - 255 wraps to 0x62.
        name = b'a' * 255
        stored = encode_name(name)
        assert stored[0] == (ord('a') - 255) & 0xFF
        assert stored[-1] == ord('a') - 1
        assert decode_name(stored) == name

    def test_stored_byte_may_be_nul(self):
        # Names are length-prefixed, so an obfuscated zero is harmless: in a
        # 65-byte name the first byte's key is 65, the code of 'A'.
        name = b'A' + b'a' * 60 + b'.MES'
        stored = encode_name(name)
        assert stored[0] == 0
        assert decode_name(stored) == name

    @pytest.mark.parametrize('name', [b'', b'a' * 256, b'tea\0party.mes'], ids=['empty', 'overlong', 'nul'])
    def test_refuses_bad_name(self, name):
        with pytest.raises(ValueError):
            encode_name(name)


@pytest.mark.unit
class TestRead:
    def test_lists_members_in_index_order(self, archive):
        with ARCFile(archive) as arc:
            assert arc.namelist() == list(CONTENTS)

    def test_entry_fields(self, archive):
        with ARCFile(archive) as arc:
            info = arc.getinfo('ALICE.MES')
            index_size = struct.unpack_from('<I', ARCHIVE)[0]
            assert info.offset == 4 + index_size
            assert info.size == len(QUEEN_LZSS)
            assert info.unpacked_size == len(QUEEN)
            assert info.compressed
            assert info.raw_name == b'ALICE.MES'
            assert not arc.getinfo('CHESHIRE.OGG').compressed

    def test_reads_stored_and_compressed_members(self, archive):
        with ARCFile(archive) as arc:
            assert {name: arc.read(name) for name in arc.namelist()} == CONTENTS

    def test_read_by_info(self, archive):
        with ARCFile(archive) as arc:
            assert arc.read(arc.files[2]) == TEA_TEA_TEA

    def test_reads_literal_only_lzss(self, tmp_path):
        # A minimal packer may send every byte as a literal; the game accepts it.
        path = tmp_path / 'Script.arc'
        path.write_bytes(build_arc([(b'ALICE.MES', literal_lzss(QUEEN), len(QUEEN))]))
        with ARCFile(path) as arc:
            assert arc.read('ALICE.MES') == QUEEN

    def test_unknown_member(self, archive):
        with ARCFile(archive) as arc, pytest.raises(KeyError):
            arc.read('DORMOUSE.MES')

    def test_empty_member(self, tmp_path):
        path = tmp_path / 'empty.arc'
        path.write_bytes(build_arc([(b'NOTHING.MES', b'', 0)]))
        with ARCFile(path) as arc:
            assert arc.read('NOTHING.MES') == b''

    def test_closed_archive(self, archive):
        arc = ARCFile(archive)
        arc.close()
        with pytest.raises(ValueError):
            arc.read('ALICE.MES')

    @pytest.mark.parametrize(
        'data',
        [
            b'',
            b'\x01\0\0',
            struct.pack('<I', 100) + bytes(20),  # index longer than the file
            ARCHIVE[:4] + b'\0' + ARCHIVE[5:],  # zero-length name
            struct.pack('<I', 5) + b'\x03' + obfuscate(b'TEA') + b'\0' + OGG,  # entry cut short by the index end
            build_arc([(b'\x81.OGG', OGG, len(OGG))]),  # undecodable cp932
        ],
        ids=['empty', 'short-header', 'index-past-eof', 'empty-name', 'truncated-entry', 'bad-cp932'],
    )
    def test_rejects_malformed(self, tmp_path, data):
        path = tmp_path / 'bad.arc'
        path.write_bytes(data)
        with pytest.raises(ValueError):
            ARCFile(path)

    def test_rejects_member_past_end_of_file(self, tmp_path):
        path = tmp_path / 'bad.arc'
        path.write_bytes(ARCHIVE[:-1])
        with pytest.raises(ValueError, match='outside'):
            ARCFile(path)

    def test_rejects_member_inside_index(self, tmp_path):
        data = bytearray(build_arc([(b'CHESHIRE.OGG', OGG, len(OGG))]))
        struct.pack_into('>I', data, 4 + 1 + len(b'CHESHIRE.OGG') + 8, 4)
        path = tmp_path / 'bad.arc'
        path.write_bytes(data)
        with pytest.raises(ValueError, match='outside'):
            ARCFile(path)

    def test_reads_archive_with_gap_after_index(self, tmp_path):
        # Not what the games' packer makes, but nothing forbids it.
        path = tmp_path / 'gap.arc'
        path.write_bytes(build_arc(MEMBERS, gap=16))
        with ARCFile(path) as arc:
            assert {name: arc.read(name) for name in arc.namelist()} == CONTENTS


@pytest.mark.unit
class TestDetection:
    def test_recognises_archive(self, archive):
        assert is_silky_arc(archive)

    @pytest.mark.parametrize(
        'data',
        [
            b'',
            bytes(16),
            struct.pack('<I', 0),  # no members
            ARCHIVE[:-1],
            build_arc(MEMBERS, gap=16),  # data does not start right after the index
            build_arc([(b'TEA\x01PARTY.MES', OGG, len(OGG))]),  # control character
            AI6WIN_ARCHIVE,
            # AdvHD v2: file count, index size, then UTF-16 names.
            struct.pack('<IIII', 1, 26, len(OGG), 0) + 'alice.ogg'.encode('utf-16-le') + b'\0\0' + OGG,
            b'LINK6\0\0\0' + bytes(0x200),
        ],
        ids=['empty', 'zeros', 'no-members', 'truncated', 'gap', 'control-char', 'ai6win', 'advhd', 'link6'],
    )
    def test_rejects_other_files(self, tmp_path, data):
        path = tmp_path / 'other.arc'
        path.write_bytes(data)
        assert not is_silky_arc(path)

    def test_missing_file(self, tmp_path):
        assert not is_silky_arc(tmp_path / 'missing.arc')


@pytest.mark.integration
class TestExtract:
    def test_extracts_members_and_manifest(self, archive, tmp_path):
        out = _extracted(archive, tmp_path)
        for name, data in CONTENTS.items():
            assert (out / name).read_bytes() == data
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert manifest['format'] == 'silky'
        assert manifest['members'] == [
            {'name': 'ALICE.MES', 'compressed': True},
            {'name': 'CHESHIRE.OGG', 'compressed': False},
            {'name': 'TEA_PARTY.BIN', 'compressed': True},
            {'name': 'WHITE_RABBIT.WAV', 'compressed': False},
            {'name': 'ハートの女王.BRT', 'compressed': True},
        ]

    def test_glob_selects_members(self, archive, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(archive) as arc:
            arc.extract_all(out, glob='*.MES')
        assert sorted(p.name for p in out.iterdir()) == ['ALICE.MES', MANIFEST_NAME]
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert manifest['members'] == [{'name': 'ALICE.MES', 'compressed': True}]

    def test_member_named_like_manifest_refused(self, tmp_path):
        path = tmp_path / 'data.arc'
        path.write_bytes(build_arc([(MANIFEST_NAME.encode(), OGG, len(OGG))]))
        with ARCFile(path) as arc, pytest.raises(ValueError, match='manifest'):
            arc.extract_all(tmp_path / 'out')

    def test_unsafe_member_name_refused(self, tmp_path):
        path = tmp_path / 'data.arc'
        path.write_bytes(build_arc([(b'../RABBIT_HOLE.OGG', OGG, len(OGG))]))
        with ARCFile(path) as arc, pytest.raises(ValueError, match='unsafe'):
            arc.extract_all(tmp_path / 'out')
        assert not (tmp_path / 'RABBIT_HOLE.OGG').exists()

    def test_extract_single_member(self, archive, tmp_path):
        with ARCFile(archive) as arc:
            arc.extract('ALICE.MES', tmp_path / 'alice.mes')
        assert (tmp_path / 'alice.mes').read_bytes() == QUEEN


@pytest.mark.integration
class TestCreate:
    def test_rebuild_from_manifest_is_byte_identical(self, archive, tmp_path):
        out = _extracted(archive, tmp_path)
        rebuilt = tmp_path / 'rebuilt.arc'
        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == ARCHIVE

    def test_without_manifest_sorts_by_name_bytes_and_compresses_by_extension(self, tmp_path):
        src = tmp_path / 'src'
        _populate(
            src,
            {'seg_000.wav': WAV, 'SEG_001.WAV': WAV, 'SEG_000A.WAV': WAV, 'ALICE.MES': QUEEN, 'CAT.OGG': OGG},
        )
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            # Plain byte order: '_' sorts after 'A' and lower case after upper.
            assert arc.namelist() == ['ALICE.MES', 'CAT.OGG', 'SEG_000A.WAV', 'SEG_001.WAV', 'seg_000.wav']
            assert [i.compressed for i in arc.files] == [True, False, False, False, False]
            assert arc.read('ALICE.MES') == QUEEN
        assert is_silky_arc(path)

    @pytest.mark.parametrize('ext', ['.MES', '.lib', '.BIN', '.area', '.BRT'])
    def test_scripts_and_data_compressed_by_default(self, tmp_path, ext):
        src = tmp_path / 'src'
        _populate(src, {'QUEEN' + ext: QUEEN})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert arc.files[0].compressed
            assert arc.files[0].size == len(QUEEN_LZSS)

    @pytest.mark.parametrize(('compress', 'expected'), [(True, [True, True]), (False, [False, False])])
    def test_compress_overrides_extension(self, tmp_path, compress, expected):
        src = tmp_path / 'src'
        _populate(src, {'A.MES': QUEEN, 'B.OGG': QUEEN})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w', compress=compress) as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert [i.compressed for i in arc.files] == expected
            assert arc.read('A.MES') == QUEEN

    def test_compress_overrides_manifest(self, archive, tmp_path):
        out = _extracted(archive, tmp_path)
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w', compress=False) as arc:
            arc.write_all(out)
        with ARCFile(path) as arc:
            assert not any(i.compressed for i in arc.files)
            assert {name: arc.read(name) for name in arc.namelist()} == CONTENTS

    def test_member_that_does_not_shrink_is_stored(self, tmp_path):
        # 'tea tea' compresses to exactly 7 bytes, which would read back as stored.
        src = tmp_path / 'src'
        _populate(src, {'TEA.MES': b'tea tea', 'EMPTY.MES': b''})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert not arc.getinfo('TEA.MES').compressed
            assert arc.read('TEA.MES') == b'tea tea'
            assert arc.read('EMPTY.MES') == b''

    def test_write_with_arcname(self, tmp_path):
        src = tmp_path / 'queen.txt'
        src.write_bytes(QUEEN)
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write(src, arcname='QUEEN.MES')
        with ARCFile(path) as arc:
            assert arc.namelist() == ['QUEEN.MES']
            assert arc.files[0].compressed
            assert arc.read('QUEEN.MES') == QUEEN

    def test_replaced_member_keeps_its_place(self, archive, tmp_path):
        out = _extracted(archive, tmp_path)
        (out / 'TEA_PARTY.BIN').write_bytes(b'Why is a raven like a writing-desk?')
        path = tmp_path / 'patched.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(out)
        with ARCFile(path) as arc:
            assert arc.namelist() == list(CONTENTS)
            assert arc.read('TEA_PARTY.BIN') == b'Why is a raven like a writing-desk?'
            assert arc.read('ALICE.MES') == QUEEN

    def test_new_files_join_sorted_manifest_in_order(self, archive, tmp_path):
        # The games' indexes are sorted, so a new member goes where it sorts.
        out = _extracted(archive, tmp_path)
        (out / 'DORMOUSE.MES').write_bytes(QUEEN)
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(out)
        with ARCFile(path) as arc:
            names = list(CONTENTS)
            assert arc.namelist() == [*names[:2], 'DORMOUSE.MES', *names[2:]]

    def test_new_files_follow_unsorted_manifest(self, tmp_path):
        path = tmp_path / 'unsorted.arc'
        path.write_bytes(build_arc([MEMBERS[3], MEMBERS[0]]))
        out = _extracted(path, tmp_path)
        (out / 'DORMOUSE.MES').write_bytes(QUEEN)
        (out / 'CAT.OGG').write_bytes(OGG)
        rebuilt = tmp_path / 'new.arc'
        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        with ARCFile(rebuilt) as arc:
            assert arc.namelist() == ['WHITE_RABBIT.WAV', 'ALICE.MES', 'CAT.OGG', 'DORMOUSE.MES']

    def test_missing_manifest_member(self, archive, tmp_path):
        out = _extracted(archive, tmp_path)
        (out / 'CHESHIRE.OGG').unlink()
        with ARCFile(tmp_path / 'new.arc', mode='w') as arc, pytest.raises(ValueError, match='missing'):
            arc.write_all(out)

    @pytest.mark.parametrize(
        'manifest',
        [
            b'{"format": "ai6win", "members": []}',
            b'{"format": "silky", "members": [{"name": "A.MES"}]}',
            b'{"format": "silky", "members": [{"name": 7, "compressed": true}]}',
            b'not json',
        ],
        ids=['other-format', 'no-compressed', 'bad-name', 'not-json'],
    )
    def test_invalid_manifest(self, tmp_path, manifest):
        src = tmp_path / 'src'
        _populate(src, {MANIFEST_NAME: manifest})
        with ARCFile(tmp_path / 'new.arc', mode='w') as arc, pytest.raises(ValueError, match='manifest'):
            arc.write_all(src)

    def test_glob_filters_files(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'ALICE.MES': QUEEN, 'CAT.OGG': OGG})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src, glob='*.MES')
        with ARCFile(path) as arc:
            assert arc.namelist() == ['ALICE.MES']

    def test_skips_output_inside_source(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'ALICE.MES': QUEEN})
        path = src / 'Script.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert arc.namelist() == ['ALICE.MES']

    def test_cp932_name_that_does_not_roundtrip(self, tmp_path):
        # 0xED40 (an NEC-selected IBM extension) decodes to U+7E8A, which
        # encodes back as the IBM extension 0xFA5C.
        raw = b'\xed\x40.OGG'
        path = tmp_path / 'data.arc'
        path.write_bytes(build_arc([(raw, OGG, len(OGG))]))
        out = tmp_path / 'out'
        with ARCFile(path) as arc:
            assert arc.files[0].raw_name == raw
            arc.extract_all(out)
        rebuilt = tmp_path / 'rebuilt.arc'
        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == path.read_bytes()

    def test_refuses_name_too_long(self, tmp_path):
        src = tmp_path / 'queen.mes'
        src.write_bytes(QUEEN)
        with ARCFile(tmp_path / 'new.arc', mode='w') as arc, pytest.raises(ValueError, match='255'):
            arc.write(src, arcname='Q' * 252 + '.MES')

    def test_refuses_name_not_cp932(self, tmp_path):
        src = tmp_path / 'queen.mes'
        src.write_bytes(QUEEN)
        with ARCFile(tmp_path / 'new.arc', mode='w') as arc, pytest.raises(ValueError, match='cp932'):
            arc.write(src, arcname='QUEEN♛.MES')

    def test_failed_create_leaves_no_partial_archive(self, tmp_path):
        src = tmp_path / 'queen.mes'
        src.write_bytes(QUEEN)
        path = tmp_path / 'new.arc'
        with pytest.raises(ValueError), ARCFile(path, mode='w') as arc:
            arc.write(src)
            raise ValueError('off with its head')
        assert path.read_bytes() == b''

    def test_empty_archive(self, tmp_path):
        path = tmp_path / 'empty.arc'
        with ARCFile(path, mode='w'):
            pass
        assert path.read_bytes() == bytes(4)
        with ARCFile(path) as arc:
            assert arc.files == []

    def test_write_requires_write_mode(self, archive, tmp_path):
        src = tmp_path / 'queen.mes'
        src.write_bytes(QUEEN)
        with ARCFile(archive) as arc, pytest.raises(ValueError):
            arc.write(src)

    def test_invalid_mode(self, tmp_path):
        with pytest.raises(ValueError):
            ARCFile(tmp_path / 'x.arc', mode='a')
