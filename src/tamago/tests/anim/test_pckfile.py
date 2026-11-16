"""Tests for the reader and writer of ANIM packs."""

import struct

import pytest

from tamago.formats.anim import PCKFile, is_pck
from tamago.tests.anim.samples import DRINK_ME, EAT_ME, LIP_SYNC, build_pck, eog, vorbis_ogg

OGG = vorbis_ogg(channels=1, granules=(0, 22050))
VOICE = eog(OGG, 22050 * 2)

MEMBERS = [
    ('b090001g.eog', VOICE),
    ('Mmock100.psb', b'PSB\x00\x03\x00\x01\x00' + DRINK_ME),
    ('mrab100.psb', b'PSB\x00\x03\x00\x01\x00' + EAT_ME),
    ('w000001a.csv', LIP_SYNC),
]


def _pack(tmp_path, members=MEMBERS, name='alice_wave.pck'):
    path = tmp_path / name
    path.write_bytes(build_pck(members))
    return path


def _source_dir(tmp_path, files):
    src = tmp_path / 'src'
    src.mkdir()
    for name, data in files.items():
        (src / name).write_bytes(data)
    return src


@pytest.mark.unit
class TestRead:
    def test_names_and_contents(self, tmp_path):
        with PCKFile(_pack(tmp_path)) as pck:
            assert [info.file_name for info in pck.files] == [name for name, _ in MEMBERS]
            for name, data in MEMBERS:
                assert pck.read(name) == data

    def test_read_by_info(self, tmp_path):
        with PCKFile(_pack(tmp_path)) as pck:
            assert pck.read(pck.files[3]) == LIP_SYNC

    def test_unknown_member(self, tmp_path):
        with PCKFile(_pack(tmp_path)) as pck, pytest.raises(KeyError, match='Cheshire'):
            pck.read('Cheshire.eog')

    def test_cp932_name(self, tmp_path):
        with PCKFile(_pack(tmp_path, [('アリス.csv', LIP_SYNC)])) as pck:
            assert pck.read('アリス.csv') == LIP_SYNC

    def test_reads_after_close_fail(self, tmp_path):
        pck = PCKFile(_pack(tmp_path))
        pck.close()
        with pytest.raises(ValueError, match='closed'):
            pck.read('w000001a.csv')

    @pytest.mark.parametrize(
        'data',
        [
            b'',
            struct.pack('<I', 5) + bytes(20),
            struct.pack('<IIII', 1, 0, 0x1000, 4) + b'alice\0',
            struct.pack('<IIII', 1, 0, 16, 4) + b'abcd',
        ],
        ids=['empty', 'index-too-long', 'data-past-end', 'no-names'],
    )
    def test_not_a_pack(self, tmp_path, data):
        path = tmp_path / 'tarts.pck'
        path.write_bytes(data)
        with pytest.raises(ValueError, match='not an ANIM pack'):
            PCKFile(path)
        assert not is_pck(path)


@pytest.mark.unit
class TestDetection:
    def test_real_layout(self, tmp_path):
        assert is_pck(_pack(tmp_path))

    @pytest.mark.parametrize(
        'mutate',
        [
            lambda d: d[:4] + struct.pack('<I', 7) + d[8:],  # reserved field set
            lambda d: d + b'\0',  # trailing data
            lambda d: d[:-1],  # last member cut short
        ],
        ids=['reserved', 'trailing', 'truncated'],
    )
    def test_strict(self, tmp_path, mutate):
        path = tmp_path / 'tarts.pck'
        path.write_bytes(mutate(build_pck(MEMBERS)))
        assert not is_pck(path)

    def test_gap_between_members(self, tmp_path):
        data = bytearray(build_pck([('a.csv', b'xx'), ('b.csv', b'yy')]))
        # Move the second member one byte later, leaving a gap.
        offset, size = struct.unpack_from('<II', data, 4 + 12 + 4)
        struct.pack_into('<II', data, 4 + 12 + 4, offset + 1, size - 1)
        path = tmp_path / 'tarts.pck'
        path.write_bytes(data)
        assert not is_pck(path)
        with PCKFile(path) as pck:  # the reader is lenient
            assert pck.read('b.csv') == b'y'

    def test_empty_pack_not_detected(self, tmp_path):
        path = tmp_path / 'tarts.pck'
        path.write_bytes(bytes(4))
        assert not is_pck(path)
        with PCKFile(path) as pck:
            assert pck.files == []


@pytest.mark.integration
class TestExtract:
    def test_extract_all_converts_eog(self, tmp_path):
        out = tmp_path / 'out'
        with PCKFile(_pack(tmp_path)) as pck:
            pck.extract_all(out, convert_eog=True)
        assert sorted(p.name for p in out.iterdir()) == ['Mmock100.psb', 'b090001g.ogg', 'mrab100.psb', 'w000001a.csv']
        assert (out / 'b090001g.ogg').read_bytes() == OGG

    def test_extract_all_as_stored(self, tmp_path):
        out = tmp_path / 'out'
        with PCKFile(_pack(tmp_path)) as pck:
            pck.extract_all(out)
        assert (out / 'b090001g.eog').read_bytes() == VOICE

    def test_eog_without_eog_suffix_gets_ogg_appended(self, tmp_path):
        out = tmp_path / 'out'
        with PCKFile(_pack(tmp_path, [('jabberwock', VOICE)])) as pck:
            pck.extract_all(out, convert_eog=True)
        assert (out / 'jabberwock.ogg').read_bytes() == OGG

    def test_glob(self, tmp_path):
        out = tmp_path / 'out'
        with PCKFile(_pack(tmp_path)) as pck:
            pck.extract_all(out, glob='*.psb')
        assert sorted(p.name for p in out.iterdir()) == ['Mmock100.psb', 'mrab100.psb']


@pytest.mark.integration
class TestCreate:
    def test_matches_hand_built_pack_sorted_ignoring_case(self, tmp_path):
        src = _source_dir(tmp_path, dict(MEMBERS))
        out = tmp_path / 'rebuilt.pck'
        with PCKFile(out, mode='w') as pck:
            # Out of order on purpose: the writer sorts.
            for name in ['w000001a.csv', 'mrab100.psb', 'b090001g.eog', 'Mmock100.psb']:
                pck.write(src / name, arcname=name)
        assert out.read_bytes() == build_pck(MEMBERS)

    def test_wraps_ogg(self, tmp_path):
        src = _source_dir(tmp_path, {'b090001g.ogg': OGG, 'w000001a.csv': LIP_SYNC})
        out = tmp_path / 'rebuilt.pck'
        with PCKFile(out, mode='w') as pck:
            pck.write_all(src, wrap_ogg=True)
        assert out.read_bytes() == build_pck([('b090001g.eog', VOICE), ('w000001a.csv', LIP_SYNC)])

    def test_without_wrap_stores_ogg_as_is(self, tmp_path):
        src = _source_dir(tmp_path, {'b090001g.ogg': OGG})
        out = tmp_path / 'rebuilt.pck'
        with PCKFile(out, mode='w') as pck:
            pck.write_all(src)
        assert out.read_bytes() == build_pck([('b090001g.ogg', OGG)])

    def test_ogg_named_file_that_is_not_ogg_is_stored_as_is(self, tmp_path):
        src = _source_dir(tmp_path, {'mock_turtle.ogg': DRINK_ME})
        out = tmp_path / 'rebuilt.pck'
        with PCKFile(out, mode='w') as pck:
            pck.write_all(src, wrap_ogg=True)
        with PCKFile(out) as pck:
            assert pck.read('mock_turtle.ogg') == DRINK_ME

    def test_extract_then_create_roundtrip(self, tmp_path):
        original = _pack(tmp_path)
        out = tmp_path / 'out'
        with PCKFile(original) as pck:
            pck.extract_all(out, convert_eog=True)
        rebuilt = tmp_path / 'rebuilt.pck'
        with PCKFile(rebuilt, mode='w') as pck:
            pck.write_all(out, wrap_ogg=True)
        assert rebuilt.read_bytes() == original.read_bytes()

    def test_subdirectories(self, tmp_path):
        src = _source_dir(tmp_path, {})
        (src / 'hall').mkdir()
        (src / 'hall' / 'door.csv').write_bytes(LIP_SYNC)
        out = tmp_path / 'rebuilt.pck'
        with PCKFile(out, mode='w') as pck:
            pck.write_all(src)
        with PCKFile(out) as pck:
            assert pck.read('hall/door.csv') == LIP_SYNC

    def test_duplicate_ignoring_case(self, tmp_path):
        src = _source_dir(tmp_path, {'alice.csv': LIP_SYNC})
        with PCKFile(tmp_path / 'out.pck', mode='w') as pck:
            pck.write(src / 'alice.csv', arcname='alice.csv')
            with pytest.raises(ValueError, match='Duplicate'):
                pck.write(src / 'alice.csv', arcname='ALICE.csv')

    def test_unencodable_name(self, tmp_path):
        src = _source_dir(tmp_path, {'alice.csv': LIP_SYNC})
        with PCKFile(tmp_path / 'out.pck', mode='w') as pck, pytest.raises(ValueError, match='cp932'):
            pck.write(src / 'alice.csv', arcname='aliceé.csv')

    def test_empty_pack(self, tmp_path):
        out = tmp_path / 'out.pck'
        with PCKFile(out, mode='w'):
            pass
        assert out.read_bytes() == bytes(4)

    def test_write_all_skips_the_output(self, tmp_path):
        src = _source_dir(tmp_path, {'alice.csv': LIP_SYNC})
        out = src / 'out.pck'
        with PCKFile(out, mode='w') as pck:
            pck.write_all(src)
        with PCKFile(out) as pck:
            assert [info.file_name for info in pck.files] == ['alice.csv']
