"""Tests for reading and writing Black Cyc image (.gtb/.gpk) and voice (.vtb/.vpk) packs."""

import struct

import pytest

from tamago.formats.blackcyc import PackFile, is_blackcyc_pack
from tamago.tests.blackcyc.samples import (
    ALICE,
    GPK,
    GPK_CONTENTS,
    GPK_MEMBERS,
    GTB,
    TEACUP,
    VPK,
    VPK_CONTENTS,
    VTB,
    build_gtb,
    build_vtb,
    write_pair,
)


@pytest.fixture
def image_pack(tmp_path):
    return write_pair(tmp_path, 'bg0', GTB, GPK, '.gtb', '.gpk')


@pytest.fixture
def voice_pack(tmp_path):
    return write_pair(tmp_path, 'aa', VTB, VPK, '.vtb', '.vpk')


def _populate(root, files):
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def _contents(pack):
    return {name: pack.read(name) for name in pack.namelist()}


@pytest.mark.unit
class TestReadImagePack:
    @pytest.mark.parametrize('which', [0, 1], ids=['index', 'data'])
    def test_opens_from_either_file(self, image_pack, which):
        with PackFile(image_pack[which]) as pack:
            assert pack.kind == 'image'
            assert pack.index_path == str(image_pack[0])
            assert pack.data_path == str(image_pack[1])
            assert _contents(pack) == GPK_CONTENTS

    def test_members_in_index_order(self, image_pack):
        with PackFile(image_pack[1]) as pack:
            assert pack.namelist() == ['alice.dwq', 'tea_party.dwq', 'teacup.dwq', 'white.dwq']
            info = pack.getinfo('teacup.dwq')
            assert info.raw_name == b'teacup'
            assert info.offset == len(ALICE) + len(GPK_MEMBERS[1][1])
            assert info.size == len(TEACUP)

    def test_last_member_runs_to_end_of_data(self, image_pack):
        with PackFile(image_pack[1]) as pack:
            last = pack.files[-1]
            assert last.offset + last.size == len(GPK)

    def test_follows_name_offsets(self, tmp_path):
        # Strings stored in reverse: names must come from name_offset[], not position.
        gtb = build_gtb(GPK_MEMBERS, [name for name, _data in reversed(GPK_MEMBERS)])
        index, _data = write_pair(tmp_path, 'ev0', gtb, GPK, '.gtb', '.gpk')
        with PackFile(index) as pack:
            assert _contents(pack) == GPK_CONTENTS

    def test_upper_case_extensions(self, tmp_path):
        index, data = write_pair(tmp_path, 'BG0', GTB, GPK, '.GTB', '.GPK')
        with PackFile(data) as pack:
            assert pack.index_path == str(index)
            assert _contents(pack) == GPK_CONTENTS

    def test_companion_found_ignoring_case(self, tmp_path):
        index, data = write_pair(tmp_path, 'bg0', GTB, GPK, '.GTB', '.gpk')
        with PackFile(data) as pack:
            assert pack.index_path == str(index)

    def test_empty_pack(self, tmp_path):
        index, _data = write_pair(tmp_path, 'sc0', struct.pack('<I', 0), b'', '.gtb', '.gpk')
        with PackFile(index) as pack:
            assert pack.files == []

    def test_missing_member(self, image_pack):
        with PackFile(image_pack[0]) as pack, pytest.raises(KeyError):
            pack.read('cheshire.dwq')


@pytest.mark.unit
class TestReadVoicePack:
    @pytest.mark.parametrize('which', [0, 1], ids=['index', 'data'])
    def test_opens_from_either_file(self, voice_pack, which):
        with PackFile(voice_pack[which]) as pack:
            assert pack.kind == 'voice'
            assert pack.namelist() == ['mad00001.vaw', 'mad00002.vaw', 'mad00010.vaw']
            assert _contents(pack) == VPK_CONTENTS

    def test_short_name_is_nul_padded(self, tmp_path):
        vtb = build_vtb([(b'dodo', b'caucus race')])
        index, _data = write_pair(tmp_path, 'bb', vtb, b'caucus race', '.vtb', '.vpk')
        with PackFile(index) as pack:
            assert pack.namelist() == ['dodo.vaw']
            assert pack.read('dodo.vaw') == b'caucus race'


@pytest.mark.unit
class TestMalformed:
    def test_missing_companion(self, tmp_path):
        path = tmp_path / 'bg0.gpk'
        path.write_bytes(GPK)
        with pytest.raises(ValueError, match='index'):
            PackFile(path)

    def test_missing_data_file(self, tmp_path):
        path = tmp_path / 'bg0.gtb'
        path.write_bytes(GTB)
        with pytest.raises(ValueError, match='data'):
            PackFile(path)

    def test_unknown_extension(self, tmp_path):
        path = tmp_path / 'bg0.dat'
        path.write_bytes(GTB)
        with pytest.raises(ValueError, match='extension'):
            PackFile(path)

    @pytest.mark.parametrize(
        'gtb',
        [
            b'\1\0',  # truncated count
            struct.pack('<I', 1000) + GTB[4:],  # tables run past the end
            GTB[:-1],  # last name unterminated
            struct.pack('<3I', 1, 99, 0) + b'alice\0',  # name offset outside the strings
            struct.pack('<3I', 1, 0, 0) + b'\0',  # empty name
            build_gtb([(b'alice', ALICE), (b'teacup', TEACUP)], [b'alice', b'teacup'])[:12]
            + struct.pack('<2I', len(ALICE), 0)
            + b'alice\0teacup\0',  # data offsets decrease
            struct.pack('<3I', 1, 0, len(GPK) + 1) + b'alice\0',  # data offset past the end
            struct.pack('<3I', 1, 0, 0) + b'\x81\0',  # not cp932
        ],
        ids=['short', 'tables', 'unterminated', 'name-offset', 'empty-name', 'order', 'data-offset', 'cp932'],
    )
    def test_bad_image_index(self, tmp_path, gtb):
        index, _data = write_pair(tmp_path, 'bg0', gtb, GPK, '.gtb', '.gpk')
        with pytest.raises(ValueError):
            PackFile(index)
        assert not is_blackcyc_pack(index)

    @pytest.mark.parametrize(
        'vtb',
        [
            VTB[:-1],  # not whole records
            b'',  # no sentinel
            VTB[:-4] + struct.pack('<I', len(VPK) + 1),  # sentinel past the end
            b'mad00001' + struct.pack('<I', 10) + b'mad00002' + struct.pack('<I', 0) + VTB[-12:],  # offsets decrease
            bytes(8) + struct.pack('<I', 0) + bytes(8) + struct.pack('<I', len(VPK)),  # empty name
        ],
        ids=['partial', 'empty', 'sentinel', 'order', 'empty-name'],
    )
    def test_bad_voice_index(self, tmp_path, vtb):
        index, _data = write_pair(tmp_path, 'aa', vtb, VPK, '.vtb', '.vpk')
        with pytest.raises(ValueError):
            PackFile(index)
        assert not is_blackcyc_pack(index)


@pytest.mark.unit
class TestIsBlackCycPack:
    @pytest.mark.parametrize('which', [0, 1])
    def test_image_pack(self, image_pack, which):
        assert is_blackcyc_pack(image_pack[which])

    @pytest.mark.parametrize('which', [0, 1])
    def test_voice_pack(self, voice_pack, which):
        assert is_blackcyc_pack(voice_pack[which])

    def test_empty_pack_is_not_recognised(self, tmp_path):
        index, _data = write_pair(tmp_path, 'sc0', struct.pack('<I', 0), b'', '.gtb', '.gpk')
        assert not is_blackcyc_pack(index)

    def test_control_characters_in_names(self, tmp_path):
        gtb = build_gtb([(b'ali\x01ce', ALICE)], [b'ali\x01ce'])
        index, _data = write_pair(tmp_path, 'bg0', gtb, ALICE, '.gtb', '.gpk')
        assert not is_blackcyc_pack(index)

    def test_other_extension(self, tmp_path):
        index, _data = write_pair(tmp_path, 'bg0', GTB, GPK, '.gtb', '.gpk')
        other = tmp_path / 'bg0.arc'
        other.write_bytes(GPK)
        assert not is_blackcyc_pack(other)

    def test_unrelated_vpk(self, tmp_path):
        path = tmp_path / 'voice.vpk'
        path.write_bytes(b'VPK1' + bytes(60))
        assert not is_blackcyc_pack(path)

    def test_missing_file(self, tmp_path):
        assert not is_blackcyc_pack(tmp_path / 'nothing.gtb')


@pytest.mark.unit
class TestExtract:
    def test_extract_all(self, image_pack, tmp_path):
        out = tmp_path / 'out'
        with PackFile(image_pack[0]) as pack:
            pack.extract_all(out)
        assert {p.name: p.read_bytes() for p in out.iterdir()} == GPK_CONTENTS

    def test_glob(self, voice_pack, tmp_path):
        out = tmp_path / 'out'
        with PackFile(voice_pack[1]) as pack:
            pack.extract_all(out, glob='mad0000*')
        assert sorted(p.name for p in out.iterdir()) == ['mad00001.vaw', 'mad00002.vaw']

    def test_refuses_unsafe_name(self, tmp_path):
        gtb = build_gtb([(b'../hatter', ALICE)], [b'../hatter'])
        index, _data = write_pair(tmp_path, 'bg0', gtb, ALICE, '.gtb', '.gpk')
        with PackFile(index) as pack, pytest.raises(ValueError, match='unsafe'):
            pack.extract_all(tmp_path / 'out')
        assert not (tmp_path / 'hatter.dwq').exists()


@pytest.mark.unit
class TestWrite:
    @pytest.mark.parametrize('target', ['bg0.gpk', 'bg0.gtb'])
    def test_rebuilds_image_pack_exactly(self, tmp_path, target):
        src = _populate(tmp_path / 'src', GPK_CONTENTS)
        with PackFile(tmp_path / target, mode='w') as pack:
            pack.write_all(src)
        assert (tmp_path / 'bg0.gtb').read_bytes() == GTB
        assert (tmp_path / 'bg0.gpk').read_bytes() == GPK

    @pytest.mark.parametrize('target', ['aa.vpk', 'aa.vtb'])
    def test_rebuilds_voice_pack_exactly(self, tmp_path, target):
        src = _populate(tmp_path / 'src', VPK_CONTENTS)
        with PackFile(tmp_path / target, mode='w') as pack:
            pack.write_all(src)
        assert (tmp_path / 'aa.vtb').read_bytes() == VTB
        assert (tmp_path / 'aa.vpk').read_bytes() == VPK

    def test_sorts_members_written_in_any_order(self, tmp_path):
        src = _populate(tmp_path / 'src', GPK_CONTENTS)
        with PackFile(tmp_path / 'bg0.gpk', mode='w') as pack:
            for name in reversed(list(GPK_CONTENTS)):
                pack.write(src / name)
        assert (tmp_path / 'bg0.gtb').read_bytes() == GTB

    def test_index_folds_case_and_strings_sort_upper(self, tmp_path):
        files = {'Hatter.dwq': b'h', 'hare.dwq': b'm', 'h_dormouse.dwq': b'd'}
        src = _populate(tmp_path / 'src', files)
        with PackFile(tmp_path / 'ta0.gpk', mode='w') as pack:
            pack.write_all(src)
        # Lower-cased: h_dormouse < hare < hatter.  Upper-cased: HARE < HATTER < H_DORMOUSE.
        expected = build_gtb(
            [(b'h_dormouse', b'd'), (b'hare', b'm'), (b'Hatter', b'h')], [b'hare', b'Hatter', b'h_dormouse']
        )
        assert (tmp_path / 'ta0.gtb').read_bytes() == expected

    def test_extension_matched_ignoring_case(self, tmp_path):
        src = _populate(tmp_path / 'src', {'ALICE.DWQ': ALICE})
        with PackFile(tmp_path / 'bg0.gpk', mode='w') as pack:
            pack.write_all(src)
        with PackFile(tmp_path / 'bg0.gpk') as pack:
            assert pack.files[0].raw_name == b'ALICE'

    def test_subdirectories_become_part_of_the_name(self, tmp_path):
        src = _populate(tmp_path / 'src', {'garden/rose.dwq': ALICE})
        with PackFile(tmp_path / 'bg0.gpk', mode='w') as pack:
            pack.write_all(src)
        with PackFile(tmp_path / 'bg0.gpk') as pack:
            assert pack.namelist() == ['garden/rose.dwq']

    def test_glob(self, tmp_path):
        src = _populate(tmp_path / 'src', GPK_CONTENTS)
        with PackFile(tmp_path / 'bg0.gpk', mode='w') as pack:
            pack.write_all(src, glob='tea*')
        with PackFile(tmp_path / 'bg0.gpk') as pack:
            assert pack.namelist() == ['tea_party.dwq', 'teacup.dwq']

    def test_skips_its_own_output(self, tmp_path):
        # A pack rebuilt into its source directory must not try to include itself.
        src = _populate(tmp_path / 'src', {**VPK_CONTENTS, 'aa.vpk': b'stale', 'aa.vtb': b'stale'})
        with PackFile(src / 'aa.vpk', mode='w') as pack:
            pack.write_all(src)
        with PackFile(src / 'aa.vpk') as pack:
            assert _contents(pack) == VPK_CONTENTS

    def test_empty_pack(self, tmp_path):
        with PackFile(tmp_path / 'sc0.gpk', mode='w'):
            pass
        assert (tmp_path / 'sc0.gtb').read_bytes() == struct.pack('<I', 0)
        assert (tmp_path / 'sc0.gpk').read_bytes() == b''
        with PackFile(tmp_path / 'aa.vpk', mode='w'):
            pass
        assert (tmp_path / 'aa.vtb').read_bytes() == bytes(12)

    @pytest.mark.parametrize(
        ('target', 'name', 'message'),
        [
            ('bg0.gpk', 'alice.png', r'\.dwq'),
            ('aa.vpk', 'alice.dwq', r'\.vaw'),
            ('bg0.gpk', '.dwq', 'empty'),
            ('aa.vpk', 'jabberwocky.vaw', '8 bytes'),
            ('bg0.gpk', 'caterpillar☃.dwq', 'cp932'),
        ],
    )
    def test_rejects_bad_names(self, tmp_path, target, name, message):
        source = tmp_path / 'member'
        source.write_bytes(b'data')
        with PackFile(tmp_path / target, mode='w') as pack, pytest.raises(ValueError, match=message):
            pack.write(source, arcname=name)

    def test_rejects_duplicate_names(self, tmp_path):
        source = tmp_path / 'member'
        source.write_bytes(b'data')
        with PackFile(tmp_path / 'bg0.gpk', mode='w') as pack:
            pack.write(source, arcname='alice.dwq')
            with pytest.raises(ValueError, match='duplicate'):
                pack.write(source, arcname='alice.DWQ')

    def test_rejects_files_of_the_wrong_kind(self, tmp_path):
        src = _populate(tmp_path / 'src', {**GPK_CONTENTS, 'notes.txt': b'Drink me'})
        with pytest.raises(ValueError, match=r'notes\.txt'), PackFile(tmp_path / 'bg0.gpk', mode='w') as pack:
            pack.write_all(src)
        # Nothing is left behind after a failure.
        assert not (tmp_path / 'bg0.gpk').exists()
        assert not (tmp_path / 'bg0.gtb').exists()

    def test_bad_mode(self, tmp_path):
        with pytest.raises(ValueError, match='mode'):
            PackFile(tmp_path / 'bg0.gpk', mode='a')

    def test_reading_requires_read_mode(self, tmp_path):
        with PackFile(tmp_path / 'bg0.gpk', mode='w') as pack, pytest.raises(ValueError, match='mode'):
            pack.read('alice.dwq')

    def test_roundtrip_via_extract(self, voice_pack, tmp_path):
        out = tmp_path / 'out'
        with PackFile(voice_pack[0]) as pack:
            pack.extract_all(out)
        (tmp_path / 'rebuilt').mkdir()
        with PackFile(tmp_path / 'rebuilt' / 'aa.vtb', mode='w') as pack:
            pack.write_all(out)
        assert (tmp_path / 'rebuilt' / 'aa.vtb').read_bytes() == VTB
        assert (tmp_path / 'rebuilt' / 'aa.vpk').read_bytes() == VPK
