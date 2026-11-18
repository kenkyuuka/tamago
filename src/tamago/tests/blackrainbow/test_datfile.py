"""Tests for reading and writing ADVDX resource archives."""

import json
import struct

import pytest
from PIL import Image

from tamago.formats.blackrainbow import MANIFEST_NAME, DATFile, decode_bmd, is_advdx_dat, is_bmd
from tamago.tests.blackrainbow.samples import (
    ALICE,
    CHESHIRE,
    CURIOUS,
    RABBIT,
    SPRITE_BGRA,
    STRIP_BGRA,
    build_bmd,
    build_dat,
    ogg,
)

# The worked example from the format notes, byte for byte.
WORKED = bytes.fromhex(
    '02000000 00000000 03000000 1C000000'
    '00000000 FFFFFFFF 29000000'
    '30305F61 6C696365 2E626D64' + '00' * 20 + '05000000' + '52414242 49'
    + '00' * 32 + '03000000' + '544541'
)  # fmt: skip

SPRITE = build_bmd(2, 2, SPRITE_BGRA, alpha=1)
STRIP = build_bmd(3, 1, STRIP_BGRA, alpha=0)
TRAILER = bytes.fromhex('3475373518F43C8853') + b'\xcc' * 23
# 32 bytes ending in the lead byte of a double-byte character: not valid cp932.
TRUNCATED_NAME = ('19_' + 'チェシャ猫' * 3 + 'の笑').encode('cp932')[:31] + b'\x83'


def _write(tmp_path, data, name='image.dat'):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _image_archive():
    """Unused slots, an unnamed member and a 32-byte name with no terminator."""
    long_name = ('000_' + 'ハートの女王' * 3).encode('cp932')[:28] + b'.bmd'
    assert len(long_name) == 32
    return build_dat(
        2,
        {0: (long_name, SPRITE), 2: ('02_白ウサギ.bmd'.encode('cp932'), STRIP), 5: (b'', SPRITE)},
        slots=8,
    )


def _members(path):
    with DATFile(path) as dat:
        return {info.slot: (info.raw_name, dat.read(info)) for info in dat.files}


@pytest.mark.unit
class TestDetection:
    def test_worked_example(self, tmp_path):
        assert is_advdx_dat(_write(tmp_path, WORKED))

    @pytest.mark.parametrize('kind', [2, 4, 5, 6])
    def test_every_kind(self, tmp_path, kind):
        assert is_advdx_dat(_write(tmp_path, build_dat(kind, {0: (b'tea.bin', CURIOUS)})))

    @pytest.mark.parametrize(
        'data',
        [
            pytest.param(b'', id='empty'),
            pytest.param(WORKED[:12], id='short'),
            pytest.param(struct.pack('<4I', 3, 0, 3, 0x1C) + WORKED[16:], id='unknown-kind'),
            pytest.param(WORKED[:12] + struct.pack('<I', 0x20) + WORKED[16:], id='wrong-base'),
            pytest.param(WORKED[:16] + struct.pack('<I', 0x1000) + WORKED[20:], id='offset-past-eof'),
            pytest.param(build_dat(2, {}, slots=2), id='no-members'),
            pytest.param(bytes(16) + ALICE, id='config-like'),
            pytest.param(bytes([1, 5, 6, 9, 10, 2, 11]), id='button-file'),
        ],
    )
    def test_rejects(self, tmp_path, data):
        assert not is_advdx_dat(_write(tmp_path, data))

    def test_missing_file(self, tmp_path):
        assert not is_advdx_dat(tmp_path / 'nothing.dat')


@pytest.mark.unit
class TestRead:
    def test_worked_example(self, tmp_path):
        with DATFile(_write(tmp_path, WORKED)) as dat:
            assert (dat.kind, dat.game_id, dat.slot_count, dat.trailer) == (2, 0, 3, b'')
            assert [(i.slot, i.raw_name, i.size) for i in dat.files] == [(0, b'00_alice.bmd', 5), (2, b'', 3)]
            assert dat.read('00_alice.bmd') == b'RABBI'
            assert dat.read(dat.files[1]) == b'TEA'

    def test_names(self, tmp_path):
        with DATFile(_write(tmp_path, _image_archive())) as dat:
            names = [(i.slot, i.name, i.file_name) for i in dat.files]
        assert names[1] == (2, '02_白ウサギ.bmd', '02_白ウサギ.bmd')
        assert names[0][1].endswith('.bmd') and len(names[0][1].encode('cp932')) == 32
        # An unnamed member gets a name from its slot and its contents.
        assert names[2] == (5, None, '005.bmd')

    def test_game_id(self, tmp_path):
        path = _write(tmp_path, build_dat(5, {0: (b'init.spt', ALICE)}, game_id=0x15432), 'sj_spt.dat')
        with DATFile(path) as dat:
            assert (dat.kind, dat.game_id) == (5, 0x15432)

    def test_extents_come_from_the_slot_table(self, tmp_path):
        # A long name overwrote slot 0's size field with "bmd\0".
        data = build_dat(2, {0: (b'a' * 32, SPRITE), 1: (b'b.bmd', STRIP)}, size_fields={0: b'bmd\0'})
        with DATFile(_write(tmp_path, data)) as dat:
            first = dat.files[0]
            assert first.size == len(SPRITE)
            assert first.stored_size == struct.unpack('<I', b'bmd\0')[0]
            assert dat.read(first) == SPRITE

    def test_trailer_after_last_member(self, tmp_path):
        data = build_dat(2, {0: (b'a.bmd', SPRITE), 1: (b'b.bmd', STRIP)}, trailer=TRAILER)
        with DATFile(_write(tmp_path, data)) as dat:
            assert dat.trailer == TRAILER
            assert dat.read('b.bmd') == STRIP

    def test_last_member_with_bad_size_runs_to_eof(self, tmp_path):
        data = build_dat(2, {0: (b'a.bmd', SPRITE), 1: (b'b' * 32, STRIP)}, size_fields={1: b'\xff' * 4})
        with DATFile(_write(tmp_path, data)) as dat:
            assert dat.read(dat.files[1]) == STRIP
            assert dat.trailer == b''

    def test_undecodable_name(self, tmp_path):
        data = build_dat(2, {19: (TRUNCATED_NAME, SPRITE)}, slots=20)
        with DATFile(_write(tmp_path, data)) as dat:
            (info,) = dat.files
            assert info.raw_name == TRUNCATED_NAME
            assert info.name is None
            assert info.file_name == '019.bmd'

    def test_unnamed_sound_and_unknown_contents(self, tmp_path):
        data = build_dat(4, {0: (b'', ogg(RABBIT)), 1: (b'', CURIOUS)})
        with DATFile(_write(tmp_path, data, 'se.dat')) as dat:
            assert [i.file_name for i in dat.files] == ['000.ogg', '001.bin']

    def test_not_an_archive(self, tmp_path):
        with pytest.raises(ValueError, match='ADVDX'):
            DATFile(_write(tmp_path, ALICE))

    def test_closed(self, tmp_path):
        dat = DATFile(_write(tmp_path, WORKED))
        dat.close()
        with pytest.raises(ValueError):
            dat.read('00_alice.bmd')


@pytest.mark.unit
class TestExtractNames:
    """Names that cannot be used as file names are replaced by slot-based ones."""

    @pytest.mark.parametrize(
        'raw', [b'..', b'.', b'sub/a.bmd', b'sub\\a.bmd', b'trailing.', b'trailing ', b'C:a.bmd', b'/abs.bmd']
    )
    def test_unsafe_names(self, tmp_path, raw):
        with DATFile(_write(tmp_path, build_dat(2, {3: (raw, SPRITE)}))) as dat:
            assert dat.files[0].file_name == '003.bmd'

    def test_duplicate_names_ignoring_case(self, tmp_path):
        data = build_dat(2, {0: (b'Tea.bmd', SPRITE), 1: (b'tea.bmd', STRIP)})
        with DATFile(_write(tmp_path, data)) as dat:
            assert [i.file_name for i in dat.files] == ['Tea.bmd', '001.bmd']

    def test_synthesized_name_does_not_collide(self, tmp_path):
        data = build_dat(2, {0: (b'002.bmd', SPRITE), 2: (b'', STRIP)})
        with DATFile(_write(tmp_path, data)) as dat:
            names = [i.file_name for i in dat.files]
        assert names[0] == '002.bmd'
        assert names[1] != '002.bmd' and names[1].endswith('.bmd')

    def test_manifest_name_is_reserved(self, tmp_path):
        data = build_dat(2, {0: (MANIFEST_NAME.encode(), SPRITE)})
        with DATFile(_write(tmp_path, data)) as dat:
            assert dat.files[0].file_name == '000.bmd'

    def test_wide_tables_pad_to_the_largest_slot(self, tmp_path):
        with DATFile(_write(tmp_path, build_dat(2, {7: (b'', SPRITE)}, slots=1200))) as dat:
            assert dat.files[0].file_name == '0007.bmd'


@pytest.mark.integration
class TestExtractAndRecreate:
    def _roundtrip(self, tmp_path, data, **extract_args):
        source = _write(tmp_path, data, 'source.dat')
        out = tmp_path / 'out'
        with DATFile(source) as dat:
            dat.extract_all(out, **extract_args)
        rebuilt = tmp_path / 'rebuilt.dat'
        with DATFile(rebuilt, mode='w') as dat:
            dat.write_all(out)
        return out, rebuilt.read_bytes()

    def test_worked_example_is_byte_identical(self, tmp_path):
        out, rebuilt = self._roundtrip(tmp_path, WORKED)
        assert sorted(p.name for p in out.iterdir()) == ['002.bin', '00_alice.bmd', MANIFEST_NAME]
        assert rebuilt == WORKED

    def test_image_archive_is_byte_identical(self, tmp_path):
        data = _image_archive()
        assert self._roundtrip(tmp_path, data)[1] == data

    def test_script_archive_keeps_game_id(self, tmp_path):
        data = build_dat(5, {0: (b'init.spt', ALICE), 1: (b'm01_01.spt', CHESHIRE)}, game_id=0x2F44B0A9)
        assert self._roundtrip(tmp_path, data)[1] == data

    def test_trailer_is_kept(self, tmp_path):
        data = build_dat(2, {0: (b'a.bmd', SPRITE), 1: (b'', STRIP)}, trailer=TRAILER)
        assert self._roundtrip(tmp_path, data)[1] == data

    def test_undecodable_name_is_kept(self, tmp_path):
        data = build_dat(2, {0: (b'a.bmd', STRIP), 19: (TRUNCATED_NAME, SPRITE)}, slots=32)
        assert self._roundtrip(tmp_path, data)[1] == data

    def test_overwritten_size_field_is_repaired(self, tmp_path):
        data = build_dat(2, {0: (b'a' * 32, SPRITE), 1: (b'b.bmd', STRIP)}, size_fields={0: b'bmd\0'})
        _, rebuilt = self._roundtrip(tmp_path, data)
        assert rebuilt == build_dat(2, {0: (b'a' * 32, SPRITE), 1: (b'b.bmd', STRIP)})

    def test_manifest_contents(self, tmp_path):
        data = build_dat(6, {1: (b'm01.rdd', RABBIT)}, slots=4, game_id=0x3DE0F71A)
        out, _ = self._roundtrip(tmp_path, data)
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert (manifest['kind'], manifest['game_id'], manifest['slots']) == (6, 0x3DE0F71A, 4)
        assert [m['slot'] for m in manifest['members']] == [1]

    def test_glob_extracts_and_rebuilds_a_subset(self, tmp_path):
        data = build_dat(2, {0: (b'a.bmd', SPRITE), 1: (b'b.bmd', STRIP), 3: (b'c.bmd', SPRITE)}, slots=4)
        out, rebuilt = self._roundtrip(tmp_path, data, glob='[ac].bmd')
        assert sorted(p.name for p in out.iterdir()) == [MANIFEST_NAME, 'a.bmd', 'c.bmd']
        assert rebuilt == build_dat(2, {0: (b'a.bmd', SPRITE), 3: (b'c.bmd', SPRITE)}, slots=4)

    def test_convert_bmd(self, tmp_path):
        data = build_dat(2, {0: (b'sprite.bmd', SPRITE), 2: (b'', STRIP), 3: (b'note.txt', ALICE)})
        out, rebuilt = self._roundtrip(tmp_path, data, convert_bmd=True)
        assert sorted(p.name for p in out.iterdir()) == ['002.png', MANIFEST_NAME, 'note.txt', 'sprite.png']
        with Image.open(out / 'sprite.png') as image:
            assert image.mode == 'RGBA'
        with DATFile(_write(tmp_path, rebuilt, 'again.dat')) as dat:
            assert [(i.slot, i.raw_name) for i in dat.files] == [(0, b'sprite.bmd'), (2, b''), (3, b'note.txt')]
            for info, original in zip(dat.files[:2], (SPRITE, STRIP), strict=True):
                assert decode_bmd(dat.read(info)).tobytes() == decode_bmd(original).tobytes()
            assert dat.read('note.txt') == ALICE

    def test_edited_member_keeps_its_slot(self, tmp_path):
        source = _write(tmp_path, _image_archive(), 'source.dat')
        out = tmp_path / 'out'
        with DATFile(source) as dat:
            dat.extract_all(out)
        (out / '02_白ウサギ.bmd').write_bytes(SPRITE)
        rebuilt = tmp_path / 'rebuilt.dat'
        with DATFile(rebuilt, mode='w') as dat:
            dat.write_all(out)
        members = _members(rebuilt)
        assert members[2] == ('02_白ウサギ.bmd'.encode('cp932'), SPRITE)
        assert sorted(members) == [0, 2, 5]

    def test_extra_file_takes_the_first_free_slot(self, tmp_path):
        source = _write(tmp_path, _image_archive(), 'source.dat')
        out = tmp_path / 'out'
        with DATFile(source) as dat:
            dat.extract_all(out)
        (out / 'tea_party.bmd').write_bytes(STRIP)
        rebuilt = tmp_path / 'rebuilt.dat'
        with DATFile(rebuilt, mode='w') as dat:
            dat.write_all(out)
        members = _members(rebuilt)
        assert members[1] == (b'tea_party.bmd', STRIP)
        with DATFile(rebuilt) as dat:
            assert dat.slot_count == 8

    def test_missing_file_named_in_manifest(self, tmp_path):
        source = _write(tmp_path, WORKED, 'source.dat')
        out = tmp_path / 'out'
        with DATFile(source) as dat:
            dat.extract_all(out)
        (out / '002.bin').unlink()
        with pytest.raises(ValueError, match=r'002\.bin'):
            with DATFile(tmp_path / 'rebuilt.dat', mode='w') as dat:
                dat.write_all(out)

    def test_arguments_override_the_manifest(self, tmp_path):
        source = _write(tmp_path, build_dat(5, {0: (b'init.spt', ALICE)}, game_id=7), 'source.dat')
        out = tmp_path / 'out'
        with DATFile(source) as dat:
            dat.extract_all(out)
        rebuilt = tmp_path / 'rebuilt.dat'
        with DATFile(rebuilt, mode='w', game_id=0x15432, slots=4) as dat:
            dat.write_all(out)
        assert rebuilt.read_bytes() == build_dat(5, {0: (b'init.spt', ALICE)}, slots=4, game_id=0x15432)


@pytest.mark.unit
class TestCreate:
    def _create(self, tmp_path, files, **kwargs):
        src = tmp_path / 'src'
        src.mkdir(exist_ok=True)
        for name, data in files.items():
            (src / name).write_bytes(data)
        out = tmp_path / 'new.dat'
        with DATFile(out, mode='w', **kwargs) as dat:
            dat.write_all(src)
        return out.read_bytes()

    def test_members_take_slots_in_name_order(self, tmp_path):
        data = self._create(tmp_path, {'b.bmd': STRIP, 'a.bmd': SPRITE})
        assert data == build_dat(2, {0: (b'a.bmd', SPRITE), 1: (b'b.bmd', STRIP)})

    @pytest.mark.parametrize(
        ('name', 'body', 'kind'),
        [('se.ogg', ogg(RABBIT), 4), ('init.spt', ALICE, 5), ('init.rdd', CURIOUS, 6), ('bg.bmd', SPRITE, 2)],
    )
    def test_kind_is_inferred(self, tmp_path, name, body, kind):
        assert struct.unpack_from('<I', self._create(tmp_path, {name: body}))[0] == kind

    def test_mixed_contents_need_a_kind(self, tmp_path):
        with pytest.raises(ValueError, match='kind'):
            self._create(tmp_path, {'a.ogg': ogg(RABBIT), 'b.spt': ALICE})

    def test_explicit_kind_slots_and_game_id(self, tmp_path):
        data = self._create(tmp_path, {'m.spt': ALICE}, kind=5, slots=3, game_id=0x258865)
        assert data == build_dat(5, {0: (b'm.spt', ALICE)}, slots=3, game_id=0x258865)

    def test_too_few_slots(self, tmp_path):
        with pytest.raises(ValueError, match='slot'):
            self._create(tmp_path, {'a.bmd': SPRITE, 'b.bmd': STRIP}, slots=1)

    def test_png_is_encoded_in_an_image_archive(self, tmp_path):
        png = tmp_path / 'tmp.png'
        Image.new('RGBA', (2, 2), (255, 0, 0, 128)).save(png)
        data = self._create(tmp_path, {'queen.png': png.read_bytes()})
        with DATFile(_write(tmp_path, data, 'check.dat')) as dat:
            (info,) = dat.files
            assert info.raw_name == b'queen.bmd'
            body = dat.read(info)
        assert is_bmd(body)
        assert decode_bmd(body).getpixel((1, 1)) == (255, 0, 0, 128)

    def test_name_of_32_bytes_is_allowed(self, tmp_path):
        name = 'x' * 28 + '.bmd'
        assert self._create(tmp_path, {name: SPRITE}) == build_dat(2, {0: (name.encode(), SPRITE)})

    def test_name_too_long(self, tmp_path):
        with pytest.raises(ValueError, match='32'):
            self._create(tmp_path, {'x' * 29 + '.bmd': SPRITE})

    def test_name_not_cp932(self, tmp_path):
        with pytest.raises(ValueError, match='cp932'):
            self._create(tmp_path, {'café☕.bmd': SPRITE}, kind=2)

    def test_subdirectories_are_refused(self, tmp_path):
        (tmp_path / 'src' / 'sub').mkdir(parents=True)
        (tmp_path / 'src' / 'sub' / 'a.bmd').write_bytes(SPRITE)
        with pytest.raises(ValueError, match='sub'):
            self._create(tmp_path, {})

    def test_explicit_slots_with_write(self, tmp_path):
        a = tmp_path / 'a.bmd'
        a.write_bytes(SPRITE)
        out = tmp_path / 'new.dat'
        with DATFile(out, mode='w', kind=2) as dat:
            dat.write(a, slot=3)
            dat.write(a, arcname='', slot=1)
        assert out.read_bytes() == build_dat(2, {1: (b'', SPRITE), 3: (b'a.bmd', SPRITE)})

    def test_duplicate_slot(self, tmp_path):
        a = tmp_path / 'a.bmd'
        a.write_bytes(SPRITE)
        with pytest.raises(ValueError, match='slot 0'):
            with DATFile(tmp_path / 'new.dat', mode='w', kind=2) as dat:
                dat.write(a, slot=0)
                dat.write(a, arcname='b.bmd', slot=0)

    def test_empty_archive_needs_members(self, tmp_path):
        with pytest.raises(ValueError, match='member'):
            self._create(tmp_path, {}, kind=2)

    def test_script_archive_without_game_id_warns(self, tmp_path, caplog):
        self._create(tmp_path, {'init.spt': ALICE})
        assert 'game ID' in caplog.text
