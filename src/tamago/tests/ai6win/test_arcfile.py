"""Tests for reading and writing AI6WIN .arc archives."""

import json
import struct

import pytest
from PIL import Image, PngImagePlugin

from tamago.formats.ai6win import MANIFEST_NAME, ARCFile, decode_name, encode_name, is_ai6win_arc
from tamago.formats.ai6win.akb import PNG_TEXT_KEY, akb_to_png, decode_akb, encode_akb, read_header
from tamago.tests.ai6win.samples import (
    AKB_EMPTY,
    AKB_RGB_CROPPED,
    AKB_RGBA,
    ARCHIVE,
    CONTENTS,
    MEMBERS,
    NAME_SIZE,
    OGG,
    QUEEN,
    QUEEN_LZSS,
    WAV,
    build_arc,
    obfuscate,
)


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / 'mes.arc'
    path.write_bytes(ARCHIVE)
    return path


def _long_name(length):
    """A name of *length* bytes none of whose bytes obfuscates to NUL.

    The key runs through every value modulo 256 in names this long, so a name
    repeating one letter always hits zero somewhere.
    """
    key = length + 1
    return bytes(ord('a') if (ord('a') + key - i) & 0xFF else ord('b') for i in range(length))


def _populate(root, files):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


@pytest.mark.unit
class TestNames:
    def test_worked_example(self):
        stored = encode_name(b'alice.mes')
        assert len(stored) == NAME_SIZE
        assert stored[:10] == bytes.fromhex('6b75716a6b3371687500')
        assert stored[10:] == bytes(NAME_SIZE - 10)
        assert decode_name(stored) == b'alice.mes'

    def test_long_name_key_wraps(self):
        name = _long_name(259)
        stored = encode_name(name)
        assert stored[:259] == obfuscate(name)
        assert decode_name(stored) == name

    def test_full_field_without_terminator(self):
        name = _long_name(NAME_SIZE)
        assert decode_name(obfuscate(name)) == name

    def test_refuses_overlong_name(self):
        with pytest.raises(ValueError, match='at most'):
            encode_name(_long_name(NAME_SIZE))

    def test_refuses_empty_name(self):
        with pytest.raises(ValueError):
            encode_name(b'')

    def test_refuses_nul(self):
        with pytest.raises(ValueError):
            encode_name(b'tea\0party.mes')

    def test_refuses_name_whose_encoding_contains_nul(self):
        # 0xF6 + key 10 wraps to 0, which would end the name early.
        with pytest.raises(ValueError):
            encode_name(b'\xf6abcdefgh')


@pytest.mark.unit
class TestRead:
    def test_lists_members_in_index_order(self, archive):
        with ARCFile(archive) as arc:
            assert arc.namelist() == [name.decode() for name, _s, _u in MEMBERS]

    def test_entry_fields(self, archive):
        with ARCFile(archive) as arc:
            info = arc.getinfo('start.mes')
            assert info.compressed
            assert info.size == len(QUEEN_LZSS)
            assert info.unpacked_size == len(QUEEN)
            assert info.offset == 4 + 0x110 * len(MEMBERS)
            ogg = arc.getinfo('cheshire.ogg')
            assert not ogg.compressed
            assert ogg.offset == info.offset + info.size

    def test_reads_stored_and_compressed_members(self, archive):
        with ARCFile(archive) as arc:
            assert {name: arc.read(name) for name in arc.namelist()} == CONTENTS

    def test_read_by_info(self, archive):
        with ARCFile(archive) as arc:
            assert arc.read(arc.files[0]) == QUEEN

    def test_unknown_member(self, archive):
        with ARCFile(archive) as arc, pytest.raises(KeyError):
            arc.read('jabberwock.mes')

    def test_empty_member(self, tmp_path):
        path = tmp_path / 'data.arc'
        path.write_bytes(build_arc([(b'empty.bin', b'', 0), (b'cheshire.ogg', OGG, len(OGG))]))
        with ARCFile(path) as arc:
            assert arc.read('empty.bin') == b''
            assert arc.read('cheshire.ogg') == OGG

    def test_closed_archive(self, archive):
        arc = ARCFile(archive)
        arc.close()
        with pytest.raises(ValueError):
            arc.read('start.mes')

    @pytest.mark.parametrize(
        'data',
        [
            b'',
            b'\x01\0\0',
            struct.pack('<I', 2) + ARCHIVE[4:0x114],  # index longer than the file
            build_arc([(b'', OGG, len(OGG))]),  # empty name
            build_arc([(b'\x81', OGG, len(OGG))]),  # undecodable cp932
        ],
        ids=['empty', 'short-header', 'truncated-index', 'empty-name', 'bad-cp932'],
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
        data = bytearray(build_arc([(b'cheshire.ogg', OGG, len(OGG))]))
        struct.pack_into('>I', data, 4 + NAME_SIZE + 8, 4)
        path = tmp_path / 'bad.arc'
        path.write_bytes(data)
        with pytest.raises(ValueError, match='outside'):
            ARCFile(path)


@pytest.mark.unit
class TestDetection:
    def test_recognises_archive(self, archive):
        assert is_ai6win_arc(archive)

    @pytest.mark.parametrize(
        'data',
        [
            b'',
            bytes(16),
            struct.pack('<I', 0),
            ARCHIVE[:-1],
            build_arc([(b'tea\x01party.mes', OGG, len(OGG))]),  # control character
            # AdvHD v2: file count, index size, then UTF-16 names.
            struct.pack('<IIII', 1, 26, len(OGG), 0) + 'alice.ogg'.encode('utf-16-le') + b'\0\0' + OGG,
            # Silky's "Azurite" variant: index size, then length-prefixed names.
            struct.pack('<I', 0x1427) + bytes([9]) + b'alice.ogg' + bytes(0x1500),
            b'LINK6\0\0\0' + bytes(0x200),
        ],
        ids=['empty', 'zeros', 'no-members', 'truncated', 'control-char', 'advhd', 'silky-azurite', 'link6'],
    )
    def test_rejects_other_files(self, tmp_path, data):
        path = tmp_path / 'other.arc'
        path.write_bytes(data)
        assert not is_ai6win_arc(path)

    def test_missing_file(self, tmp_path):
        assert not is_ai6win_arc(tmp_path / 'missing.arc')


@pytest.mark.integration
class TestExtract:
    def test_extracts_members_and_manifest(self, archive, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(archive) as arc:
            arc.extract_all(out)
        for name, data in CONTENTS.items():
            assert (out / name).read_bytes() == data
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert manifest['format'] == 'ai6win'
        assert manifest['members'] == [
            {'name': 'start.mes', 'compressed': True},
            {'name': 'cheshire.ogg', 'compressed': False},
            {'name': 'mpeg/rabbit.mov', 'compressed': True},
            {'name': 'backlog.area', 'compressed': True},
            {'name': '01.WAV', 'compressed': False},
        ]

    def test_glob_selects_members(self, archive, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(archive) as arc:
            arc.extract_all(out, glob='*.mes')
        assert sorted(p.name for p in out.iterdir()) == [MANIFEST_NAME, 'start.mes']
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert manifest['members'] == [{'name': 'start.mes', 'compressed': True}]

    def test_member_named_like_manifest_refused(self, tmp_path):
        path = tmp_path / 'data.arc'
        path.write_bytes(build_arc([(MANIFEST_NAME.encode(), OGG, len(OGG))]))
        with ARCFile(path) as arc, pytest.raises(ValueError, match='manifest'):
            arc.extract_all(tmp_path / 'out')


@pytest.mark.integration
class TestCreate:
    def test_rebuild_from_manifest_is_byte_identical(self, archive, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(archive) as arc:
            arc.extract_all(out)
        rebuilt = tmp_path / 'rebuilt.arc'
        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == ARCHIVE

    def test_without_manifest_sorts_and_compresses_by_extension(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'start.mes': QUEEN, 'voice/alice.ogg': OGG, 'title.WAV': WAV, 'mpeg/op.MOV': QUEEN})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert arc.namelist() == ['mpeg/op.MOV', 'start.mes', 'title.WAV', 'voice/alice.ogg']
            assert [i.compressed for i in arc.files] == [True, True, False, False]
            assert arc.read('start.mes') == QUEEN
            assert arc.read('voice/alice.ogg') == OGG

    @pytest.mark.parametrize(('compress', 'expected'), [(True, [True, True]), (False, [False, False])])
    def test_compress_overrides_extension(self, tmp_path, compress, expected):
        src = tmp_path / 'src'
        _populate(src, {'a.mes': QUEEN, 'b.ogg': QUEEN})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w', compress=compress) as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert [i.compressed for i in arc.files] == expected
            assert arc.read('a.mes') == QUEEN

    def test_compress_overrides_manifest(self, archive, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(archive) as arc:
            arc.extract_all(out)
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w', compress=False) as arc:
            arc.write_all(out)
        with ARCFile(path) as arc:
            assert not any(i.compressed for i in arc.files)
            assert {name: arc.read(name) for name in arc.namelist()} == CONTENTS

    def test_member_that_does_not_shrink_is_stored(self, tmp_path):
        # 'tea tea' compresses to exactly 7 bytes, which would read back as stored.
        src = tmp_path / 'src'
        _populate(src, {'tea.mes': b'tea tea', 'empty.mes': b''})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert arc.getinfo('tea.mes').size == 7
            assert arc.read('tea.mes') == b'tea tea'
            assert arc.read('empty.mes') == b''

    def test_write_with_arcname(self, tmp_path):
        src = tmp_path / 'queen.txt'
        src.write_bytes(QUEEN)
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write(src, arcname='court/queen.mes')
        with ARCFile(path) as arc:
            assert arc.namelist() == ['court/queen.mes']
            assert arc.files[0].compressed
            assert arc.read('court/queen.mes') == QUEEN

    def test_new_files_follow_manifest_members(self, archive, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(archive) as arc:
            arc.extract_all(out)
        (out / 'aaa.mes').write_bytes(QUEEN)
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(out)
        with ARCFile(path) as arc:
            assert arc.namelist() == [name.decode() for name, _s, _u in MEMBERS] + ['aaa.mes']

    def test_missing_manifest_member(self, archive, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(archive) as arc:
            arc.extract_all(out)
        (out / 'cheshire.ogg').unlink()
        with ARCFile(tmp_path / 'new.arc', mode='w') as arc, pytest.raises(ValueError, match='missing'):
            arc.write_all(out)

    def test_invalid_manifest(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {MANIFEST_NAME: b'{"format": "advdx", "members": []}'})
        with ARCFile(tmp_path / 'new.arc', mode='w') as arc, pytest.raises(ValueError, match='manifest'):
            arc.write_all(src)

    def test_glob_filters_files(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'start.mes': QUEEN, 'voice/alice.ogg': OGG})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src, glob='*.mes')
        with ARCFile(path) as arc:
            assert arc.namelist() == ['start.mes']

    def test_skips_output_inside_source(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'start.mes': QUEEN})
        path = src / 'mes.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert arc.namelist() == ['start.mes']

    def test_cp932_name_that_does_not_roundtrip(self, tmp_path):
        # 0xED40 (an NEC-selected IBM extension) decodes to U+7E8A, which
        # encodes back as the IBM extension 0xFA5C.
        raw = b'\xed\x40.mes'
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


def _canonical(akb: bytes) -> bytes:
    """*akb* re-encoded with Okumura's LZSS, as the games' packer would have stored it."""
    header = read_header(akb)
    return encode_akb(decode_akb(akb), header.background, (header.left, header.top, header.right, header.bottom))


@pytest.fixture
def layer(tmp_path):
    """An image archive: two AKBs, an incremental AKB+ and a script."""
    members = [
        (b'ev/alice01.akb', _canonical(AKB_RGB_CROPPED)),
        (b'kuro.akb', AKB_EMPTY),
        (b'tea_party.akb', b'AKB+' + AKB_RGBA[4:]),
        (b'start.mes', QUEEN),
    ]
    path = tmp_path / 'Layer.arc'
    path.write_bytes(build_arc([(name, data, len(data)) for name, data in members]))
    return path


@pytest.mark.integration
class TestAKBConversion:
    def test_extracts_images_as_png(self, layer, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(layer) as arc:
            arc.extract_all(out, convert_akb=True)
        assert sorted(p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_file()) == [
            MANIFEST_NAME,
            'ev/alice01.png',
            'kuro.png',
            'start.mes',
            'tea_party.akb',
        ]
        with Image.open(out / 'ev' / 'alice01.png') as image:
            assert image.tobytes() == decode_akb(AKB_RGB_CROPPED).tobytes()
        manifest = json.loads((out / MANIFEST_NAME).read_text(encoding='utf-8'))
        assert manifest['members'] == [
            {'name': 'ev/alice01.akb', 'compressed': False, 'file': 'ev/alice01.png'},
            {'name': 'kuro.akb', 'compressed': False, 'file': 'kuro.png'},
            {'name': 'tea_party.akb', 'compressed': False},
            {'name': 'start.mes', 'compressed': False},
        ]

    def test_incremental_image_left_unconverted(self, layer, tmp_path, caplog):
        with ARCFile(layer) as arc:
            arc.extract_all(tmp_path / 'out', convert_akb=True)
        assert 'tea_party.akb' in caplog.text
        assert 'AKB+' in caplog.text

    def test_rebuild_is_byte_identical(self, layer, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(layer) as arc:
            arc.extract_all(out, convert_akb=True)
        rebuilt = tmp_path / 'rebuilt.arc'
        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == layer.read_bytes()

    def test_edited_png_is_encoded(self, layer, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(layer) as arc:
            arc.extract_all(out, convert_akb=True)
        Image.new('RGB', (4, 3), (0x4F, 0x86, 0xC6)).save(out / 'kuro.png')
        rebuilt = tmp_path / 'rebuilt.arc'
        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        with ARCFile(rebuilt) as arc:
            assert decode_akb(arc.read('kuro.akb')).getcolors() == [(12, (0x4F, 0x86, 0xC6))]

    def test_png_name_collision(self, tmp_path):
        akb = _canonical(AKB_RGBA)
        path = tmp_path / 'Layer.arc'
        path.write_bytes(build_arc([(b'tea.akb', akb, len(akb)), (b'tea.png', OGG, len(OGG))]))
        out = tmp_path / 'out'
        with ARCFile(path) as arc:
            arc.extract_all(out, convert_akb=True)
        assert (out / 'tea.png').read_bytes() == OGG
        assert (out / 'tea.akb.png').is_file()
        rebuilt = tmp_path / 'rebuilt.arc'
        with ARCFile(rebuilt, mode='w') as arc:
            arc.write_all(out)
        assert rebuilt.read_bytes() == path.read_bytes()

    def test_extract_single_member(self, layer, tmp_path):
        with ARCFile(layer) as arc:
            written = arc.extract('kuro.akb', tmp_path / 'kuro.akb', convert_akb=True)
            assert written == str(tmp_path / 'kuro.png')
            assert arc.extract('start.mes', tmp_path / 'start.mes', convert_akb=True) == str(tmp_path / 'start.mes')
        with Image.open(written) as image:
            assert image.size == (4, 3)

    def test_without_conversion_images_stay_akb(self, layer, tmp_path):
        out = tmp_path / 'out'
        with ARCFile(layer) as arc:
            arc.extract_all(out)
        assert (out / 'kuro.akb').read_bytes() == AKB_EMPTY

    def test_new_png_becomes_akb_member(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'bg/garden.png': akb_to_png(AKB_RGBA), 'start.mes': QUEEN})
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write_all(src)
        with ARCFile(path) as arc:
            assert arc.namelist() == ['bg/garden.akb', 'start.mes']
            assert not arc.getinfo('bg/garden.akb').compressed
            assert decode_akb(arc.read('bg/garden.akb')).tobytes() == decode_akb(AKB_RGBA).tobytes()

    def test_explicit_png_name_is_stored_as_is(self, tmp_path):
        png = akb_to_png(AKB_RGBA)
        (tmp_path / 'cat.png').write_bytes(png)
        path = tmp_path / 'new.arc'
        with ARCFile(path, mode='w') as arc:
            arc.write(tmp_path / 'cat.png', arcname='cat.png')
        with ARCFile(path) as arc:
            assert arc.read('cat.png') == png

    def test_bad_png_reports_file(self, tmp_path):
        info = PngImagePlugin.PngInfo()
        info.add_text(PNG_TEXT_KEY, 'not json')
        Image.new('RGB', (1, 1)).save(tmp_path / 'hatter.png', pnginfo=info)
        with pytest.raises(ValueError, match=r'hatter\.png'), ARCFile(tmp_path / 'new.arc', mode='w') as arc:
            arc.write(tmp_path / 'hatter.png')

    def test_manifest_file_must_be_string(self, tmp_path):
        src = tmp_path / 'src'
        _populate(src, {'kuro.png': b''})
        manifest = {'format': 'ai6win', 'members': [{'name': 'kuro.akb', 'compressed': False, 'file': 3}]}
        (src / MANIFEST_NAME).write_text(json.dumps(manifest), encoding='utf-8')
        with ARCFile(tmp_path / 'new.arc', mode='w') as arc, pytest.raises(ValueError, match='manifest'):
            arc.write_all(src)
