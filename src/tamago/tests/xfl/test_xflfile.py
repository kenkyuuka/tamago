import os
import struct

import pytest

from tamago.formats.xfl.xflfile import XFL_MAGIC, XFLFile, XFLInfo


def _build_xfl(files: list[tuple[str, bytes]], index_size: int | None = None) -> bytes:
    """Build an XFL archive from (name, data) pairs, stored in the given order."""
    if index_size is None:
        index_size = len(files) * 40
    buf = bytearray(struct.pack('<4sII', XFL_MAGIC, index_size, len(files)))
    offset = 0
    for name, data in files:
        buf += name.encode('cp932').ljust(32, b'\x00')
        buf += struct.pack('<II', offset, len(data))
        offset += len(data)
    for _name, data in files:
        buf += data
    return bytes(buf)


ALICE = b'Alice was beginning to get very tired of sitting by her sister on the bank.'
RABBIT = b'Oh dear! Oh dear! I shall be late!'
HATTER = b'Why is a raven like a writing-desk?'

LOOKING_GLASS = _build_xfl([('alice.txt', b'Through the looking-glass.'), ('jabberwock.txt', b"'Twas brillig")])


@pytest.fixture
def simple_xfl(tmp_path):
    path = tmp_path / 'wonderland.xfl'
    path.write_bytes(_build_xfl([('alice.txt', ALICE), ('hatter.txt', HATTER), ('rabbit.txt', RABBIT)]))
    return path


@pytest.fixture
def nested_xfl(tmp_path):
    path = tmp_path / 'voice.xfl'
    path.write_bytes(
        _build_xfl(
            [
                ('alice.txt', ALICE),
                ('glass.xfl', LOOKING_GLASS),
                ('rabbit.txt', RABBIT),
            ]
        )
    )
    return path


# -- reading ------------------------------------------------------------------


@pytest.mark.integration
class TestRead:
    def test_lists_members_in_index_order(self, simple_xfl):
        with XFLFile(simple_xfl) as xfl:
            assert [f.file_name for f in xfl.files] == ['alice.txt', 'hatter.txt', 'rabbit.txt']
            assert [f.size for f in xfl.files] == [len(ALICE), len(HATTER), len(RABBIT)]

    def test_offsets_are_absolute(self, simple_xfl):
        with XFLFile(simple_xfl) as xfl:
            base = 12 + 3 * 40
            assert [f.offset for f in xfl.files] == [base, base + len(ALICE), base + len(ALICE) + len(HATTER)]

    def test_read_by_info_and_name(self, simple_xfl):
        with XFLFile(simple_xfl) as xfl:
            assert xfl.read(xfl.files[1]) == HATTER
            assert xfl.read('rabbit.txt') == RABBIT

    def test_read_missing_member(self, simple_xfl):
        with XFLFile(simple_xfl) as xfl, pytest.raises(KeyError):
            xfl.read('cheshire.txt')

    def test_read_after_close(self, simple_xfl):
        xfl = XFLFile(simple_xfl)
        xfl.close()
        with pytest.raises(ValueError):
            xfl.read('alice.txt')

    def test_zero_length_member(self, tmp_path):
        path = tmp_path / 'empty.xfl'
        path.write_bytes(_build_xfl([('alice.txt', ALICE), ('blank.sfap0', b''), ('rabbit.txt', RABBIT)]))
        with XFLFile(path) as xfl:
            assert xfl.read('blank.sfap0') == b''
            assert xfl.read('rabbit.txt') == RABBIT

    def test_cp932_names(self, tmp_path):
        path = tmp_path / 'jp.xfl'
        path.write_bytes(_build_xfl([('アリス.txt', ALICE)]))
        with XFLFile(path) as xfl:
            assert xfl.files[0].file_name == 'アリス.txt'

    def test_data_base_follows_count_not_index_size(self, tmp_path):
        # The engine ignores index_size and starts data right after count * 40 bytes of index.
        path = tmp_path / 'odd.xfl'
        path.write_bytes(_build_xfl([('alice.txt', ALICE)], index_size=999))
        with XFLFile(path) as xfl:
            assert xfl.read('alice.txt') == ALICE

    def test_bad_magic(self, tmp_path):
        path = tmp_path / 'bad.xfl'
        path.write_bytes(b'LG\x01\x00' + bytes(8))
        with pytest.raises(ValueError):
            XFLFile(path)

    def test_too_small(self, tmp_path):
        path = tmp_path / 'tiny.xfl'
        path.write_bytes(b'LB\x01')
        with pytest.raises(ValueError):
            XFLFile(path)

    def test_truncated_index(self, tmp_path):
        path = tmp_path / 'trunc.xfl'
        path.write_bytes(_build_xfl([('alice.txt', ALICE), ('rabbit.txt', RABBIT)])[:60])
        with pytest.raises(ValueError):
            XFLFile(path)

    def test_member_out_of_bounds(self, tmp_path):
        path = tmp_path / 'short.xfl'
        path.write_bytes(_build_xfl([('alice.txt', ALICE)])[:-5])
        with pytest.raises(ValueError):
            XFLFile(path)


@pytest.mark.integration
class TestNestedRead:
    def test_nested_members_are_flattened_with_directory_prefix(self, nested_xfl):
        with XFLFile(nested_xfl) as xfl:
            assert [f.file_name for f in xfl.files] == [
                'alice.txt',
                'glass/alice.txt',
                'glass/jabberwock.txt',
                'rabbit.txt',
            ]

    def test_colliding_names_are_distinct(self, nested_xfl):
        with XFLFile(nested_xfl) as xfl:
            assert xfl.read('alice.txt') == ALICE
            assert xfl.read('glass/alice.txt') == b'Through the looking-glass.'

    def test_nested_archives_are_listed(self, nested_xfl):
        with XFLFile(nested_xfl) as xfl:
            assert xfl.archives == ['glass']

    def test_xfl_name_without_magic_is_a_plain_member(self, tmp_path):
        path = tmp_path / 'plain.xfl'
        path.write_bytes(_build_xfl([('fake.xfl', b'not an archive at all')]))
        with XFLFile(path) as xfl:
            assert [f.file_name for f in xfl.files] == ['fake.xfl']
            assert xfl.read('fake.xfl') == b'not an archive at all'

    def test_magic_without_xfl_extension_is_a_plain_member(self, tmp_path):
        path = tmp_path / 'plain.xfl'
        path.write_bytes(_build_xfl([('glass.bin', LOOKING_GLASS)]))
        with XFLFile(path) as xfl:
            assert [f.file_name for f in xfl.files] == ['glass.bin']

    def test_broken_nested_header_is_a_plain_member(self, tmp_path):
        broken = XFL_MAGIC + struct.pack('<II', 40 * 50, 50)  # claims 50 entries, has none
        path = tmp_path / 'plain.xfl'
        path.write_bytes(_build_xfl([('glass.xfl', broken)]))
        with XFLFile(path) as xfl:
            assert [f.file_name for f in xfl.files] == ['glass.xfl']

    def test_doubly_nested(self, tmp_path):
        inner = _build_xfl([('mock.xfl', _build_xfl([('turtle.txt', b'Beautiful Soup')]))])
        path = tmp_path / 'deep.xfl'
        path.write_bytes(_build_xfl([('gryphon.xfl', inner)]))
        with XFLFile(path) as xfl:
            assert [f.file_name for f in xfl.files] == ['gryphon/mock/turtle.txt']
            assert xfl.archives == ['gryphon', 'gryphon/mock']
            assert xfl.read('gryphon/mock/turtle.txt') == b'Beautiful Soup'


# -- extraction ---------------------------------------------------------------


@pytest.mark.integration
class TestExtract:
    def test_extract_all(self, simple_xfl, tmp_path):
        out = tmp_path / 'out'
        with XFLFile(simple_xfl) as xfl:
            xfl.extract_all(out)
        assert (out / 'alice.txt').read_bytes() == ALICE
        assert (out / 'hatter.txt').read_bytes() == HATTER
        assert (out / 'rabbit.txt').read_bytes() == RABBIT

    def test_extract_nested_as_directories(self, nested_xfl, tmp_path):
        out = tmp_path / 'out'
        with XFLFile(nested_xfl) as xfl:
            xfl.extract_all(out)
        assert (out / 'alice.txt').read_bytes() == ALICE
        assert (out / 'glass' / 'alice.txt').read_bytes() == b'Through the looking-glass.'
        assert (out / 'glass' / 'jabberwock.txt').read_bytes() == b"'Twas brillig"
        assert not (out / 'glass.xfl').exists()

    def test_extract_empty_nested_archive_creates_directory(self, tmp_path):
        path = tmp_path / 'hollow.xfl'
        path.write_bytes(_build_xfl([('pool.xfl', _build_xfl([]))]))
        out = tmp_path / 'out'
        with XFLFile(path) as xfl:
            assert xfl.files == []
            xfl.extract_all(out)
        assert (out / 'pool').is_dir()

    def test_extract_rejects_path_traversal(self, tmp_path):
        # A nested archive named '...xfl' maps to directory '..'.
        path = tmp_path / 'evil.xfl'
        path.write_bytes(_build_xfl([('...xfl', _build_xfl([('queen.txt', b'Off with her head!')]))]))
        out = tmp_path / 'out'
        with XFLFile(path) as xfl, pytest.raises(ValueError, match='outside'):
            xfl.extract_all(out)
        assert not (tmp_path / 'queen.txt').exists()

    def test_extract_glob(self, nested_xfl, tmp_path):
        out = tmp_path / 'out'
        with XFLFile(nested_xfl) as xfl:
            xfl.extract_all(out, glob='glass/*')
        assert sorted(os.listdir(out)) == ['glass']
        assert sorted(os.listdir(out / 'glass')) == ['alice.txt', 'jabberwock.txt']


# -- creation -----------------------------------------------------------------


def _write_files(root, files: dict[str, bytes]):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


@pytest.mark.integration
class TestWrite:
    def test_layout_is_exact(self, tmp_path):
        src = tmp_path / 'src'
        _write_files(src, {'alice.txt': ALICE, 'hatter.txt': HATTER, 'rabbit.txt': RABBIT})
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write_all(src)
        assert out.read_bytes() == _build_xfl([('alice.txt', ALICE), ('hatter.txt', HATTER), ('rabbit.txt', RABBIT)])

    def test_members_are_sorted_in_engine_order(self, tmp_path):
        src = tmp_path / 'src'
        _write_files(
            src,
            {'tbox01.lwg': b'1', 'Thumbs.db': b'2', 'hatter-1.txt': b'3', 'hatter.txt': b'4', 'dormouse_2.wav': b'5'},
        )
        files = sorted(src.iterdir())
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            for f in reversed(files):
                xfl.write(f)
        with XFLFile(out) as xfl:
            assert [f.file_name for f in xfl.files] == [
                'dormouse_2.wav',
                'hatter.txt',
                'hatter-1.txt',
                'tbox01.lwg',
                'Thumbs.db',
            ]

    def test_write_with_arcname(self, tmp_path):
        src = tmp_path / 'tale.bin'
        src.write_bytes(ALICE)
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write(src, arcname='alice.txt')
        with XFLFile(out) as xfl:
            assert xfl.read('alice.txt') == ALICE

    def test_zero_length_member(self, tmp_path):
        src = tmp_path / 'src'
        _write_files(src, {'alice.txt': ALICE, 'blank.sfap0': b''})
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write_all(src)
        with XFLFile(out) as xfl:
            assert xfl.read('blank.sfap0') == b''
            assert xfl.read('alice.txt') == ALICE

    def test_subdirectories_become_nested_archives(self, tmp_path):
        src = tmp_path / 'src'
        _write_files(src, {'alice.txt': ALICE, 'glass/alice.txt': b'Through the looking-glass.'})
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write_all(src)
        expected = _build_xfl(
            [('alice.txt', ALICE), ('glass.xfl', _build_xfl([('alice.txt', b'Through the looking-glass.')]))]
        )
        assert out.read_bytes() == expected

    def test_arcname_with_backslash_is_nested(self, tmp_path):
        src = tmp_path / 'turtle.txt'
        src.write_bytes(b'Beautiful Soup')
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write(src, arcname='gryphon\\mock\\turtle.txt')
        with XFLFile(out) as xfl:
            assert [f.file_name for f in xfl.files] == ['gryphon/mock/turtle.txt']

    def test_empty_directory_becomes_empty_nested_archive(self, tmp_path):
        src = tmp_path / 'src'
        (src / 'pool').mkdir(parents=True)
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write_all(src)
        assert out.read_bytes() == _build_xfl([('pool.xfl', _build_xfl([]))])

    def test_write_all_glob(self, tmp_path):
        src = tmp_path / 'src'
        _write_files(src, {'alice.txt': ALICE, 'rabbit.wav': RABBIT, 'glass/alice.txt': b'x'})
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write_all(src, glob='*.txt')
        with XFLFile(out) as xfl:
            assert sorted(f.file_name for f in xfl.files) == ['alice.txt', 'glass/alice.txt']

    def test_31_byte_name_is_accepted(self, tmp_path):
        name = 'a' * 27 + '.txt'
        src = tmp_path / name
        src.write_bytes(ALICE)
        out = tmp_path / 'out.xfl'
        with XFLFile(out, mode='w') as xfl:
            xfl.write(src)
        with XFLFile(out) as xfl:
            assert xfl.files[0].file_name == name

    def test_32_byte_name_is_stored_without_terminator(self, tmp_path, caplog):
        # Shipped archives contain names that fill the whole field with no NUL.
        name = 'a' * 28 + '.txt'
        src = tmp_path / 'tale.txt'
        src.write_bytes(ALICE)
        out = tmp_path / 'out.xfl'
        with caplog.at_level('WARNING'):
            with XFLFile(out, mode='w') as xfl:
                xfl.write(src, arcname=name)
        assert 'no NUL terminator' in caplog.text
        assert out.read_bytes() == _build_xfl([(name, ALICE)])
        with XFLFile(out) as xfl:
            assert xfl.files[0].file_name == name
            assert xfl.read(name) == ALICE

    def test_33_byte_name_is_rejected(self, tmp_path):
        src = tmp_path / 'tale.txt'
        src.write_bytes(ALICE)
        with XFLFile(tmp_path / 'out.xfl', mode='w') as xfl, pytest.raises(ValueError, match='too long'):
            xfl.write(src, arcname='a' * 29 + '.txt')

    def test_name_length_counts_cp932_bytes(self, tmp_path):
        src = tmp_path / 'tale.txt'
        src.write_bytes(ALICE)
        with XFLFile(tmp_path / 'out.xfl', mode='w') as xfl, pytest.raises(ValueError, match='too long'):
            xfl.write(src, arcname='アリス' * 5 + '.txt')  # 15 chars, 34 bytes

    def test_unencodable_name_is_rejected(self, tmp_path):
        src = tmp_path / 'tale.txt'
        src.write_bytes(ALICE)
        with XFLFile(tmp_path / 'out.xfl', mode='w') as xfl, pytest.raises(ValueError, match='CP932'):
            xfl.write(src, arcname='aliceé.txt')

    def test_duplicate_name_is_rejected(self, tmp_path):
        src = tmp_path / 'tale.txt'
        src.write_bytes(ALICE)
        with XFLFile(tmp_path / 'out.xfl', mode='w') as xfl:
            xfl.write(src, arcname='alice.txt')
            with pytest.raises(ValueError, match='duplicate'):
                xfl.write(src, arcname='Alice.txt')

    def test_file_and_nested_archive_collision_is_rejected(self, tmp_path):
        src = tmp_path / 'tale.txt'
        src.write_bytes(ALICE)
        with XFLFile(tmp_path / 'out.xfl', mode='w') as xfl:
            xfl.write(src, arcname='glass.xfl')
            with pytest.raises(ValueError, match='glass'):
                xfl.write(src, arcname='glass/alice.txt')

    def test_write_requires_write_mode(self, simple_xfl, tmp_path):
        with XFLFile(simple_xfl) as xfl, pytest.raises(ValueError):
            xfl.write(tmp_path / 'x', arcname='x')

    def test_invalid_mode(self, tmp_path):
        with pytest.raises(ValueError):
            XFLFile(tmp_path / 'out.xfl', mode='a')


@pytest.mark.integration
class TestRoundtrip:
    def test_extract_and_recreate_is_byte_identical(self, tmp_path):
        original = _build_xfl(
            [
                ('0001.wav', b'curiouser'),
                ('0001_2.wav', b'and curiouser'),
                ('0215.wav', b'off with'),
                ('0215-1.wav', b'her head'),
                ('1.xfl', _build_xfl([('0001.wav', b'drink me'), ('0002.wav', b'eat me')])),
                ('tbox01.lwg', b'lobster'),
                ('Thumbs.db', b'quadrille'),
            ]
        )
        path = tmp_path / 'voice.xfl'
        path.write_bytes(original)
        out = tmp_path / 'out'
        with XFLFile(path) as xfl:
            xfl.extract_all(out)
        rebuilt = tmp_path / 'rebuilt.xfl'
        with XFLFile(rebuilt, mode='w') as xfl:
            xfl.write_all(out)
        assert rebuilt.read_bytes() == original


@pytest.mark.unit
def test_info_repr():
    info = XFLInfo('alice.txt', 12, 34)
    assert 'alice.txt' in repr(info)
