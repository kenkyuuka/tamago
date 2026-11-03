"""Tests for the Ren'Py RPA archive reader and writer."""

import pathlib
import pickle
import zlib

import pytest

from tamago.formats.rpa import RPAFile

FIXTURES = pathlib.Path(__file__).resolve().parent / 'fixtures'

# renpy-8.5.3.rpa was built by the Ren'Py 8.5.3 SDK's own distribute pipeline.
ENGINE_FIXTURE = FIXTURES / 'renpy-8.5.3.rpa'
ENGINE_FIXTURE_MEMBERS = {
    'wonderland/rabbit_hole.txt': b'Alice was beginning to get very tired of sitting by her sister on the bank.\n',
    'wonderland/tea_party/hatter.txt': b'Why is a raven like a writing-desk?\n',
    'wonderland/tea_party/empty_cup.txt': b'',
    'wonderland/tea_party/drink_me.bin': bytes(range(256)),
    'wonderland/不思議の国/アリス.txt': b'Curiouser and curiouser!\n',
}

KEY = 0x42424242
RPA3_HEADER_SIZE = 34


def _rpa3(path, members, key=KEY, protocol=2):
    """Write an RPA-3.0 archive by hand, independently of the writer under test.

    *members* maps a name to a list of ``(prefix, body)`` pairs. A prefix of
    ``None`` writes a two-element ``(offset, length)`` entry. The stored length
    counts the prefix.
    """
    body = bytearray()
    index = {}
    for name, segments in members.items():
        entries = []
        for prefix, data in segments:
            offset = RPA3_HEADER_SIZE + len(body)
            body += data
            if prefix is None:
                entries.append((offset ^ key, len(data) ^ key))
            else:
                entries.append((offset ^ key, (len(prefix) + len(data)) ^ key, prefix))
        index[name] = entries
    _write_rpa3(path, bytes(body), zlib.compress(pickle.dumps(index, protocol)), key)


def _write_rpa3(path, body, compressed_index, key=KEY):
    index_offset = RPA3_HEADER_SIZE + len(body)
    pathlib.Path(path).write_bytes(b'RPA-3.0 %016x %08x\n' % (index_offset, key) + body + compressed_index)


class _Payload:
    """Pickles to a call of os.mkdir, which must never run on read."""

    def __init__(self, path):
        self.path = str(path)

    def __reduce__(self):
        import os

        return (os.mkdir, (self.path,))


@pytest.mark.integration
class TestEngineFixture:
    def test_lists_every_member(self):
        with RPAFile(ENGINE_FIXTURE) as rpa:
            assert sorted(f.file_name for f in rpa.files) == sorted(ENGINE_FIXTURE_MEMBERS)

    @pytest.mark.parametrize('name', sorted(ENGINE_FIXTURE_MEMBERS))
    def test_reads_member(self, name):
        with RPAFile(ENGINE_FIXTURE) as rpa:
            assert rpa.read(name) == ENGINE_FIXTURE_MEMBERS[name]

    def test_extract_all(self, tmp_path):
        with RPAFile(ENGINE_FIXTURE) as rpa:
            rpa.extract_all(tmp_path)
        for name, data in ENGINE_FIXTURE_MEMBERS.items():
            assert (tmp_path / name).read_bytes() == data

    def test_extract_all_glob(self, tmp_path):
        with RPAFile(ENGINE_FIXTURE) as rpa:
            rpa.extract_all(tmp_path, glob='*/hatter.txt')
        found = [p for p in tmp_path.rglob('*') if p.is_file()]
        assert [p.name for p in found] == ['hatter.txt']


@pytest.mark.integration
class TestReadVersions:
    def test_rpa2_has_no_key(self, tmp_path):
        path = tmp_path / 'old.rpa'
        data = b'Who are you? said the Caterpillar.'
        header_size = 25
        index = {'caterpillar.txt': [(header_size, len(data))]}
        path.write_bytes(b'RPA-2.0 %016x\n' % (header_size + len(data)) + data + zlib.compress(pickle.dumps(index, 2)))
        with RPAFile(path) as rpa:
            assert rpa.read('caterpillar.txt') == data

    def _make_rpa1(self, tmp_path):
        data = b'We are all mad here.'
        (tmp_path / 'cat.rpa').write_bytes(b'padding!' + data)
        (tmp_path / 'cat.rpi').write_bytes(zlib.compress(pickle.dumps({'cheshire.txt': [(8, len(data))]}, 2)))
        return data

    def test_rpa1_opened_by_index_file(self, tmp_path):
        data = self._make_rpa1(tmp_path)
        with RPAFile(tmp_path / 'cat.rpi') as rpa:
            assert rpa.read('cheshire.txt') == data

    def test_rpa1_opened_by_data_file(self, tmp_path):
        data = self._make_rpa1(tmp_path)
        with RPAFile(tmp_path / 'cat.rpa') as rpa:
            assert rpa.read('cheshire.txt') == data

    def test_rpa1_missing_data_file(self, tmp_path):
        (tmp_path / 'cat.rpi').write_bytes(zlib.compress(pickle.dumps({'cheshire.txt': [(0, 1)]}, 2)))
        with pytest.raises(ValueError, match='missing'):
            RPAFile(tmp_path / 'cat.rpi')

    def test_unknown_version_rejected(self, tmp_path):
        path = tmp_path / 'future.rpa'
        path.write_bytes(b'RPA-9.9 0000000000000022 42424242\n')
        with pytest.raises(ValueError, match=r'RPA-9\.9'):
            RPAFile(path)

    def test_unrecognised_file_rejected(self, tmp_path):
        path = tmp_path / 'looking_glass.rpa'
        path.write_bytes(b'Jabberwocky, not an archive at all')
        with pytest.raises(ValueError, match='not a recognised RPA'):
            RPAFile(path)

    def test_non_default_key(self, tmp_path):
        path = tmp_path / 'key.rpa'
        _rpa3(path, {'door.txt': [(b'', b'The key was too small.')]}, key=0xDEADBEEF)
        with RPAFile(path) as rpa:
            assert rpa.read('door.txt') == b'The key was too small.'


@pytest.mark.integration
class TestEntryShapes:
    def test_two_element_entry(self, tmp_path):
        path = tmp_path / 'two.rpa'
        _rpa3(path, {'mouse.txt': [(None, b'a long tale')]})
        with RPAFile(path) as rpa:
            assert rpa.read('mouse.txt') == b'a long tale'

    def test_stored_length_includes_prefix(self, tmp_path):
        """Engines that read prefixed entries bound the prefix and body together by the stored length."""
        path = tmp_path / 'prefix.rpa'
        # The second member directly follows the first: over-reading would pull in its bytes.
        _rpa3(path, {'queen.txt': [(b'Off ', b'with their heads!')], 'knave.txt': [(b'', b'XXXXXXXX')]})
        with RPAFile(path) as rpa:
            assert rpa.read('queen.txt') == b'Off with their heads!'

    def test_size_includes_prefix(self, tmp_path):
        path = tmp_path / 'prefix.rpa'
        _rpa3(path, {'queen.txt': [(b'Off ', b'with their heads!')]})
        with RPAFile(path) as rpa:
            assert rpa.files[0].size == len(b'Off with their heads!')

    def test_prefix_longer_than_stored_length_rejected(self, tmp_path):
        path = tmp_path / 'bad.rpa'
        index = {'queen.txt': [(RPA3_HEADER_SIZE ^ KEY, 1 ^ KEY, b'Off with')]}
        _write_rpa3(path, b'', zlib.compress(pickle.dumps(index, 2)))
        with pytest.raises(ValueError, match=r'queen\.txt'):
            RPAFile(path)

    def test_multiple_segments_are_joined(self, tmp_path):
        path = tmp_path / 'multi.rpa'
        _rpa3(path, {'tarts.txt': [(None, b'The Queen of Hearts, '), (None, b'she made some tarts')]})
        with RPAFile(path) as rpa:
            assert rpa.read('tarts.txt') == b'The Queen of Hearts, she made some tarts'
            assert rpa.files[0].size == len(b'The Queen of Hearts, she made some tarts')

    def test_empty_member(self, tmp_path):
        path = tmp_path / 'empty.rpa'
        _rpa3(path, {'empty_cup.txt': [(b'', b'')]})
        with RPAFile(path) as rpa:
            assert rpa.read('empty_cup.txt') == b''


@pytest.mark.integration
class TestIndexEncodings:
    """Older writers encode names and prefixes differently from current Ren'Py."""

    def test_python3_bytes_at_protocol_2(self, tmp_path):
        """Python 3 pickles bytes at protocol 2 through _codecs.encode, a global."""
        path = tmp_path / 'p3.rpa'
        _rpa3(path, {'queen.txt': [(b'Off \xff', b'with their heads!')]}, protocol=2)
        with RPAFile(path) as rpa:
            assert rpa.read('queen.txt') == b'Off \xffwith their heads!'

    def test_python3_empty_bytes_at_protocol_2(self, tmp_path):
        """Empty bytes at protocol 2 pickle as a call to the bytes builtin."""
        path = tmp_path / 'p3.rpa'
        _rpa3(path, {'dormouse.txt': [(b'', b'Twinkle, twinkle')]}, protocol=2)
        assert b'bytes' in zlib.decompress(path.read_bytes()[RPA3_HEADER_SIZE + len(b'Twinkle, twinkle') :])
        with RPAFile(path) as rpa:
            assert rpa.read('dormouse.txt') == b'Twinkle, twinkle'

    def test_python2_byte_strings(self, tmp_path):
        """Python 2 writes names and prefixes as 8-bit strings; names hold UTF-8."""
        path = tmp_path / 'p2.rpa'
        data = b'with their heads!'
        name = 'アリス.txt'.encode()
        prefix = b'Off \xff'
        offset = RPA3_HEADER_SIZE ^ KEY
        length = (len(prefix) + len(data)) ^ KEY

        def short_binstring(value):
            return b'U' + bytes([len(value)]) + value

        def binint(value):
            return b'J' + value.to_bytes(4, 'little')

        # Protocol 2 opcodes, as Python 2's pickler emits them for this index.
        raw = (
            b'\x80\x02}'
            + short_binstring(name)
            + b']'
            + binint(offset)
            + binint(length)
            + short_binstring(prefix)
            + b'\x87as.'
        )
        _write_rpa3(path, data, zlib.compress(raw))
        with RPAFile(path) as rpa:
            assert rpa.read('アリス.txt') == prefix + data

    def test_text_prefix_is_latin1(self, tmp_path):
        """Some writers store the prefix as text, whose code points are the original bytes."""
        path = tmp_path / 'text.rpa'
        data = b'with their heads!'
        prefix = 'Off \xff'
        index = {'queen.txt': [(RPA3_HEADER_SIZE ^ KEY, (len(prefix) + len(data)) ^ KEY, prefix)]}
        _write_rpa3(path, data, zlib.compress(pickle.dumps(index, 2)))
        with RPAFile(path) as rpa:
            assert rpa.read('queen.txt') == b'Off \xffwith their heads!'

    def test_text_prefix_outside_latin1_rejected(self, tmp_path):
        path = tmp_path / 'text.rpa'
        index = {'queen.txt': [(RPA3_HEADER_SIZE ^ KEY, 1 ^ KEY, 'アリス')]}
        _write_rpa3(path, b'', zlib.compress(pickle.dumps(index, 2)))
        with pytest.raises(ValueError, match=r'queen\.txt'):
            RPAFile(path)

    def test_none_prefix_is_empty(self, tmp_path):
        path = tmp_path / 'none.rpa'
        index = {'queen.txt': [(RPA3_HEADER_SIZE ^ KEY, 3 ^ KEY, None)]}
        _write_rpa3(path, b'Off', zlib.compress(pickle.dumps(index, 2)))
        with RPAFile(path) as rpa:
            assert rpa.read('queen.txt') == b'Off'

    def test_highest_protocol(self, tmp_path):
        path = tmp_path / 'p5.rpa'
        _rpa3(path, {'queen.txt': [(b'Off ', b'with their heads!')]}, protocol=5)
        with RPAFile(path) as rpa:
            assert rpa.read('queen.txt') == b'Off with their heads!'


@pytest.mark.integration
class TestHostileArchives:
    def test_index_cannot_execute_code(self, tmp_path):
        marker = tmp_path / 'eat_me'
        path = tmp_path / 'evil.rpa'
        _write_rpa3(path, b'', zlib.compress(pickle.dumps({'a': [_Payload(marker)]}, 2)))
        with pytest.raises(ValueError, match='index'):
            RPAFile(path)
        assert not marker.exists()

    @pytest.mark.parametrize('protocol', [0, 2, 5])
    def test_root_payload_cannot_execute_code(self, tmp_path, protocol):
        marker = tmp_path / 'eat_me'
        path = tmp_path / 'evil.rpa'
        _write_rpa3(path, b'', zlib.compress(pickle.dumps(_Payload(marker), protocol)))
        with pytest.raises(ValueError, match='index'):
            RPAFile(path)
        assert not marker.exists()

    @pytest.mark.parametrize(
        'name',
        ['../escape.txt', 'wonderland/../../escape.txt', '/etc/escape.txt', '..\\escape.txt', 'C:\\escape.txt', ''],
    )
    def test_extract_all_refuses_unsafe_names(self, tmp_path, name):
        path = tmp_path / 'evil.rpa'
        _rpa3(path, {'safe.txt': [(b'', b'ok')], name: [(b'', b'gotcha')]})
        out = tmp_path / 'deep' / 'out'
        with RPAFile(path) as rpa, pytest.raises(ValueError, match='unsafe'):
            rpa.extract_all(out)
        # Refused up front: nothing at all is written.
        assert not out.exists()
        assert not (tmp_path / 'deep' / 'escape.txt').exists()

    def test_unsafe_name_outside_glob_does_not_block(self, tmp_path):
        path = tmp_path / 'evil.rpa'
        _rpa3(path, {'safe.txt': [(b'', b'ok')], '../escape.txt': [(b'', b'gotcha')]})
        with RPAFile(path) as rpa:
            rpa.extract_all(tmp_path / 'out', glob='safe*')
        assert (tmp_path / 'out' / 'safe.txt').read_bytes() == b'ok'

    def test_member_past_end_of_file(self, tmp_path):
        path = tmp_path / 'trunc.rpa'
        index = {'long.txt': [(RPA3_HEADER_SIZE ^ KEY, 4096 ^ KEY, b'')]}
        _write_rpa3(path, b'short', zlib.compress(pickle.dumps(index, 2)))
        with RPAFile(path) as rpa, pytest.raises(ValueError, match=r'long\.txt'):
            rpa.read('long.txt')

    def test_negative_offset_rejected(self, tmp_path):
        path = tmp_path / 'neg.rpa'
        index = {'neg.txt': [(-1 ^ KEY, 1 ^ KEY, b'')]}
        _write_rpa3(path, b'', zlib.compress(pickle.dumps(index, 2)))
        with pytest.raises(ValueError, match=r'neg\.txt'):
            RPAFile(path)

    def test_index_offset_past_end_rejected(self, tmp_path):
        path = tmp_path / 'far.rpa'
        path.write_bytes(b'RPA-3.0 %016x %08x\n' % (1 << 40, KEY))
        with pytest.raises(ValueError, match='offset'):
            RPAFile(path)

    def test_bad_hex_header_rejected(self, tmp_path):
        path = tmp_path / 'hex.rpa'
        path.write_bytes(b'RPA-3.0 not-hex-at-all!! 42424242\n')
        with pytest.raises(ValueError, match='header'):
            RPAFile(path)

    def test_corrupt_index_rejected(self, tmp_path):
        path = tmp_path / 'corrupt.rpa'
        _write_rpa3(path, b'', b'this is not zlib data')
        with pytest.raises(ValueError, match='index'):
            RPAFile(path)

    @pytest.mark.parametrize('value', [[], {'a': 1}, {'a': []}, {'a': ['x']}, {'a': [(1,)]}, {'a': [('x', 'y')]}])
    def test_wrong_index_shape_rejected(self, tmp_path, value):
        path = tmp_path / 'shape.rpa'
        _write_rpa3(path, b'', zlib.compress(pickle.dumps(value, 2)))
        with pytest.raises(ValueError):
            RPAFile(path)

    def test_oversized_index_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr('tamago.formats.rpa.rpafile.MAX_INDEX_SIZE', 1024)
        path = tmp_path / 'bomb.rpa'
        _write_rpa3(path, b'', zlib.compress(b'\0' * 1_000_000))
        with pytest.raises(ValueError, match='index'):
            RPAFile(path)

    def test_failed_open_closes_file(self, tmp_path, recwarn):
        path = tmp_path / 'bad.rpa'
        path.write_bytes(b'not an archive')
        with pytest.raises(ValueError):
            RPAFile(path)
        assert not [w for w in recwarn if issubclass(w.category, ResourceWarning)]


@pytest.mark.integration
class TestWrite:
    def _tree(self, root):
        for name, data in ENGINE_FIXTURE_MEMBERS.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    def test_roundtrip(self, tmp_path):
        src = tmp_path / 'src'
        self._tree(src)
        path = tmp_path / 'out.rpa'
        with RPAFile(path, mode='w') as rpa:
            rpa.write_all(src)
        with RPAFile(path) as rpa:
            assert {f.file_name: rpa.read(f) for f in rpa.files} == ENGINE_FIXTURE_MEMBERS

    def test_header_is_rpa3_with_default_key(self, tmp_path):
        src = tmp_path / 'src'
        self._tree(src)
        path = tmp_path / 'out.rpa'
        with RPAFile(path, mode='w') as rpa:
            rpa.write_all(src)
        header = path.read_bytes()[:RPA3_HEADER_SIZE]
        assert header.startswith(b'RPA-3.0 ')
        assert header.endswith(b' 42424242\n')

    def test_custom_key(self, tmp_path):
        source = tmp_path / 'door.txt'
        source.write_bytes(b'Drink me')
        path = tmp_path / 'out.rpa'
        with RPAFile(path, mode='w', key=0xDEADBEEF) as rpa:
            rpa.write(source)
        assert path.read_bytes()[:RPA3_HEADER_SIZE].endswith(b' deadbeef\n')
        with RPAFile(path) as rpa:
            assert rpa.read('door.txt') == b'Drink me'

    @pytest.mark.parametrize('key', [-1, 1 << 32])
    def test_key_out_of_range(self, tmp_path, key):
        with pytest.raises(ValueError, match='key'):
            RPAFile(tmp_path / 'out.rpa', mode='w', key=key)

    def test_index_holds_only_plain_types(self, tmp_path):
        """Old engines must be able to load the index, so it stays free of pickle globals."""
        import pickletools

        source = tmp_path / 'door.txt'
        source.write_bytes(b'Drink me')
        path = tmp_path / 'out.rpa'
        with RPAFile(path, mode='w') as rpa:
            rpa.write(source)
        raw = path.read_bytes()
        offset = int(raw[8:24], 16)
        ops = [op.name for op, _arg, _pos in pickletools.genops(zlib.decompress(raw[offset:]))]
        assert not {'GLOBAL', 'STACK_GLOBAL', 'REDUCE'} & set(ops)
        assert ops[0] == 'PROTO'
        assert raw[offset:] and zlib.decompress(raw[offset:])[1] == 2

    def test_glob(self, tmp_path):
        src = tmp_path / 'src'
        self._tree(src)
        path = tmp_path / 'out.rpa'
        with RPAFile(path, mode='w') as rpa:
            rpa.write_all(src, glob='*.bin')
        with RPAFile(path) as rpa:
            assert [f.file_name for f in rpa.files] == ['wonderland/tea_party/drink_me.bin']

    def test_backslashes_normalised(self, tmp_path):
        source = tmp_path / 'door.txt'
        source.write_bytes(b'Drink me')
        path = tmp_path / 'out.rpa'
        with RPAFile(path, mode='w') as rpa:
            rpa.write(source, arcname='hall\\door.txt')
        with RPAFile(path) as rpa:
            assert rpa.read('hall/door.txt') == b'Drink me'

    def test_write_all_skips_the_archive_itself(self, tmp_path):
        """Packing a directory into an archive inside it must terminate and leave the archive out."""
        (tmp_path / 'door.txt').write_bytes(b'Drink me')
        path = tmp_path / 'out.rpa'
        with RPAFile(path, mode='w') as rpa:
            rpa.write_all(tmp_path)
        with RPAFile(path) as rpa:
            assert [f.file_name for f in rpa.files] == ['door.txt']

    def test_duplicate_name_rejected(self, tmp_path):
        source = tmp_path / 'door.txt'
        source.write_bytes(b'Drink me')
        with RPAFile(tmp_path / 'out.rpa', mode='w') as rpa:
            rpa.write(source)
            with pytest.raises(ValueError, match=r'door\.txt'):
                rpa.write(source)

    def test_empty_archive(self, tmp_path):
        path = tmp_path / 'out.rpa'
        RPAFile(path, mode='w').close()
        with RPAFile(path) as rpa:
            assert rpa.files == []

    def test_write_requires_write_mode(self):
        with RPAFile(ENGINE_FIXTURE) as rpa, pytest.raises(ValueError, match="mode='w'"):
            rpa.write(ENGINE_FIXTURE)

    def test_invalid_mode(self, tmp_path):
        with pytest.raises(ValueError, match='mode'):
            RPAFile(tmp_path / 'out.rpa', mode='a')


@pytest.mark.unit
class TestRead:
    def test_missing_member(self):
        with RPAFile(ENGINE_FIXTURE) as rpa, pytest.raises(KeyError):
            rpa.read('wonderland/jabberwock.txt')

    def test_read_after_close(self):
        rpa = RPAFile(ENGINE_FIXTURE)
        rpa.close()
        with pytest.raises(ValueError, match='closed'):
            rpa.read('wonderland/rabbit_hole.txt')
