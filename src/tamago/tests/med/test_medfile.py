"""Tests for the MD (".med") archive reader and writer."""

import struct

import pytest

from tamago.formats.med import MEDFile, decrypt_script, encrypt_script, is_med_header

VIEW_PLAIN = b'\x00#RULE_VIEWER\x00:VIEW_0\x00{\x00'

ALICE = b'Alice was beginning to get very tired of sitting by her sister on the bank.'
PRS = b'YB\x83\x04' + b'\x10\x00' * 20  # PRS image signature, then filler
WADY = b'WADY' + bytes(range(40))


def _script(lines, count, opcodes=b'\x01\x00\x02\x00\x03\x00'):
    """A plaintext script: 16-byte header, opcodes, then NUL-terminated cp932 strings."""
    text = b''.join(line.encode('cp932') + b'\0' for line in lines)
    body = opcodes + text
    return struct.pack('<4I', len(body), len(opcodes), 0x00010002, count) + body


def _view_script(count=3):
    body = VIEW_PLAIN + 'アリス'.encode('cp932') + b'\0'
    return struct.pack('<4I', len(body), 0, 0, count) + body


SCRIPTS = {
    'RABBIT_HOLE': _script(['アリス「ウサギを追いかけなきゃ。」', 'Down, down, down.'], 17),
    'TEA_PARTY': _script(['帽子屋「席はないよ。」', 'Why is a raven like a writing-desk?'], 5),
    '_VIEW': _view_script(3),
    'CROQUET': _script(['女王「首をはねよ。」'], 11),
}


def _add_cipher(data, keyword, sign):
    out = bytearray(data)
    for i in range(16, len(out)):
        out[i] = (out[i] + sign * keyword[i % len(keyword)]) & 0xFF
    return bytes(out)


def _build(members, signature=b'MDN1', *, keyword=None, junk=b'\0' * 8, pad=b'\0', counters=None):
    """Assemble an MD archive by hand, independently of the writer under test.

    *members* maps names to plaintext contents.  For type '0' archives, *keyword*
    encrypts each script and counters default to the running total of each
    script's header field at 0x0C.
    """
    is_script = signature[3:4] == b'0'
    names = [n.encode('cp932') for n in members]
    field = max(map(len, names)) + 1
    entry_size = field + (12 if is_script else 8)
    offset = 16 + entry_size * len(members)
    index = bytearray()
    data = bytearray()
    running = 0
    for i, (raw_name, content) in enumerate(zip(names, members.values(), strict=True)):
        looks_like_script = len(content) >= 16 and struct.unpack_from('<I', content)[0] + 16 == len(content)
        if is_script:
            counter = counters[i] if counters else running
            if looks_like_script:
                running += struct.unpack_from('<I', content, 12)[0]
        stored = _add_cipher(content, keyword, -1) if is_script and keyword and looks_like_script else content
        index += raw_name + b'\0' + pad * (field - len(raw_name) - 1)
        if is_script:
            index += struct.pack('<I', counter)
        index += struct.pack('<II', len(stored), offset + len(data))
        data += stored
    header = signature + struct.pack('<HH', entry_size, len(members)) + junk
    return bytes(header + index + data)


def _write(tmp_path, members, name='md_test.med', **kwargs):
    path = tmp_path / name
    path.write_bytes(_build(members, **kwargs))
    return path


def _contents(path, **kwargs):
    with MEDFile(path, **kwargs) as med:
        return {info.file_name: med.read(info) for info in med.files}


@pytest.mark.unit
class TestCipher:
    def test_decrypt_adds_keyword_by_member_position(self):
        # Byte 0x10 uses key[0x10 % 5] = key[1].
        data = bytes(16) + b'\x00\x00\x00'
        assert decrypt_script(data, b'Alice') == bytes(16) + b'lic'

    def test_header_is_untouched(self):
        script = SCRIPTS['RABBIT_HOLE']
        assert encrypt_script(script, b'goro5656')[:16] == script[:16]

    def test_roundtrip(self):
        script = SCRIPTS['TEA_PARTY']
        encrypted = encrypt_script(script, b'ikawork4441')
        assert encrypted != script
        assert encrypted == _add_cipher(script, b'ikawork4441', -1)
        assert decrypt_script(encrypted, b'ikawork4441') == script


@pytest.mark.unit
class TestRead:
    def test_image_archive(self, tmp_path):
        path = _write(tmp_path, {'BG_HALL': PRS, 'CH_ALICE_01': PRS[::-1], 'アリス': PRS + b'!'})
        with MEDFile(path) as med:
            assert med.signature == 'MDN1'
            assert [i.file_name for i in med.files] == ['BG_HALL', 'CH_ALICE_01', 'アリス']
            assert all(i.counter is None for i in med.files)
            assert med.read('アリス') == PRS + b'!'

    def test_audio_archive(self, tmp_path):
        assert _contents(_write(tmp_path, {'M01': WADY}, signature=b'MDE6')) == {'M01': WADY}

    def test_garbage_padding_is_ignored(self, tmp_path):
        path = _write(tmp_path, {'BG_HALL': PRS, 'CH_ALICE_01': ALICE}, junk=b'WAVCONVB', pad=b'\xf8')
        assert _contents(path) == {'BG_HALL': PRS, 'CH_ALICE_01': ALICE}

    def test_script_archive_with_keyword(self, tmp_path):
        path = _write(tmp_path, SCRIPTS, signature=b'MDE0', keyword=b'goro5656')
        with MEDFile(path, keyword='goro5656') as med:
            assert med.signature == 'MDE0'
            assert [i.counter for i in med.files] == [0, 17, 22, 25]
            assert {i.file_name: med.read(i) for i in med.files} == SCRIPTS

    @pytest.mark.parametrize(
        'keyword',
        ['goro5656', 'ikawork4441', 'mikudayo0513', 'misdo0407', 'Alice', 'e010exstia01lusteris'],
    )
    def test_keyword_is_recovered(self, tmp_path, keyword):
        path = _write(tmp_path, SCRIPTS, signature=b'MDE0', keyword=keyword.encode())
        with MEDFile(path) as med:
            assert med.keyword == keyword
            assert med.read('RABBIT_HOLE') == SCRIPTS['RABBIT_HOLE']

    def test_false_shorter_period_is_rejected(self, tmp_path):
        # This 23-byte keyword's 24 known keystream bytes are 'TeaPartyHatT' twice, so
        # period 12 fits the known plaintext too.  Only scoring the decrypted scripts
        # tells it apart from the real keyword.
        keyword = 'yHatTTeaPartyHatTeaPart'
        path = _write(tmp_path, SCRIPTS, signature=b'MDE0', keyword=keyword.encode())
        with MEDFile(path) as med:
            assert med.keyword == keyword

    def test_no_view_script_leaves_keyword_unknown(self, tmp_path):
        scripts = {k: v for k, v in SCRIPTS.items() if k != '_VIEW'}
        path = _write(tmp_path, scripts, signature=b'MDE0', keyword=b'goro5656')
        with MEDFile(path) as med:
            assert med.keyword is None
            assert len(med.files) == 3
            with pytest.raises(ValueError, match='keyword'):
                med.read('CROQUET')

    def test_no_decrypt_returns_stored_bytes(self, tmp_path):
        path = _write(tmp_path, SCRIPTS, signature=b'MDE0', keyword=b'goro5656')
        with MEDFile(path, decrypt=False) as med:
            assert med.read('CROQUET') == _add_cipher(SCRIPTS['CROQUET'], b'goro5656', -1)

    def test_non_script_member_in_script_archive_is_not_decrypted(self, tmp_path):
        members = dict(SCRIPTS, ZZ_NOTES=ALICE)
        path = _write(tmp_path, members, signature=b'MDE0', keyword=b'goro5656')
        assert _contents(path)['ZZ_NOTES'] == ALICE

    def test_extract_all(self, tmp_path):
        path = _write(tmp_path, SCRIPTS, signature=b'MDE0', keyword=b'goro5656')
        out = tmp_path / 'out'
        with MEDFile(path) as med:
            med.extract_all(out, glob='*A*')
        assert sorted(p.name for p in out.iterdir()) == ['RABBIT_HOLE', 'TEA_PARTY']
        assert (out / 'TEA_PARTY').read_bytes() == SCRIPTS['TEA_PARTY']


@pytest.mark.unit
class TestReadCorrupt:
    def test_bad_magic(self, tmp_path):
        path = tmp_path / 'tea.med'
        path.write_bytes(b'Twinkle, twinkle, little bat!')
        with pytest.raises(ValueError, match='MD'):
            MEDFile(path)

    def test_member_past_end(self, tmp_path):
        data = bytearray(_build({'BG_HALL': PRS}))
        struct.pack_into('<I', data, 16 + 8, 0x7FFFFFFF)
        path = tmp_path / 'bad.med'
        path.write_bytes(data)
        with pytest.raises(ValueError, match='past the end'):
            MEDFile(path)

    def test_truncated_index(self, tmp_path):
        path = tmp_path / 'bad.med'
        path.write_bytes(_build({'BG_HALL': PRS, 'BG_GARDEN': PRS})[:30])
        with pytest.raises(ValueError, match='index'):
            MEDFile(path)

    @pytest.mark.parametrize(('signature', 'entry_size'), [(b'MDN1', 8), (b'MDE0', 12)])
    def test_entry_too_small(self, tmp_path, signature, entry_size):
        path = tmp_path / 'bad.med'
        path.write_bytes(signature + struct.pack('<HH', entry_size, 0) + bytes(8))
        with pytest.raises(ValueError, match='entry size'):
            MEDFile(path)


@pytest.mark.unit
class TestDetect:
    @pytest.mark.parametrize('magic', [b'MDE0', b'MDE1', b'MDN1', b'MDE6', b'MDN6'])
    def test_known_signatures(self, magic):
        assert is_med_header(magic + struct.pack('<HH', 20, 4) + bytes(8))

    @pytest.mark.parametrize(
        'header', [b'MZ\x90\x00' + bytes(12), b'MDXX' + bytes(12), b'MDE0\x00\x00' + bytes(10), b'MD'], ids=repr
    )
    def test_rejects(self, header):
        assert not is_med_header(header)


def _make_source(tmp_path, files):
    src = tmp_path / 'src'
    src.mkdir()
    for name, data in files.items():
        (src / name).write_bytes(data)
    return src


@pytest.mark.unit
class TestWrite:
    def test_image_roundtrip_and_layout(self, tmp_path):
        files = {'BG_HALL': PRS, 'CH_ALICE_01': ALICE, 'アリス': PRS}
        out = tmp_path / 'md_gra.med'
        with MEDFile(out, mode='w') as med:
            med.write_all(_make_source(tmp_path, files))
        raw = out.read_bytes()
        assert raw[:4] == b'MDE1'
        longest = max(len(name.encode('cp932')) for name in files)
        entry_size, count = struct.unpack_from('<HH', raw, 4)
        assert (entry_size, count) == (longest + 1 + 8, 3)
        assert raw[8:16] == bytes(8)
        # Data starts right after the index, back to back.
        _size, first = struct.unpack_from('<II', raw, 16 + entry_size - 8)
        assert first == 16 + entry_size * 3
        assert _contents(out) == files

    def test_audio_signature_is_inferred(self, tmp_path):
        out = tmp_path / 'md_bgm.med'
        with MEDFile(out, mode='w') as med:
            med.write_all(_make_source(tmp_path, {'M01': WADY, 'M02': WADY}))
        assert out.read_bytes()[:4] == b'MDE6'

    def test_explicit_signature(self, tmp_path):
        out = tmp_path / 'md_gra.med'
        with MEDFile(out, mode='w', signature='MDN1') as med:
            med.write_all(_make_source(tmp_path, {'BG_HALL': PRS}))
        assert out.read_bytes()[:4] == b'MDN1'

    @pytest.mark.parametrize('signature', ['MD', 'XXE1', 'MDE', 'MDEX'])
    def test_invalid_signature(self, tmp_path, signature):
        with pytest.raises(ValueError, match='signature'):
            MEDFile(tmp_path / 'out.med', mode='w', signature=signature)

    def test_script_archive(self, tmp_path):
        out = tmp_path / 'md_scr.med'
        with MEDFile(out, mode='w', keyword='goro5656') as med:
            med.write_all(_make_source(tmp_path, SCRIPTS))
        # Sorted by name, so the counters follow that order.
        ordered = dict(sorted(SCRIPTS.items()))
        assert out.read_bytes() == _build(ordered, signature=b'MDE0', keyword=b'goro5656')
        with MEDFile(out) as med:
            assert med.keyword == 'goro5656'
            assert {i.file_name: med.read(i) for i in med.files} == SCRIPTS

    def test_plaintext_scripts_without_keyword_raise(self, tmp_path):
        with MEDFile(tmp_path / 'md_scr.med', mode='w') as med:
            src = _make_source(tmp_path, SCRIPTS)
            with pytest.raises(ValueError, match='keyword'):
                med.write(src / '_VIEW')

    def test_encrypted_scripts_with_keyword_raise(self, tmp_path):
        src = _make_source(tmp_path, {'_VIEW': encrypt_script(SCRIPTS['_VIEW'], b'goro5656')})
        with MEDFile(tmp_path / 'md_scr.med', mode='w', keyword='goro5656') as med:
            with pytest.raises(ValueError, match='already encrypted'):
                med.write(src / '_VIEW')

    def test_stored_encrypted_scripts_roundtrip_without_keyword(self, tmp_path):
        source = _write(tmp_path, SCRIPTS, signature=b'MDE0', keyword=b'goro5656')
        raw_dir = tmp_path / 'raw'
        with MEDFile(source, decrypt=False) as med:
            med.extract_all(raw_dir)
        out = tmp_path / 'rebuilt.med'
        with MEDFile(out, mode='w', signature='MDE0') as med:
            for name in SCRIPTS:
                med.write(raw_dir / name)
        assert out.read_bytes() == source.read_bytes()

    def test_duplicate_name_raises(self, tmp_path):
        src = _make_source(tmp_path, {'BG_HALL': PRS})
        with MEDFile(tmp_path / 'out.med', mode='w') as med:
            med.write(src / 'BG_HALL')
            with pytest.raises(ValueError, match='Duplicate'):
                med.write(src / 'BG_HALL')

    def test_unencodable_name_raises(self, tmp_path):
        src = _make_source(tmp_path, {'BG_HALL': PRS})
        with MEDFile(tmp_path / 'out.med', mode='w') as med, pytest.raises(ValueError, match='cp932'):
            med.write(src / 'BG_HALL', arcname='🐇')

    def test_empty_name_raises(self, tmp_path):
        src = _make_source(tmp_path, {'BG_HALL': PRS})
        with MEDFile(tmp_path / 'out.med', mode='w') as med, pytest.raises(ValueError, match='empty'):
            med.write(src / 'BG_HALL', arcname='')

    def test_source_may_change_after_write(self, tmp_path):
        src = _make_source(tmp_path, {'BG_HALL': PRS})
        out = tmp_path / 'out.med'
        with MEDFile(out, mode='w') as med:
            med.write(src / 'BG_HALL')
            (src / 'BG_HALL').write_bytes(b'Painted roses')
        assert _contents(out) == {'BG_HALL': PRS}

    def test_does_not_pack_itself(self, tmp_path):
        src = _make_source(tmp_path, {'BG_HALL': PRS})
        out = src / 'out.med'
        with MEDFile(out, mode='w') as med:
            med.write_all(src)
        assert _contents(out) == {'BG_HALL': PRS}

    def test_invalid_mode(self, tmp_path):
        with pytest.raises(ValueError, match='mode'):
            MEDFile(tmp_path / 'out.med', mode='a')
