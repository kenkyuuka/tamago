"""Tests for reading whole Humongous SCUMM files and extracting their resources."""

import logging
import sys

import pytest
from PIL import Image

from tamago.cli import detect_format, get_format_handlers, main
from tamago.formats.scumm import KIND_INDEX, KIND_MUSIC, KIND_ROOMS, KIND_SPEECH, HEFile, file_kind
from tamago.formats.scumm.handler import SCUMMHandler
from tamago.tests.scumm import samples
from tamago.tests.scumm.samples import xor

NAMED = [
    'room-001/background.png',
    'room-001/room.rmda',
    'room-001/objects/object-0007-Cheshire_Cat-01.png',
    'room-001/script-0001.scrp',
    'room-001/sound-0002.wav',
    'room-001/sound-0003.wav',
    'room-001/image-0004.png',
    'room-001/costume-0001.akos',
    'room-001/costume-0001-Alice_shrinks/cel-000.png',
]
POSITIONAL = [
    'room-001/background.png',
    'room-001/room.rmda',
    'room-001/objects/object-0007-Cheshire_Cat-01.png',
    'room-001/scrp-000.scrp',
    'room-001/soun-000.wav',
    'room-001/digi-000.wav',
    'room-001/awiz-000.png',
    'room-001/akos-000.akos',
    'room-001/akos-000-Alice_shrinks/cel-000.png',
]
RAW = [
    'room-001/background.rmim',
    'room-001/room.rmda',
    'room-001/script-0001.scrp',
    'room-001/sound-0002.soun',
    'room-001/sound-0003.digi',
    'room-001/image-0004.awiz',
    'room-001/costume-0001.akos',
]


@pytest.fixture
def game(tmp_path):
    """Alice.he0 / .he1 (obfuscated, like every HE game) and .he2 / .he4 (plain, like HE >= 80)."""
    rooms, room_offsets, places = samples.room_file()
    (tmp_path / 'Alice.he0').write_bytes(xor(samples.index_file(room_offsets, places)))
    (tmp_path / 'Alice.he1').write_bytes(xor(rooms))
    (tmp_path / 'Alice.he2').write_bytes(samples.speech_file()[0])
    (tmp_path / 'Alice.he4').write_bytes(samples.music_file(old=False))
    return tmp_path


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, 'argv', ['tamago', *map(str, argv)])
    main()


@pytest.mark.unit
class TestKinds:
    @pytest.mark.parametrize(
        ('name', 'kind'),
        [('Alice.he0', KIND_INDEX), ('Alice.he1', KIND_ROOMS), ('Alice.he2', KIND_SPEECH), ('Alice.he4', KIND_MUSIC)],
    )
    def test_file_kind(self, game, name, kind):
        assert file_kind((game / name).read_bytes()[:8]) == kind
        assert detect_format(game / name) == 'scumm'

    def test_plain_room_file_and_any_name(self, game):
        rooms = game / 'ALICE.(A)'
        rooms.write_bytes(samples.room_file()[0])
        assert detect_format(rooms) == 'scumm'

    @pytest.mark.parametrize('data', [b'MZ\x90\0\3\0\0\0', b'SCRP\0\0\0\x08', b'LECF'])
    def test_not_scumm(self, tmp_path, data):
        path = tmp_path / 'Alice.he3'
        path.write_bytes(data)
        assert file_kind(data) is None
        assert detect_format(path) != 'scumm'


@pytest.mark.integration
class TestRooms:
    def test_names_from_index(self, game):
        assert HEFile(game / 'Alice.he1').namelist() == NAMED

    def test_names_without_index(self, game):
        assert HEFile(game / 'Alice.he1', use_index=False).namelist() == POSITIONAL
        (game / 'Alice.he0').unlink()
        assert HEFile(game / 'Alice.he1').namelist() == POSITIONAL

    def test_raw_blocks(self, game):
        rooms, _offsets, places = samples.room_file()
        he = HEFile(game / 'Alice.he1')
        assert he.namelist(convert=False) == RAW
        lflf_body = 16
        for name, tag in zip(RAW, ['RMIM', 'RMDA', 'SCRP', 'SOUN', 'DIGI', 'AWIZ', 'AKOS'], strict=True):
            _room, offset, size = places[tag]
            assert he.read(name, convert=False) == rooms[lflf_body + offset : lflf_body + offset + size]

    def test_sounds(self, game):
        he = HEFile(game / 'Alice.he1')
        assert he.read('room-001/sound-0002.wav') == samples.wav(samples.MOCK_TURTLE, 11025)
        assert he.read('room-001/sound-0003.wav') == samples.wav(samples.WHITE_RABBIT, 11000)

    def test_background(self, game, tmp_path):
        HEFile(game / 'Alice.he1').extract_all(tmp_path / 'out', glob='*background*')
        im = Image.open(tmp_path / 'out' / 'room-001' / 'background.png')
        assert im.mode == 'P'
        assert im.size == (samples.BACKGROUND_WIDTH, samples.BACKGROUND_HEIGHT)
        assert list(im.tobytes()) == samples.BACKGROUND_PIXELS
        assert im.convert('RGB').getpixel((0, 0)) == samples.rgb(0x2A)

    def test_object_transparency(self, game, tmp_path):
        HEFile(game / 'Alice.he1').extract_all(tmp_path / 'out', glob='*objects*')
        im = Image.open(tmp_path / 'out' / 'room-001' / 'objects' / 'object-0007-Cheshire_Cat-01.png')
        assert im.mode == 'RGBA'
        assert im.size == (16, 2)
        # Strip A is opaque, even where it uses the transparent colour 5.
        assert im.getpixel((0, 0)) == (*samples.rgb(10), 255)
        assert im.getpixel((0, 1)) == (*samples.rgb(5), 255)
        # Strip B is a transparent codec: its colour-5 pixels are see-through.
        assert im.getpixel((8, 0)) == (*samples.rgb(20), 255)
        assert im.getpixel((9, 0))[3] == 0
        assert im.getpixel((8, 1)) == (*samples.rgb(24), 255)

    def test_wiz_image_uses_room_palette(self, game, tmp_path):
        HEFile(game / 'Alice.he1').extract_all(tmp_path / 'out', glob='*image-*')
        im = Image.open(tmp_path / 'out' / 'room-001' / 'image-0004.png')
        assert im.mode == 'RGBA'
        assert im.size == (samples.WIZ_WIDTH, samples.WIZ_HEIGHT)
        assert im.getpixel((0, 0))[3] == 0
        assert im.getpixel((1, 0)) == (*samples.rgb(40), 255)
        assert im.getpixel((2, 0)) == (*samples.rgb(41), 255)
        assert all(im.getpixel((x, 1))[3] == 0 for x in range(4))
        assert im.getpixel((3, 2)) == (*samples.rgb(42), 255)

    def test_unconvertible_image_is_written_as_stored(self, game, tmp_path, caplog):
        rooms = samples.room_file()[0]
        broken = rooms.replace(samples.BACKGROUND_BMAP, bytes([99]) + samples.BACKGROUND_BMAP[1:])
        (game / 'Alice.he1').write_bytes(xor(broken))
        out = tmp_path / 'out'
        with caplog.at_level(logging.WARNING):
            HEFile(game / 'Alice.he1').extract_all(out)
        assert not (out / 'room-001' / 'background.png').exists()
        assert (out / 'room-001' / 'background.rmim').read_bytes()[:4] == b'RMIM'
        assert 'unknown BMAP background codec 99' in caplog.text
        assert (out / 'room-001' / 'sound-0002.wav').is_file()

    def test_glob(self, game, tmp_path):
        assert HEFile(game / 'Alice.he1').extract_all(tmp_path / 'out', glob='*.wav') == 2
        assert sorted(p.name for p in (tmp_path / 'out' / 'room-001').iterdir()) == ['sound-0002.wav', 'sound-0003.wav']


@pytest.mark.integration
class TestSpeechMusicIndex:
    @pytest.mark.parametrize('obfuscated', [False, True])
    def test_speech(self, game, obfuscated):
        data, offsets = samples.speech_file()
        if obfuscated:  # as in Freddi Fish 1
            (game / 'Alice.he2').write_bytes(xor(data))
        he = HEFile(game / 'Alice.he2')
        assert he.namelist() == [f'talk-{offset:09d}.wav' for offset in offsets]
        assert he.read(f'talk-{offsets[0]:09d}.wav') == samples.wav(samples.QUEEN, 11000)
        assert he.read(f'talk-{offsets[1]:09d}.wav') == samples.wav(samples.WHITE_RABBIT, 11025)
        assert he.read(f'talk-{offsets[1]:09d}.talk', convert=False)[:4] == b'TALK'

    @pytest.mark.parametrize('old', [True, False])
    def test_music(self, game, old):
        (game / 'Alice.he4').write_bytes(samples.music_file(old=old))
        he = HEFile(game / 'Alice.he4')
        assert he.namelist() == ['song-4000.wav', 'song-4001.wav']
        assert he.read('song-4000.wav') == samples.wav(samples.MOCK_TURTLE, 11025)
        assert he.read('song-4001.wav') == samples.wav(samples.QUEEN, 11000)
        assert he.namelist(convert=False) == ['song-4000.digi', 'song-4001.digi']

    def test_index_blocks(self, game):
        he = HEFile(game / 'Alice.he0')
        names = he.namelist()
        assert names[:4] == ['rnam.bin', 'maxs.bin', 'diri.bin', 'dirr.bin']
        assert he.read('dlfl.bin')[:4] == b'DLFL'


@pytest.mark.integration
class TestCommands:
    def test_entry_point_registered(self):
        assert get_format_handlers()['scumm'].load() is SCUMMHandler

    def test_top_level_extract(self, game, tmp_path, monkeypatch):
        out = tmp_path / 'out'
        _run(monkeypatch, 'extract', game / 'Alice.he1', out)
        assert sorted(str(p.relative_to(out)) for p in out.rglob('*') if p.is_file()) == sorted(NAMED)

    def test_no_convert_and_no_index(self, game, tmp_path, monkeypatch):
        out = tmp_path / 'out'
        _run(monkeypatch, 'scumm', 'extract', '--no-convert', '--no-index', game / 'Alice.he1', out)
        assert (out / 'room-001' / 'soun-000.soun').read_bytes()[:4] == b'SOUN'
        assert not list(out.rglob('*.png'))

    def test_create_is_refused(self, game, tmp_path, monkeypatch, capsys):
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, 'create', '--format', 'scumm', game, tmp_path / 'Alice.he1')
        assert e.value.code == 1
        assert 'not supported' in capsys.readouterr().err

    def test_not_scumm(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / 'Alice.he1'
        path.write_bytes(b'Down the rabbit-hole')
        with pytest.raises(SystemExit):
            _run(monkeypatch, 'scumm', 'extract', path, tmp_path / 'out')
        assert 'not a Humongous SCUMM resource file' in capsys.readouterr().err
