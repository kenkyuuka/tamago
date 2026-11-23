"""Tests for the block container, sound conversion and the index file."""

import pytest

from tamago.formats.scumm import BlockError, deobfuscate, detect_key, iter_blocks, parse_index, sound_to_wav
from tamago.formats.scumm.blocks import Block
from tamago.formats.scumm.index import _room_names
from tamago.tests.scumm import samples
from tamago.tests.scumm.samples import block, digi, xor


def _block(data: bytes) -> Block:
    return next(iter_blocks(data))


@pytest.mark.unit
class TestBlocks:
    def test_children(self):
        data = block('LFLF', block('SCRP', b'Drink me') + block('SCRP', b'Eat me'))
        parent = _block(data)
        assert parent.tag == 'LFLF'
        assert [c.body for c in parent.children()] == [b'Drink me', b'Eat me']

    def test_ignores_a_stray_tail_byte(self):
        soun = _block(block('SOUN', digi(b'Tea') + b'\x80'))
        assert [c.tag for c in soun.children()] == ['DIGI']

    def test_bad_size_raises(self):
        with pytest.raises(BlockError):
            list(iter_blocks(b'SCRP\0\0\0\x40Drink me'))

    def test_data_that_is_not_blocks(self):
        assert _block(block('SCRP', b'Who are YOU?')).try_children() is None

    @pytest.mark.parametrize(
        ('data', 'key'), [(b'LECF\0\0\0\x08', 0), (xor(b'LECF\0\0\0\x08'), 0x69), (b'MZ\x90\0', None)]
    )
    def test_detect_key(self, data, key):
        assert detect_key(data) == key

    def test_deobfuscate_is_its_own_inverse(self):
        text = b'Curiouser and curiouser!'
        assert deobfuscate(deobfuscate(text)) == text
        assert deobfuscate(text) == xor(text)


@pytest.mark.unit
class TestSound:
    def test_digi(self):
        assert sound_to_wav(_block(digi(samples.MOCK_TURTLE, 11000))) == samples.wav(samples.MOCK_TURTLE, 11000)

    def test_soun_wrapper_and_sbng(self):
        data = block('SOUN', digi(samples.QUEEN, 11025, sbng=b'\x00\x20') + b'\x80')
        assert sound_to_wav(_block(data)) == samples.wav(samples.QUEEN, 11025)

    def test_talk(self):
        data = digi(samples.WHITE_RABBIT, 7000, tag='TALK')
        assert sound_to_wav(_block(data)) == samples.wav(samples.WHITE_RABBIT, 7000)

    def test_ignores_garbage_bits_and_channels(self):
        body = block('HSHD', samples.hshd(11025, bits=16, channels=2)) + block('SDAT', samples.QUEEN)
        assert sound_to_wav(_block(block('DIGI', body))) == samples.wav(samples.QUEEN, 11025)

    def test_wsou_holds_a_wav(self):
        wav = samples.wav(samples.QUEEN, 22050)
        assert sound_to_wav(_block(block('WSOU', wav))) == wav

    @pytest.mark.parametrize(
        'data',
        [
            block('DIGI', block('HSHD', samples.hshd(11025))),  # no SDAT
            block('DIGI', b'\x10*I\0 garbage, not blocks'),
            block('DIGI', block('HSHD', samples.hshd(0)) + block('SDAT', b'x')),
            block('SCRP', b'Drink me'),
        ],
    )
    def test_not_convertible(self, data):
        with pytest.raises(ValueError):
            sound_to_wav(_block(data))


@pytest.mark.unit
class TestIndex:
    @pytest.mark.parametrize('obfuscated', [True, False])
    def test_parse(self, obfuscated):
        _data, room_offsets, places = samples.room_file()
        index = samples.index_file(room_offsets, places)
        parsed = parse_index(xor(index) if obfuscated else index)
        assert parsed.room_offsets == room_offsets
        assert parsed.room_at(16) == 1
        assert parsed.room_at(99) is None
        assert parsed.resources == {
            (1, places['RMIM'][1]): ('room-image', 1),
            (1, places['RMDA'][1]): ('room', 1),
            (1, places['SCRP'][1]): ('script', 1),
            (1, places['SOUN'][1]): ('sound', 2),
            (1, places['DIGI'][1]): ('sound', 3),
            (1, places['AWIZ'][1]): ('image', 4),
            (1, places['AKOS'][1]): ('costume', 1),
        }

    def test_not_an_index(self):
        with pytest.raises(ValueError):
            parse_index(b'MZ\x90\0\3\0\0\0')

    def test_old_room_names(self):
        # HE < 80: u8 room + 9 bytes XOR 0xFF, then a zero byte.
        name = bytes(b ^ 0xFF for b in b'garden'.ljust(9, b'\0'))
        assert _room_names(bytes([3]) + name + b'\0') == {3: 'garden'}

    def test_new_room_names(self):
        body = b'\x01\x00rabbit-hole\0\x02\x00tea-party\0\0\0'
        assert _room_names(body) == {1: 'rabbit-hole', 2: 'tea-party'}
