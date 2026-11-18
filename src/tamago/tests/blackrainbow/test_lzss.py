"""Tests for the LZSS variant used by _BMD images."""

import os
import random

import pytest

from tamago.formats.blackrainbow import lzss
from tamago.tests.blackrainbow.samples import ALICE, CHESHIRE, lzss_literals


@pytest.mark.unit
class TestDecompress:
    def test_worked_example(self):
        # Three literals, then a 6-byte reference to ring position 0xFEE that
        # overlaps the bytes it is writing, then one more literal.
        assert lzss.decompress(bytes.fromhex('17414243EEF344'), 10) == b'ABCABCABCD'

    def test_literals(self):
        assert lzss.decompress(lzss_literals(ALICE), len(ALICE)) == ALICE

    def test_reference_into_initial_zeros(self):
        # Position 0x000 has never been written, so it reads as zero.
        assert lzss.decompress(bytes([0x01, 0x41, 0x00, 0x02]), 6) == b'A\0\0\0\0\0'

    def test_stops_at_expected_size(self):
        assert lzss.decompress(lzss_literals(ALICE), 5) == ALICE[:5]

    def test_truncated_stream_raises(self):
        with pytest.raises(ValueError, match='LZSS'):
            lzss.decompress(lzss_literals(ALICE)[:-3], len(ALICE))

    def test_truncated_reference_raises(self):
        with pytest.raises(ValueError, match='LZSS'):
            lzss.decompress(bytes([0x01, 0x41, 0xEE]), 4)

    def test_empty(self):
        assert lzss.decompress(b'', 0) == b''


def _samples():
    rng = random.Random(1865)  # noqa: S311 — deterministic seed for test reproducibility
    noise = bytes(rng.randrange(256) for _ in range(5000))
    pixels = b''.join(bytes([i % 7, i % 5, 200, 255]) for i in range(3000))
    return {
        'empty': b'',
        'one': b'A',
        'short': b'Alice',
        'prose': ALICE + CHESHIRE,
        'zeros': bytes(10000),
        'noise': noise,
        'noise_repeated': noise[:3000] * 3,
        'pixels': pixels,
        # A repeat exactly 4096 bytes back: the furthest a reference can reach.
        'far_repeat': noise[:4096] + noise[:100],
        'random_bytes': os.urandom(2000),
    }


@pytest.mark.unit
class TestCompress:
    @pytest.mark.parametrize('name', sorted(_samples()))
    def test_roundtrip(self, name):
        data = _samples()[name]
        assert lzss.decompress(lzss.compress(data), len(data)) == data

    def test_repetitive_data_shrinks(self):
        data = CHESHIRE * 20
        # The best case is one 2-byte reference (plus a flag bit) per 18 bytes.
        assert len(lzss.compress(data)) < len(data) // 7

    def test_noise_costs_at_most_one_flag_byte_per_eight(self):
        data = _samples()['noise']
        assert len(lzss.compress(data)) <= len(data) + (len(data) + 7) // 8

    def test_final_flag_byte_has_no_stray_bits(self):
        # 3 literals: the last flag byte must have only its low 3 bits set.
        assert lzss.compress(b'Tea') == bytes([0x07]) + b'Tea'
