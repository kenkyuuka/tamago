"""Tests for MurmurHash2 as YU-RIS uses it."""

import os

import pytest

from tamago.formats.yuris import hashing
from tamago.tests.yuris.samples import murmur2 as reference


@pytest.mark.unit
class TestMurmur2:
    @pytest.mark.parametrize(
        'data, expected',
        [
            (b'', 0),
            (b'Alice', 0x2DC7455F),
            (b'bg\\rabbit.png', 0x54BB81B9),
            (b'Curiouser and curiouser!', 0xB2FA1DB5),
        ],
    )
    def test_known_values(self, data, expected):
        assert hashing.murmur2(data) == expected

    @pytest.mark.parametrize('length', range(9))
    def test_every_tail_length_matches_reference(self, length):
        data = b'Tweedledee'[:length]
        assert hashing.murmur2(data) == reference(data)

    def test_accepts_memoryview_and_bytearray(self):
        assert hashing.murmur2(memoryview(b'Alice')) == hashing.murmur2(bytearray(b'Alice')) == 0x2DC7455F

    def test_python_fallback_matches(self):
        data = os.urandom(4099)
        assert hashing.murmur2_py(data) == reference(data) == hashing.murmur2(data)

    @pytest.mark.skipif(hashing._murmur_accel is None, reason="C accelerator not built")
    def test_accelerator_matches_fallback(self):
        for size in (0, 1, 2, 3, 4, 5, 1000, 65537):
            data = os.urandom(size)
            assert hashing._murmur_accel.murmur2(data) == hashing.murmur2_py(data)
