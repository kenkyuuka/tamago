"""Tests for the Okumura LZSS encoder used by AI6WIN archives."""

import random

import pytest

from tamago.formats.ai6win import lzss
from tamago.tests.ai6win.samples import (
    QUEEN,
    QUEEN_LZSS,
    TEA_TEA_TEA,
    TEA_TEA_TEA_LZSS,
    ZEROS_TEA,
    ZEROS_TEA_LZSS,
)

_rng = random.Random(1865)  # noqa: S311 — deterministic seed for test reproducibility
_ALICE_TEXT = (
    b"Alice was beginning to get very tired of sitting by her sister on the bank, "
    b"and of having nothing to do: once or twice she had peeped into the book her "
    b"sister was reading, but it had no pictures or conversations in it.\r\n"
) * 60


@pytest.mark.unit
class TestCompress:
    @pytest.mark.parametrize(
        ('data', 'expected'),
        [
            (ZEROS_TEA, ZEROS_TEA_LZSS),
            (TEA_TEA_TEA, TEA_TEA_TEA_LZSS),
            (QUEEN, QUEEN_LZSS),
        ],
        ids=['initial-ring-reference', 'overlapping-reference', 'long-reference'],
    )
    def test_matches_okumura_output(self, data, expected):
        assert lzss.compress(data) == expected

    def test_empty(self):
        assert lzss.compress(b'') == b''

    def test_single_byte(self):
        assert lzss.compress(b'A') == b'\x01A'

    def test_short_match_sent_as_literals(self):
        # A two-byte repeat is below the minimum match length.
        assert lzss.compress(b'abab') == b'\x0fabab'

    @pytest.mark.parametrize(
        'data',
        [
            _ALICE_TEXT,
            bytes(10000),
            b'\xff' * 5000,
            bytes(_rng.randrange(256) for _ in range(6000)),
            bytes(_rng.randrange(4) for _ in range(9000)),
            b'Drink me',
        ],
        ids=['text', 'zeros', 'ones', 'random', 'low-entropy', 'short'],
    )
    def test_roundtrip(self, data):
        packed = lzss.compress(data)
        assert lzss.decompress(packed, len(data)) == data

    def test_compresses_repetitive_text(self):
        # The best LZSS can do is 2 1/8 bytes per 18-byte match, about 12%.
        assert len(lzss.compress(_ALICE_TEXT)) < len(_ALICE_TEXT) // 7


@pytest.mark.unit
class TestDecompress:
    def test_reference_into_initial_ring(self):
        assert lzss.decompress(ZEROS_TEA_LZSS, len(ZEROS_TEA)) == ZEROS_TEA

    def test_truncated_stream(self):
        with pytest.raises(ValueError):
            lzss.decompress(QUEEN_LZSS[:-2], len(QUEEN))


def _accel_samples():
    rng = random.Random(1951)  # noqa: S311 — deterministic seed for test reproducibility
    samples = {
        'empty': b'',
        'one': b'A',
        'abab': b'abab',
        'zeros_tea': ZEROS_TEA,
        'tea_tea_tea': TEA_TEA_TEA,
        'queen': QUEEN,
        'text': _ALICE_TEXT,
        'zeros': bytes(10000),
        'ones': b'\xff' * 5000,
        'random': bytes(rng.randrange(256) for _ in range(6000)),
        'low_entropy': bytes(rng.randrange(4) for _ in range(20000)),
        'tea_party': b''.join(b'Tea' + bytes([rng.randrange(3)]) for _ in range(3000)),
    }
    for size in (17, 18, 19, 35, 36, 37):
        samples[f'short_{size}'] = (b'Drink me! ' * 4)[:size]
    return samples


@pytest.mark.unit
@pytest.mark.skipif(lzss._lzss_accel is None, reason="C accelerator not built")
class TestAccelerator:
    @pytest.mark.parametrize('name', sorted(_accel_samples()))
    def test_compress_matches_fallback(self, name):
        data = _accel_samples()[name]
        assert lzss._lzss_accel.compress_okumura(data) == lzss.compress_py(data)

    def test_compress_accepts_memoryview(self):
        assert lzss._lzss_accel.compress_okumura(memoryview(QUEEN)) == QUEEN_LZSS
