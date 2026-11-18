"""Tests for the JSON form of PSB value trees."""

import json
import struct

import pytest

from tamago.formats.psb import ExtraResource, Float32, IntArray, Resource
from tamago.formats.psb.jsontree import from_json, to_json


def f32(x):
    return Float32(struct.unpack('<f', struct.pack('<f', x))[0])


TREE = {
    'name': 'Cheshire Cat',
    'grin': f32(0.6),
    'zero': Float32(0.0),
    'precise': 0.1,
    'count': 7,
    'none': None,
    'flag': True,
    'pixel': Resource(3),
    'mesh': ExtraResource(1),
    'packed': IntArray([1, 2, 3]),
    'list': [1, f32(2.5), 'tea'],
    'tagged': {'$resource': 2},
}


@pytest.mark.unit
class TestJsonTree:
    def test_roundtrip_through_json_text(self):
        back = from_json(json.loads(json.dumps(to_json(TREE))))
        assert back == TREE
        assert type(back['grin']) is Float32
        assert type(back['precise']) is float
        assert type(back['packed']) is IntArray
        assert type(back['count']) is int

    def test_single_floats_are_short(self):
        assert json.dumps(to_json({'g': f32(0.6)})) == '{"g": 0.6}'

    def test_single_float_keeps_its_bits(self):
        for x in (0.6, 1 / 3, 3.4e38, 1e-45, -2.75):
            v = f32(x)
            assert struct.pack('<f', from_json(to_json(v))) == struct.pack('<f', v)

    def test_tags(self):
        assert to_json(Resource(3)) == {'$resource': 3}
        assert to_json(ExtraResource(1)) == {'$extra': 1}
        assert to_json(0.1) == {'$double': 0.1}
        assert to_json(IntArray([4])) == {'$intarray': [4]}

    def test_real_dict_that_looks_like_a_tag_is_wrapped(self):
        assert to_json({'$extra': 1}) == {'$dict': {'$extra': 1}}
        assert from_json(to_json({'$dict': {}})) == {'$dict': {}}
