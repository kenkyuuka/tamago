"""Tests for reading and writing PSB files."""

import struct

import pytest

from tamago.formats.psb import (
    PSB,
    ExtraResource,
    Float32,
    IntArray,
    PSBError,
    Resource,
    decrypt,
    find_key,
    is_psb,
    read,
)
from tamago.formats.psb.psbfile import build_names, pack_array, write
from tamago.tests.psb.samples import (
    DRINK_ME,
    EAT_ME,
    KEY,
    TRIE_BASE,
    TRIE_CHECK,
    TRIE_LEAVES,
    TRIE_SIZE,
    encrypt_header,
    encrypt_v2,
    tiny_psb,
)

TREE = {'hat': 'mad', 'tea': [5, -2, 0.5, None, Resource(0)]}


@pytest.mark.unit
def test_package_exports_write():
    from tamago.formats import psb

    assert 'write' in psb.__all__
    assert psb.read(psb.write(psb.PSB(root={'cheshire': 'grin'}))).root == {'cheshire': 'grin'}


@pytest.mark.unit
class TestNames:
    def test_builds_trie_as_e_mote_does(self):
        base, check, leaves = build_names(['hat', 'tea'])
        assert base == [TRIE_BASE.get(i, 0) for i in range(TRIE_SIZE)]
        assert check == [TRIE_CHECK.get(i, 0) for i in range(TRIE_SIZE)]
        assert leaves == TRIE_LEAVES

    def test_base_needs_only_its_childrens_slots_free(self):
        # 'b' has children 'a' and 'e' only; its base may sit on a used slot.
        base, check, leaves = build_names(['0', '1', '2', 'ba', 'be'])
        node_b = base[0] + ord('b')
        assert check[base[node_b] + ord('a')] == node_b
        assert base[node_b] < max(leaves)

    def test_names_with_shared_prefixes_and_utf8(self):
        names = sorted(['arrow', 'arrow_3', 'angle', '頭部', '頭'], key=str.encode)
        psb = PSB(root={n: i for i, n in enumerate(names)})
        assert read(write(psb)).root == psb.root


@pytest.mark.unit
class TestArrays:
    @pytest.mark.parametrize(
        'items, expected',
        [
            ([], '0d 00 0d'),
            ([1, 2], '0d 02 0d 01 02'),
            ([0, 0x100], '0d 02 0e 00 00 00 01'),
            ([0x10000], '0d 01 0f 00 00 01'),
            ([0x1000000], '0d 01 10 00 00 00 01'),
        ],
    )
    def test_narrowest_widths(self, items, expected):
        assert pack_array(items) == bytes.fromhex(expected)

    def test_count_width_grows(self):
        assert pack_array([0] * 300)[:4] == bytes.fromhex('0e 2c 01 0d')


@pytest.mark.unit
class TestRead:
    @pytest.mark.parametrize('version', [2, 3, 4])
    def test_plain(self, version):
        data, _ = tiny_psb(version)
        psb = read(data)
        assert psb.version == version
        assert psb.key is None
        assert psb.root == TREE
        assert psb.resources == [DRINK_ME]
        assert psb.extra_resources == []

    def test_value_types(self):
        psb = read(tiny_psb()[0])
        tea = psb.root['tea']
        assert type(tea[0]) is int and type(tea[1]) is int
        assert isinstance(tea[2], Float32)
        assert tea[1] == -2

    def test_extra_resources(self):
        data, _ = tiny_psb(4, extra=[EAT_ME, DRINK_ME])
        assert read(data).extra_resources == [EAT_ME, DRINK_ME]

    def test_without_resources(self):
        psb = read(tiny_psb()[0], resources=False)
        assert psb.root == TREE and psb.resources == []

    @pytest.mark.parametrize('version', [3, 4])
    def test_header_encrypted_key_is_recovered(self, version):
        data = encrypt_header(tiny_psb(version)[0])
        assert find_key(data) == KEY
        psb = read(data)
        assert psb.key == KEY and psb.flags == 1
        assert psb.root == TREE

    def test_v2_encrypted_with_given_key(self):
        data, h = tiny_psb(2)
        enc = encrypt_v2(data, h)
        assert read(enc, KEY).root == TREE

    def test_v2_encrypted_with_unknown_key(self):
        data, h = tiny_psb(2)
        with pytest.raises(PSBError, match='unknown key'):
            read(encrypt_v2(data, h))

    def test_v2_encrypted_with_known_key(self):
        data, h = tiny_psb(2)
        psb = read(encrypt_v2(data, h, 0x473AB96D))
        assert psb.key == 0x473AB96D and psb.root == TREE

    def test_decrypt(self):
        data = tiny_psb(3)[0]
        assert decrypt(encrypt_header(data)) == data

    def test_bad_checksum_is_a_warning(self, caplog):
        data = bytearray(tiny_psb(3)[0])
        data[0x28] ^= 1
        assert read(bytes(data)).root == TREE
        assert 'checksum' in caplog.text

    def test_wrong_checksum_rejects_recovered_key(self):
        data = bytearray(encrypt_header(tiny_psb(3)[0]))
        data[0x28] ^= 1
        with pytest.raises(PSBError, match='checksum'):
            find_key(bytes(data))

    def test_not_psb(self):
        assert not is_psb(DRINK_ME)
        with pytest.raises(PSBError):
            read(DRINK_ME)

    def test_unknown_value_type(self):
        data, h = tiny_psb(3)
        data = bytearray(data)
        data[h['root']] = 0x30
        with pytest.raises(PSBError):
            read(bytes(data))


@pytest.mark.unit
class TestWrite:
    @pytest.mark.parametrize('version', [2, 3, 4])
    def test_lays_out_as_e_mote_does(self, version):
        data, _ = tiny_psb(version)
        assert write(read(data)) == data

    def test_v4_extra_resources_layout(self):
        data, _ = tiny_psb(4, extra=[EAT_ME, DRINK_ME])
        assert write(read(data)) == data

    @pytest.mark.parametrize('version', [3, 4])
    def test_header_encryption(self, version):
        data = encrypt_header(tiny_psb(version)[0])
        assert write(read(data)) == data

    def test_v2_encryption(self):
        data, h = tiny_psb(2)
        enc = encrypt_v2(data, h)
        assert write(read(enc, KEY)) == enc

    def test_body_encryption_flag(self):
        psb = PSB(root={'alice': 'curiouser'}, flags=3, key=KEY)
        data = write(psb)
        assert b'curiouser' not in data
        assert read(data).root == psb.root

    @pytest.mark.parametrize(
        'value, encoded',
        [
            (0, '04'),
            (1, '05 01'),
            (127, '05 7f'),
            (128, '06 80 00'),
            (-1, '05 ff'),
            (-128, '05 80'),
            (-129, '06 7f ff'),
            (0x7FFFFFFF, '08 ff ff ff 7f'),
            (0x80000000, '09 00 00 00 80 00'),
            (None, '01'),
            (False, '02'),
            (True, '03'),
            (Float32(0.0), '1d'),
            (Float32(1.5), '1e 00 00 c0 3f'),
            (1.5, '1f 00 00 00 00 00 00 f8 3f'),
            (Resource(1), '19 01'),
            (Resource(0x100), '1a 00 01'),
            (ExtraResource(2), '22 02'),
            (IntArray([1, 2]), '0d 02 0d 01 02'),
        ],
    )
    def test_value_encoding(self, value, encoded):
        resources = [b''] * 0x101
        psb = PSB(root={'v': value}, resources=resources, extra_resources=[b''] * 3, version=4)
        data = write(psb)
        root = struct.unpack_from('<I', data, 0x24)[0]
        # dict, keys [0], offsets [0], then the value.
        assert data[root : root + 9] == bytes.fromhex('21 0d 01 0d 00 0d 01 0d 00')
        assert data[root + 9 : root + 9 + len(bytes.fromhex(encoded))] == bytes.fromhex(encoded)
        assert read(data).root == {'v': value}

    def test_identical_siblings_are_stored_once(self):
        data = write(PSB(root={'l': ['twinkle', 'twinkle', 'bat', 'twinkle']}))
        root = struct.unpack_from('<I', data, 0x24)[0]
        # dict header (9 bytes), then the list: 0x20, offsets [0, 0, 2, 0].
        assert data[root + 9 : root + 9 + 8] == bytes.fromhex('20 0d 04 0d 00 00 02 00')
        assert read(data).root == {'l': ['twinkle', 'twinkle', 'bat', 'twinkle']}

    def test_dict_keys_are_written_in_name_order(self):
        psb = PSB(root={'tea': 1, 'hat': 2})
        assert list(read(write(psb)).root) == ['hat', 'tea']

    def test_strings_are_shared(self):
        data = write(PSB(root={'a': 'Alice', 'b': ['Alice', 'Alice']}))
        assert data.count(b'Alice\0') == 1

    def test_rejects_non_dict_root(self):
        with pytest.raises(TypeError):
            write(PSB(root=['not', 'a', 'dict']))

    def test_rejects_extra_resources_before_v4(self):
        with pytest.raises(ValueError):
            write(PSB(root={}, extra_resources=[DRINK_ME], version=3))

    def test_rejects_unknown_types(self):
        with pytest.raises(TypeError):
            write(PSB(root={'cat': object()}))

    def test_empty_root(self):
        assert read(write(PSB(root={}))).root == {}
