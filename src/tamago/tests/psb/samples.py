"""Synthetic PSB data for tests, assembled by hand rather than with the code under test.

The tree is ``{"hat": "mad", "tea": [5, -2, 0.5, None, Resource(0)]}`` with
one resource chunk.  Its names trie (``hat``, ``tea``) is worked out by hand
below.
"""

import struct
import zlib

KEY = 0x0A11CE5

DRINK_ME = b"Drink me, said the bottle; but Alice was not going to do that in a hurry."
EAT_ME = b"Eat me, said the cake, in currants, beautifully marked."


def keystream(key, n):
    """The PSB keystream, written after GARbro's byte loop (``ArcPSB.cs``, ``Decrypt``)."""
    k = [0x075BCD15, 0x159A55E5, 0x1F123BB5, key, 0]
    out = bytearray()
    for _ in range(n):
        if k[4] == 0:
            v5 = k[3]
            v6 = (k[0] ^ (k[0] << 11)) & 0xFFFFFFFF
            k[0], k[1] = k[1], k[2]
            eax = v6 ^ v5 ^ ((v6 ^ (v5 >> 11)) >> 8)
            k[2] = v5
            k[3] = eax
            k[4] = eax
        out.append(k[4] & 0xFF)
        k[4] >>= 8
    return bytes(out)


def xor(data, stream):
    return bytes(a ^ b for a, b in zip(data, stream, strict=True))


# Names "hat" (0) and "tea" (1).  The root's base is 1, so 'h' (0x68) is node
# 0x69 and 't' (0x74) node 0x75.  Depth first: "h" takes base 1 for 'a' (node
# 0x62); "ha" can't take 1 ('t' would be 0x75), so 2 (node 0x76); "hat" puts
# its NUL leaf at 1.  "t" takes 1 for 'e' (0x66); "te" takes 2 for 'a' (0x63,
# since 0x62 is used); "tea"'s leaf goes to the lowest free slot, 2.
TRIE_BASE = {0: 1, 1: 0, 2: 1, 0x62: 2, 0x63: 2, 0x66: 2, 0x69: 1, 0x75: 1, 0x76: 1}
TRIE_CHECK = {1: 0x76, 2: 0x63, 0x62: 0x69, 0x63: 0x66, 0x66: 0x75, 0x69: 0, 0x75: 0, 0x76: 0x62}
TRIE_LEAVES = [1, 2]
TRIE_SIZE = 0x77


def array(items, width):
    """A packed array with a 1-byte count and *width*-byte elements."""
    return bytes([0x0D, len(items), 0x0C + width]) + b''.join(i.to_bytes(width, 'little') for i in items)


def names_section():
    base = [TRIE_BASE.get(i, 0) for i in range(TRIE_SIZE)]
    check = [TRIE_CHECK.get(i, 0) for i in range(TRIE_SIZE)]
    return array(base, 1) + array(check, 1) + array(TRIE_LEAVES, 1)


def tree():
    # The list: 5, -2, 0.5 (single), null, resource 0.
    values = [b'\x05\x05', b'\x05\xfe', b'\x1e' + struct.pack('<f', 0.5), b'\x01', b'\x19\x00']
    offsets, at = [], 0
    for v in values:
        offsets.append(at)
        at += len(v)
    tea = b'\x20' + array(offsets, 1) + b''.join(values)
    hat = b'\x15\x00'  # string 0, "mad"
    return b'\x21' + array([0, 1], 1) + array([0, len(hat)], 1) + hat + tea


def tiny_psb(version=3, resources=(DRINK_ME,), extra=()):
    """A plain PSB holding the tree above, laid out as E-mote's compiler does."""
    hl = {2: 0x28, 3: 0x2C, 4: 0x38}[version]
    out = bytearray(hl)
    h = {'header_length': hl}
    h['names'] = len(out)
    out += names_section()
    h['root'] = len(out)
    out += tree()
    h['strings'] = len(out)
    out += array([0], 1)
    h['strings_data'] = len(out)
    out += b'mad\0'

    def table(chunks):
        offsets, at = [], 0
        for c in chunks:
            offsets.append(at)
            at += len(c)
        return array(offsets, 1 if at < 256 else 2), array([len(c) for c in chunks], 1), b''.join(chunks)

    if version >= 4:
        eo, el, ed = table(list(extra))
        h['extra_offsets'] = len(out)
        out += eo
        h['extra_lengths'] = len(out)
        out += el
        if ed:
            out += bytes(-len(out) % 0x40)
        h['extra_data'] = len(out)
        out += ed
    co, cl, cd = table(list(resources))
    h['chunk_offsets'] = len(out)
    out += co
    h['chunk_lengths'] = len(out)
    out += cl
    out += bytes(-len(out) % 0x20)
    h['chunk_data'] = len(out)
    out += cd

    fields = [
        'header_length',
        'names',
        'strings',
        'strings_data',
        'chunk_offsets',
        'chunk_lengths',
        'chunk_data',
        'root',
    ]
    if version >= 4:
        fields += ['extra_offsets', 'extra_lengths', 'extra_data']
    words = [h[f] for f in fields]
    out[0:8] = b'PSB\0' + struct.pack('<HH', version, 0)
    out[8:0x28] = struct.pack('<8I', *words[:8])
    if version >= 3:
        out[0x28:0x2C] = struct.pack('<I', zlib.adler32(struct.pack(f'<{len(words)}I', *words)))
    if version >= 4:
        out[0x2C:0x38] = struct.pack('<3I', *words[8:])
    return bytes(out), h


def encrypt_header(data, key=KEY):
    """Encrypt a version 3+ PSB's header, as E-mote does with flag 1."""
    hl = {3: 0x2C, 4: 0x38}[data[4]]
    out = bytearray(data)
    out[6] = 1
    out[8:hl] = xor(out[8:hl], keystream(key, hl - 8))
    return bytes(out)


def encrypt_v2(data, h, key=KEY):
    """Encrypt a version 2 PSB: its names-to-resource-offsets region, no flag set."""
    out = bytearray(data)
    lo, hi = h['names'], h['chunk_offsets']
    out[lo:hi] = xor(out[lo:hi], keystream(key, hi - lo))
    return bytes(out)
