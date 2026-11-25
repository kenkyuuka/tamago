"""Synthetic Artemis PFS archives, built without the library so that tests check it independently."""

import hashlib
import struct

__all__ = [
    'ALICE',
    'CHESHIRE',
    'CONTENTS',
    'DATA_ORDER',
    'EXAMPLE',
    'EXAMPLE_MEMBERS',
    'HATTER',
    'MEMBERS',
    'QUEEN',
    'QUEEN_NAME',
    'build_pfs',
    'xor',
]

ALICE = b'Down the Rabbit-Hole\n'
HATTER = b'Why is a raven like a writing-desk?\n'
# Longer than the 20-byte key, so the key wraps around within the member.
QUEEN = b'Off with her head! Off with his head! Sentence first, verdict afterwards.\n'
# "The Queen of Hearts", in cp932.
QUEEN_NAME = 'ハートの女王\\court.txt'
CHESHIRE = b'\x89PNG\r\n\x1a\n' + b'We are all mad here.' * 3

# The worked example of the format notes: two members, in index and data order.
EXAMPLE_MEMBERS = [(b'alice.txt', ALICE), (b'tea\\hatter.txt', HATTER)]
EXAMPLE = bytes.fromhex(
    '7066385b000000020000000900000061'
    '6c6963652e7478740000000062000000'
    '150000000e0000007465615c68617474'
    '65722e74787400000000770000002400'
    '00000300000011000000000000002f00'
    '00000000000000000000000000003b00'
    '000049ee96924787e9e0297b4300c8f5'
    '09c9b85db2ad075ae998dc0e80a1e429'
    '5b4314cff25d889959bbe86ca1968e0e'
    '87e8eb6e044607d9f742ee'
)


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_pfs(
    members: list[tuple[bytes, bytes]],
    version: int = 8,
    data_order: list[int] | None = None,
) -> bytes:
    """Build an archive from ``(raw_name, contents)`` pairs, in index order.

    *data_order* lists the members' indexes in the order their data is
    stored (default: index order).
    """
    order = list(range(len(members))) if data_order is None else data_order
    block = 12 if version == 2 else 4
    entries_size = sum(4 + len(name) + block + 8 for name, _data in members)
    if version == 2:
        index_size = 8 + entries_size
    else:
        index_size = 4 + entries_size + 4 + 8 * (len(members) + 1) + 4

    offsets = {}
    offset = 7 + index_size
    for i in order:
        offsets[i] = offset
        offset += len(members[i][1])

    index = bytearray(struct.pack('<II', 0, len(members)) if version == 2 else struct.pack('<I', len(members)))
    table = []
    for i, (name, data) in enumerate(members):
        index += struct.pack('<I', len(name)) + name
        index += b'\x10' + bytes(11) if version == 2 else bytes(4)
        # The table points at the offset field, counting from the first entry (file offset 0x0B).
        table.append(len(index) + 7 - 0x0B)
        index += struct.pack('<II', offsets[i], len(data))
    if version != 2:
        table_pos = len(index)
        index += struct.pack('<I', len(members) + 1)
        index += b''.join(struct.pack('<Q', t) for t in table) + bytes(8)
        index += struct.pack('<I', table_pos)
    assert len(index) == index_size

    key = hashlib.sha1(index, usedforsecurity=False).digest() if version == 8 else None
    body = b''.join(xor(members[i][1], key) if key else members[i][1] for i in order)
    return b'pf%d' % version + struct.pack('<I', index_size) + bytes(index) + body


# Sorted by name bytes, as in the games' indexes.  The data is stored in a
# different order, as the games' packer does.
MEMBERS = [
    (b'Cheshire.png', CHESHIRE),
    (b'alice.txt', ALICE),
    (b'tea\\hatter.txt', HATTER),
    (QUEEN_NAME.encode('cp932'), QUEEN),
]
DATA_ORDER = [1, 3, 0, 2]
CONTENTS = {
    'Cheshire.png': CHESHIRE,
    'alice.txt': ALICE,
    'tea\\hatter.txt': HATTER,
    QUEEN_NAME: QUEEN,
}
