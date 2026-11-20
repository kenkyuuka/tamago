"""Synthetic Black Cyc packs, built without the library so that tests check it independently."""

import struct


def dwq(kind: bytes, payload: bytes) -> bytes:
    """Return a DWQ image: the 64-byte header the engine expects, then *payload*."""
    header = kind.ljust(16) + bytes(16) + struct.pack('<III', len(payload), 800, 600) + b'    '
    return header + b'PACKTYPE=8A'.ljust(16) + payload


def vaw(payload: bytes) -> bytes:
    """Return a voice in the readable-header form the games' voice packs use."""
    return b'IF PACKTYPE==2  CUT THIS 108BYTETHEN REMAKE OGG PACKTYPE=2      ' + bytes(44) + payload


PNG = b'\x89PNG\r\n\x1a\n'
ALICE = dwq(b'PNG', PNG + b'Alice was beginning to get very tired')
TEA_PARTY = dwq(b'PNG', PNG + b'No room! No room!')
TEACUP = dwq(b'PNG', PNG + b'Have some wine')
WHITE = dwq(b'BMP', b'BM' + b'\xff' * 10)


def build_gtb(members: list[tuple[bytes, bytes]], string_order: list[bytes]) -> bytes:
    """Return the ``.gtb`` index for ``(name, data)`` pairs, in index order.

    *string_order* lists the names in the order their strings are stored.
    """
    blob = b''
    name_offsets = {}
    for name in string_order:
        name_offsets[name] = len(blob)
        blob += name + b'\0'
    data_offsets = []
    offset = 0
    for _name, data in members:
        data_offsets.append(offset)
        offset += len(data)
    n = len(members)
    return (
        struct.pack('<I', n)
        + struct.pack(f'<{n}I', *(name_offsets[name] for name, _data in members))
        + struct.pack(f'<{n}I', *data_offsets)
        + blob
    )


def build_vtb(members: list[tuple[bytes, bytes]]) -> bytes:
    """Return the ``.vtb`` index for ``(name, data)`` pairs, in index order."""
    index = b''
    offset = 0
    for name, data in members:
        index += name.ljust(8, b'\0') + struct.pack('<I', offset)
        offset += len(data)
    return index + bytes(8) + struct.pack('<I', offset)


# Sorted by lower-cased name, as the games' packs are: '_' (0x5F) sorts before
# 'c' (0x63), but after 'C' (0x43), so the strings are stored in another order.
GPK_MEMBERS = [
    (b'alice', ALICE),
    (b'tea_party', TEA_PARTY),
    (b'teacup', TEACUP),
    (b'white', WHITE),
]
GTB = build_gtb(GPK_MEMBERS, [b'alice', b'teacup', b'tea_party', b'white'])
GPK = b''.join(data for _name, data in GPK_MEMBERS)
GPK_CONTENTS = {name.decode() + '.dwq': data for name, data in GPK_MEMBERS}

VPK_MEMBERS = [
    (b'mad00001', vaw(b'OggS' + b'Why is a raven like a writing-desk?')),
    (b'mad00002', vaw(b'OggS' + b'Twinkle, twinkle, little bat!')),
    (b'mad00010', vaw(b'OggS' + b'It was the best butter')),
]
VTB = build_vtb(VPK_MEMBERS)
VPK = b''.join(data for _name, data in VPK_MEMBERS)
VPK_CONTENTS = {name.decode() + '.vaw': data for name, data in VPK_MEMBERS}


def write_pair(directory, stem: str, index: bytes, data: bytes, index_ext: str, data_ext: str):
    """Write a pack pair to *directory*; return the paths of the index and the data file."""
    index_path = directory / f'{stem}{index_ext}'
    data_path = directory / f'{stem}{data_ext}'
    index_path.write_bytes(index)
    data_path.write_bytes(data)
    return index_path, data_path
