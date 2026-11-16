"""Synthetic ANIM data for tests, built independently of the code under test."""

import struct

DRINK_ME = b"Drink me, said the bottle; but Alice was not going to do that in a hurry."
EAT_ME = b"Eat me, said the cake, in currants, beautifully marked."
LIP_SYNC = b"0.00,0.10,0.35,0.20\r\n"


def ogg_page(granule, body, *, first=False):
    """One Ogg page holding *body* (under 255 bytes).  The CRC is left at 0: nothing here checks it."""
    assert len(body) < 255
    flags = 0x02 if first else 0
    return struct.pack('<4sBBqIIIB', b'OggS', 0, flags, granule, 0x0A11CE, 0, 0, 1) + bytes([len(body)]) + body


def vorbis_ogg(channels=2, rate=44100, granules=(0, 48000, 96000)):
    """A minimal Ogg Vorbis stream: an identification header, then pages ending at *granules*."""
    ident = b'\x01vorbis' + struct.pack('<IBIiii', 0, channels, rate, 0, 0, 0) + b'\xb8\x01'
    pages = [ogg_page(0, ident, first=True)]
    pages += [ogg_page(g, b'down the rabbit hole' + bytes([i])) for i, g in enumerate(granules)]
    return b''.join(pages)


def eog(ogg, pcm_size):
    return b'CRM\x00' + struct.pack('<I', pcm_size) + ogg


def build_pck(members):
    """Assemble a pack from (name, data) pairs, in the order given."""
    names = b''.join(name.encode('cp932') + b'\0' for name, _ in members)
    offset = 4 + 12 * len(members) + len(names)
    index = struct.pack('<I', len(members))
    for _, data in members:
        index += struct.pack('<III', 0, offset, len(data))
        offset += len(data)
    return index + names + b''.join(data for _, data in members)
