"""Humongous sound blocks (DIGI, TALK, WSOU) to WAV."""

from __future__ import annotations

import struct

import construct

from tamago.formats.scumm.blocks import Block, BlockError, iter_blocks
from tamago.formats.scumm.structs import SoundHeader

SOUND_TAGS = frozenset({'SOUN', 'DIGI', 'TALK', 'WSOU'})


def wav_bytes(samples: bytes, rate: int, *, bits: int = 8, channels: int = 1) -> bytes:
    """A PCM WAV file holding *samples*."""
    block_align = channels * bits // 8
    fmt = struct.pack('<HHIIHH', 1, channels, rate, rate * block_align, block_align, bits)
    data = struct.pack('<4sI', b'data', len(samples)) + samples
    if len(samples) % 2:
        data += b'\0'  # RIFF chunks are word-aligned
    body = b'WAVE' + struct.pack('<4sI', b'fmt ', len(fmt)) + fmt + data
    return struct.pack('<4sI', b'RIFF', len(body)) + body


def _unwrap(block: Block) -> Block:
    """The DIGI/TALK/WSOU inside a SOUN wrapper (or *block* itself)."""
    if block.tag != 'SOUN':
        return block
    children = block.try_children()
    if not children or children[0].tag not in SOUND_TAGS - {'SOUN'}:
        raise ValueError("SOUN holds no digital sound")
    return children[0]


def sound_to_wav(block: Block) -> bytes:
    """Convert a sound block (``SOUN``, ``DIGI``, ``TALK`` or ``WSOU``) to a WAV file.

    ``DIGI``/``TALK`` hold 8-bit unsigned mono PCM at the ``HSHD`` sample rate;
    the header's bits/channels fields are ignored, as the engine does. A
    ``WSOU`` already wraps a WAV file. Raises :class:`ValueError` for anything else.
    """
    block = _unwrap(block)
    if block.tag == 'WSOU':
        body = block.body
        if body[:4] != b'RIFF':
            raise ValueError("WSOU holds no RIFF data")
        return body
    if block.tag not in ('DIGI', 'TALK'):
        raise ValueError(f"{block.tag} is not a digital sound")
    try:
        children = list(iter_blocks(block.data, block.body_offset, block.end))
    except BlockError as e:
        raise ValueError(f"malformed {block.tag}: {e}") from None
    header = next((c for c in children if c.tag == 'HSHD'), None)
    sdat = next((c for c in children if c.tag == 'SDAT'), None)
    if header is None or sdat is None:
        raise ValueError(f"{block.tag} lacks HSHD or SDAT")
    try:
        rate = SoundHeader.parse(header.body).rate
    except construct.ConstructError as e:
        raise ValueError(f"malformed HSHD: {e}") from None
    if rate == 0:
        raise ValueError("HSHD gives a sample rate of 0")
    return wav_bytes(sdat.body, rate)
