import logging

from tamago.formats.scumm.audio import sound_to_wav, wav_bytes
from tamago.formats.scumm.blocks import XOR_KEY, Block, BlockError, deobfuscate, detect_key, iter_blocks
from tamago.formats.scumm.hefile import (
    KIND_INDEX,
    KIND_MUSIC,
    KIND_ROOMS,
    KIND_SPEECH,
    HEFile,
    Member,
    file_kind,
    is_he_file,
)
from tamago.formats.scumm.index import Index, parse_index

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'KIND_INDEX',
    'KIND_MUSIC',
    'KIND_ROOMS',
    'KIND_SPEECH',
    'XOR_KEY',
    'Block',
    'BlockError',
    'HEFile',
    'Index',
    'Member',
    'deobfuscate',
    'detect_key',
    'file_kind',
    'is_he_file',
    'iter_blocks',
    'parse_index',
    'sound_to_wav',
    'wav_bytes',
]
