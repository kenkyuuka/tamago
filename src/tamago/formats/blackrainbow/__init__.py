import logging

from tamago.formats.blackrainbow import lzss
from tamago.formats.blackrainbow.bmd import BMD_MAGIC, bmd_to_png, decode_bmd, encode_bmd, is_bmd, png_to_bmd
from tamago.formats.blackrainbow.datfile import (
    KIND_IMAGE,
    KIND_READ,
    KIND_SCRIPT,
    KIND_SOUND,
    KINDS,
    MANIFEST_NAME,
    DATFile,
    DATInfo,
    is_advdx_dat,
)

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'BMD_MAGIC',
    'KINDS',
    'KIND_IMAGE',
    'KIND_READ',
    'KIND_SCRIPT',
    'KIND_SOUND',
    'MANIFEST_NAME',
    'DATFile',
    'DATInfo',
    'bmd_to_png',
    'decode_bmd',
    'encode_bmd',
    'is_advdx_dat',
    'is_bmd',
    'lzss',
    'png_to_bmd',
]
