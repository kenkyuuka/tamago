import logging

from tamago.formats.ai6win import akb, lzss
from tamago.formats.ai6win.arcfile import (
    COMPRESSED_EXTENSIONS,
    MANIFEST_NAME,
    ARCFile,
    ARCInfo,
    decode_name,
    encode_name,
    is_ai6win_arc,
    should_compress,
)

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'COMPRESSED_EXTENSIONS',
    'MANIFEST_NAME',
    'ARCFile',
    'ARCInfo',
    'akb',
    'decode_name',
    'encode_name',
    'is_ai6win_arc',
    'lzss',
    'should_compress',
]
