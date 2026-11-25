import logging

from tamago.formats.silky.arcfile import (
    COMPRESSED_EXTENSIONS,
    MANIFEST_NAME,
    ARCFile,
    ARCInfo,
    decode_name,
    encode_name,
    is_silky_arc,
    should_compress,
)

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'COMPRESSED_EXTENSIONS',
    'MANIFEST_NAME',
    'ARCFile',
    'ARCInfo',
    'decode_name',
    'encode_name',
    'is_silky_arc',
    'should_compress',
]
