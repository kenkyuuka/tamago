import logging

from tamago.formats.advhd.arcfile import (
    ARCFile,
    ARCInfo,
    decompress_psp,
    decrypt_script,
    encrypt_script,
    is_script_file,
)

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'ARCFile',
    'ARCInfo',
    'decompress_psp',
    'decrypt_script',
    'encrypt_script',
    'is_script_file',
]
