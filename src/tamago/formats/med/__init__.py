import logging

from tamago.formats.med.medfile import (
    MEDFile,
    MEDInfo,
    decrypt_script,
    encrypt_script,
    is_med_header,
    recover_keyword,
)

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'MEDFile',
    'MEDInfo',
    'decrypt_script',
    'encrypt_script',
    'is_med_header',
    'recover_keyword',
]
