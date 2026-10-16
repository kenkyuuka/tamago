import logging

from tamago.formats.xfl.collation import lstrcmpi_key
from tamago.formats.xfl.xflfile import XFL_MAGIC, XFLFile, XFLInfo

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'XFL_MAGIC',
    'XFLFile',
    'XFLInfo',
    'lstrcmpi_key',
]
