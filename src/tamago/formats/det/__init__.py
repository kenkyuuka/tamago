import logging

from tamago.formats.det.detfile import DETFile, DETInfo

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'DETFile',
    'DETInfo',
]
