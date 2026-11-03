import logging

from tamago.formats.rpa.rpafile import RPAFile, RPAInfo, RPASegment

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'RPAFile',
    'RPAInfo',
    'RPASegment',
]
