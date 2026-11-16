import logging

from tamago.formats.anim.eog import is_eog, pcm_size, unwrap_eog, wrap_ogg
from tamago.formats.anim.pckfile import PCKFile, PCKInfo, is_pck

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'PCKFile',
    'PCKInfo',
    'is_eog',
    'is_pck',
    'pcm_size',
    'unwrap_eog',
    'wrap_ogg',
]
