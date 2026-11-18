import logging

from tamago.formats.psb.crypt import Keystream, recover_key
from tamago.formats.psb.psbfile import KNOWN_KEYS, PSB, PSBError, decrypt, find_key, is_psb, read, read_file
from tamago.formats.psb.values import ExtraResource, Float32, IntArray, Resource

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'KNOWN_KEYS',
    'PSB',
    'ExtraResource',
    'Float32',
    'IntArray',
    'Keystream',
    'PSBError',
    'Resource',
    'decrypt',
    'find_key',
    'is_psb',
    'read',
    'read_file',
    'recover_key',
]
